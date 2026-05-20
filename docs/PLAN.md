# peid-rs — Implementation Plan

A Rust port of PEiD's signature-matching engine and CLI, reusing the original
`userdb.txt` and `external.txt` signature databases, extended with multi-format
binary support (PE / ELF / Mach-O, x86 / x86_64 / ARM / AArch64) and .NET
assembly detection.

## Goals

- Identify packers / cryptors / compilers in executable files via byte-pattern
  signatures, reusing PEiD's existing DB files unchanged.
- Match PEiD's CLI surface where reasonable (`-norm`, `-deep`, `-hard`, `-r`,
  `-nr`, `-time`, positional paths).
- Support PE, ELF, and Mach-O across x86 / x86_64 / ARM / AArch64.
- Detect .NET assemblies as a first-class fact (groundwork for future .NET
  packer detection).

## Non-goals (v1)

- No GUI, task viewer, hex viewer, disassembler.
- No PEiD plugins (Win32 DLL ABI).
- No heuristic / modified-file scanning beyond what Deep + Hardcore inherently
  give.
- No .NET-specific signature DB, no metadata-stream walker, no IL parsing.
- No Rich-header compiler classification.
- No single-file .NET deployment unbundling.

## Repository layout

```
peid-rs/
  Cargo.toml                # workspace root
  docs/
    PLAN.md                 # this file
  app-peid/                 # PEiD reference assets (read-only)
    userdb.txt
    external.txt
    PEiD.exe
    readme.txt
  crates/
    peid-rs/                # engine library
      Cargo.toml
      src/
        lib.rs              # public re-exports
        binary.rs           # BinaryView / BinaryFormat / Arch / DotNetInfo
        db/
          mod.rs
          parser.rs         # PEiD INI parser
        signature.rs        # Signature, Token, SignatureDb (first-byte buckets)
        scanner.rs          # Normal / Deep / Hardcore / Raw modes
        stats.rs            # counters + timing
    peid-rs-cli/            # binary `peid-rs`
      Cargo.toml
      src/main.rs
```

## Dependencies

- `goblin`   — PE + ELF + Mach-O parsing
- `clap`     — CLI args (derive)
- `walkdir`  — recursive directory scanning
- `memmap2`  — large-file mmap for Hardcore
- `rayon`   — parallel file scan
- `anyhow`   — CLI-boundary error context

No `serde`, no `aho-corasick`. First-byte bucketing covers Hardcore performance.

## Data model

```rust
// signature.rs
pub enum Token { Byte(u8), Wildcard }

pub struct Signature {
    pub name: String,
    pub pattern: Vec<Token>,
    pub ep_only: bool,
    pub source: SigSource,    // Internal (userdb.txt) | External (external.txt)
}

pub struct SignatureDb {
    sigs: Vec<Signature>,
    by_first: [Vec<u32>; 256],  // sigs indexed by their first concrete byte
    wild_start: Vec<u32>,       // sigs that begin with a wildcard
}

// binary.rs
pub enum BinaryFormat { Pe, Elf, MachO }

pub enum Arch {
    X86, X86_64, Arm, AArch64, Mips, MipsLE, RiscV, PowerPc, Other(&'static str),
}

pub struct DotNetInfo {
    pub runtime_version: (u16, u16),
    pub metadata_version: String,
    pub il_only: bool,
    pub mixed_mode: bool,
    pub requires_32bit: bool,
    pub prefers_32bit: bool,
    pub strong_named: bool,
    pub native_entry_point: bool,
    pub entry_token_or_rva: u32,
}

pub struct BinaryView<'a> {
    pub format: BinaryFormat,
    pub arch: Arch,
    pub dotnet: Option<DotNetInfo>,
    pub entry_point_offset: Option<usize>,
    pub entry_section: Option<std::ops::Range<usize>>,
    pub bytes: &'a [u8],
}
```

## DB parser

PEiD format, line-oriented:

```
;comment
[Display name]
signature = 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10
ep_only = true
```

Parser contract:

- Strip BOM if present; accept CRLF or LF.
- Skip blank lines and `;`-prefixed comments.
- `[...]` opens a record; subsequent `key = value` lines fill it.
- A record commits on the next `[` or EOF.
- `signature` value: split on whitespace, each token is `??` → `Wildcard`, or
  two hex chars (any case) → `Byte`. Malformed token → return error with
  file/line context. Trailing `??` tokens are allowed.
- `ep_only` value: case-insensitive `true` / `false`.
- Default DB resolution (CLI layer): `--db <path>` → `./userdb.txt` →
  exe-dir / `userdb.txt` → `<workspace-root>/app-peid/userdb.txt`. Same for
  `external.txt`.

## Matcher + bucketing

```rust
fn matches(pattern: &[Token], hay: &[u8], at: usize) -> bool;
```

- Bounds check up front; returns false if `at + pattern.len() > hay.len()`.
- For each token: `Wildcard` skips, `Byte` compares.

`SignatureDb::build`:

- For each signature, find the offset of the first concrete byte (if any).
- Store the signature index in `by_first[that_byte]`.
- If the entire pattern is wildcards (degenerate) or begins with `??`, store
  in `wild_start`. At scan position `p`, try `by_first[hay[p]]` ∪ `wild_start`.

`scan_at(at)` matches the signature using the offset to align the concrete
byte at `hay[at]`. Concretely, if the signature's first concrete byte is at
position `k`, we test against `hay[at - k ..]` (skipped when `k > at`).

## Binary parsing

Single entry: `BinaryView::parse(bytes)`. Dispatch on goblin's `Object`:

- **PE**: walk section table, find section containing AddressOfEntryPoint,
  translate to file offset via `EP - virtual_address + pointer_to_raw_data`.
  `entry_section` = (raw_pointer .. raw_pointer + raw_size).
  Then check optional header data directory 14
  (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`); if non-zero, parse 72-byte
  `IMAGE_COR20_HEADER` at that RVA → `DotNetInfo`. Read metadata version
  string from `#~`-stream header.
- **ELF**: scan program headers for the `PT_LOAD` segment containing
  `e_entry`; EP file offset = `e_entry - p_vaddr + p_offset`. `entry_section`
  = that segment's file range.
- **Mach-O**: prefer `LC_MAIN` (its `entryoff` is already a file offset). Fall
  back to `LC_UNIXTHREAD` → resolve via `__TEXT,__text`. `entry_section` =
  `__TEXT,__text` file range.

Architecture mapping comes straight from goblin's machine fields. EP that
points outside any section / segment yields `entry_point_offset = None`
(scanner then skips EP / Deep modes for that file; Hardcore still works).

## Scanner

```rust
pub enum Mode { Normal, Deep, Hardcore, Raw }

pub fn scan<'a>(db: &SignatureDb, view: &BinaryView<'a>, mode: Mode) -> Option<&'a Signature>;
```

Mode semantics (first match wins):

- **Normal**: test each signature at `entry_point_offset`. `ep_only=true`
  signatures are tested only here; `ep_only=false` signatures are also tested
  here (PEiD behavior — non-EP sigs still tried at EP in normal mode).
- **Deep**: sliding-window scan over `entry_section`. Both flavors of sig.
- **Hardcore**: sliding-window scan over the entire mapped file.
- **Raw**: same as Hardcore but used when no header can be parsed; only
  reachable via the `--raw` CLI flag.

Scan-position lookup uses `db.by_first[hay[p]]` + `db.wild_start`.

## CLI

Binary name: `peid-rs`.

```
peid-rs [OPTIONS] <PATHS>...

  -norm                 Normal scan (default)
  -deep                 Deep scan (EP section)
  -hard                 Hardcore scan (entire file)
  -r                    Recurse into subdirectories
  -nr                   Do not recurse (overrides -r)
  -time                 Show statistics on exit
      --raw             Treat input as headerless blob; force whole-file scan
      --db <FILE>       Override userdb.txt path
      --ext <FILE>      Override external.txt path
      --no-ext          Skip external.txt
```

Scan-mode flags are an `ArgGroup` (mutually exclusive). Multi-file work is
parallelised with rayon; output is buffered per-file then printed in
deterministic input order. Exit code is always 0 unless a hard I/O error
occurs at startup (DB load failure, etc.). "Nothing found" is not a failure.

### Output format

```
<path>   (<format> [.NET] <arch>) : <result>
```

Examples:

```
C:\path\PEiD.exe        (PE x86)              : UPX 2.90 [LZMA] -> ...
C:\path\app.exe         (PE .NET x86)         : .NET Framework v4.0.30319 (IL only)
C:\path\fw.bin          (ELF aarch64)         : Nothing found *
C:\path\junk.bin                              : Unrecognized binary format
```

- `*` prefix on a sig name → match came from `external.txt`.
- Trailing `*` on "Nothing found" → external DB was consulted but found nothing.
- `.NET`-aware fallback only fires when no byte signature hit.

## Build sequence

1. Workspace scaffold + empty crates.
2. `db/parser.rs` + unit tests on inlined samples drawn from the real
   `userdb.txt` / `external.txt`.
3. `signature.rs` matcher + `SignatureDb` bucketing + tests covering:
   leading wildcards, all-wildcard pattern, boundary scan position.
4. `binary.rs` PE parsing + EP file-offset; test against `app-peid/PEiD.exe`.
5. `binary.rs` .NET detection (data dir 14 + CLI header + metadata version).
6. `binary.rs` ELF + Mach-O parsing.
7. `scanner.rs` Normal mode end-to-end.
8. Deep + Hardcore.
9. CLI crate: clap, walkdir, rayon, `-raw`, output formatter, `-time` stats.
10. Smoke test on `app-peid/PEiD.exe`; verify a known signature lights up.

## Defaults

- Symlinks during `-r`: not followed (`walkdir` default).
- File-size cap for mmap: none; let mmap fail naturally on edge cases.
- Color output: none in v1.
- Lowercase hex tokens in DB: accepted.
- BOM and CRLF in DB: accepted.

## Future work (out of v1)

- `.NET`-specific signature DB (`dotnet-userdb.txt`) loaded conditionally for
  CLR PEs; scan windows extended to CLI header + metadata + resources.
- Plaintext .NET-packer marker DB (`ConfusedByAttribute`, `SmartAssembly`, ...).
- Rich-header MSVC version detection.
- arch-tagged signatures + arch-aware scan filtering.
- Multiple-match reporting mode.
