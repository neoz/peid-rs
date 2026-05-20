# peid-rs

A Rust port of [PEiD][peid]'s signature-matching engine and CLI, extended to
work across PE, ELF, and Mach-O binaries (x86 / x86_64 / ARM / AArch64), with
.NET assembly detection and a section-name heuristic that catches modern
packers — including VMProtect 3.x — that obfuscate the entry point.

PEiD's original `userdb.txt` / `external.txt` signature databases are reused
unchanged: ~4,400 signatures load in ~50 ms.

[peid]: https://en.wikipedia.org/wiki/PEiD

## Build

```
cargo build --release
```

The CLI binary lands at `target/release/peid-rs[.exe]`.

## Usage

```
peid-rs [OPTIONS] <PATHS>...
```

| Flag             | Effect                                                       |
| ---------------- | ------------------------------------------------------------ |
| `-norm`          | Normal scan (default): match at the entry point              |
| `-deep`          | Deep scan: search the entry-point's section                  |
| `-hard`          | Hardcore scan: search the entire file                        |
| `-r`             | Recurse into subdirectories                                  |
| `-nr`            | Do not recurse (overrides `-r`)                              |
| `-time`          | Print statistics on exit                                     |
| `--raw`          | Treat input as a headerless blob; force whole-file scan      |
| `--db <FILE>`    | Override `userdb.txt` path                                   |
| `--ext <FILE>`   | Override `external.txt` path                                 |
| `--no-ext`       | Skip `external.txt`                                          |
| `--json`         | Emit one JSON object per file (JSONL)                        |

Both single-dash (`-norm`) and double-dash (`--norm`) forms work, mirroring
PEiD's original CLI.

### Examples

```
peid-rs PEiD.exe
PEiD.exe : (PE x86) UPX -> www.upx.sourceforge.net

peid-rs -r C:\tools
... one line per scanned file ...

peid-rs --db userdb.txt --json *.exe | jq .

peid-rs -hard -time --no-ext C:\suspicious.bin
```

### Output

```
<path> : (<format> [.NET] <arch>) <result>
```

Examples:

```
foo.exe       : (PE x86)            UPX -> www.upx.sourceforge.net
managed.dll   : (PE .NET x86)       Microsoft Visual C# / Basic .NET
linux.so      : (ELF aarch64)       Nothing found *
mac.dylib     : (Mach-O x86_64)     Nothing found *
vmp.exe       : (PE x86_64)         VMProtect 3.x (heuristic) [section: .qWo, .xz@]
```

Conventions inherited from PEiD:

- A `*` prefix on a signature name → match came from `external.txt`.
- A trailing `*` on `Nothing found` → `external.txt` was consulted.
- `(PE .NET x86)` → CLR header was found in the PE; the binary is a .NET
  assembly.

## How detection works

Three detectors run in order; the first to fire wins:

1. **Byte signatures** (PEiD format, wildcards via `??`). Scanned at either
   the entry point (Normal), the EP section (Deep), or the whole file
   (Hardcore). A first-byte bucket index keeps Hardcore fast even on
   multi-MB binaries.
2. **Section-name detector** (PE only). Catches a few dozen packers via
   distinctive section names (`UPX0`, `.aspack`, `.themida`, `.enigma1`,
   `.MPRESS1`, `FSG!`, ...), plus a heuristic for VMProtect 3.x that flags
   PE files with multiple short `.XYZ` sections outside the standard set
   where at least one is large enough to plausibly hold a VM payload.
3. **.NET fallback**. If no signature or section rule fired but the PE has
   a CLR data directory, the result reports the .NET runtime version and IL
   / mixed-mode flag.

## Supported binaries

|              | PE  | ELF | Mach-O |
| ------------ | --- | --- | ------ |
| x86          | yes | yes | yes    |
| x86_64       | yes | yes | yes    |
| ARM / Thumb  | yes | yes | yes    |
| AArch64      | yes | yes | yes    |
| MIPS / RISC-V / PowerPC | parsed; signatures may not match (DB is mostly x86 stubs) |

The PEiD signature database is overwhelmingly composed of x86 entry-point
stubs. Non-x86 binaries will parse correctly and report `(Format arch)
Nothing found *` unless they happen to share a stub shape with an x86 entry
(rare but does occur for some Linux UPX builds).

## Signature database

`userdb.txt` is loaded from, in order:

1. `--db <path>` if supplied.
2. `./userdb.txt` (current directory).
3. The binary's directory.
4. `app-peid/userdb.txt` relative to the current directory or its parent.

`external.txt` is loaded the same way; pass `--no-ext` to skip it entirely.

Malformed signatures (typos, bad hex tokens) are silently dropped; the
`-time` summary shows how many were skipped.

## Library

The engine is published as the `peid-rs` library crate inside this
workspace; the CLI is the thin `peid-rs-cli` binary on top. Direct embedding:

```rust
use peid_rs::{BinaryView, SignatureDb, scan, Mode};
use peid_rs::db::{parse_db_lossy, SigSource};

let body = std::fs::read_to_string("userdb.txt")?;
let db = SignatureDb::build(parse_db_lossy(&body, SigSource::Internal).signatures);

let bytes = std::fs::read("target.exe")?;
let view = BinaryView::parse(&bytes)?;
if let Some(sig) = scan(&db, &view, Mode::Normal) {
    println!("{}", sig.name);
}
```

## Status

v1: PE / ELF / Mach-O parsing, byte-signature engine, section-name detector
with VMProtect 3.x heuristic, .NET detection, three scan modes plus
`--raw`, parallel directory scanning, text and JSONL output.

Not yet: .NET-specific signature database, Rich-header MSVC version
detection, plugin support.

## License

MIT OR Apache-2.0
