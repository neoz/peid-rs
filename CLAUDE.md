# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / test / run

```
cargo check --workspace                # fast compile sanity
cargo test --workspace --quiet         # unit tests
cargo test -p peid-rs <name>           # single test by name substring
cargo run --quiet -- <args>            # debug build of the CLI
cargo build --release                  # release binary at target/release/peid-rs[.exe]
```

The CLI binary is `peid-rs` (not `peid-rs-cli`). PEiD's original single-dash
flags work via an argv preprocessor (`-norm`, `-deep`, `-hard`, `-r`, `-nr`,
`-time`), so both `-norm` and `--norm` are accepted.

For interactive smoke testing on Windows the default DB path
`./userdb.txt` resolves to the one at the repo root. To use the bundled
PEiD DB instead, pass `--db app-peid/userdb.txt`.

## Workspace layout

Two-crate Cargo workspace.

- `crates/peid-rs/` — engine library. Pure analysis; no I/O beyond what the
  caller passes in.
- `crates/peid-rs-cli/` — thin CLI on top. Owns clap, walkdir, rayon, mmap,
  output formatting.

`app-peid/` is the original PEiD distribution kept as untracked reference
assets — it has its own `.git/` and is listed in `.gitignore` at the repo
root. Do not commit or modify it. `target/` and `peid-rs.exe` at the root
are also gitignored.

## How a scan composes

`scan_file` in `crates/peid-rs-cli/src/main.rs` is the orchestration point.
On a successful `BinaryView::parse`, several detectors run and their
outputs are combined into a single `ScanResult`:

1. **`scanner::scan`** — byte-signature engine. Three modes (Normal at EP,
   Deep over the EP section, Hardcore over the whole file). `SignatureDb`
   uses first-byte bucketing to keep Hardcore fast on multi-MB binaries.
2. **`section_db::detect_pe`** — PE section-name rules (UPX, ASPack,
   Themida, ...) plus a VMProtect-3.x heuristic (≥2 short `.XYZ` sections
   outside the standard set with at least one ≥ 100 KB). Runs only as a
   fallback when the byte-sig scan returns `None`.
3. **`toolchain::detect`** — linker / compiler / language / platform.
4. **`entropy::analyze`** — Shannon entropy per section / segment.
5. **`imphash::compute`** — PE import hash (Mandiant algorithm).

For files goblin can't parse, `fileinfo::detect` runs instead and produces
either a magic-byte hit (PDF / PNG / ZIP / etc.) or a text classification
(encoding + line ending + content kind from a small sniffer + extension
hints).

The `Finding` enum in `main.rs` carries the chosen result. Both
`render_text` and `render_json` consume the same `ScanResult` so output
shapes stay in lockstep.

## Conventions that matter

- **PEiD DB files are not UTF-8.** Author names use Latin-1 / CP1252.
  `read_db_text` in the CLI reads bytes and decodes with
  `String::from_utf8_lossy`. Never call `std::fs::read_to_string` on
  `userdb.txt` / `external.txt`.
- **The DB parser is lossy by design.** `parse_db_lossy` drops individual
  malformed records (bad hex tokens, etc.) instead of aborting the load;
  the CLI surfaces a "skipped N" count under `-time`. Real-world
  `userdb.txt` files contain typos (`J3`, ...) that PEiD itself tolerates.
- **First match wins** for byte signatures, by design. The same name may
  appear under multiple `[section]` headers with different patterns —
  that's expected.
- **Do not add byte-pattern scans over `view.bytes` for language /
  detector heuristics.** The detector's own pattern literals get embedded
  in the compiled binary's `.rdata`, so the detector then detects itself
  when run on its own image (we hit this with the Rust panic-string and
  "Go build ID: " scans). Prefer section names, structured fields
  (linker version, optional headers, load commands), or magic-byte
  windows at known section offsets.
- **VMProtect 3.x heuristic** is intentionally loose: two or more short
  `.XYZ` sections outside the standard list (`STANDARD_SECTIONS` in
  `section_db.rs`) with at least one >= `LARGE_PAYLOAD_BYTES` (100 KB).
  If you tighten it, re-check both VMProtect.exe and VMProtect_Con.exe
  in the test corpus — they use different inserted-section layouts.
- **DB resolution order** (in `resolve_db_default`): `--db <path>` flag
  → `./userdb.txt` → `<exe dir>/userdb.txt` → `<cwd>/app-peid/userdb.txt`
  → `<cwd>/../app-peid/userdb.txt`. Same for `external.txt`. `--no-ext`
  skips the external DB entirely.

## Adding a new detector

If it produces a packer / compiler name:
- For PE/ELF/Mach-O byte-signature-style: add entries to `userdb.txt`.
  No code change.
- For section-name rules: edit `RULES` in `section_db.rs`.
- For a new heuristic that needs file structure inspection: add a module
  under `crates/peid-rs/src/`, expose a `detect(view: &BinaryView) -> ...`
  function, call it from `scan_file` in the CLI, add a new `Finding`
  variant if the result type doesn't fit existing ones.

If it produces toolchain info (compiler / linker / language / platform):
extend `toolchain.rs` for the relevant format. Keep the language check
section-name- or structured-field-based — see the self-scan caveat above.

JSON output is constructed in `render_json` in the CLI; add fields there
when a new piece of info should be machine-readable. Text output lives
in `render_text` and appends to a `[k v; k v; ...]` bracket suffix.

## Reference docs

- `docs/PLAN.md` — original v1 design plan (still mostly accurate).
- `README.md` — user-facing usage, CLI flags, output examples.
- `app-peid/readme.txt` — original PEiD documentation (CLI surface we
  model after, scan-mode definitions).
