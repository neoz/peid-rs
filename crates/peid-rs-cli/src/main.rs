use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{ArgGroup, Parser};
use memmap2::Mmap;
use rayon::prelude::*;
use walkdir::WalkDir;

use peid_rs::binary::{BinaryFormat, BinaryParseError, BinaryView, DotNetInfo};
use peid_rs::db::{parse_db_lossy, SigSource};
use peid_rs::scanner::{scan, Mode};
use peid_rs::section_db::{detect_pe as detect_pe_sections, SectionHit};
use peid_rs::signature::{Signature, SignatureDb};
use peid_rs::toolchain::{detect as detect_toolchain, ToolchainInfo};

#[derive(Parser, Debug)]
#[command(
    name = "peid-rs",
    version,
    about = "PEiD signature scanner (PE / ELF / Mach-O)",
    group = ArgGroup::new("mode").args(["norm", "deep", "hard"]).multiple(false),
)]
struct Args {
    paths: Vec<PathBuf>,

    #[arg(long = "norm", help = "Normal scan (default): match at the entry point")]
    norm: bool,
    #[arg(long = "deep", help = "Deep scan: search the entry section")]
    deep: bool,
    #[arg(long = "hard", help = "Hardcore scan: search the entire file")]
    hard: bool,

    #[arg(short = 'r', help = "Recurse into subdirectories")]
    recurse: bool,
    #[arg(long = "nr", help = "Do not recurse (overrides -r)")]
    no_recurse: bool,

    #[arg(long = "time", help = "Print statistics on exit")]
    time: bool,

    #[arg(long = "raw", help = "Treat input as headerless blob; force whole-file scan")]
    raw: bool,

    #[arg(long = "db", value_name = "FILE", help = "Override userdb.txt path")]
    db: Option<PathBuf>,
    #[arg(long = "ext", value_name = "FILE", help = "Override external.txt path")]
    ext: Option<PathBuf>,
    #[arg(long = "no-ext", help = "Skip external.txt")]
    no_ext: bool,

    #[arg(long = "json", help = "Emit one JSON object per file (JSONL)")]
    json: bool,
}

fn main() -> Result<()> {
    let argv = preprocess_argv(std::env::args().collect());
    let args = Args::parse_from(argv);

    if args.paths.is_empty() {
        anyhow::bail!("no input paths; pass files or directories");
    }

    let mode = if args.hard || args.raw {
        Mode::Hardcore
    } else if args.deep {
        Mode::Deep
    } else {
        Mode::Normal
    };
    let recurse = args.recurse && !args.no_recurse;

    let started = Instant::now();
    let (db, skipped) = load_db(&args)?;
    let load_elapsed = started.elapsed();

    let files = collect_files(&args.paths, recurse);

    let scanned = AtomicUsize::new(0);
    let identified = AtomicUsize::new(0);
    let unrecognized = AtomicUsize::new(0);
    let pe_files = AtomicUsize::new(0);
    let elf_files = AtomicUsize::new(0);
    let macho_files = AtomicUsize::new(0);
    let dotnet_files = AtomicUsize::new(0);

    let results: Vec<(PathBuf, String)> = files
        .par_iter()
        .map(|path| {
            scanned.fetch_add(1, Ordering::Relaxed);
            let line = match scan_file(path, &db, mode, args.raw) {
                Ok(result) => {
                    match result.outcome() {
                        Outcome::SignatureHit | Outcome::SectionHit => {
                            identified.fetch_add(1, Ordering::Relaxed);
                        }
                        Outcome::Unrecognized => {
                            unrecognized.fetch_add(1, Ordering::Relaxed);
                        }
                        Outcome::DotNetFallback | Outcome::Nothing => {}
                    }
                    match result.format {
                        Some(BinaryFormat::Pe) => {
                            pe_files.fetch_add(1, Ordering::Relaxed);
                        }
                        Some(BinaryFormat::Elf) => {
                            elf_files.fetch_add(1, Ordering::Relaxed);
                        }
                        Some(BinaryFormat::MachO) => {
                            macho_files.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {}
                    }
                    if result.is_dotnet {
                        dotnet_files.fetch_add(1, Ordering::Relaxed);
                    }
                    if args.json {
                        render_json(path, &result)
                    } else {
                        render_text(&result, &db)
                    }
                }
                Err(e) => {
                    if args.json {
                        format!(
                            "{{\"path\":{},\"error\":{}}}",
                            serde_json::Value::String(path.display().to_string()),
                            serde_json::Value::String(format!("{}", e))
                        )
                    } else {
                        format!("{}", e)
                    }
                }
            };
            (path.clone(), line)
        })
        .collect();

    for (path, line) in &results {
        if args.json {
            println!("{}", line);
        } else {
            println!("{} : {}", path.display(), line);
        }
    }

    if args.time {
        let elapsed = started.elapsed();
        eprintln!();
        eprintln!("--- statistics ---");
        eprintln!("signatures loaded : {} (skipped {})", db.len(), skipped);
        eprintln!("files scanned     : {}", scanned.load(Ordering::Relaxed));
        eprintln!(
            "  PE              : {}",
            pe_files.load(Ordering::Relaxed)
        );
        eprintln!(
            "  ELF             : {}",
            elf_files.load(Ordering::Relaxed)
        );
        eprintln!(
            "  Mach-O          : {}",
            macho_files.load(Ordering::Relaxed)
        );
        eprintln!(
            "  .NET assemblies : {}",
            dotnet_files.load(Ordering::Relaxed)
        );
        eprintln!(
            "identified        : {}",
            identified.load(Ordering::Relaxed)
        );
        eprintln!(
            "unrecognized      : {}",
            unrecognized.load(Ordering::Relaxed)
        );
        eprintln!("db load time      : {:.3?}", load_elapsed);
        eprintln!("total time        : {:.3?}", elapsed);
    }

    Ok(())
}

fn preprocess_argv(mut argv: Vec<String>) -> Vec<String> {
    for arg in argv.iter_mut().skip(1) {
        if let Some(rest) = arg.strip_prefix('-') {
            if !rest.starts_with('-') && rest.len() >= 2 && rest.chars().all(|c| c.is_ascii_alphabetic() || c == '_') {
                *arg = format!("--{}", rest);
            }
        }
    }
    argv
}

struct ScanResult {
    format: Option<BinaryFormat>,
    arch: Option<String>,
    is_dotnet: bool,
    finding: Finding,
    toolchain: ToolchainInfo,
}

enum Finding {
    Signature {
        name: String,
        source: SigSource,
    },
    Section {
        packer: String,
        section: String,
    },
    DotNet {
        label: String,
    },
    Nothing,
    Unrecognized {
        reason: String,
    },
}

impl ScanResult {
    fn outcome(&self) -> Outcome {
        match self.finding {
            Finding::Signature { .. } => Outcome::SignatureHit,
            Finding::Section { .. } => Outcome::SectionHit,
            Finding::DotNet { .. } => Outcome::DotNetFallback,
            Finding::Nothing => Outcome::Nothing,
            Finding::Unrecognized { .. } => Outcome::Unrecognized,
        }
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    SignatureHit,
    SectionHit,
    DotNetFallback,
    Nothing,
    Unrecognized,
}

fn scan_file(path: &Path, db: &SignatureDb, mode: Mode, raw: bool) -> Result<ScanResult> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("mmapping {}", path.display()))?;

    if raw {
        let view = BinaryView {
            format: BinaryFormat::Pe,
            arch: peid_rs::Arch::Other("raw".into()),
            dotnet: None,
            entry_point_offset: None,
            entry_section: None,
            bytes: &mmap,
        };
        let hit = scan(db, &view, Mode::Hardcore);
        return Ok(build_result(
            None,
            None,
            false,
            hit,
            None,
            None,
            ToolchainInfo::default(),
        ));
    }

    match BinaryView::parse(&mmap) {
        Ok(view) => {
            let format = Some(view.format);
            let arch = Some(view.arch.as_str().to_string());
            let is_dotnet = view.dotnet.is_some();
            let hit = scan(db, &view, mode);
            let section_hit = if hit.is_none() {
                detect_pe_sections(&view)
            } else {
                None
            };
            let toolchain = detect_toolchain(&view);
            Ok(build_result(
                format,
                arch,
                is_dotnet,
                hit,
                section_hit,
                view.dotnet.as_ref(),
                toolchain,
            ))
        }
        Err(BinaryParseError::Unrecognized) => Ok(ScanResult {
            format: None,
            arch: None,
            is_dotnet: false,
            finding: Finding::Unrecognized {
                reason: "unrecognized format".to_string(),
            },
            toolchain: ToolchainInfo::default(),
        }),
        Err(BinaryParseError::Goblin(s)) => Ok(ScanResult {
            format: None,
            arch: None,
            is_dotnet: false,
            finding: Finding::Unrecognized { reason: s },
            toolchain: ToolchainInfo::default(),
        }),
    }
}

fn build_result(
    format: Option<BinaryFormat>,
    arch: Option<String>,
    is_dotnet: bool,
    hit: Option<&Signature>,
    section_hit: Option<SectionHit>,
    dotnet: Option<&DotNetInfo>,
    toolchain: ToolchainInfo,
) -> ScanResult {
    let finding = if let Some(sig) = hit {
        Finding::Signature {
            name: sig.name.clone(),
            source: sig.source,
        }
    } else if let Some(s) = section_hit {
        Finding::Section {
            packer: s.packer.to_string(),
            section: s.section,
        }
    } else if let Some(info) = dotnet {
        Finding::DotNet {
            label: dotnet_label(info),
        }
    } else {
        Finding::Nothing
    };
    ScanResult {
        format,
        arch,
        is_dotnet,
        finding,
        toolchain,
    }
}

fn render_text(result: &ScanResult, db: &SignatureDb) -> String {
    let tag = format_tag(result.format, result.arch.as_deref(), result.is_dotnet);
    let body = match &result.finding {
        Finding::Signature { name, source } => {
            let prefix = if matches!(source, SigSource::External) { "* " } else { "" };
            format!("{}{}{}", tag, prefix, name)
        }
        Finding::Section { packer, section } => {
            format!("{}{} [section: {}]", tag, packer, section)
        }
        Finding::DotNet { label } => format!("{}{}", tag, label),
        Finding::Nothing => {
            let suffix = if db.has_external { " *" } else { "" };
            format!("{}Nothing found{}", tag, suffix)
        }
        Finding::Unrecognized { reason } => {
            if reason == "unrecognized format" {
                "Unrecognized binary format".to_string()
            } else {
                format!("Not a valid binary ({})", reason)
            }
        }
    };
    let mut bits: Vec<String> = Vec::new();
    if let Some(l) = &result.toolchain.linker {
        bits.push(format!("linker {}", l));
    }
    if let Some(c) = &result.toolchain.compiler {
        bits.push(format!("compiler {}", c));
    }
    if let Some(p) = &result.toolchain.platform {
        bits.push(format!("platform {}", p));
    }
    if bits.is_empty() {
        body
    } else {
        format!("{}  [{}]", body, bits.join("; "))
    }
}

fn render_json(path: &Path, result: &ScanResult) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "path".to_string(),
        serde_json::Value::String(path.display().to_string()),
    );
    obj.insert(
        "format".to_string(),
        match result.format {
            Some(BinaryFormat::Pe) => serde_json::Value::String("PE".into()),
            Some(BinaryFormat::Elf) => serde_json::Value::String("ELF".into()),
            Some(BinaryFormat::MachO) => serde_json::Value::String("Mach-O".into()),
            None => serde_json::Value::Null,
        },
    );
    obj.insert(
        "arch".to_string(),
        match &result.arch {
            Some(a) => serde_json::Value::String(a.clone()),
            None => serde_json::Value::Null,
        },
    );
    obj.insert(
        "dotnet".to_string(),
        serde_json::Value::Bool(result.is_dotnet),
    );
    let (detector, name, source, section) = match &result.finding {
        Finding::Signature { name, source } => (
            "signature",
            Some(name.clone()),
            Some(match source {
                SigSource::Internal => "internal",
                SigSource::External => "external",
            }),
            None,
        ),
        Finding::Section { packer, section } => {
            ("section", Some(packer.clone()), None, Some(section.clone()))
        }
        Finding::DotNet { label } => ("dotnet", Some(label.clone()), None, None),
        Finding::Nothing => ("none", None, None, None),
        Finding::Unrecognized { reason } => ("unrecognized", Some(reason.clone()), None, None),
    };
    obj.insert(
        "detector".to_string(),
        serde_json::Value::String(detector.to_string()),
    );
    obj.insert(
        "result".to_string(),
        name.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
    );
    obj.insert(
        "source".to_string(),
        source
            .map(|s| serde_json::Value::String(s.to_string()))
            .unwrap_or(serde_json::Value::Null),
    );
    obj.insert(
        "section".to_string(),
        section.map(serde_json::Value::String).unwrap_or(serde_json::Value::Null),
    );

    let mut tc = serde_json::Map::new();
    tc.insert(
        "linker".to_string(),
        result
            .toolchain
            .linker
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    tc.insert(
        "compiler".to_string(),
        result
            .toolchain
            .compiler
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    tc.insert(
        "platform".to_string(),
        result
            .toolchain
            .platform
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
    );
    obj.insert("toolchain".to_string(), serde_json::Value::Object(tc));

    serde_json::Value::Object(obj).to_string()
}

fn format_tag(format: Option<BinaryFormat>, arch: Option<&str>, is_dotnet: bool) -> String {
    let fmt = match format {
        Some(BinaryFormat::Pe) => "PE",
        Some(BinaryFormat::Elf) => "ELF",
        Some(BinaryFormat::MachO) => "Mach-O",
        None => return String::new(),
    };
    let dotnet = if is_dotnet { " .NET" } else { "" };
    match arch {
        Some(a) => format!("({}{} {}) ", fmt, dotnet, a),
        None => format!("({}{}) ", fmt, dotnet),
    }
}

fn dotnet_label(info: &DotNetInfo) -> String {
    let kind = if info.runtime_version.0 >= 2 && !info.metadata_version.is_empty() {
        if info.metadata_version.starts_with("v4") {
            ".NET Framework/Core"
        } else if info.metadata_version.starts_with("v2") {
            ".NET Framework v2"
        } else {
            ".NET"
        }
    } else {
        ".NET"
    };
    let mode = if info.mixed_mode {
        "mixed mode"
    } else {
        "IL only"
    };
    let ver = if info.metadata_version.is_empty() {
        format!("{}.{}", info.runtime_version.0, info.runtime_version.1)
    } else {
        info.metadata_version.clone()
    };
    format!("{} {} ({})", kind, ver, mode)
}

fn load_db(args: &Args) -> Result<(SignatureDb, usize)> {
    let mut sigs = Vec::new();
    let mut skipped_total = 0usize;

    let main = args
        .db
        .clone()
        .or_else(|| resolve_db_default("userdb.txt"))
        .context(
            "could not locate userdb.txt; pass --db or run from a directory containing it",
        )?;
    let body = read_db_text(&main)?;
    let outcome = parse_db_lossy(&body, SigSource::Internal);
    skipped_total += outcome.skipped.len();
    sigs.extend(outcome.signatures);

    if !args.no_ext {
        let ext = args.ext.clone().or_else(|| resolve_db_default("external.txt"));
        if let Some(p) = ext {
            if p.exists() {
                let body = read_db_text(&p)?;
                let outcome = parse_db_lossy(&body, SigSource::External);
                skipped_total += outcome.skipped.len();
                sigs.extend(outcome.signatures);
            }
        }
    }

    Ok((SignatureDb::build(sigs), skipped_total))
}

fn read_db_text(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn resolve_db_default(name: &str) -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = {
        let mut v = vec![PathBuf::from(name)];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join(name));
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            v.push(cwd.join("app-peid").join(name));
            if let Some(parent) = cwd.parent() {
                v.push(parent.join("app-peid").join(name));
            }
        }
        v
    };
    candidates.into_iter().find(|p| p.is_file())
}

fn collect_files(paths: &[PathBuf], recurse: bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_file() {
            out.push(p.clone());
        } else if p.is_dir() {
            let walker = if recurse {
                WalkDir::new(p)
            } else {
                WalkDir::new(p).max_depth(1)
            };
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    out.push(entry.into_path());
                }
            }
        }
    }
    out
}
