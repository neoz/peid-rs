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
use peid_rs::signature::{Signature, SignatureDb};

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
                Ok(report) => {
                    match report.outcome {
                        Outcome::Hit => {
                            identified.fetch_add(1, Ordering::Relaxed);
                        }
                        Outcome::Nothing => {}
                        Outcome::Unrecognized => {
                            unrecognized.fetch_add(1, Ordering::Relaxed);
                        }
                        Outcome::DotNetFallback => {}
                    }
                    match report.format {
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
                    if report.is_dotnet {
                        dotnet_files.fetch_add(1, Ordering::Relaxed);
                    }
                    report.line
                }
                Err(e) => format!("{}", e),
            };
            (path.clone(), line)
        })
        .collect();

    for (path, line) in &results {
        println!("{} : {}", path.display(), line);
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

struct Report {
    line: String,
    outcome: Outcome,
    format: Option<BinaryFormat>,
    is_dotnet: bool,
}

enum Outcome {
    Hit,
    Nothing,
    DotNetFallback,
    Unrecognized,
}

fn scan_file(path: &Path, db: &SignatureDb, mode: Mode, raw: bool) -> Result<Report> {
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
        return Ok(format_report(None, None, false, hit, db, mode));
    }

    match BinaryView::parse(&mmap) {
        Ok(view) => {
            let hit = scan(db, &view, mode);
            Ok(format_report(
                Some(view.format),
                Some(view.arch.as_str().to_string()),
                view.dotnet.is_some(),
                hit,
                db,
                mode,
            ).with_dotnet(view.dotnet.as_ref()))
        }
        Err(BinaryParseError::Unrecognized) => Ok(Report {
            line: "Unrecognized binary format".to_string(),
            outcome: Outcome::Unrecognized,
            format: None,
            is_dotnet: false,
        }),
        Err(BinaryParseError::Goblin(s)) => Ok(Report {
            line: format!("Not a valid binary ({})", s),
            outcome: Outcome::Unrecognized,
            format: None,
            is_dotnet: false,
        }),
    }
}

impl Report {
    fn with_dotnet(mut self, dn: Option<&DotNetInfo>) -> Self {
        match (&self.outcome, dn) {
            (Outcome::Nothing, Some(info)) => {
                self.line = format!(
                    "{} : {}",
                    self.line.trim_end_matches(" *"),
                    dotnet_label(info)
                );
                self.outcome = Outcome::DotNetFallback;
            }
            _ => {}
        }
        self
    }
}

fn format_report(
    format: Option<BinaryFormat>,
    arch: Option<String>,
    is_dotnet: bool,
    hit: Option<&Signature>,
    db: &SignatureDb,
    _mode: Mode,
) -> Report {
    let tag = format_tag(format, arch.as_deref(), is_dotnet);
    match hit {
        Some(sig) => {
            let prefix = if matches!(sig.source, SigSource::External) {
                "* "
            } else {
                ""
            };
            Report {
                line: format!("{}{}{}", tag, prefix, sig.name),
                outcome: Outcome::Hit,
                format,
                is_dotnet,
            }
        }
        None => {
            let suffix = if db.has_external { " *" } else { "" };
            Report {
                line: format!("{}Nothing found{}", tag, suffix),
                outcome: Outcome::Nothing,
                format,
                is_dotnet,
            }
        }
    }
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
