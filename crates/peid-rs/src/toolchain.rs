use crate::binary::{BinaryFormat, BinaryView};

#[derive(Clone, Debug, Default)]
pub struct ToolchainInfo {
    pub linker: Option<String>,
    pub compiler: Option<String>,
    pub platform: Option<String>,
    pub source: ToolchainSource,
    pub rich_entries: Vec<RichEntry>,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum ToolchainSource {
    #[default]
    Unknown,
    PeOptionalHeader,
    RichHeader,
    PeOptionalAndRich,
    ElfComment,
    MachOBuildVersion,
}

#[derive(Clone, Debug)]
pub struct RichEntry {
    pub prod_id: u16,
    pub build: u16,
    pub count: u32,
    pub product: &'static str,
}

impl ToolchainInfo {
    pub fn is_empty(&self) -> bool {
        self.linker.is_none() && self.compiler.is_none() && self.platform.is_none()
    }
}

pub fn detect(view: &BinaryView<'_>) -> ToolchainInfo {
    match view.format {
        BinaryFormat::Pe => detect_pe(view),
        BinaryFormat::Elf => detect_elf(view),
        BinaryFormat::MachO => detect_macho(view),
    }
}

fn detect_pe(view: &BinaryView<'_>) -> ToolchainInfo {
    let pe = match goblin::pe::PE::parse(view.bytes) {
        Ok(pe) => pe,
        Err(_) => return ToolchainInfo::default(),
    };
    let mut info = ToolchainInfo::default();

    if let Some(opt) = pe.header.optional_header.as_ref() {
        let maj = opt.standard_fields.major_linker_version;
        let min = opt.standard_fields.minor_linker_version;
        if maj != 0 || min != 0 {
            info.linker = Some(format!(
                "{}.{}{}",
                maj,
                min,
                classify_msvc_linker(maj, min)
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default()
            ));
            info.source = ToolchainSource::PeOptionalHeader;
        }
    }

    if let Some(entries) = parse_rich_header(view.bytes) {
        let latest = entries.iter().max_by_key(|e| e.prod_id);
        let (label, build) = match latest {
            Some(e) => (e.product, e.build),
            None => ("MSVC", 0),
        };
        info.compiler = Some(format!(
            "{} (Rich: {} entries, latest build {})",
            label,
            entries.len(),
            build
        ));
        info.rich_entries = entries;
        info.source = match info.source {
            ToolchainSource::PeOptionalHeader => ToolchainSource::PeOptionalAndRich,
            _ => ToolchainSource::RichHeader,
        };
    }

    info
}

fn classify_msvc_linker(maj: u8, min: u8) -> Option<&'static str> {
    match (maj, min) {
        (6, 0) => Some("VC6"),
        (7, 0) => Some("VS .NET 2002"),
        (7, 1) => Some("VS .NET 2003"),
        (8, 0) => Some("VS 2005"),
        (9, 0) => Some("VS 2008"),
        (10, 0) => Some("VS 2010"),
        (11, 0) => Some("VS 2012"),
        (12, 0) => Some("VS 2013"),
        (14, 0) => Some("VS 2015"),
        (14, 10..=19) => Some("VS 2017"),
        (14, 20..=29) => Some("VS 2019"),
        (14, 30..=49) => Some("VS 2022"),
        (2, _) => Some("GNU ld / MinGW"),
        _ => None,
    }
}

fn parse_rich_header(bytes: &[u8]) -> Option<Vec<RichEntry>> {
    let scan_end = bytes.len().min(0x400);
    let region = &bytes[..scan_end];
    let mut rich_pos = None;
    let mut i = 0;
    while i + 4 <= region.len() {
        if &region[i..i + 4] == b"Rich" {
            rich_pos = Some(i);
            break;
        }
        i += 1;
    }
    let rich_pos = rich_pos?;
    if rich_pos + 8 > region.len() {
        return None;
    }
    let key = u32::from_le_bytes([
        region[rich_pos + 4],
        region[rich_pos + 5],
        region[rich_pos + 6],
        region[rich_pos + 7],
    ]);

    let mut dans_pos = None;
    let mut p = rich_pos;
    while p >= 4 {
        p -= 4;
        let w = u32::from_le_bytes([region[p], region[p + 1], region[p + 2], region[p + 3]]);
        if w ^ key == 0x536E_6144 {
            dans_pos = Some(p);
            break;
        }
        if rich_pos.saturating_sub(p) > 0x300 {
            break;
        }
    }
    let dans_pos = dans_pos?;

    let entries_start = dans_pos + 16;
    if entries_start >= rich_pos {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut q = entries_start;
    while q + 8 <= rich_pos {
        let cid = u32::from_le_bytes([region[q], region[q + 1], region[q + 2], region[q + 3]]) ^ key;
        let cnt = u32::from_le_bytes([
            region[q + 4],
            region[q + 5],
            region[q + 6],
            region[q + 7],
        ]) ^ key;
        let prod_id = (cid >> 16) as u16;
        let build = (cid & 0xFFFF) as u16;
        out.push(RichEntry {
            prod_id,
            build,
            count: cnt,
            product: classify_prod_id(prod_id),
        });
        q += 8;
    }
    Some(out)
}

fn classify_prod_id(prod_id: u16) -> &'static str {
    match prod_id {
        0x0001 => "Import (Total)",
        0x0002 => "Linker (Total)",
        0x0003 => "Cvtres",
        0x0004 => "Utc1_2_Asm (VC 1.20)",
        0x0005 => "Utc1_2_C (VC 1.20)",
        0x0006 => "Utc1_2_CPP (VC 1.20)",
        0x0007..=0x000C => "VC C/C++ compiler (5.x-6.0)",
        0x000D | 0x0015..=0x0017 => "VC 7.x C/C++",
        0x0018..=0x001D => "VS 2003 (VC 7.1)",
        0x002A..=0x0030 => "VS 2005 (VC 8.0)",
        0x003C..=0x0044 => "VS 2008 (VC 9.0)",
        0x004D..=0x005D => "VS 2010 (VC 10.0)",
        0x005E..=0x0067 => "VS 2012 (VC 11.0)",
        0x0078..=0x0083 => "VS 2013 (VC 12.0)",
        0x009A..=0x00A3 => "VS 2015 (VC 14.0)",
        0x00AA..=0x00B3 => "VS 2017 (VC 14.1)",
        0x00FD..=0x010D => "VS 2019 (VC 14.2)",
        0x010E..=0x0140 => "VS 2022 (VC 14.3)",
        _ => "MSVC tool",
    }
}

fn detect_elf(view: &BinaryView<'_>) -> ToolchainInfo {
    let elf = match goblin::elf::Elf::parse(view.bytes) {
        Ok(e) => e,
        Err(_) => return ToolchainInfo::default(),
    };
    let mut info = ToolchainInfo::default();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".comment" {
            let start = sh.sh_offset as usize;
            let end = start.saturating_add(sh.sh_size as usize).min(view.bytes.len());
            if start >= end {
                continue;
            }
            let buf = &view.bytes[start..end];
            let entries: Vec<String> = buf
                .split(|&b| b == 0)
                .filter_map(|s| std::str::from_utf8(s).ok())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            if entries.is_empty() {
                continue;
            }
            for s in &entries {
                if s.starts_with("GCC:") || s.contains("gcc version") {
                    info.compiler = Some(s.clone());
                } else if s.to_ascii_lowercase().contains("clang") {
                    info.compiler = Some(s.clone());
                } else if s.to_ascii_lowercase().contains("rust") {
                    info.compiler = Some(s.clone());
                }
            }
            if info.compiler.is_none() {
                info.compiler = entries.into_iter().next();
            }
            info.source = ToolchainSource::ElfComment;
            break;
        }
    }
    info
}

fn detect_macho(view: &BinaryView<'_>) -> ToolchainInfo {
    use goblin::mach::load_command::CommandVariant;
    use goblin::mach::Mach;
    let mach = match Mach::parse(view.bytes) {
        Ok(m) => m,
        Err(_) => return ToolchainInfo::default(),
    };
    let bin = match mach {
        Mach::Binary(b) => b,
        Mach::Fat(_) => return ToolchainInfo::default(),
    };
    let mut info = ToolchainInfo::default();
    for lc in bin.load_commands.iter() {
        match lc.command {
            CommandVariant::BuildVersion(bv) => {
                let platform = match bv.platform {
                    1 => "macOS",
                    2 => "iOS",
                    3 => "tvOS",
                    4 => "watchOS",
                    5 => "bridgeOS",
                    6 => "Mac Catalyst",
                    7 => "iOS simulator",
                    8 => "tvOS simulator",
                    9 => "watchOS simulator",
                    10 => "DriverKit",
                    _ => "unknown",
                };
                info.platform = Some(format!(
                    "{} minos={} sdk={}",
                    platform,
                    decode_macho_version(bv.minos),
                    decode_macho_version(bv.sdk),
                ));
                info.source = ToolchainSource::MachOBuildVersion;
            }
            CommandVariant::VersionMinMacosx(v) => {
                if info.platform.is_none() {
                    info.platform = Some(format!(
                        "macOS minos={} sdk={}",
                        decode_macho_version(v.version),
                        decode_macho_version(v.sdk),
                    ));
                    info.source = ToolchainSource::MachOBuildVersion;
                }
            }
            CommandVariant::VersionMinIphoneos(v) => {
                if info.platform.is_none() {
                    info.platform = Some(format!(
                        "iOS minos={} sdk={}",
                        decode_macho_version(v.version),
                        decode_macho_version(v.sdk),
                    ));
                    info.source = ToolchainSource::MachOBuildVersion;
                }
            }
            _ => {}
        }
    }
    info
}

fn decode_macho_version(v: u32) -> String {
    let major = (v >> 16) & 0xFFFF;
    let minor = (v >> 8) & 0xFF;
    let patch = v & 0xFF;
    if patch == 0 {
        format!("{}.{}", major, minor)
    } else {
        format!("{}.{}.{}", major, minor, patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_decode() {
        assert_eq!(decode_macho_version(0x000A_0F00), "10.15");
        assert_eq!(decode_macho_version(0x000B_0202), "11.2.2");
    }

    #[test]
    fn linker_classifier_known_versions() {
        assert_eq!(classify_msvc_linker(14, 39), Some("VS 2022"));
        assert_eq!(classify_msvc_linker(14, 16), Some("VS 2017"));
        assert_eq!(classify_msvc_linker(6, 0), Some("VC6"));
        assert_eq!(classify_msvc_linker(2, 30), Some("GNU ld / MinGW"));
    }
}
