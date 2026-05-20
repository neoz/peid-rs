use crate::binary::{BinaryFormat, BinaryView};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionMatchKind {
    Equals,
    StartsWith,
}

#[derive(Clone, Debug)]
pub struct SectionRule {
    pub needle: &'static str,
    pub kind: SectionMatchKind,
    pub name: &'static str,
}

const RULES: &[SectionRule] = &[
    SectionRule { needle: ".vmp",       kind: SectionMatchKind::StartsWith, name: "VMProtect" },
    SectionRule { needle: ".themida",   kind: SectionMatchKind::Equals,     name: "Themida / WinLicense" },
    SectionRule { needle: ".winlice",   kind: SectionMatchKind::StartsWith, name: "Themida / WinLicense" },
    SectionRule { needle: ".enigma",    kind: SectionMatchKind::StartsWith, name: "Enigma Protector" },
    SectionRule { needle: "UPX0",       kind: SectionMatchKind::Equals,     name: "UPX" },
    SectionRule { needle: "UPX1",       kind: SectionMatchKind::Equals,     name: "UPX" },
    SectionRule { needle: "UPX!",       kind: SectionMatchKind::Equals,     name: "UPX" },
    SectionRule { needle: ".aspack",    kind: SectionMatchKind::Equals,     name: "ASPack" },
    SectionRule { needle: ".adata",     kind: SectionMatchKind::Equals,     name: "ASPack" },
    SectionRule { needle: ".petite",    kind: SectionMatchKind::Equals,     name: "Petite" },
    SectionRule { needle: ".MPRESS1",   kind: SectionMatchKind::Equals,     name: "MPRESS" },
    SectionRule { needle: ".MPRESS2",   kind: SectionMatchKind::Equals,     name: "MPRESS" },
    SectionRule { needle: ".nsp",       kind: SectionMatchKind::StartsWith, name: "NsPack" },
    SectionRule { needle: ".pec",       kind: SectionMatchKind::StartsWith, name: "PECompact" },
    SectionRule { needle: "PEC2",       kind: SectionMatchKind::Equals,     name: "PECompact 2" },
    SectionRule { needle: ".neolite",   kind: SectionMatchKind::Equals,     name: "Neolite" },
    SectionRule { needle: ".neolit",    kind: SectionMatchKind::Equals,     name: "Neolite" },
    SectionRule { needle: ".pelock",    kind: SectionMatchKind::StartsWith, name: "PELock" },
    SectionRule { needle: ".perplex",   kind: SectionMatchKind::Equals,     name: "Perplex" },
    SectionRule { needle: ".RLPack",    kind: SectionMatchKind::Equals,     name: "RLPack" },
    SectionRule { needle: ".svkp",      kind: SectionMatchKind::Equals,     name: "SVKP" },
    SectionRule { needle: ".y0da",      kind: SectionMatchKind::StartsWith, name: "yoda's Protector" },
    SectionRule { needle: "yC",         kind: SectionMatchKind::Equals,     name: "yoda's Crypter" },
    SectionRule { needle: "yP",         kind: SectionMatchKind::Equals,     name: "yoda's Protector" },
    SectionRule { needle: ".kkrunchy",  kind: SectionMatchKind::Equals,     name: "kkrunchy" },
    SectionRule { needle: "kkrunchy",   kind: SectionMatchKind::Equals,     name: "kkrunchy" },
    SectionRule { needle: ".WWP32",     kind: SectionMatchKind::Equals,     name: "WWPack32" },
    SectionRule { needle: ".WWPACK",    kind: SectionMatchKind::Equals,     name: "WWPack" },
    SectionRule { needle: ".Upack",     kind: SectionMatchKind::Equals,     name: "Upack" },
    SectionRule { needle: ".ByDwing",   kind: SectionMatchKind::Equals,     name: "Upack (ByDwing)" },
    SectionRule { needle: ".MEW",       kind: SectionMatchKind::Equals,     name: "MEW" },
    SectionRule { needle: "FSG!",       kind: SectionMatchKind::Equals,     name: "FSG" },
    SectionRule { needle: ".MaskPE",    kind: SectionMatchKind::Equals,     name: "MaskPE" },
    SectionRule { needle: ".pebundle",  kind: SectionMatchKind::Equals,     name: "PEBundle" },
    SectionRule { needle: ".packed",    kind: SectionMatchKind::Equals,     name: "ProtectExe / generic packer" },
    SectionRule { needle: ".rmnet",     kind: SectionMatchKind::Equals,     name: "Ramnit (suspicious)" },
    SectionRule { needle: ".taz",       kind: SectionMatchKind::Equals,     name: "Some taz packer" },
    SectionRule { needle: ".boom",      kind: SectionMatchKind::Equals,     name: "The Boomerang List Builder" },
    SectionRule { needle: ".charmve",   kind: SectionMatchKind::Equals,     name: "PIN tool" },
    SectionRule { needle: "ProCrypt",   kind: SectionMatchKind::Equals,     name: "ProCrypt" },
    SectionRule { needle: "Themida",    kind: SectionMatchKind::Equals,     name: "Themida" },
    SectionRule { needle: ".ccg",       kind: SectionMatchKind::Equals,     name: "CCG Packer" },
    SectionRule { needle: ".gentee",    kind: SectionMatchKind::Equals,     name: "Gentee" },
    SectionRule { needle: "lzma",       kind: SectionMatchKind::Equals,     name: "LZMA SFX" },
    SectionRule { needle: ".spack",     kind: SectionMatchKind::Equals,     name: "Simple Pack" },
    SectionRule { needle: ".tsuarez",   kind: SectionMatchKind::Equals,     name: "Tsuarez" },
    SectionRule { needle: ".tsustub",   kind: SectionMatchKind::Equals,     name: "Tsuarez stub" },
    SectionRule { needle: ".confuser",  kind: SectionMatchKind::Equals,     name: "ConfuserEx (.NET)" },
    SectionRule { needle: ".netshrink", kind: SectionMatchKind::Equals,     name: ".netshrink (.NET)" },
];

#[derive(Clone, Debug)]
pub struct SectionHit {
    pub packer: &'static str,
    pub section: String,
}

pub fn detect_pe(view: &BinaryView<'_>) -> Option<SectionHit> {
    if view.format != BinaryFormat::Pe {
        return None;
    }
    let pe = match goblin::pe::PE::parse(view.bytes) {
        Ok(pe) => pe,
        Err(_) => return None,
    };
    let names: Vec<String> = pe
        .sections
        .iter()
        .map(|s| {
            s.name()
                .unwrap_or("")
                .trim_end_matches('\0')
                .trim_end()
                .to_string()
        })
        .collect();

    for (idx, name) in names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        for rule in RULES {
            let hit = match rule.kind {
                SectionMatchKind::Equals => name.eq_ignore_ascii_case(rule.needle),
                SectionMatchKind::StartsWith => name
                    .to_ascii_lowercase()
                    .starts_with(&rule.needle.to_ascii_lowercase()),
            };
            if hit {
                let _ = idx;
                return Some(SectionHit {
                    packer: rule.name,
                    section: name.clone(),
                });
            }
        }
    }

    let mut weird = Vec::new();
    let mut weird_large = false;
    const LARGE_PAYLOAD_BYTES: u32 = 100 * 1024;
    for (sec, name) in pe.sections.iter().zip(names.iter()) {
        if name.is_empty() {
            continue;
        }
        let rest = match name.strip_prefix('.') {
            Some(r) => r,
            None => continue,
        };
        if rest.is_empty() || rest.len() > 5 {
            continue;
        }
        if is_standard_section(name) {
            continue;
        }
        weird.push(name.clone());
        let size = if sec.virtual_size != 0 {
            sec.virtual_size
        } else {
            sec.size_of_raw_data
        };
        if size >= LARGE_PAYLOAD_BYTES {
            weird_large = true;
        }
    }
    if weird.len() >= 2 && weird_large {
        return Some(SectionHit {
            packer: "VMProtect 3.x (heuristic)",
            section: weird.join(", "),
        });
    }

    None
}

const STANDARD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
    ".reloc", ".tls", ".pdata", ".xdata", ".CRT", ".gfids", ".didat",
    ".qtmetad", ".debug", ".note", ".eh_fr", ".code", ".init", ".fini",
    ".sxdata", ".vsdata", ".buildid", ".00cfg", ".giats", ".retplne",
    ".voltbl",
];

fn is_standard_section(name: &str) -> bool {
    STANDARD_SECTIONS
        .iter()
        .any(|s| s.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_matching_equals_and_startswith() {
        let upx = RULES.iter().find(|r| r.needle == "UPX0").unwrap();
        assert_eq!(upx.kind, SectionMatchKind::Equals);
        let vmp = RULES.iter().find(|r| r.needle == ".vmp").unwrap();
        assert_eq!(vmp.kind, SectionMatchKind::StartsWith);
    }
}
