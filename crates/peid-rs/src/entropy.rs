use crate::binary::{BinaryFormat, BinaryView};

pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

#[derive(Clone, Debug)]
pub struct SectionEntropy {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
}

pub fn shannon(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

pub fn analyze(view: &BinaryView<'_>) -> Vec<SectionEntropy> {
    match view.format {
        BinaryFormat::Pe => analyze_pe(view),
        BinaryFormat::Elf => analyze_elf(view),
        BinaryFormat::MachO => analyze_macho(view),
    }
}

pub fn has_suspicious(entries: &[SectionEntropy]) -> bool {
    entries.iter().any(|e| e.entropy >= HIGH_ENTROPY_THRESHOLD)
}

fn analyze_pe(view: &BinaryView<'_>) -> Vec<SectionEntropy> {
    let pe = match goblin::pe::PE::parse(view.bytes) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::with_capacity(pe.sections.len());
    for sec in &pe.sections {
        let name = sec
            .name()
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        let start = sec.pointer_to_raw_data as usize;
        let size = sec.size_of_raw_data as usize;
        if let Some(buf) = view.bytes.get(start..start.saturating_add(size)) {
            out.push(SectionEntropy {
                name,
                size: buf.len(),
                entropy: shannon(buf),
            });
        }
    }
    out
}

fn analyze_elf(view: &BinaryView<'_>) -> Vec<SectionEntropy> {
    let elf = match goblin::elf::Elf::parse(view.bytes) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
            continue;
        }
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if let Some(buf) = view.bytes.get(start..start.saturating_add(size)) {
            if buf.is_empty() {
                continue;
            }
            out.push(SectionEntropy {
                name,
                size: buf.len(),
                entropy: shannon(buf),
            });
        }
    }
    out
}

fn analyze_macho(view: &BinaryView<'_>) -> Vec<SectionEntropy> {
    use goblin::mach::load_command::CommandVariant;
    use goblin::mach::Mach;
    let mach = match Mach::parse(view.bytes) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let bin = match mach {
        Mach::Binary(b) => b,
        Mach::Fat(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for lc in bin.load_commands.iter() {
        match lc.command {
            CommandVariant::Segment32(seg) => {
                let name = bytes_to_str(&seg.segname).to_string();
                let start = seg.fileoff as usize;
                let size = seg.filesize as usize;
                if let Some(buf) = view.bytes.get(start..start.saturating_add(size)) {
                    if !buf.is_empty() {
                        out.push(SectionEntropy {
                            name,
                            size: buf.len(),
                            entropy: shannon(buf),
                        });
                    }
                }
            }
            CommandVariant::Segment64(seg) => {
                let name = bytes_to_str(&seg.segname).to_string();
                let start = seg.fileoff as usize;
                let size = seg.filesize as usize;
                if let Some(buf) = view.bytes.get(start..start.saturating_add(size)) {
                    if !buf.is_empty() {
                        out.push(SectionEntropy {
                            name,
                            size: buf.len(),
                            entropy: shannon(buf),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn bytes_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_bytes_is_max() {
        let bytes: Vec<u8> = (0..=255).collect();
        let h = shannon(&bytes);
        assert!((h - 8.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_single_byte_is_zero() {
        let bytes = vec![0x42u8; 1024];
        assert_eq!(shannon(&bytes), 0.0);
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(shannon(&[]), 0.0);
    }
}
