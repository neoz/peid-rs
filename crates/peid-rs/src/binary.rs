use std::ops::Range;

use goblin::Object;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    AArch64,
    Mips,
    MipsLE,
    RiscV,
    PowerPc,
    PowerPc64,
    Other(String),
}

impl Arch {
    pub fn as_str(&self) -> &str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::AArch64 => "aarch64",
            Arch::Mips => "mips",
            Arch::MipsLE => "mipsle",
            Arch::RiscV => "riscv",
            Arch::PowerPc => "ppc",
            Arch::PowerPc64 => "ppc64",
            Arch::Other(s) => s.as_str(),
        }
    }
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct BinaryView<'a> {
    pub format: BinaryFormat,
    pub arch: Arch,
    pub dotnet: Option<DotNetInfo>,
    pub entry_point_offset: Option<usize>,
    pub entry_section: Option<Range<usize>>,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub enum BinaryParseError {
    Unrecognized,
    Goblin(String),
}

impl std::fmt::Display for BinaryParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryParseError::Unrecognized => write!(f, "unrecognized binary format"),
            BinaryParseError::Goblin(s) => write!(f, "parse error: {}", s),
        }
    }
}

impl std::error::Error for BinaryParseError {}

impl<'a> BinaryView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, BinaryParseError> {
        let obj = Object::parse(bytes).map_err(|e| BinaryParseError::Goblin(e.to_string()))?;
        match obj {
            Object::PE(pe) => Ok(parse_pe(bytes, &pe)),
            Object::Elf(elf) => Ok(parse_elf(bytes, &elf)),
            Object::Mach(mach) => parse_mach(bytes, mach).ok_or(BinaryParseError::Unrecognized),
            _ => Err(BinaryParseError::Unrecognized),
        }
    }
}

fn parse_pe<'a>(bytes: &'a [u8], pe: &goblin::pe::PE) -> BinaryView<'a> {
    let arch = arch_from_pe_machine(pe.header.coff_header.machine);
    let ep_rva = pe.entry as u32;

    let (entry_point_offset, entry_section) = pe_entry_offsets(pe, ep_rva);

    let dotnet = pe_dotnet_info(bytes, pe);

    BinaryView {
        format: BinaryFormat::Pe,
        arch,
        dotnet,
        entry_point_offset,
        entry_section,
        bytes,
    }
}

fn pe_entry_offsets(
    pe: &goblin::pe::PE,
    ep_rva: u32,
) -> (Option<usize>, Option<Range<usize>>) {
    for sec in &pe.sections {
        let va = sec.virtual_address;
        let vsize = if sec.virtual_size != 0 {
            sec.virtual_size
        } else {
            sec.size_of_raw_data
        };
        if ep_rva >= va && ep_rva < va.saturating_add(vsize) {
            let raw = sec.pointer_to_raw_data as usize;
            let raw_size = sec.size_of_raw_data as usize;
            let offset = raw + (ep_rva - va) as usize;
            let section_range = raw..(raw.saturating_add(raw_size));
            return (Some(offset), Some(section_range));
        }
    }
    (None, None)
}

fn pe_rva_to_offset(pe: &goblin::pe::PE, rva: u32) -> Option<usize> {
    for sec in &pe.sections {
        let va = sec.virtual_address;
        let vsize = if sec.virtual_size != 0 {
            sec.virtual_size
        } else {
            sec.size_of_raw_data
        };
        if rva >= va && rva < va.saturating_add(vsize) {
            return Some(sec.pointer_to_raw_data as usize + (rva - va) as usize);
        }
    }
    None
}

fn arch_from_pe_machine(machine: u16) -> Arch {
    use goblin::pe::header::*;
    match machine {
        COFF_MACHINE_X86 => Arch::X86,
        COFF_MACHINE_X86_64 => Arch::X86_64,
        COFF_MACHINE_ARM | COFF_MACHINE_ARMNT | COFF_MACHINE_THUMB => Arch::Arm,
        COFF_MACHINE_ARM64 => Arch::AArch64,
        COFF_MACHINE_RISCV32 | COFF_MACHINE_RISCV64 | COFF_MACHINE_RISCV128 => Arch::RiscV,
        COFF_MACHINE_POWERPC => Arch::PowerPc,
        COFF_MACHINE_POWERPCFP => Arch::PowerPc,
        other => Arch::Other(format!("pe-machine-0x{:04x}", other)),
    }
}

const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;
const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;

fn pe_dotnet_info(bytes: &[u8], pe: &goblin::pe::PE) -> Option<DotNetInfo> {
    let opt = pe.header.optional_header.as_ref()?;
    let dir = opt.data_directories.get_clr_runtime_header()?;
    if dir.size == 0 || dir.virtual_address == 0 {
        return None;
    }
    let cli_off = pe_rva_to_offset(pe, dir.virtual_address)?;
    let cli = bytes.get(cli_off..cli_off.checked_add(72)?)?;

    let major = u16::from_le_bytes([cli[4], cli[5]]);
    let minor = u16::from_le_bytes([cli[6], cli[7]]);
    let md_rva = u32::from_le_bytes([cli[8], cli[9], cli[10], cli[11]]);
    let md_size = u32::from_le_bytes([cli[12], cli[13], cli[14], cli[15]]);
    let flags = u32::from_le_bytes([cli[16], cli[17], cli[18], cli[19]]);
    let entry = u32::from_le_bytes([cli[20], cli[21], cli[22], cli[23]]);

    let metadata_version = read_metadata_version(bytes, pe, md_rva, md_size).unwrap_or_default();

    let il_only = flags & COMIMAGE_FLAGS_ILONLY != 0;
    Some(DotNetInfo {
        runtime_version: (major, minor),
        metadata_version,
        il_only,
        mixed_mode: !il_only,
        requires_32bit: flags & COMIMAGE_FLAGS_32BITREQUIRED != 0,
        prefers_32bit: flags & COMIMAGE_FLAGS_32BITPREFERRED != 0,
        strong_named: flags & COMIMAGE_FLAGS_STRONGNAMESIGNED != 0,
        native_entry_point: flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT != 0,
        entry_token_or_rva: entry,
    })
}

fn read_metadata_version(
    bytes: &[u8],
    pe: &goblin::pe::PE,
    md_rva: u32,
    md_size: u32,
) -> Option<String> {
    if md_rva == 0 || md_size < 20 {
        return None;
    }
    let off = pe_rva_to_offset(pe, md_rva)?;
    let end = off.checked_add(md_size as usize)?.min(bytes.len());
    let buf = bytes.get(off..end)?;
    if buf.len() < 16 {
        return None;
    }
    let sig = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if sig != 0x424A_5342 {
        return None;
    }
    let length = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
    let str_start = 16usize;
    let str_end = str_start.checked_add(length)?.min(buf.len());
    let str_bytes = buf.get(str_start..str_end)?;
    let nul = str_bytes.iter().position(|&b| b == 0).unwrap_or(str_bytes.len());
    Some(String::from_utf8_lossy(&str_bytes[..nul]).into_owned())
}

fn parse_elf<'a>(bytes: &'a [u8], elf: &goblin::elf::Elf) -> BinaryView<'a> {
    let arch = arch_from_elf_machine(elf.header.e_machine, elf.little_endian);
    let entry = elf.header.e_entry;

    let mut entry_point_offset = None;
    let mut entry_section = None;
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD {
            continue;
        }
        let vstart = ph.p_vaddr;
        let vend = ph.p_vaddr.saturating_add(ph.p_memsz);
        if entry >= vstart && entry < vend {
            let off = ph.p_offset as usize + (entry - vstart) as usize;
            entry_point_offset = Some(off);
            let seg_start = ph.p_offset as usize;
            let seg_end = seg_start.saturating_add(ph.p_filesz as usize);
            entry_section = Some(seg_start..seg_end);
            break;
        }
    }

    BinaryView {
        format: BinaryFormat::Elf,
        arch,
        dotnet: None,
        entry_point_offset,
        entry_section,
        bytes,
    }
}

fn arch_from_elf_machine(machine: u16, little_endian: bool) -> Arch {
    use goblin::elf::header::*;
    match machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::AArch64,
        EM_MIPS | EM_MIPS_RS3_LE => {
            if little_endian {
                Arch::MipsLE
            } else {
                Arch::Mips
            }
        }
        EM_RISCV => Arch::RiscV,
        EM_PPC => Arch::PowerPc,
        EM_PPC64 => Arch::PowerPc64,
        other => Arch::Other(format!("elf-machine-{}", other)),
    }
}

fn parse_mach<'a>(bytes: &'a [u8], mach: goblin::mach::Mach<'a>) -> Option<BinaryView<'a>> {
    use goblin::mach::Mach;
    let bin = match mach {
        Mach::Binary(b) => b,
        Mach::Fat(_) => return None,
    };
    let arch = arch_from_mach_cputype(bin.header.cputype, bin.header.cpusubtype);

    let mut entry_point_offset: Option<usize> = None;
    let mut entry_section: Option<Range<usize>> = None;

    for lc in bin.load_commands.iter() {
        match lc.command {
            goblin::mach::load_command::CommandVariant::Main(m) => {
                entry_point_offset = Some(m.entryoff as usize);
            }
            goblin::mach::load_command::CommandVariant::Segment32(seg) => {
                let name = bytes_to_str(&seg.segname);
                if name == "__TEXT" {
                    let start = seg.fileoff as usize;
                    let end = start.saturating_add(seg.filesize as usize);
                    entry_section = Some(start..end);
                }
            }
            goblin::mach::load_command::CommandVariant::Segment64(seg) => {
                let name = bytes_to_str(&seg.segname);
                if name == "__TEXT" {
                    let start = seg.fileoff as usize;
                    let end = start.saturating_add(seg.filesize as usize);
                    entry_section = Some(start..end);
                }
            }
            _ => {}
        }
    }

    Some(BinaryView {
        format: BinaryFormat::MachO,
        arch,
        dotnet: None,
        entry_point_offset,
        entry_section,
        bytes,
    })
}

fn bytes_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn arch_from_mach_cputype(cputype: u32, _cpusubtype: u32) -> Arch {
    use goblin::mach::cputype::*;
    match cputype {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM => Arch::Arm,
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Arch::AArch64,
        CPU_TYPE_POWERPC => Arch::PowerPc,
        CPU_TYPE_POWERPC64 => Arch::PowerPc64,
        other => Arch::Other(format!("macho-cputype-{}", other)),
    }
}
