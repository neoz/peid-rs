use md5::{Digest, Md5};

use crate::binary::{BinaryFormat, BinaryView};

#[derive(Clone, Debug)]
pub struct ImpHash {
    pub hex: String,
    pub entries: usize,
}

pub fn compute(view: &BinaryView<'_>) -> Option<ImpHash> {
    if view.format != BinaryFormat::Pe {
        return None;
    }
    let pe = goblin::pe::PE::parse(view.bytes).ok()?;
    if pe.imports.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::with_capacity(pe.imports.len());
    for imp in &pe.imports {
        let dll = normalize_dll(imp.dll);
        let func = normalize_func(&imp.name, imp.ordinal);
        parts.push(format!("{}.{}", dll, func));
    }
    let joined = parts.join(",");
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    let digest = hasher.finalize();
    let hex = digest.iter().fold(String::with_capacity(32), |mut acc, b| {
        acc.push_str(&format!("{:02x}", b));
        acc
    });
    Some(ImpHash {
        hex,
        entries: parts.len(),
    })
}

fn normalize_dll(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let stripped_exts = ["dll", "ocx", "sys", "drv"];
    if let Some(dot) = lower.rfind('.') {
        let ext = &lower[dot + 1..];
        if stripped_exts.iter().any(|e| *e == ext) {
            return lower[..dot].to_string();
        }
    }
    lower
}

fn normalize_func(name: &str, ordinal: u16) -> String {
    if let Some(rest) = name.strip_prefix("ORDINAL ") {
        if let Ok(o) = rest.trim().parse::<u16>() {
            return format!("ord{}", o);
        }
        return format!("ord{}", ordinal);
    }
    if name.is_empty() {
        return format!("ord{}", ordinal);
    }
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dll_strips_known_extensions() {
        assert_eq!(normalize_dll("KERNEL32.DLL"), "kernel32");
        assert_eq!(normalize_dll("ws2_32.dll"), "ws2_32");
        assert_eq!(normalize_dll("user32.OcX"), "user32");
        assert_eq!(normalize_dll("driver.sys"), "driver");
    }

    #[test]
    fn normalize_dll_keeps_unknown_extensions() {
        assert_eq!(normalize_dll("MyLib.so"), "mylib.so");
        assert_eq!(normalize_dll("noext"), "noext");
    }

    #[test]
    fn normalize_func_handles_ordinal_marker() {
        assert_eq!(normalize_func("ORDINAL 17", 17), "ord17");
        assert_eq!(normalize_func("", 42), "ord42");
        assert_eq!(normalize_func("CreateFileW", 0), "createfilew");
    }
}
