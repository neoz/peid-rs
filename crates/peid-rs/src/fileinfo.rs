#[derive(Clone, Debug)]
pub enum FileInfo {
    Magic(MagicHit),
    Text(TextInfo),
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub enum MagicCategory {
    Archive,
    Compressed,
    Document,
    Image,
    Audio,
    Video,
    Database,
    Bytecode,
    Font,
    Other,
}

impl MagicCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            MagicCategory::Archive => "Archive",
            MagicCategory::Compressed => "Compressed",
            MagicCategory::Document => "Document",
            MagicCategory::Image => "Image",
            MagicCategory::Audio => "Audio",
            MagicCategory::Video => "Video",
            MagicCategory::Database => "Database",
            MagicCategory::Bytecode => "Bytecode",
            MagicCategory::Font => "Font",
            MagicCategory::Other => "Other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MagicHit {
    pub category: MagicCategory,
    pub name: &'static str,
}

#[derive(Clone, Debug)]
pub struct TextInfo {
    pub encoding: TextEncoding,
    pub line_ending: LineEnding,
    pub kind: TextKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextEncoding {
    Ascii,
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
    Latin1OrUnknown,
}

impl TextEncoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            TextEncoding::Ascii => "ASCII",
            TextEncoding::Utf8 => "UTF-8",
            TextEncoding::Utf8Bom => "UTF-8 BOM",
            TextEncoding::Utf16Le => "UTF-16 LE",
            TextEncoding::Utf16Be => "UTF-16 BE",
            TextEncoding::Latin1OrUnknown => "Latin-1?",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineEnding {
    Lf,
    Crlf,
    Cr,
    Mixed,
    None,
}

impl LineEnding {
    pub fn as_str(&self) -> &'static str {
        match self {
            LineEnding::Lf => "LF",
            LineEnding::Crlf => "CRLF",
            LineEnding::Cr => "CR",
            LineEnding::Mixed => "mixed",
            LineEnding::None => "no-newline",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextKind {
    Plain,
    Markdown,
    Json,
    Xml,
    Html,
    Toml,
    Yaml,
    GitIgnore,
    PeidSignatureDb,
    Shebang(String),
    SourceCode(&'static str),
}

impl TextKind {
    pub fn label(&self) -> String {
        match self {
            TextKind::Plain => "Plain text".to_string(),
            TextKind::Markdown => "Markdown".to_string(),
            TextKind::Json => "JSON".to_string(),
            TextKind::Xml => "XML".to_string(),
            TextKind::Html => "HTML".to_string(),
            TextKind::Toml => "TOML".to_string(),
            TextKind::Yaml => "YAML".to_string(),
            TextKind::GitIgnore => ".gitignore".to_string(),
            TextKind::PeidSignatureDb => "PEiD signature database".to_string(),
            TextKind::Shebang(s) => format!("Script ({})", s),
            TextKind::SourceCode(lang) => format!("Source code ({})", lang),
        }
    }
}

pub fn detect(bytes: &[u8], path_hint: Option<&str>) -> FileInfo {
    if let Some(m) = detect_magic(bytes) {
        return FileInfo::Magic(m);
    }
    if let Some(t) = detect_text(bytes, path_hint) {
        return FileInfo::Text(t);
    }
    FileInfo::Unknown
}

fn detect_magic(bytes: &[u8]) -> Option<MagicHit> {
    let b = bytes;
    let starts = |needle: &[u8]| b.len() >= needle.len() && &b[..needle.len()] == needle;
    let at = |off: usize, needle: &[u8]| {
        b.len() >= off + needle.len() && &b[off..off + needle.len()] == needle
    };

    if starts(b"%PDF-") {
        return Some(MagicHit { category: MagicCategory::Document, name: "PDF" });
    }
    if starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(MagicHit { category: MagicCategory::Image, name: "PNG" });
    }
    if starts(&[0xFF, 0xD8, 0xFF]) {
        return Some(MagicHit { category: MagicCategory::Image, name: "JPEG" });
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some(MagicHit { category: MagicCategory::Image, name: "GIF" });
    }
    if starts(b"BM") && b.len() > 14 {
        return Some(MagicHit { category: MagicCategory::Image, name: "BMP" });
    }
    if starts(b"RIFF") && at(8, b"WEBP") {
        return Some(MagicHit { category: MagicCategory::Image, name: "WebP" });
    }
    if starts(b"RIFF") && at(8, b"WAVE") {
        return Some(MagicHit { category: MagicCategory::Audio, name: "WAV" });
    }
    if starts(b"RIFF") && at(8, b"AVI ") {
        return Some(MagicHit { category: MagicCategory::Video, name: "AVI" });
    }
    if at(4, b"ftyp") {
        return Some(MagicHit { category: MagicCategory::Video, name: "MP4 / ISO BMFF" });
    }
    if starts(b"ID3") || (b.len() >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0) {
        return Some(MagicHit { category: MagicCategory::Audio, name: "MP3" });
    }
    if starts(b"OggS") {
        return Some(MagicHit { category: MagicCategory::Audio, name: "Ogg" });
    }
    if starts(b"fLaC") {
        return Some(MagicHit { category: MagicCategory::Audio, name: "FLAC" });
    }
    if starts(&[0x1F, 0x8B]) {
        return Some(MagicHit { category: MagicCategory::Compressed, name: "gzip" });
    }
    if starts(b"BZh") {
        return Some(MagicHit { category: MagicCategory::Compressed, name: "bzip2" });
    }
    if starts(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(MagicHit { category: MagicCategory::Compressed, name: "xz" });
    }
    if starts(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(MagicHit { category: MagicCategory::Compressed, name: "Zstandard" });
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        return Some(MagicHit { category: MagicCategory::Archive, name: "ZIP" });
    }
    if starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(MagicHit { category: MagicCategory::Archive, name: "7-Zip" });
    }
    if starts(b"Rar!\x1A\x07") {
        return Some(MagicHit { category: MagicCategory::Archive, name: "RAR" });
    }
    if at(257, b"ustar") {
        return Some(MagicHit { category: MagicCategory::Archive, name: "tar" });
    }
    if starts(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        return Some(MagicHit { category: MagicCategory::Bytecode, name: "Java class / Mach-O FAT" });
    }
    if starts(&[0x00, 0x61, 0x73, 0x6D]) {
        return Some(MagicHit { category: MagicCategory::Bytecode, name: "WebAssembly" });
    }
    if starts(b"SQLite format 3\0") {
        return Some(MagicHit { category: MagicCategory::Database, name: "SQLite 3" });
    }
    if starts(&[0x00, 0x01, 0x00, 0x00, 0x00]) || starts(b"OTTO") || starts(b"true") || starts(b"typ1") {
        return Some(MagicHit { category: MagicCategory::Font, name: "TrueType / OpenType" });
    }
    if starts(b"wOFF") {
        return Some(MagicHit { category: MagicCategory::Font, name: "WOFF" });
    }
    if starts(b"wOF2") {
        return Some(MagicHit { category: MagicCategory::Font, name: "WOFF2" });
    }
    None
}

fn detect_text(bytes: &[u8], path_hint: Option<&str>) -> Option<TextInfo> {
    let sample_len = bytes.len().min(8192);
    let (encoding, body_start) = detect_encoding(&bytes[..sample_len]);
    let body = &bytes[body_start..sample_len];

    if matches!(encoding, TextEncoding::Latin1OrUnknown)
        && !looks_like_text(body)
    {
        return None;
    }

    let line_ending = detect_line_ending(body);
    let kind = detect_text_kind(body, path_hint);
    Some(TextInfo {
        encoding,
        line_ending,
        kind,
    })
}

fn detect_encoding(sample: &[u8]) -> (TextEncoding, usize) {
    if sample.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return (TextEncoding::Utf8Bom, 3);
    }
    if sample.starts_with(&[0xFF, 0xFE]) {
        return (TextEncoding::Utf16Le, 2);
    }
    if sample.starts_with(&[0xFE, 0xFF]) {
        return (TextEncoding::Utf16Be, 2);
    }
    if std::str::from_utf8(sample).is_ok() {
        if sample.iter().all(|&b| b < 0x80) {
            return (TextEncoding::Ascii, 0);
        }
        return (TextEncoding::Utf8, 0);
    }
    (TextEncoding::Latin1OrUnknown, 0)
}

fn looks_like_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    if sample.iter().any(|&b| b == 0) {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7F) || b >= 0x80)
        .count();
    printable * 100 / sample.len() >= 90
}

fn detect_line_ending(body: &[u8]) -> LineEnding {
    let mut lf = 0u32;
    let mut crlf = 0u32;
    let mut cr_only = 0u32;
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\r' {
            if i + 1 < body.len() && body[i + 1] == b'\n' {
                crlf += 1;
                i += 2;
                continue;
            } else {
                cr_only += 1;
            }
        } else if body[i] == b'\n' {
            lf += 1;
        }
        i += 1;
    }
    let kinds = [lf > 0, crlf > 0, cr_only > 0]
        .iter()
        .filter(|&&b| b)
        .count();
    if kinds == 0 {
        LineEnding::None
    } else if kinds > 1 {
        LineEnding::Mixed
    } else if crlf > 0 {
        LineEnding::Crlf
    } else if lf > 0 {
        LineEnding::Lf
    } else {
        LineEnding::Cr
    }
}

fn detect_text_kind(body: &[u8], path_hint: Option<&str>) -> TextKind {
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => &lossy_slice(body),
    };

    let trimmed = text.trim_start();
    if let Some(rest) = trimmed.strip_prefix("#!") {
        let line = rest.lines().next().unwrap_or("");
        return TextKind::Shebang(line.trim().to_string());
    }

    if trimmed.starts_with("<?xml") {
        return TextKind::Xml;
    }
    if trimmed.to_ascii_lowercase().starts_with("<!doctype html")
        || trimmed.to_ascii_lowercase().starts_with("<html")
    {
        return TextKind::Html;
    }
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && looks_like_json(trimmed)
    {
        return TextKind::Json;
    }
    if looks_like_peid_db(text) {
        return TextKind::PeidSignatureDb;
    }
    if looks_like_toml(text) {
        return TextKind::Toml;
    }

    if let Some(p) = path_hint {
        let lp = p.to_ascii_lowercase();
        if lp.ends_with(".md") || lp.ends_with(".markdown") {
            return TextKind::Markdown;
        }
        if lp.ends_with(".json") {
            return TextKind::Json;
        }
        if lp.ends_with(".toml") {
            return TextKind::Toml;
        }
        if lp.ends_with(".yaml") || lp.ends_with(".yml") {
            return TextKind::Yaml;
        }
        if lp.ends_with(".xml") {
            return TextKind::Xml;
        }
        if lp.ends_with(".html") || lp.ends_with(".htm") {
            return TextKind::Html;
        }
        if lp.ends_with(".gitignore") || lp.ends_with("/.gitignore") || lp == ".gitignore" {
            return TextKind::GitIgnore;
        }
        if lp.ends_with(".rs") {
            return TextKind::SourceCode("Rust");
        }
        if lp.ends_with(".py") {
            return TextKind::SourceCode("Python");
        }
        if lp.ends_with(".js") {
            return TextKind::SourceCode("JavaScript");
        }
        if lp.ends_with(".ts") {
            return TextKind::SourceCode("TypeScript");
        }
        if lp.ends_with(".c") || lp.ends_with(".h") {
            return TextKind::SourceCode("C");
        }
        if lp.ends_with(".cc")
            || lp.ends_with(".cpp")
            || lp.ends_with(".cxx")
            || lp.ends_with(".hpp")
        {
            return TextKind::SourceCode("C++");
        }
        if lp.ends_with(".go") {
            return TextKind::SourceCode("Go");
        }
        if lp.ends_with(".java") {
            return TextKind::SourceCode("Java");
        }
        if lp.ends_with(".sh") || lp.ends_with(".bash") {
            return TextKind::SourceCode("Shell");
        }
        if lp.ends_with(".ps1") {
            return TextKind::SourceCode("PowerShell");
        }
    }

    TextKind::Plain
}

fn looks_like_json(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    let starts_ok = trimmed.starts_with('{') || trimmed.starts_with('[');
    if !starts_ok {
        return false;
    }
    let ends_ok = trimmed.ends_with('}') || trimmed.ends_with(']');
    if !ends_ok {
        return false;
    }
    let mut quote = false;
    let mut escape = false;
    for ch in trimmed.chars().take(2048) {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if quote => escape = true,
            '"' => quote = !quote,
            _ => {}
        }
    }
    !quote
}

fn looks_like_toml(s: &str) -> bool {
    let mut saw_section_or_key = false;
    for line in s.lines().take(40) {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.starts_with('[') && l.contains(']') {
            saw_section_or_key = true;
            continue;
        }
        if let Some(eq) = l.find('=') {
            let key = l[..eq].trim();
            if !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.') {
                saw_section_or_key = true;
                continue;
            }
        }
        return false;
    }
    saw_section_or_key
}

fn looks_like_peid_db(s: &str) -> bool {
    let mut saw_section = false;
    let mut saw_signature = false;
    for line in s.lines().take(40) {
        let l = line.trim();
        if l.starts_with(';') || l.is_empty() {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            saw_section = true;
        }
        if l.to_ascii_lowercase().starts_with("signature") && l.contains('=') {
            saw_signature = true;
        }
        if saw_section && saw_signature {
            return true;
        }
    }
    false
}

fn lossy_slice(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_magic() {
        let m = detect_magic(b"%PDF-1.7\n...").unwrap();
        assert_eq!(m.name, "PDF");
    }

    #[test]
    fn png_magic() {
        let m = detect_magic(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00]).unwrap();
        assert_eq!(m.name, "PNG");
    }

    #[test]
    fn gzip_magic() {
        let m = detect_magic(&[0x1F, 0x8B, 0x08, 0x00]).unwrap();
        assert_eq!(m.name, "gzip");
    }

    #[test]
    fn text_utf8_lf() {
        let info = match detect(b"hello\nworld\n", None) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert_eq!(info.encoding, TextEncoding::Ascii);
        assert_eq!(info.line_ending, LineEnding::Lf);
        assert_eq!(info.kind, TextKind::Plain);
    }

    #[test]
    fn text_utf8_crlf() {
        let info = match detect(b"line1\r\nline2\r\n", None) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert_eq!(info.line_ending, LineEnding::Crlf);
    }

    #[test]
    fn shebang_detected() {
        let info = match detect(b"#!/usr/bin/env python3\nprint(1)\n", None) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        match info.kind {
            TextKind::Shebang(s) => assert!(s.contains("python3")),
            other => panic!("expected shebang, got {:?}", other),
        }
    }

    #[test]
    fn peid_db_detected() {
        let sample = "[Packer]\nsignature = 60 68\nep_only = true\n";
        let info = match detect(sample.as_bytes(), None) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert_eq!(info.kind, TextKind::PeidSignatureDb);
    }

    #[test]
    fn toml_via_content() {
        let sample = "[package]\nname = \"x\"\nversion = \"0.1.0\"\n";
        let info = match detect(sample.as_bytes(), None) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert_eq!(info.kind, TextKind::Toml);
    }

    #[test]
    fn markdown_by_extension() {
        let info = match detect(b"# Title\n", Some("readme.md")) {
            FileInfo::Text(t) => t,
            _ => panic!("expected text"),
        };
        assert_eq!(info.kind, TextKind::Markdown);
    }

    #[test]
    fn binary_blob_returns_unknown() {
        let blob = [0x00u8, 0xFF, 0x00, 0xFF, 0xAA, 0x55];
        assert!(matches!(detect(&blob, None), FileInfo::Unknown));
    }
}
