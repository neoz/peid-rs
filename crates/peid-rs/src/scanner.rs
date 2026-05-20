use crate::binary::BinaryView;
use crate::signature::{Signature, SignatureDb};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Deep,
    Hardcore,
    Raw,
}

pub fn scan<'a>(db: &'a SignatureDb, view: &BinaryView<'_>, mode: Mode) -> Option<&'a Signature> {
    match mode {
        Mode::Normal => scan_normal(db, view),
        Mode::Deep => scan_window(db, view.bytes, view.entry_section.clone()),
        Mode::Hardcore | Mode::Raw => scan_window(db, view.bytes, Some(0..view.bytes.len())),
    }
}

fn scan_normal<'a>(db: &'a SignatureDb, view: &BinaryView<'_>) -> Option<&'a Signature> {
    let ep = view.entry_point_offset?;
    db.match_at(view.bytes, ep, None)
}

fn scan_window<'a>(
    db: &'a SignatureDb,
    bytes: &[u8],
    range: Option<std::ops::Range<usize>>,
) -> Option<&'a Signature> {
    let range = range?;
    db.match_window(bytes, range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{Arch, BinaryFormat};
    use crate::db::SigSource;
    use crate::signature::{Signature, Token};

    fn mk_db(sigs: Vec<Signature>) -> SignatureDb {
        SignatureDb::build(sigs)
    }

    fn mk_sig(name: &str, pat: Vec<Token>, ep_only: bool) -> Signature {
        Signature {
            name: name.to_string(),
            pattern: pat,
            ep_only,
            source: SigSource::Internal,
        }
    }

    #[test]
    fn normal_hits_ep_offset() {
        let bytes = vec![0x00, 0x00, 0x60, 0xE8, 0xAA];
        let view = BinaryView {
            format: BinaryFormat::Pe,
            arch: Arch::X86,
            dotnet: None,
            entry_point_offset: Some(2),
            entry_section: Some(0..bytes.len()),
            bytes: &bytes,
        };
        let db = mk_db(vec![mk_sig(
            "x",
            vec![Token::Byte(0x60), Token::Byte(0xE8)],
            true,
        )]);
        let hit = scan(&db, &view, Mode::Normal).unwrap();
        assert_eq!(hit.name, "x");
    }

    #[test]
    fn deep_finds_sig_inside_section() {
        let bytes = vec![0xCC, 0xCC, 0x90, 0x60, 0xE8, 0xCC];
        let view = BinaryView {
            format: BinaryFormat::Pe,
            arch: Arch::X86,
            dotnet: None,
            entry_point_offset: Some(0),
            entry_section: Some(2..bytes.len()),
            bytes: &bytes,
        };
        let db = mk_db(vec![mk_sig(
            "deep",
            vec![Token::Byte(0x60), Token::Byte(0xE8)],
            false,
        )]);
        let hit = scan(&db, &view, Mode::Deep).unwrap();
        assert_eq!(hit.name, "deep");
    }

    #[test]
    fn hardcore_scans_full_file() {
        let bytes = vec![0x00; 1024]
            .into_iter()
            .chain([0x60, 0xE8].into_iter())
            .chain(std::iter::repeat(0x00).take(16))
            .collect::<Vec<_>>();
        let view = BinaryView {
            format: BinaryFormat::Pe,
            arch: Arch::X86_64,
            dotnet: None,
            entry_point_offset: None,
            entry_section: None,
            bytes: &bytes,
        };
        let db = mk_db(vec![mk_sig(
            "hc",
            vec![Token::Byte(0x60), Token::Byte(0xE8)],
            false,
        )]);
        let hit = scan(&db, &view, Mode::Hardcore).unwrap();
        assert_eq!(hit.name, "hc");
    }
}
