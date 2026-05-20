use std::fmt;

use crate::db::SigSource;
use crate::signature::{Signature, Token};

#[derive(Debug)]
pub struct DbParseError {
    pub line: usize,
    pub kind: DbParseErrorKind,
}

#[derive(Debug)]
pub enum DbParseErrorKind {
    BadHexToken(String),
    KeyOutsideSection(String),
    UnknownKey(String),
    BadBool(String),
    EmptySignature,
}

impl fmt::Display for DbParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: ", self.line)?;
        match &self.kind {
            DbParseErrorKind::BadHexToken(t) => write!(f, "bad hex token {:?}", t),
            DbParseErrorKind::KeyOutsideSection(k) => {
                write!(f, "key {:?} appears before any [section]", k)
            }
            DbParseErrorKind::UnknownKey(k) => write!(f, "unknown key {:?}", k),
            DbParseErrorKind::BadBool(v) => write!(f, "expected true/false, got {:?}", v),
            DbParseErrorKind::EmptySignature => write!(f, "signature is empty"),
        }
    }
}

impl std::error::Error for DbParseError {}

pub struct ParseOutcome {
    pub signatures: Vec<Signature>,
    pub skipped: Vec<DbParseError>,
}

pub fn parse_db(input: &str, source: SigSource) -> Result<Vec<Signature>, DbParseError> {
    Ok(parse_db_lossy(input, source).signatures)
}

pub fn parse_db_lossy(input: &str, source: SigSource) -> ParseOutcome {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);

    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_pattern: Option<Vec<Token>> = None;
    let mut current_ep_only: bool = false;
    let mut current_dirty: bool = false;

    fn commit(
        out: &mut Vec<Signature>,
        name: &mut Option<String>,
        pattern: &mut Option<Vec<Token>>,
        ep_only: &mut bool,
        dirty: &mut bool,
        source: SigSource,
    ) {
        if !*dirty {
            if let (Some(n), Some(p)) = (name.take(), pattern.take()) {
                out.push(Signature {
                    name: n,
                    pattern: p,
                    ep_only: *ep_only,
                    source,
                });
            }
        }
        *name = None;
        *pattern = None;
        *ep_only = false;
        *dirty = false;
    }

    for (i, raw_line) in input.lines().enumerate() {
        let lineno = i + 1;
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            commit(
                &mut out,
                &mut current_name,
                &mut current_pattern,
                &mut current_ep_only,
                &mut current_dirty,
                source,
            );
            let name = match rest.rfind(']') {
                Some(idx) => rest[..idx].to_string(),
                None => rest.to_string(),
            };
            current_name = Some(name);
            current_pattern = None;
            current_ep_only = false;
            current_dirty = false;
            continue;
        }
        let (key, value) = match line.find('=') {
            Some(eq) => (line[..eq].trim(), line[eq + 1..].trim()),
            None => continue,
        };
        if current_name.is_none() {
            skipped.push(DbParseError {
                line: lineno,
                kind: DbParseErrorKind::KeyOutsideSection(key.to_string()),
            });
            continue;
        }
        match key.to_ascii_lowercase().as_str() {
            "signature" => match parse_pattern(value) {
                Ok(pattern) if !pattern.is_empty() => {
                    current_pattern = Some(pattern);
                }
                Ok(_) => {
                    skipped.push(DbParseError {
                        line: lineno,
                        kind: DbParseErrorKind::EmptySignature,
                    });
                    current_dirty = true;
                }
                Err(tok) => {
                    skipped.push(DbParseError {
                        line: lineno,
                        kind: DbParseErrorKind::BadHexToken(tok),
                    });
                    current_dirty = true;
                }
            },
            "ep_only" => match value.to_ascii_lowercase().as_str() {
                "true" => current_ep_only = true,
                "false" => current_ep_only = false,
                other => {
                    skipped.push(DbParseError {
                        line: lineno,
                        kind: DbParseErrorKind::BadBool(other.to_string()),
                    });
                    current_dirty = true;
                }
            },
            other => {
                skipped.push(DbParseError {
                    line: lineno,
                    kind: DbParseErrorKind::UnknownKey(other.to_string()),
                });
            }
        }
    }
    commit(
        &mut out,
        &mut current_name,
        &mut current_pattern,
        &mut current_ep_only,
        &mut current_dirty,
        source,
    );
    ParseOutcome {
        signatures: out,
        skipped,
    }
}

fn parse_pattern(value: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    for tok in value.split_whitespace() {
        if tok == "??" || tok.eq_ignore_ascii_case("?") {
            tokens.push(Token::Wildcard);
            continue;
        }
        if tok.len() != 2 {
            return Err(tok.to_string());
        }
        let b = u8::from_str_radix(tok, 16).map_err(|_| tok.to_string())?;
        tokens.push(Token::Byte(b));
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Token;

    #[test]
    fn parses_external_sample() {
        let src = "\
;comment line
[Name of the Packer v1.0]
signature = 50 E8 ?? ?? ?? ?? 58 25 ?? F0 FF FF
ep_only = true
";
        let sigs = parse_db(src, SigSource::External).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "Name of the Packer v1.0");
        assert!(sigs[0].ep_only);
        assert_eq!(sigs[0].pattern.len(), 12);
        assert_eq!(sigs[0].pattern[0], Token::Byte(0x50));
        assert_eq!(sigs[0].pattern[2], Token::Wildcard);
        assert!(matches!(sigs[0].source, SigSource::External));
    }

    #[test]
    fn handles_bom_and_crlf() {
        let src = "\u{feff}[a]\r\nsignature = 90 90\r\nep_only = false\r\n";
        let sigs = parse_db(src, SigSource::Internal).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "a");
        assert!(!sigs[0].ep_only);
    }

    #[test]
    fn lowercase_hex_accepted() {
        let src = "[x]\nsignature = ab cd ef\nep_only = true\n";
        let sigs = parse_db(src, SigSource::Internal).unwrap();
        assert_eq!(sigs[0].pattern[0], Token::Byte(0xAB));
        assert_eq!(sigs[0].pattern[2], Token::Byte(0xEF));
    }

    #[test]
    fn commits_multiple_records() {
        let src = "\
[one]
signature = 60
ep_only = true
[two]
signature = ?? C3
ep_only = false
";
        let sigs = parse_db(src, SigSource::Internal).unwrap();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].name, "one");
        assert_eq!(sigs[1].name, "two");
        assert_eq!(sigs[1].pattern[0], Token::Wildcard);
    }

    #[test]
    fn lossy_drops_bad_record_and_continues() {
        let src = "\
[bad]
signature = ZZ
ep_only = true
[good]
signature = 90
ep_only = true
";
        let outcome = parse_db_lossy(src, SigSource::Internal);
        assert_eq!(outcome.signatures.len(), 1);
        assert_eq!(outcome.signatures[0].name, "good");
        assert_eq!(outcome.skipped.len(), 1);
        match &outcome.skipped[0].kind {
            DbParseErrorKind::BadHexToken(t) => assert_eq!(t, "ZZ"),
            other => panic!("wrong error: {:?}", other),
        }
    }
}
