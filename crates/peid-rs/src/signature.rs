use crate::db::SigSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Byte(u8),
    Wildcard,
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub name: String,
    pub pattern: Vec<Token>,
    pub ep_only: bool,
    pub source: SigSource,
}

impl Signature {
    pub fn first_concrete(&self) -> Option<(usize, u8)> {
        for (i, t) in self.pattern.iter().enumerate() {
            if let Token::Byte(b) = *t {
                return Some((i, b));
            }
        }
        None
    }
}

pub fn matches(pattern: &[Token], hay: &[u8], at: usize) -> bool {
    let end = match at.checked_add(pattern.len()) {
        Some(e) if e <= hay.len() => e,
        _ => return false,
    };
    let slice = &hay[at..end];
    for (t, &b) in pattern.iter().zip(slice.iter()) {
        match *t {
            Token::Wildcard => {}
            Token::Byte(p) => {
                if p != b {
                    return false;
                }
            }
        }
    }
    true
}

pub struct SignatureDb {
    sigs: Vec<Signature>,
    by_first: Vec<Vec<u32>>,
    wild_start: Vec<u32>,
    pub has_external: bool,
}

impl SignatureDb {
    pub fn build(sigs: Vec<Signature>) -> Self {
        let mut by_first: Vec<Vec<u32>> = (0..256).map(|_| Vec::new()).collect();
        let mut wild_start: Vec<u32> = Vec::new();
        let mut has_external = false;
        for (idx, sig) in sigs.iter().enumerate() {
            if matches!(sig.source, SigSource::External) {
                has_external = true;
            }
            match sig.first_concrete() {
                Some((0, b)) => by_first[b as usize].push(idx as u32),
                Some(_) | None => wild_start.push(idx as u32),
            }
        }
        SignatureDb {
            sigs,
            by_first,
            wild_start,
            has_external,
        }
    }

    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.sigs
    }

    pub fn match_at(&self, hay: &[u8], at: usize, ep_only_required: Option<bool>) -> Option<&Signature> {
        if at >= hay.len() {
            return None;
        }
        let first = hay[at] as usize;
        let candidates = self.by_first[first].iter().chain(self.wild_start.iter());
        for &i in candidates {
            let sig = &self.sigs[i as usize];
            if let Some(req) = ep_only_required {
                if req && !sig.ep_only {
                    continue;
                }
            }
            if matches(&sig.pattern, hay, at) {
                return Some(sig);
            }
        }
        None
    }

    pub fn match_window<'a>(
        &'a self,
        hay: &[u8],
        range: std::ops::Range<usize>,
    ) -> Option<&'a Signature> {
        let end = range.end.min(hay.len());
        let start = range.start.min(end);
        for pos in start..end {
            if let Some(s) = self.match_at(hay, pos, None) {
                return Some(s);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str, pat: Vec<Token>, ep_only: bool) -> Signature {
        Signature {
            name: name.to_string(),
            pattern: pat,
            ep_only,
            source: SigSource::Internal,
        }
    }

    #[test]
    fn matches_simple() {
        let pat = vec![Token::Byte(0x60), Token::Byte(0xE8)];
        assert!(matches(&pat, &[0x60, 0xE8, 0x00], 0));
        assert!(matches(&pat, &[0xAA, 0x60, 0xE8], 1));
        assert!(!matches(&pat, &[0x60, 0x00], 0));
    }

    #[test]
    fn matches_wildcard() {
        let pat = vec![Token::Byte(0x60), Token::Wildcard, Token::Byte(0xC3)];
        assert!(matches(&pat, &[0x60, 0xFF, 0xC3], 0));
        assert!(matches(&pat, &[0x60, 0x00, 0xC3], 0));
        assert!(!matches(&pat, &[0x60, 0x00, 0xC4], 0));
    }

    #[test]
    fn matches_bounds() {
        let pat = vec![Token::Byte(0x60), Token::Byte(0xE8)];
        assert!(!matches(&pat, &[0x60], 0));
        assert!(!matches(&pat, &[0x60, 0xE8], 1));
    }

    #[test]
    fn db_buckets_by_first_concrete() {
        let s1 = sig("a", vec![Token::Byte(0x60), Token::Byte(0xE8)], true);
        let s2 = sig("b", vec![Token::Wildcard, Token::Byte(0xC3)], true);
        let db = SignatureDb::build(vec![s1, s2]);
        let hay = &[0x60, 0xE8, 0x00];
        let m = db.match_at(hay, 0, None).expect("should match a");
        assert_eq!(m.name, "a");
        let hay2 = &[0xAB, 0xC3];
        let m2 = db.match_at(hay2, 0, None).expect("should match b via wild_start");
        assert_eq!(m2.name, "b");
    }

    #[test]
    fn db_respects_ep_only_filter() {
        let s_ep = sig("ep", vec![Token::Byte(0x90)], true);
        let s_any = sig("any", vec![Token::Byte(0x91)], false);
        let db = SignatureDb::build(vec![s_ep, s_any]);
        assert!(db.match_at(&[0x90], 0, Some(true)).is_some());
        assert!(db.match_at(&[0x91], 0, Some(true)).is_none());
        assert!(db.match_at(&[0x91], 0, Some(false)).is_some());
        assert!(db.match_at(&[0x91], 0, None).is_some());
    }
}
