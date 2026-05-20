pub mod parser;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigSource {
    Internal,
    External,
}

pub use parser::{parse_db, parse_db_lossy, DbParseError, ParseOutcome};
