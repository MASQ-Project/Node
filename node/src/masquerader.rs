// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::discriminator::UnmaskedChunk;
use crate::sub_lib::cryptde::PublicKey;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::marker::Send;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum MasqueradeError {
    NotThisMasquerader, // This masquerader can't unmask this data. Try another one.
    LowLevelDataError(String), // Error below the level of the masquerade protocol.
    MidLevelDataError(String), // Error in the syntax or semantics of the masquerade protocol.
    HighLevelDataError(String), // Error extracting a LiveCoresPackage from the masquerade.
}

impl Display for MasqueradeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            MasqueradeError::LowLevelDataError(ref s) => write!(f, "Low-level data error: {}", s),
            MasqueradeError::MidLevelDataError(ref s) => write!(f, "Mid-level data error: {}", s),
            MasqueradeError::HighLevelDataError(ref s) => write!(f, "High-level data error: {}", s),
            MasqueradeError::NotThisMasquerader => write!(f, "Data not for this masquerader"),
        }
    }
}

pub trait Masquerader: Send {
    fn try_unmask(&self, item: &[u8]) -> Result<UnmaskedChunk, MasqueradeError>;
    fn mask(&self, data: &[u8]) -> Result<Vec<u8>, MasqueradeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masquerade_errors_are_displayable() {
        assert_eq!(
            &format!(
                "{}",
                MasqueradeError::LowLevelDataError(String::from("blah"))
            ),
            "Low-level data error: blah"
        );
        assert_eq!(
            &format!(
                "{}",
                MasqueradeError::MidLevelDataError(String::from("blah"))
            ),
            "Mid-level data error: blah"
        );
        assert_eq!(
            &format!(
                "{}",
                MasqueradeError::HighLevelDataError(String::from("blah"))
            ),
            "High-level data error: blah"
        );
        assert_eq!(
            &format!("{}", MasqueradeError::NotThisMasquerader),
            "Data not for this masquerader"
        );
    }
}
