// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use discriminator::UnmaskedChunk;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::marker::Send;

#[derive(Debug, PartialEq)]
pub enum MasqueradeError {
    LowLevelDataError(String),
    MidLevelDataError(String),
    HighLevelDataError(String),
    UnexpectedComponent(String),
}

impl Display for MasqueradeError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let (prefix, payload) = match self {
            &MasqueradeError::LowLevelDataError(ref s) => ("Low-level data error", s),
            &MasqueradeError::MidLevelDataError(ref s) => ("Mid-level data error", s),
            &MasqueradeError::HighLevelDataError(ref s) => ("High-level data error", s),
            &MasqueradeError::UnexpectedComponent(ref s) => ("Unexpected component indicator", s),
        };
        write!(f, "{}: {}", prefix, payload)
    }
}

pub trait Masquerader: Send {
    fn try_unmask(&self, item: &[u8]) -> Option<UnmaskedChunk>;
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
            &format!(
                "{}",
                MasqueradeError::UnexpectedComponent(String::from("blah"))
            ),
            "Unexpected component indicator: blah"
        );
    }
}
