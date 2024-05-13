// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use core::str::FromStr;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CrashPoint {
    Message,
    Panic,
    Error,
    None,
}

const NONE: usize = 0;
const PANIC: usize = 1;
const ERROR: usize = 2;
const MESSAGE: usize = 3;

impl FromStr for CrashPoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "none" => Ok(CrashPoint::None),
            "panic" => Ok(CrashPoint::Panic),
            "error" => Ok(CrashPoint::Error),
            "message" => Ok(CrashPoint::Message),
            s => Err(format!(
                "Crash point must be 'none', 'panic', 'error', or 'message'; not '{}'",
                s
            )),
        }
    }
}

impl Display for CrashPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            CrashPoint::None => "none".to_string(),
            CrashPoint::Panic => "panic".to_string(),
            CrashPoint::Error => "error".to_string(),
            CrashPoint::Message => "message".to_string(),
        };
        write!(f, "{}", string)
    }
}

impl From<usize> for CrashPoint {
    fn from(number: usize) -> Self {
        match number {
            PANIC => CrashPoint::Panic,
            ERROR => CrashPoint::Error,
            MESSAGE => CrashPoint::Message,
            _ => CrashPoint::None,
        }
    }
}

impl From<CrashPoint> for usize {
    fn from(crash_point: CrashPoint) -> Self {
        match crash_point {
            CrashPoint::Message => MESSAGE,
            CrashPoint::Panic => PANIC,
            CrashPoint::Error => ERROR,
            CrashPoint::None => NONE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(NONE, 0);
        assert_eq!(PANIC, 1);
        assert_eq!(ERROR, 2);
        assert_eq!(MESSAGE, 3);
    }

    #[test]
    fn from_str_to_crash_point() {
        assert_eq!(CrashPoint::from_str("none"), Ok(CrashPoint::None));
        assert_eq!(CrashPoint::from_str("panic"), Ok(CrashPoint::Panic));
        assert_eq!(CrashPoint::from_str("error"), Ok(CrashPoint::Error));
        assert_eq!(CrashPoint::from_str("message"), Ok(CrashPoint::Message));
        assert_eq!(
            CrashPoint::from_str("booga"),
            Err(
                "Crash point must be 'none', 'panic', 'error', or 'message'; not 'booga'"
                    .to_string()
            )
        );
    }

    #[test]
    fn from_crash_point_to_string() {
        assert_eq!(CrashPoint::None.to_string(), "none".to_string());
        assert_eq!(CrashPoint::Panic.to_string(), "panic".to_string());
        assert_eq!(CrashPoint::Error.to_string(), "error".to_string());
        assert_eq!(CrashPoint::Message.to_string(), "message".to_string());
    }

    #[test]
    fn from_usize_to_crash_point() {
        assert_eq!(CrashPoint::from(NONE), CrashPoint::None);
        assert_eq!(CrashPoint::from(PANIC), CrashPoint::Panic);
        assert_eq!(CrashPoint::from(ERROR), CrashPoint::Error);
        assert_eq!(CrashPoint::from(MESSAGE), CrashPoint::Message);
    }

    #[test]
    fn from_crash_point_to_usize() {
        let none = usize::from(CrashPoint::None);
        let panic = usize::from(CrashPoint::Panic);
        let error = usize::from(CrashPoint::Error);
        let message = usize::from(CrashPoint::Message);

        assert_eq!(none, NONE);
        assert_eq!(panic, PANIC);
        assert_eq!(error, ERROR);
        assert_eq!(message, MESSAGE);
    }
}
