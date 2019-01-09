// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Debug, PartialEq, Clone)]
pub enum CrashPoint {
    Panic,
    Error,
    None,
}

const PANIC: usize = 1;
const ERROR: usize = 2;
const NONE: usize = 0;

impl Display for CrashPoint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let numeric = match self {
            CrashPoint::Panic => PANIC,
            CrashPoint::Error => ERROR,
            CrashPoint::None => NONE,
        };
        write!(f, "{}", numeric)
    }
}

impl From<usize> for CrashPoint {
    fn from(number: usize) -> Self {
        match number {
            PANIC => CrashPoint::Panic,
            ERROR => CrashPoint::Error,
            _ => CrashPoint::None,
        }
    }
}

impl Into<usize> for CrashPoint {
    fn into(self) -> usize {
        match self {
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
    fn into() {
        assert_eq!(CrashPoint::None, 0.into());
        assert_eq!(CrashPoint::Panic, 1.into());
        assert_eq!(CrashPoint::Error, 2.into());
    }

    #[test]
    fn from() {
        assert_eq!(0usize, CrashPoint::None.into());
        assert_eq!(1usize, CrashPoint::Panic.into());
        assert_eq!(2usize, CrashPoint::Error.into());
    }

    #[test]
    fn fmt() {
        assert_eq!("0", format!("{}", CrashPoint::None));
        assert_eq!("1", format!("{}", CrashPoint::Panic));
        assert_eq!("2", format!("{}", CrashPoint::Error));
    }
}
