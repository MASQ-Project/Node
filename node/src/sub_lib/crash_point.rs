// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use clap::arg_enum;

arg_enum! {
    #[derive(Debug, PartialEq, Clone)]
    pub enum CrashPoint {
        Panic,
        Error,
        None,
    }
}

const PANIC: usize = 1;
const ERROR: usize = 2;
const NONE: usize = 0;

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
        let none: usize = CrashPoint::None.into();
        let panic: usize = CrashPoint::Panic.into();
        let error: usize = CrashPoint::Error.into();

        assert_eq!(0usize, none);
        assert_eq!(1usize, panic);
        assert_eq!(2usize, error);
    }
}
