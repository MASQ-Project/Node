// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::str::FromStr;
use std::cmp::Ordering;
use std::fmt;
use serde::{Deserialize, Serialize};
use serde_derive::{Serialize, Deserialize};

pub const FUTURE_VERSION: DataVersion = DataVersion {
    major: 0xFFFF,
    minor: 0xFFFF,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataVersion {
    pub major: u16,
    pub minor: u16,
}

impl PartialOrd for DataVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.major.partial_cmp(&other.major) {
            None => None,
            Some(Ordering::Equal) => self.minor.partial_cmp(&other.minor),
            Some(ordering) => Some(ordering),
        }
    }
}

impl fmt::Display for DataVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if *self == FUTURE_VERSION {
            write!(f, "?.?")
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

impl FromStr for DataVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('.');
        let numbers_opt: Option<Vec<u16>> = parts.fold(Some(vec![]), |sofar, part| {
            match (sofar, part.parse::<u16>()) {
                (None, _) => None,
                (Some(_), Err(_)) => None,
                (Some(prefix), Ok(n)) => {
                    let mut whole = prefix;
                    whole.push(n);
                    Some(whole)
                }
            }
        });
        match numbers_opt {
            None => Err(format!(
                "DataVersion syntax is <major>.<minor>, not '{}'",
                s
            )),
            Some(ref numbers) if numbers.len() != 2 => Err(format!(
                "DataVersion syntax is <major>.<minor>, not '{}'",
                s
            )),
            Some(numbers) => Ok(DataVersion::new(numbers[0], numbers[1])),
        }
    }
}

impl DataVersion {
    pub fn new(major: u16, minor: u16) -> DataVersion {
        if (major > 4095) || (minor > 4095) {
            panic!(
                "DataVersion major and minor components range from 0-4095, not '{}.{}'",
                major, minor
            );
        }
        DataVersion { major, minor }
    }
}

/// `dv!(major, minor)` is simply a shortcut for `DataVersion::new(major, minor)`.
#[macro_export]
macro_rules! dv {
    ($j:expr, $n:expr) => {
        $crate::data_version::DataVersion::new($j, $n)
    };
}


#[cfg(test)]
mod test {
    use crate::data_version::{DataVersion, FUTURE_VERSION};
    use std::str::FromStr;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            FUTURE_VERSION,
            DataVersion {
                major: 0xFFFF,
                minor: 0xFFFF,
            }
        );
    }

    #[test]
    #[should_panic(
    expected = "DataVersion major and minor components range from 0-4095, not '4096.0'"
    )]
    fn dataversions_cant_have_major_too_big() {
        let _ = dv!(4096, 0);
    }

    #[test]
    #[should_panic(
    expected = "DataVersion major and minor components range from 0-4095, not '0.4096'"
    )]
    fn dataversions_cant_have_minor_too_big() {
        let _ = dv!(0, 4096);
    }

    #[test]
    fn dataversions_can_be_compared() {
        let low_low_version = dv!(2, 3);
        let low_high_version = dv!(2, 8);
        let high_low_version = dv!(7, 4);
        let high_high_version = dv!(7, 6);

        assert!(low_low_version < low_high_version);
        assert!(low_low_version < high_low_version);
        assert!(low_low_version < high_high_version);
        assert!(low_high_version > low_low_version);
        assert!(low_high_version < high_low_version);
        assert!(low_high_version < high_high_version);
        assert!(high_low_version > low_low_version);
        assert!(high_low_version > low_high_version);
        assert!(high_low_version < high_high_version);
        assert!(high_high_version > low_low_version);
        assert!(high_high_version > low_high_version);
        assert!(high_high_version > high_low_version);
    }

    #[test]
    fn dataversions_are_display() {
        let subject = dv!(2, 3);

        let result = format!("{}", subject);

        assert_eq!(result, "2.3".to_string());
    }

    #[test]
    fn future_version_is_special() {
        let subject = FUTURE_VERSION;

        let result = format!("{}", subject);

        assert_eq!(result, "?.?".to_string());
    }

    #[test]
    fn dataversions_are_from_str_good() {
        let result = DataVersion::from_str("1.2");

        assert_eq!(result, Ok(dv!(1, 2)));
    }

    #[test]
    fn dataversions_arent_parsed_when_major_is_nonnumeric() {
        let result = DataVersion::from_str("a.2");

        assert_eq!(
            result,
            Err("DataVersion syntax is <major>.<minor>, not 'a.2'".to_string())
        );
    }

    #[test]
    fn dataversions_arent_parsed_when_minor_is_nonnumeric() {
        let result = DataVersion::from_str("1.b");

        assert_eq!(
            result,
            Err("DataVersion syntax is <major>.<minor>, not '1.b'".to_string())
        );
    }

    #[test]
    fn dataversions_arent_parsed_when_no_dot_is_present() {
        let result = DataVersion::from_str("1v2");

        assert_eq!(
            result,
            Err("DataVersion syntax is <major>.<minor>, not '1v2'".to_string())
        );
    }

    #[test]
    fn dataversions_arent_parsed_when_too_many_dots_are_present() {
        let result = DataVersion::from_str("1.2.3");

        assert_eq!(
            result,
            Err("DataVersion syntax is <major>.<minor>, not '1.2.3'".to_string())
        );
    }

}