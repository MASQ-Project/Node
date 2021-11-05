// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde_derive::*;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataVersion([u8; 3]);

impl FromStr for DataVersion {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split('.').collect::<Vec<&str>>();
        if parts.len() == 2 {
            let major = match parts[0].parse::<u16>() {
                Ok(v) => v,
                Err(_) => return Err(String::from("Unable to parse DataVersion")),
            };

            let minor = match parts[1].parse::<u16>() {
                Ok(v) => v,
                Err(_) => return Err(String::from("Unable to parse DataVersion")),
            };

            DataVersion::new(major, minor)
        } else {
            Err(String::from("Unable to parse DataVersion"))
        }
    }
}

impl Debug for DataVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl fmt::Display for DataVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.major(), self.minor())
    }
}

impl DataVersion {
    pub fn new(major: u16, minor: u16) -> Result<Self, String> {
        if major >= 4096 {
            return Err(String::from("Major version out of bounds"));
        }

        if minor >= 4096 {
            return Err(String::from("Minor version out of bounds"));
        }

        let a = (major & 0xFF0) >> 4;
        let b = ((major & 0x0F) << 4) | ((minor & 0xF00) >> 8);
        let c = minor & 0xFF;

        Ok(DataVersion([a as u8, b as u8, c as u8]))
    }

    pub fn major(self) -> u16 {
        (u16::from(self.0[0]) << 4) | ((u16::from(self.0[1]) & 0xF0) >> 4)
    }

    pub fn minor(self) -> u16 {
        ((u16::from(self.0[1]) & 0x0F) << 8) | u16::from(self.0[2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_an_error_if_major_version_is_out_of_bounds() {
        let result = DataVersion::new(4096, 1);

        assert_eq!(result, Err(String::from("Major version out of bounds")));
    }

    #[test]
    fn new_returns_an_error_if_minor_version_is_out_of_bounds() {
        let result = DataVersion::new(1, 4096);

        assert_eq!(result, Err(String::from("Minor version out of bounds")));
    }

    #[test]
    fn new_works() {
        let result = DataVersion::new(0x112, 0x233);

        assert_eq!(result, Ok(DataVersion([0x11, 0x22, 0x33])));
    }

    #[test]
    fn try_from_returns_an_error_if_there_is_no_period() {
        let result = DataVersion::from_str("123");

        assert_eq!(result, Err(String::from("Unable to parse DataVersion")));
    }

    #[test]
    fn try_from_returns_an_error_if_there_is_more_than_one_period() {
        let result = DataVersion::from_str("1.2.3");

        assert_eq!(result, Err(String::from("Unable to parse DataVersion")));
    }

    #[test]
    fn try_from_returns_an_error_if_the_major_version_fails_to_parse() {
        let result = DataVersion::from_str("4d.12");

        assert_eq!(result, Err(String::from("Unable to parse DataVersion")));
    }

    #[test]
    fn try_from_returns_an_error_if_the_minor_version_fails_to_parse() {
        let result = DataVersion::from_str("12.4d");

        assert_eq!(result, Err(String::from("Unable to parse DataVersion")));
    }

    #[test]
    fn try_from_returns_an_error_if_the_major_version_is_out_of_bounds() {
        let result = DataVersion::from_str("4096.1");

        assert_eq!(result, Err(String::from("Major version out of bounds")));
    }

    #[test]
    fn try_from_returns_an_error_if_the_minor_version_is_out_of_bounds() {
        let result = DataVersion::from_str("1.4096");

        assert_eq!(result, Err(String::from("Minor version out of bounds")));
    }

    #[test]
    fn try_from_works() {
        let result = DataVersion::from_str("274.563");

        assert_eq!(result, Ok(DataVersion([0x11, 0x22, 0x33])));
    }

    #[test]
    fn major_works() {
        let subject = DataVersion([0x11, 0x22, 0x33]);

        assert_eq!(subject.major(), 0x112);
    }

    #[test]
    fn minor_works() {
        let subject = DataVersion([0x11, 0x22, 0x33]);

        assert_eq!(subject.minor(), 0x233);
    }

    #[test]
    fn display_works() {
        let subject = DataVersion([0x11, 0x22, 0x33]);

        assert_eq!(format!("{}", subject), String::from("274.563"));
    }
}
