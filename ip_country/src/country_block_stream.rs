// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::countries::Countries;
use csv::{StringRecord, StringRecordIter};
use std::cmp::Ordering;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct Country {
    pub index: usize,
    pub iso3166: String,
    pub name: String,
}

impl Country {
    pub fn new(index: usize, iso3166: &str, name: &str) -> Self {
        Self {
            index,
            iso3166: iso3166.to_string(),
            name: name.to_string(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum IpRange {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl IpRange {
    pub fn new(start: IpAddr, end: IpAddr) -> Self {
        match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => IpRange::V4(start, end),
            (IpAddr::V6(start), IpAddr::V6(end)) => IpRange::V6(start, end),
            (start, end) => panic!(
                "Start and end addresses must be of the same type, not {} and {}",
                start, end
            ),
        }
    }

    pub fn contains(&self, ip_addr: IpAddr) -> bool {
        match self {
            IpRange::V4(begin, end) => match ip_addr {
                IpAddr::V4(candidate) => Self::contains_inner(
                    u32::from(*begin) as u128,
                    u32::from(*end) as u128,
                    u32::from(candidate) as u128,
                ),
                IpAddr::V6(_candidate) => false,
            },
            IpRange::V6(begin, end) => match ip_addr {
                IpAddr::V4(_candidate) => false,
                IpAddr::V6(candidate) => Self::contains_inner(
                    u128::from(*begin),
                    u128::from(*end),
                    u128::from(candidate),
                ),
            },
        }
    }

    pub fn start(&self) -> IpAddr {
        match self {
            IpRange::V4(start, _) => IpAddr::V4(*start),
            IpRange::V6(start, _) => IpAddr::V6(*start),
        }
    }

    pub fn end(&self) -> IpAddr {
        match self {
            IpRange::V4(_, end) => IpAddr::V4(*end),
            IpRange::V6(_, end) => IpAddr::V6(*end),
        }
    }

    pub fn ordering_by_range(&self, ip_addr: IpAddr) -> Ordering {
        match (ip_addr, self) {
            (IpAddr::V4(ip), IpRange::V4(low, high)) => {
                Self::compare_with_range::<u32, Ipv4Addr>(ip, *low, *high)
            }
            (IpAddr::V6(ip), IpRange::V6(low, high)) => {
                Self::compare_with_range::<u128, Ipv6Addr>(ip, *low, *high)
            }
            (ip, range) => panic!("Mismatch ip ({}) and range ({:?}) versions", ip, range),
        }
    }

    fn compare_with_range<SingleIntegerIPRep, IP>(examined: IP, low: IP, high: IP) -> Ordering
    where
        SingleIntegerIPRep: From<IP> + PartialOrd,
    {
        let (low_end, high_end) = (
            SingleIntegerIPRep::from(low),
            SingleIntegerIPRep::from(high),
        );
        let ip_num = SingleIntegerIPRep::from(examined);
        if ip_num < low_end {
            Ordering::Greater
        } else if ip_num > high_end {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }

    fn contains_inner(begin: u128, end: u128, candidate: u128) -> bool {
        (begin <= candidate) && (candidate <= end)
    }
}

pub fn are_consecutive(first: IpAddr, second: IpAddr) -> bool {
    match (first, second) {
        (IpAddr::V4(first), IpAddr::V4(second)) => {
            let first = u32::from(first);
            let second = u32::from(second);
            second == first + 1
        }
        (IpAddr::V6(first), IpAddr::V6(second)) => {
            let first = u128::from(first);
            let second = u128::from(second);
            second == first + 1
        }
        (first, second) => panic!(
            "IP addresses must be of the same type, not {} and {}",
            first, second
        ),
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CountryBlock {
    pub ip_range: IpRange,
    pub country: Country,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn ip_range_finds_ipv4_address() {
        let subject = IpRange::V4(
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
        );

        let result_start = subject.contains(IpAddr::from_str("1.2.3.4").unwrap());
        let result_end = subject.contains(IpAddr::from_str("4.3.2.1").unwrap());

        assert_eq!(result_start, true);
        assert_eq!(result_end, true);
    }

    #[test]
    fn ip_range_doesnt_find_ipv4_address() {
        let subject = IpRange::V4(
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
        );

        let result_start = subject.contains(IpAddr::from_str("1.2.3.3").unwrap());
        let result_end = subject.contains(IpAddr::from_str("4.3.2.2").unwrap());

        assert_eq!(result_start, false);
        assert_eq!(result_end, false);
    }

    #[test]
    fn ip_range_finds_ipv6_address() {
        let subject = IpRange::V6(
            Ipv6Addr::from_str("1:2:3:4:0:0:0:0").unwrap(),
            Ipv6Addr::from_str("4:3:2:1:0:0:0:0").unwrap(),
        );

        let result_start = subject.contains(IpAddr::from_str("1:2:3:4:0:0:0:0").unwrap());
        let result_end = subject.contains(IpAddr::from_str("4:3:2:1:0:0:0:0").unwrap());

        assert_eq!(result_start, true);
        assert_eq!(result_end, true);
    }

    #[test]
    fn ip_range_doesnt_find_ipv6_address() {
        let subject = IpRange::V6(
            Ipv6Addr::from_str("0:0:0:0:1:2:3:4").unwrap(),
            Ipv6Addr::from_str("0:0:0:0:4:3:2:1").unwrap(),
        );

        let result_start = subject.contains(IpAddr::from_str("0:0:0:0:1:2:3:3").unwrap());
        let result_end = subject.contains(IpAddr::from_str("0:0:0:0:4:3:2:2").unwrap());

        assert_eq!(result_start, false);
        assert_eq!(result_end, false);
    }

    #[test]
    fn ip_range_doesnt_find_ipv6_address_in_ipv4_range() {
        let subject = IpRange::V4(
            Ipv4Addr::from_str("1.2.3.4").unwrap(),
            Ipv4Addr::from_str("4.3.2.1").unwrap(),
        );

        let result = subject.contains(IpAddr::from_str("1:2:3:4:0:0:0:0").unwrap());

        assert_eq!(result, false);
    }

    #[test]
    fn ip_range_doesnt_find_ipv4_address_in_ipv6_range() {
        let subject = IpRange::V6(
            Ipv6Addr::from_str("0:0:0:0:1:2:3:4").unwrap(),
            Ipv6Addr::from_str("0:0:0:0:4:3:2:1").unwrap(),
        );

        let result = subject.contains(IpAddr::from_str("1.2.3.4").unwrap());

        assert_eq!(result, false);
    }

    #[test]
    #[should_panic(
        expected = "Mismatch ip (1.2.3.4) and range (V6(::1:2:3:4, ::4:3:2:1)) versions"
    )]
    fn ip_range_panics_on_v4_v6_mismatch() {
        let subject = IpRange::V6(
            Ipv6Addr::from_str("0:0:0:0:1:2:3:4").unwrap(),
            Ipv6Addr::from_str("0:0:0:0:4:3:2:1").unwrap(),
        );
        let ip = Ipv4Addr::from_str("1.2.3.4").unwrap();

        let _result = subject.ordering_by_range(IpAddr::V4(ip));
    }
}
