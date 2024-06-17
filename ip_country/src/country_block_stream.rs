use std::cmp::Ordering;
use csv::{StringRecord, StringRecordIter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, PartialEq, Debug)]
pub struct Country {
    pub index: usize,
    pub iso3166: String,
    pub name: String,
    pub free_world: bool,
}

impl Country {
    pub fn new(index: usize, iso3166: &str, name: &str, free_world: bool) -> Self {
        Self {
            index,
            iso3166: iso3166.to_string(),
            name: name.to_string(),
            free_world,
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum IpRange {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

impl IpRange {
    //TODO make 2 new functions "before", "after" to check if ip is in the range or before, or after
    // ipV4 you can represent as u32 and ipV6 as u128
    // can reuse guts of contains for before and after and then replace arms of match witch calls to those fns
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

    pub fn in_range(&self, ip_addr: IpAddr) -> Ordering {
        match (ip_addr, self) {
            (IpAddr::V4(ip), IpRange::V4(low, hi) )=> {
                let (low_range, hi_range) = (u32::from(*low), u32::from(*hi));
                let ip_num = u32::from(ip);
                if ip_num < low_range {
                    Ordering::Greater
                } else if ip_num > hi_range {
                    Ordering::Less
                }
                else {
                    Ordering::Equal
                }
            },
            (IpAddr::V6(ip), IpRange::V6(low, hi)) => {
                let (low_range, hi_range) = (u128::from(*low), u128::from(*hi));
                let ip_num = u128::from(ip);
                if ip_num < low_range {
                    Ordering::Greater
                } else if ip_num > hi_range {
                    Ordering::Less
                }
                else {
                    Ordering::Equal
                }
            }
            (_ip, _range) => panic!("Mismatch ip and range versions")
            //TODO write test for this panic!
        }

    }

    fn contains_inner(begin: u128, end: u128, candidate: u128) -> bool {
        (candidate >= begin) && (candidate <= end)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct CountryBlock {
    pub ip_range: IpRange,
    pub country: Country,
}

impl TryFrom<StringRecord> for CountryBlock {
    type Error = String;

    fn try_from(string_record: StringRecord) -> Result<Self, Self::Error> {
        let mut iter = string_record.iter();
        let start_ip = Self::ip_addr_from_iter(&mut iter)?;
        let end_ip = Self::ip_addr_from_iter(&mut iter)?;
        let iso3166 = match iter.next() {
            None => return Err("CSV line contains no ISO 3166 country code".to_string()),
            Some(s) => s,
        };
        if iter.next().is_some() {
            return Err(format!(
                "CSV line should contain 3 elements, but contains {}",
                string_record.len()
            ));
        };
        Self::validate_ip_addresses(start_ip, end_ip)?;
        let country = Country::try_from(iso3166)?;
        let country_block = match (start_ip, end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) => CountryBlock {
                ip_range: IpRange::V4(start, end),
                country,
            },
            (IpAddr::V6(start), IpAddr::V6(end)) => CountryBlock {
                ip_range: IpRange::V6(start, end),
                country,
            },
            (start, end) => panic!(
                "Start and end addresses must be of the same type, not {} and {}",
                start, end
            ),
        };
        Ok(country_block)
    }
}

impl CountryBlock {
    fn ip_addr_from_iter(iter: &mut StringRecordIter) -> Result<IpAddr, String> {
        let ip_string = match iter.next() {
            None => return Err("Missing IP address in CSV record".to_string()),
            Some(s) => s,
        };
        let ip_addr = match IpAddr::from_str(ip_string) {
            Err(e) => {
                return Err(format!(
                    "Invalid ({:?}) IP address in CSV record: '{}'",
                    e, ip_string
                ))
            }
            Ok(ip) => ip,
        };
        Ok(ip_addr)
    }

    fn validate_ip_addresses(start_ip: IpAddr, end_ip: IpAddr) -> Result<(), String> {
        match (start_ip, end_ip) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                if u32::from(start_v4) > u32::from(end_v4) {
                    Err(format!(
                        "Ending address {} is less than starting address {}",
                        end_v4, start_v4
                    ))
                } else {
                    Ok(())
                }
            }
            (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
                if u128::from(start_v6) > u128::from(end_v6) {
                    Err(format!(
                        "Ending address {} is less than starting address {}",
                        end_v6, start_v6
                    ))
                } else {
                    Ok(())
                }
            }
            (s, e) => Err(format!(
                "Beginning address {} and ending address {} must be the same IP address version",
                s, e
            )),
        }
    }
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
    fn try_from_works_for_ipv4() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "AS"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Ok(CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("1.2.3.4").unwrap(),
                    Ipv4Addr::from_str("5.6.7.8").unwrap()
                ),
                country: Country::try_from("AS").unwrap().clone(),
            })
        );
    }

    #[test]
    fn try_from_works_for_ipv6() {
        let string_record = StringRecord::from(vec![
            "1234:2345:3456:4567:5678:6789:789A:89AB",
            "4321:5432:6543:7654:8765:9876:A987:BA98",
            "VN",
        ]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Ok(CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("1234:2345:3456:4567:5678:6789:789A:89AB").unwrap(),
                    Ipv6Addr::from_str("4321:5432:6543:7654:8765:9876:A987:BA98").unwrap()
                ),
                country: Country::try_from("VN").unwrap().clone(),
            })
        );
    }

    #[test]
    fn try_from_fails_for_bad_ip_syntax() {
        let string_record = StringRecord::from(vec!["Ooga", "Booga", "AS"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err("Invalid (AddrParseError(Ip)) IP address in CSV record: 'Ooga'".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_missing_start_ip() {
        let strings: Vec<&str> = vec![];
        let string_record = StringRecord::from(strings);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(result, Err("Missing IP address in CSV record".to_string()));
    }

    #[test]
    fn try_from_fails_for_missing_end_ip() {
        let string_record = StringRecord::from(vec!["1.2.3.4"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(result, Err("Missing IP address in CSV record".to_string()));
    }

    #[test]
    fn try_from_fails_for_reversed_ipv4_addresses() {
        let string_record = StringRecord::from(vec!["4.3.2.1", "1.2.3.4", "ZZ"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err("Ending address 1.2.3.4 is less than starting address 4.3.2.1".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_reversed_ipv6_addresses() {
        let string_record = StringRecord::from(vec!["8:7:6:5:4:3:2:1", "1:2:3:4:5:6:7:8", "ZZ"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err(
                "Ending address 1:2:3:4:5:6:7:8 is less than starting address 8:7:6:5:4:3:2:1"
                    .to_string()
            )
        );
    }

    #[test]
    fn try_from_fails_for_mixed_ip_types() {
        let string_record_46 = StringRecord::from(vec!["4.3.2.1", "1:2:3:4:5:6:7:8", "ZZ"]);
        let string_record_64 = StringRecord::from(vec!["1:2:3:4:5:6:7:8", "4.3.2.1", "ZZ"]);

        let result_46 = CountryBlock::try_from(string_record_46);
        let result_64 = CountryBlock::try_from(string_record_64);

        assert_eq!(result_46, Err("Beginning address 4.3.2.1 and ending address 1:2:3:4:5:6:7:8 must be the same IP address version".to_string()));
        assert_eq!(result_64, Err("Beginning address 1:2:3:4:5:6:7:8 and ending address 4.3.2.1 must be the same IP address version".to_string()));
    }

    #[test]
    fn try_from_fails_for_unrecognized_iso3166() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "XY"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err("'XY' is not a valid ISO3166 country code".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_missing_iso3166() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err("CSV line contains no ISO 3166 country code".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_too_many_elements() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "US", "extra"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(
            result,
            Err("CSV line should contain 3 elements, but contains 4".to_string())
        );
    }
}
