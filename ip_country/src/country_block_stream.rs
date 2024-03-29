
use std::net::IpAddr;
use std::str::FromStr;
use csv::{StringRecord, StringRecordIter};
use crate::bit_queue::BitQueue;

#[derive(Clone, PartialEq, Debug)]
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

#[derive(Clone, PartialEq, Debug)]
pub struct CountryBlock {
    start_ip: IpAddr,
    end_ip: IpAddr,
    country: Country,
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
            return Err(format!("CSV line should contain 3 elements, but contains {}", string_record.len()))
        };
        let country = Country::try_from(iso3166)?;
        Ok(CountryBlock {
            start_ip,
            end_ip,
            country
        })
    }
}

impl CountryBlock {
    pub fn serialize_to(&self, bit_queue: &mut BitQueue) {
        todo!()
    }

    fn ip_addr_from_iter(iter: &mut StringRecordIter) -> Result<IpAddr, String> {
        let ip_string = match iter.next() {
            None => return Err("Missing IP address in CSV record".to_string()),
            Some (s) => s,
        };
        let ip_addr = match IpAddr::from_str(ip_string) {
            Err(e) => return Err(format!("Invalid IP address in CSV record: '{}'", ip_string)),
            Ok(ip) => ip,
        };
        Ok(ip_addr)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use crate::countries::{COUNTRIES, INDEX_BY_ISO3166};
    use super::*;

    #[test]
    fn try_from_works_for_ipv4() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "AS"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq! (result, Ok(CountryBlock {
            start_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            end_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            country: Country::try_from("AS").unwrap().clone(),
        }));
    }

    #[test]
    fn try_from_works_for_ipv6() {
        let string_record = StringRecord::from(vec![
            "1234:2345:3456:4567:5678:6789:789A:89AB",
            "4321:5432:6543:7654:8765:9876:A987:BA98",
            "VN"
        ]);

        let result = CountryBlock::try_from(string_record);

        assert_eq! (result, Ok(CountryBlock {
            start_ip: IpAddr::from_str("1234:2345:3456:4567:5678:6789:789A:89AB").unwrap(),
            end_ip: IpAddr::from_str("4321:5432:6543:7654:8765:9876:A987:BA98").unwrap(),
            country: Country::try_from("VN").unwrap().clone(),
        }));
    }

    #[test]
    fn try_from_fails_for_bad_ip_syntax() {
        let string_record = StringRecord::from(vec!["Ooga", "Booga", "AS"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(result, Err("Invalid IP address in CSV record: 'Ooga'".to_string()));
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
    fn try_from_fails_for_missing_iso3166() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(result, Err("CSV line contains no ISO 3166 country code".to_string()));
    }

    #[test]
    fn try_from_fails_for_too_many_elements() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "US", "extra"]);

        let result = CountryBlock::try_from(string_record);

        assert_eq!(result, Err("CSV line should contain 3 elements, but contains 4".to_string()));
    }
}