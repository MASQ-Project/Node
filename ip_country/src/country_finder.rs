use crate::country_block_serde::CountryBlockDeserializer;
use crate::country_block_stream::{Country, CountryBlock};
use itertools::Itertools;
use lazy_static::lazy_static;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(not(test))]
lazy_static! {
    pub static ref COUNTRY_CODE_FINDER: CountryCodeFinder = CountryCodeFinder::new(
        crate::dbip_country::ipv4_country_data(),
        crate::dbip_country::ipv6_country_data()
    );
}

#[cfg(test)]
lazy_static! {
    pub static ref COUNTRY_CODE_FINDER: CountryCodeFinder = CountryCodeFinder::new(
        crate::test_dbip_country::ipv4_country_data(),
        crate::test_dbip_country::ipv6_country_data()
    );
}

pub struct CountryCodeFinder {
    pub ipv4: Vec<CountryBlock>,
    pub ipv6: Vec<CountryBlock>,
}

impl CountryCodeFinder {
    pub fn new(ipv4_data: (Vec<u64>, usize), ipv6_data: (Vec<u64>, usize)) -> Self {
        Self {
            ipv4: CountryBlockDeserializer::<Ipv4Addr, u8, 4>::new(ipv4_data)
                .into_iter()
                .collect_vec(),
            ipv6: CountryBlockDeserializer::<Ipv6Addr, u16, 8>::new(ipv6_data)
                .into_iter()
                .collect_vec(),
        }
    }

    pub fn find_country(
        &self,
        ip_addr: IpAddr,
    ) -> Option<Country> {
        let country_blocks: &[CountryBlock] = match ip_addr {
            IpAddr::V4(_) => self.ipv4.as_slice(),
            IpAddr::V6(_) => self.ipv6.as_slice(),
        };
        let block_index =
            country_blocks.binary_search_by(|block| block.ip_range.ordering_by_range(ip_addr));
        let country = match block_index {
            Ok(index) => country_blocks[index].country.clone(),
            _ => Country::try_from("ZZ").expect("expected Country"),
        };
        match country.iso3166.as_str() {
            "ZZ" => None,
            _ => Some(country),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::country_block_serde::CountryBlockDeserializer;
    use lazy_static::lazy_static;
    use std::str::FromStr;
    use std::time::SystemTime;
    use crate::dbip_country;

    lazy_static! {
        static ref COUNTRY_CODE_FINDER_TEST: CountryCodeFinder =
            CountryCodeFinder::new(ipv4_country_data(), ipv6_country_data());
        static ref FULL_COUNTRY_CODE_FINDER: CountryCodeFinder = CountryCodeFinder::new(
            crate::dbip_country::ipv4_country_data(),
            crate::dbip_country::ipv6_country_data()
        );
    }

    pub fn ipv4_country_data() -> (Vec<u64>, usize) {
        (
            vec![
                0x0080000300801003,
                0x82201C0902E01807,
                0x28102E208388840B,
                0x605C0100AB76020E,
                0x0000000000000000,
            ],
            271,
        )
    }

    pub fn ipv6_country_data() -> (Vec<u64>, usize) {
        (
            vec![
                0x3000040000400007,
                0x00C0001400020000,
                0xA80954B000000700,
                0x4000000F0255604A,
                0x0300004000040004,
                0xE04AAC8380003800,
                0x00018000A4000001,
                0x2AB0003485C0001C,
                0x0600089000000781,
                0xC001D20700007000,
                0x00424000001E04AA,
                0x15485C0001C00018,
                0xC90000007812AB00,
                0x2388000700006002,
                0x000001E04AAC00C5,
                0xC0001C0001801924,
                0x0007812AB0063485,
                0x0070000600C89000,
                0x1E04AAC049D23880,
                0xC000180942400000,
                0x12AB025549BA0001,
                0x0040002580000078,
                0xAC8B800038000300,
                0x000000000001E04A,
            ],
            1513,
        )
    }

    #[test]
    fn finds_ipv4_address_in_fourth_block() {
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER_TEST,
            IpAddr::from_str("1.0.6.15").unwrap(),
        );

        assert_eq!(result, Some(Country::try_from("AU").unwrap()))
    }

    #[test]
    fn does_not_find_ipv4_address_in_zz_block() {
        let time_start = SystemTime::now();
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER_TEST,
            IpAddr::from_str("0.0.5.0").unwrap(),
        );
        let time_end = SystemTime::now();

        assert_eq!(result, None);
        let duration = time_end.duration_since(time_start).unwrap();
        assert!(
            duration.as_secs() < 1,
            "Duration of the search was too long: {} ms",
            duration.as_millis()
        );
    }

    #[test]
    fn finds_ipv6_address_in_fourth_block() {
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER_TEST,
            IpAddr::from_str("1:0:5:0:0:0:0:0").unwrap(),
        );

        assert_eq!(result, Some(Country::try_from("AU").unwrap()))
    }

    #[test]
    fn does_not_find_ipv6_address_in_zz_block() {
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER_TEST,
            IpAddr::from_str("0:0:5:0:0:0:0:0").unwrap(),
        );

        assert_eq!(result, None)
    }

    #[test]
    fn real_test_ipv4_with_google() {
        let result = FULL_COUNTRY_CODE_FINDER.find_country(
            IpAddr::from_str("142.250.191.132").unwrap(), // dig www.google.com A
        )
        .unwrap();

        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "US".to_string());
        assert_eq!(result.name, "United States".to_string());
    }

    #[test]
    fn real_test_ipv4_with_cz_ip() {
        let result = CountryCodeFinder::find_country(
            &FULL_COUNTRY_CODE_FINDER,
            IpAddr::from_str("77.75.77.222").unwrap(), // dig www.seznam.cz A
        )
        .unwrap();

        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "CZ".to_string());
        assert_eq!(result.name, "Czechia".to_string());
    }

    #[test]
    fn real_test_ipv4_with_sk_ip() {
        let _ = CountryCodeFinder::find_country(
            &FULL_COUNTRY_CODE_FINDER,
            IpAddr::from_str("213.81.185.100").unwrap(), // dig www.zoznam.sk A
        )
        .unwrap();
        let time_start = SystemTime::now();

        let result = CountryCodeFinder::find_country(
            &FULL_COUNTRY_CODE_FINDER,
            IpAddr::from_str("213.81.185.100").unwrap(), // dig www.zoznam.sk A
        )
        .unwrap();

        let time_end = SystemTime::now();
        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "SK".to_string());
        assert_eq!(result.name, "Slovakia".to_string());
        let duration = time_end.duration_since(time_start).unwrap();
        assert!(
            duration.as_secs() < 1,
            "Duration of the search was too long: {} ms",
            duration.as_millis()
        );
    }

    #[test]
    fn real_test_ipv6_with_google() {
        let _ = CountryCodeFinder::find_country(
            &FULL_COUNTRY_CODE_FINDER,
            IpAddr::from_str("2607:f8b0:4009:814::2004").unwrap(), // dig www.google.com AAAA
        )
        .unwrap();
        let time_start = SystemTime::now();

        let result = CountryCodeFinder::find_country(
            &FULL_COUNTRY_CODE_FINDER,
            IpAddr::from_str("2607:f8b0:4009:814::2004").unwrap(), // dig www.google.com AAAA
        )
        .unwrap();

        let time_end = SystemTime::now();
        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "US".to_string());
        assert_eq!(result.name, "United States".to_string());
        let duration = time_end.duration_since(time_start).unwrap();
        assert!(
            duration.as_secs() < 1,
            "Duration of the search was too long: {} ms",
            duration.as_millis()
        );
    }

    #[test]
    fn country_blocks_for_ipv4_and_ipv6_are_deserialized_filled_into_vecs() {
        let time_start = SystemTime::now();

        let deserializer_ipv4 = CountryBlockDeserializer::<Ipv4Addr, u8, 4>::new(
            crate::dbip_country::ipv4_country_data(),
        );
        let deserializer_ipv6 = CountryBlockDeserializer::<Ipv6Addr, u16, 8>::new(
            crate::dbip_country::ipv6_country_data(),
        );

        let time_end = SystemTime::now();
        let time_start_fill = SystemTime::now();
        let _ = deserializer_ipv4.collect_vec();
        let _ = deserializer_ipv6.collect_vec();
        let time_end_fill = SystemTime::now();
        let duration_deserialize = time_end.duration_since(time_start).unwrap();
        let duration_fill = time_end_fill.duration_since(time_start_fill).unwrap();
        assert!(
            duration_deserialize.as_secs() < 15,
            "Duration of the deserialization was too long: {} ms",
            duration_deserialize.as_millis()
        );
        assert!(
            duration_fill.as_secs() < 8,
            "Duration of the filling the vectors was too long: {} ms",
            duration_fill.as_millis()
        );
    }

    #[test]
    fn check_ipv4_ipv6_country_blocks_length() {
        let _result = FULL_COUNTRY_CODE_FINDER.find_country(
            IpAddr::from_str("142.250.191.132").unwrap(),
        ).unwrap();
        let country_block_len_ipv4 = FULL_COUNTRY_CODE_FINDER.ipv4.len();
        let country_block_len_ipv6 = FULL_COUNTRY_CODE_FINDER.ipv6.len();

        assert_eq!(country_block_len_ipv4, dbip_country::ipv4_country_block_count());
        assert_eq!(country_block_len_ipv6, dbip_country::ipv6_country_block_count());
    }
}
