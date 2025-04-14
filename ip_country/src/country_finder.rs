// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::countries::Countries;
use crate::country_block_serde::CountryBlockDeserializer;
use crate::country_block_stream::{Country, CountryBlock};
use crate::dbip_country;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

lazy_static! {
    pub static ref COUNTRY_CODE_FINDER: CountryCodeFinder<'static> = CountryCodeFinder::new(
        &dbip_country::COUNTRIES,
        dbip_country::ipv4_country_data(),
        dbip_country::ipv6_country_data()
    );
}

pub struct CountryCodeFinder<'a> {
    pub countries: &'a Countries,
    pub ipv4: Vec<CountryBlock>,
    pub ipv6: Vec<CountryBlock>,
}

impl<'a> CountryCodeFinder<'a> {
    pub fn new(
        countries: &'a Countries,
        ipv4_data: (Vec<u64>, usize),
        ipv6_data: (Vec<u64>, usize),
    ) -> Self {
        Self {
            countries,
            ipv4: CountryBlockDeserializer::<Ipv4Addr, u8, 4>::new(ipv4_data, countries)
                .into_iter()
                .collect_vec(),
            ipv6: CountryBlockDeserializer::<Ipv6Addr, u16, 8>::new(ipv6_data, countries)
                .into_iter()
                .collect_vec(),
        }
    }

    pub fn find_country(&'a self, ip_addr: IpAddr) -> Option<&'a Country> {
        let country_blocks: &[CountryBlock] = match ip_addr {
            IpAddr::V4(_) => self.ipv4.as_slice(),
            IpAddr::V6(_) => self.ipv6.as_slice(),
        };
        let block_index =
            country_blocks.binary_search_by(|block| block.ip_range.ordering_by_range(ip_addr));
        let country = match block_index {
            Ok(index) => &country_blocks[index].country,
            _ => self
                .countries
                .country_from_code("ZZ")
                .expect("expected Country"),
        };
        match country.iso3166.as_str() {
            "ZZ" => None,
            _ => Some(country),
        }
    }

    pub fn ensure_init(&self) {
        //This should provoke lazy_static to perform the value initialization
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::country_block_serde::{Ipv4CountryBlockDeserializer, Ipv6CountryBlockDeserializer};
    use crate::country_block_stream::IpRange;
    use crate::dbip_country;
    use crate::dbip_country::COUNTRIES;
    use std::str::FromStr;
    use std::time::SystemTime;

    fn select_country(countries: &Countries, percentage: u8) -> &Country {
        // 0% is the first country; 100% is the last country
        let country_count_f = countries.len() as f64;
        let percentage_f = percentage as f64;
        let index = (percentage_f * country_count_f / 101.0).trunc() as usize;
        countries.country_from_index(index).unwrap()
    }

    #[test]
    fn finds_ipv4_address() {
        COUNTRY_CODE_FINDER.ensure_init();
        let country = select_country(&COUNTRIES, 50);
        let ip_range = &COUNTRY_CODE_FINDER
            .ipv4
            .iter()
            .find(|block| block.country == *country)
            .unwrap()
            .ip_range;
        let input_ip = match ip_range {
            IpRange::V4(start, _) => IpAddr::V4(start.clone()),
            _ => panic!("Expected IPv4"),
        };

        let result = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, input_ip).unwrap();

        assert_eq!(result, country);
    }

    #[test]
    fn does_not_find_ipv4_address_in_zz_block() {
        COUNTRY_CODE_FINDER.ensure_init();
        let ip_range = &COUNTRY_CODE_FINDER
            .ipv4
            .iter()
            .find(|block| &block.country.iso3166 == "ZZ")
            .unwrap()
            .ip_range;
        let input_ip = match ip_range {
            IpRange::V4(start, _) => IpAddr::V4(start.clone()),
            _ => panic!("Expected IPv4"),
        };

        let result = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, input_ip);

        assert_eq!(result, None);
    }

    #[test]
    fn finds_ipv6_address() {
        COUNTRY_CODE_FINDER.ensure_init();
        let country = select_country(&COUNTRIES, 50);
        let ip_range = &COUNTRY_CODE_FINDER
            .ipv6
            .iter()
            .find(|block| block.country == *country)
            .unwrap()
            .ip_range;
        let input_ip = match ip_range {
            IpRange::V6(start, _) => IpAddr::V6(start.clone()),
            _ => panic!("Expected IPv6"),
        };

        let result = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, input_ip).unwrap();

        assert_eq!(result, country);
    }

    #[test]
    fn does_not_find_ipv6_address_in_zz_block() {
        COUNTRY_CODE_FINDER.ensure_init();
        let ip_range = &COUNTRY_CODE_FINDER
            .ipv6
            .iter()
            .find(|block| &block.country.iso3166 == "ZZ")
            .unwrap()
            .ip_range;
        let input_ip = match ip_range {
            IpRange::V6(start, _) => IpAddr::V6(start.clone()),
            _ => panic!("Expected IPv6"),
        };

        let result = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, input_ip);

        assert_eq!(result, None)
    }

    #[test]
    fn real_test_ipv4_with_google() {
        if dbip_country::COUNTRIES.country_from_code("US").is_err() {
            eprintln!("Country data must be generated (see ip_country/main.rs) in dbip_country.rs before this test will work");
            return;
        }
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER,
            IpAddr::from_str("142.250.191.132").unwrap(), // dig www.google.com A
        )
        .unwrap();

        assert_eq!(result.iso3166, "US".to_string());
        assert_eq!(result.name, "United States".to_string());
    }

    #[test]
    fn real_test_ipv4_with_cz_ip() {
        if dbip_country::COUNTRIES.country_from_code("CZ").is_err() {
            eprintln!("Country data must be generated (see ip_country/main.rs) in dbip_country.rs before this test will work");
            return;
        }
        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER,
            IpAddr::from_str("77.75.77.222").unwrap(), // dig www.seznam.cz A
        )
        .unwrap();

        assert_eq!(result.iso3166, "CZ".to_string());
        assert_eq!(result.name, "Czechia".to_string());
    }

    #[test]
    fn real_test_ipv4_with_sk_ip() {
        if dbip_country::COUNTRIES.country_from_code("SK").is_err() {
            eprintln!("Country data must be generated (see ip_country/main.rs) in dbip_country.rs before this test will work");
            return;
        }
        let time_start = SystemTime::now();

        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER,
            IpAddr::from_str("213.81.185.100").unwrap(), // dig www.zoznam.sk A
        )
        .unwrap();

        let time_end = SystemTime::now();
        let duration = time_end.duration_since(time_start).unwrap();

        assert_eq!(result.iso3166, "SK".to_string());
        assert_eq!(result.name, "Slovakia".to_string());
        assert!(
            duration.as_millis() < 1,
            "Duration of the search was too long: {} millisecond",
            duration.as_millis()
        );
    }

    #[test]
    fn real_test_ipv6_with_google() {
        if dbip_country::COUNTRIES.country_from_code("US").is_err() {
            eprintln!("Country data must be generated (see ip_country/main.rs) in dbip_country.rs before this test will work");
            return;
        }
        let time_start = SystemTime::now();

        let result = CountryCodeFinder::find_country(
            &COUNTRY_CODE_FINDER,
            IpAddr::from_str("2607:f8b0:4009:814::2004").unwrap(), // dig www.google.com AAAA
        )
        .unwrap();

        let time_end = SystemTime::now();
        let duration = time_end.duration_since(time_start).unwrap();

        assert_eq!(result.iso3166, "US".to_string());
        assert_eq!(result.name, "United States".to_string());
        assert!(
            duration.as_millis() < 1,
            "Duration of the search was too long: {} ms",
            duration.as_millis()
        );
    }

    #[test]
    fn country_blocks_for_ipv4_and_ipv6_are_deserialized_and_inserted_into_vecs() {
        let time_start = SystemTime::now();

        let deserializer_ipv4 = Ipv4CountryBlockDeserializer::new(
            dbip_country::ipv4_country_data(),
            &dbip_country::COUNTRIES,
        );
        let deserializer_ipv6 = Ipv6CountryBlockDeserializer::new(
            dbip_country::ipv6_country_data(),
            &dbip_country::COUNTRIES,
        );

        let time_end = SystemTime::now();
        let time_start_fill = SystemTime::now();

        let country_block_finder_ipv4 = deserializer_ipv4.collect_vec();
        let country_block_finder_ipv6 = deserializer_ipv6.collect_vec();

        let time_end_fill = SystemTime::now();
        let duration_deserialize = time_end.duration_since(time_start).unwrap();
        let duration_fill = time_end_fill.duration_since(time_start_fill).unwrap();

        assert_eq!(
            country_block_finder_ipv4.len(),
            dbip_country::ipv4_country_block_count()
        );
        assert_eq!(
            country_block_finder_ipv6.len(),
            dbip_country::ipv6_country_block_count()
        );
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
        let country_block_len_ipv4 = COUNTRY_CODE_FINDER.ipv4.len();
        let country_block_len_ipv6 = COUNTRY_CODE_FINDER.ipv6.len();

        assert_eq!(
            country_block_len_ipv4,
            dbip_country::ipv4_country_block_count()
        );
        assert_eq!(
            country_block_len_ipv6,
            dbip_country::ipv6_country_block_count()
        );
    }
}
