use crate::ip_country::DBIPParser;
use std::io;
use std::any::Any;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;
use maxminddb::geoip2::City;
use maxminddb::{Reader, Within};
use serde::Deserialize;
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};
use crate::countries::Countries;
use crate::country_block_stream::{Country, CountryBlock, IpRange};

pub struct MMDBParser {
}

impl DBIPParser for MMDBParser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn parse(
        &self,
        stdin: &mut dyn io::Read,
        errors: &mut Vec<String>,
    ) -> (FinalBitQueue, FinalBitQueue, Countries) {
        let mut bytes: Vec<u8> = vec![];
eprintln!("Reading stdin");
        match stdin.read_to_end(&mut bytes) {
            Ok(_) => {}
            Err(e) => {
                todo!("Error reading from stdin: {}", e);
            }
        };
eprintln!("Making Reader");
        let reader = match Reader::from_source(bytes) {
            Ok(r) => r,
            Err(e) => {
                todo!("Error opening MaxMind DB: {}", e);
            }
        };
        let mut country_pairs: HashSet<(String, String)> = HashSet::new();

        let ip_network = match Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0) {
            Ok(ipn) => ipn,
            Err(e) => {
                todo!("Error creating IP network: {}", e);
            }
        };
eprintln!("Calling within() for IPv4");
        let within = match reader.within::<City>(
            IpNetwork::V4(ip_network),
        ) {
            Ok(w) => w,
            Err(e) => {
                todo!("Error creating within iterator: {}", e);
            }
        };
eprintln!("Extracting IPv4 data");
        let ipv4_ranges = Self::extract_data(within, &mut country_pairs, errors);

        let ip_network = match Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0) {
            Ok(ipn) => ipn,
            Err(e) => {
                todo!("Error creating IP network: {}", e);
            }
        };
eprintln!("Calling within() for IPv6");
        let within = match reader.within::<City>(
            IpNetwork::V6(ip_network),
        ) {
            Ok(w) => w,
            Err(e) => {
                todo!("Error creating within iterator: {}", e);
            }
        };
eprintln!("Extracting IPv6 data");
        let ipv6_ranges = Self::extract_data(within, &mut country_pairs, errors);

eprintln!("Creating Countries structure");
        let country_pairs_vec = country_pairs.into_iter().collect_vec();
        let countries = Countries::new(country_pairs_vec);

        let make_country_blocks = |ranges: Vec<(String, IpRange)>| {
            ranges.into_iter().map(|(code, ip_range)| {
                match countries.country_from_code(code.as_str()) {
                    Ok(country) => CountryBlock {
                        ip_range,
                        country: country.clone(),
                    },
                    Err(e) => {
                        eprintln!("Error finding country from code {} for IP range {:?}: {}", code, ip_range, e);
                        CountryBlock {
                            ip_range,
                            country: Country::new(0, "ZZ", "Unknown"),
                        }
                    }
                }
            }).collect_vec()
        };
        let mut serializer = CountryBlockSerializer::new();
eprintln!("Making IPv4 CountryBlocks");
        let country_blocks = make_country_blocks(ipv4_ranges);
eprintln!("Serializing IPv4 CountryBlocks");
        country_blocks.into_iter().for_each(|block| serializer.add(block));
eprintln!("Making IPv6 CountryBlocks");
        let country_blocks = make_country_blocks(ipv6_ranges);
eprintln!("Serializing IPv6 CountryBlocks");
        country_blocks.into_iter().for_each(|block| serializer.add(block));
eprintln!("Finishing serialization");
        let (ipv4_bit_queue, ipv6_bit_queue) = serializer.finish();

eprintln!("Returning final tuple");
        (ipv4_bit_queue, ipv6_bit_queue, countries)
    }
}

impl MMDBParser {
    pub fn new() -> Self {
        Self {

        }
    }

    fn extract_data<'de>(
        within: Within<'de, City<'de>, Vec<u8>>,
        country_pairs: &mut HashSet<(String, String)>,
        _errors: &mut Vec<String>
    ) -> Vec<(String, IpRange)> {
        let mut coded_ranges: Vec<(String, IpRange)> = vec![];
        within.for_each(|item_result| {
            match item_result {
                Ok(item) => {
                    match item.info.country {
                        Some(country) => {
                            match (country.iso_code, country.names.map(|ns| ns.get("en").map(|n| n.to_string()))) {
                                (Some(code), Some(Some(name))) => {
                                    country_pairs.insert((code.to_string(), name.to_string()));
                                    let ip_range = Self::ipn_to_range(item.ip_net);
                                    coded_ranges.push((code.to_string(), ip_range));
                                }
                                (Some(code), Some(None)) => {
                                    todo!("Country code {:?} found but no name", code);
                                }
                                (None, Some(Some(name))) => {
                                    todo!("Country code not found for country: {:?}", name);
                                }
                                // (None, Some(None)) => {
                                //     todo!("Country code and name not found for item: {:?}", item);
                                // }
                                _ => {
                                    todo!("What's this?")
                                }
                            }
                        }
                        None => todo!("Country info not found for item: {:?}", item),
                    }
                }
                Err(e) => {
                    todo!("Error processing item: {}", e);
                }
            }
        });
        coded_ranges
    }

    fn ipn_to_range(ipn: IpNetwork) -> IpRange {
        match ipn {
            IpNetwork::V4(ipn) => IpRange::V4 (ipn.network().into(), ipn.broadcast().into()),
            IpNetwork::V6(ipn) => IpRange::V6 (ipn.network().into(), ipn.broadcast().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::min;
    use std::fs::File;
    use std::net::IpAddr;
    use std::str::FromStr;
    use crate::country_finder::CountryCodeFinder;

    #[test]
    fn happy_path() {
        let file = PathBuf::from("data/dbip-country-lite.mmdb");
        let mut stdin = File::open(&file).unwrap();
        let subject = MMDBParser::new();
        let mut errors = vec![];

        let (ipv4_bit_queue, ipv6_bit_queue, countries) =
            subject.parse(&mut stdin, &mut errors);

        let expected_errors: Vec<String> = vec![];
        assert_eq!(errors, expected_errors);
eprintln! ("No errors! Creating CountryCodeFinder");
        let country_code_finder = CountryCodeFinder::new(
            &countries,
            country_data_from_bit_queue(ipv4_bit_queue),
            country_data_from_bit_queue(ipv6_bit_queue)
        );
eprintln!("Finding country for 55.55.55.55");
        let ipv4_five_country = country_code_finder.find_country(IpAddr::from_str("55.55.55.55").unwrap());
        assert_eq!(ipv4_five_country.map(|c| c.iso3166.clone()), Some("US".to_string()));
eprintln!("Finding country for 5555:5555:5555:5555:5555:5555:5555");
        let ipv6_five_country = country_code_finder.find_country(IpAddr::from_str("5555:5555:5555:5555:5555:5555:5555:5555").unwrap());
        assert_eq!(ipv6_five_country.map(|c| c.iso3166.clone()), Some("CH".to_string()));
    }

    fn country_data_from_bit_queue(mut bit_queue: FinalBitQueue) -> (Vec<u64>, usize) {
        let len = bit_queue.bit_queue.len();
        let mut result = vec![];
        loop {
            let len = bit_queue.bit_queue.len();
            let next_len = min(64, len);
            if next_len == 0 { break; }
            match bit_queue.bit_queue.take_bits(next_len) {
                Some(bits) => result.push(bits),
                None => break
            }
        }
        (result, len)
    }
}
