use crate::ip_country::DBIPParser;
use std::io;
use std::any::Any;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use ipnetwork::{IpNetwork, Ipv6Network};
use itertools::Itertools;
use maxminddb::geoip2::City;
use maxminddb::{Reader, Within};
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};
use crate::countries::Countries;
use crate::country_block_stream::{are_consecutive, Country, CountryBlock, IpRange};

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
        match stdin.read_to_end(&mut bytes) {
            Ok(_) => {}
            Err(e) => {
                errors.push(format!("Error reading from stdin: {}", e));
            }
        };
        let reader = match Reader::from_source(bytes) {
            Ok(r) => r,
            Err(e) => {
                errors.push(format!("Error opening MaxMind DB: {}", e));
                return (FinalBitQueue::default(), FinalBitQueue::default(), Countries::new(vec![]));
            }
        };
        let mut country_pairs: HashSet<(String, String)> = HashSet::new();
        let ip_network = Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).expect("Ipv6Network stopped working");
        let ip_ranges = match reader.within::<City>(
            IpNetwork::V6(ip_network),
        ) {
            Ok(w) => {
                Self::extract_data(w, &mut country_pairs, errors)            },
            Err(e) => {
                errors.push(format!("Error creating within iterator: {}", e));
                vec![]
            }
        };

        let country_pairs_vec = country_pairs.into_iter().collect_vec();
        let countries = Countries::new(country_pairs_vec);

        let mut make_country_blocks = |ranges: Vec<(String, IpRange)>| {
            ranges.into_iter().map(|(code, ip_range)| {
                match countries.country_from_code(code.as_str()) {
                    Ok(country) => CountryBlock {
                        ip_range,
                        country: country.clone(),
                    },
                    Err(e) => {
                        errors.push(format!("Error finding country from code {} for IP range {:?}: {}", code, ip_range, e));
                        CountryBlock {
                            ip_range,
                            country: Country::new(0, "ZZ", "Unknown"),
                        }
                    }
                }
            }).collect_vec()
        };
        let mut serializer = CountryBlockSerializer::new();
        let country_blocks = make_country_blocks(ip_ranges);
        country_blocks.into_iter().for_each(|block| serializer.add(block));
        let (ipv4_bit_queue, ipv6_bit_queue) = serializer.finish();

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
        errors: &mut Vec<String>
    ) -> Vec<(String, IpRange)> {
        let mut coded_ranges: Vec<(String, IpRange)> = vec![];
        let mut add_or_coalesce = |code: &str, ip_range: IpRange| {
            let new_range_opt = match coded_ranges.last() {
                None => None,
                Some((last_code, last_range)) => {
                    if (last_code == code) && are_consecutive(last_range.end(), ip_range.start()) {
                        Some(IpRange::new(last_range.start(), ip_range.end()))
                    }
                    else {
                        None
                    }
                }
            };
            if let Some(new_range) = new_range_opt {
                // coalesce with last range
                let _ = coded_ranges.pop();
                coded_ranges.push((code.to_string(), new_range));
            } else {
                // add new range
                coded_ranges.push((code.to_string(), ip_range));
            }
        };
        within.for_each(|item_result| {
            match item_result {
                Ok(item) => {
                    let ip_range = Self::ipn_to_range(item.ip_net);
                    match item.info.country {
                        Some(country) => {
                            match (country.iso_code, country.names.map(|ns| ns.get("en").map(|n| n.to_string()))) {
                                (Some(code), Some(Some(name))) => {
                                    country_pairs.insert((code.to_string(), name.to_string()));
                                    add_or_coalesce(code, ip_range);
                                }
                                (Some(code), _) => {
                                    errors.push(format!("Country code {:?} found but no name - using 'Unknown'", code));
                                    country_pairs.insert((code.to_string(), "Unknown".to_string()));
                                    add_or_coalesce(code, ip_range);
                                }
                                (None, Some(Some(name))) => {
                                    errors.push(format!("Country code not found for country: {:?} - using Sentinel", name));
                                    country_pairs.insert(("ZZ".to_string(), "Sentinel".to_string()));
                                    add_or_coalesce("ZZ", ip_range);
                                }
                                (None, _) => {
                                    errors.push(format!("Country code and name not found for range: {:?} - using Sentinel", item.ip_net));
                                    country_pairs.insert(("ZZ".to_string(), "Sentinel".to_string()));
                                    add_or_coalesce("ZZ", ip_range);
                                }
                            }
                        }
                        None => {
                            errors.push(format!("No country information found for range: {:?} - using Sentinel", item.ip_net));
                            country_pairs.insert(("ZZ".to_string(), "Sentinel".to_string()));
                            let ip_range = Self::ipn_to_range(item.ip_net);
                            add_or_coalesce("ZZ", ip_range);
                        },
                    }
                },
                Err(e) => {
                    errors.push(format!("Error processing item: {}", e));
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
    use std::io::Read;
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::str::FromStr;
    use crate::country_block_serde::{CountryBlockDeserializer, Ipv4CountryBlockDeserializer, Ipv6CountryBlockDeserializer};
    use crate::country_finder::CountryCodeFinder;

    struct BadRead {
        delegate: Box<dyn Read>
    }

    impl Read for BadRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.delegate.read(buf) {
                Ok(len) => {
                    if len == 0 {
                        Err(io::Error::from(io::ErrorKind::BrokenPipe))
                    } else {
                        Ok(len)
                    }
                }
                Err(e) => Err(e)
            }
        }
    }

    #[test]
    fn bad_stream() {
        /*
            54.36.84.100/22,France,FR
            142.44.196.0/25,India,IN
            142.44.196.128/25,India,IN
            5555:5555:5555:5555:5555:5555:5555:5555/96,Czechia,CZ
         */
        let file = PathBuf::from("data/country-scratch-out.mmdb");
        let delegate = File::open(&file).unwrap();
        let mut stdin = BadRead {
            delegate: Box::new(delegate)
        };
        let subject = MMDBParser::new();
        let mut errors = vec![];

        let result = subject.parse(&mut stdin, &mut errors);

        assert_eq!(
            errors,
            vec!["Error reading from stdin: broken pipe".to_string()]
        );
        let country_code_finder = CountryCodeFinder::new(
            &result.2,
            country_data_from_bit_queue(result.0),
            country_data_from_bit_queue(result.1)
        );

        let ipv4_country = country_code_finder.find_country(IpAddr::from_str("54.36.84.100").unwrap());
        assert_eq!(ipv4_country.map(|c| c.iso3166.clone()), Some("FR".to_string()));
        let ipv4_country = country_code_finder.find_country(IpAddr::from_str("142.44.196.0").unwrap());
        assert_eq!(ipv4_country.map(|c| c.iso3166.clone()), Some("IN".to_string()));
        let ipv6_country = country_code_finder.find_country(IpAddr::from_str("5555:5555:5555:5555:5555:5555:5555:5555").unwrap());
        assert_eq!(ipv6_country.map(|c| c.iso3166.clone()), Some("CZ".to_string()));
    }

    #[test]
    fn improperly_formatted() {
        /*
            <text file>
         */
        let file = PathBuf::from("data/improperly-formatted.mmdb");
        let mut stdin = File::open(&file).unwrap();
        let subject = MMDBParser::new();
        let mut errors = vec![];

        let result = subject.parse(&mut stdin, &mut errors);

        assert_eq!(
            errors,
            vec!["Error opening MaxMind DB: Invalid database: Could not find MaxMind DB metadata in file.".to_string()]
        );
        assert_eq!(result.0.block_count, 0);
        assert_eq!(result.1.block_count, 0);
        assert_eq!(result.2.len(), 1); // ZZ only
    }

    #[test]
    fn corrupted() {
        /*
            <corrupted version of mmdb file>
         */
        let file = PathBuf::from("data/corrupted.mmdb");
        let mut stdin = File::open(&file).unwrap();
        let subject = MMDBParser::new();
        let mut errors = vec![];

        let result = subject.parse(&mut stdin, &mut errors);

        assert_eq!(
            errors,
            vec![
                "Error processing item: Invalid database: the MaxMind DB file's data pointer resolves to an invalid location".to_string(),
                "Error processing item: Invalid database: the MaxMind DB file's data pointer resolves to an invalid location".to_string(),
                "Error processing item: Invalid database: the MaxMind DB file's data pointer resolves to an invalid location".to_string(),
            ]
        );
        assert_eq!(result.0.block_count, 3);
        assert_eq!(result.1.block_count, 3);
        assert_eq!(result.2.len(), 3);
    }

    #[test]
    fn happy_path() {
        /*
            54.36.84.100/22,France,FR
            142.44.196.0/25,India,IN
            142.44.196.128/25,India,IN
            5555:5555:5555:5555:5555:5555:5555:5555/96,Czechia,CZ
        */
        let file = PathBuf::from("data/country-scratch-out.mmdb");
        let mut stdin = File::open(&file).unwrap();
        let subject = MMDBParser::new();
        let mut errors = vec![];

        let (ipv4_bits, ipv6_bits, countries) = subject.parse(&mut stdin, &mut errors);

        let ipv4_data = to_u64s(ipv4_bits);
        let ipv4_country_blocks = Ipv4CountryBlockDeserializer::new(ipv4_data, &countries)
            .collect::<Vec<CountryBlock>>();
        let ipv6_data = to_u64s(ipv6_bits);
        let ipv6_country_blocks = Ipv6CountryBlockDeserializer::new(ipv6_data, &countries)
            .collect::<Vec<CountryBlock>>();
        assert_eq!(
            ipv4_country_blocks,
            vec![
                CountryBlock {
                    ip_range: IpRange::V4(Ipv4Addr::new(0, 0, 0, 0).into(), Ipv4Addr::new(54, 36, 83, 255).into()),
                    country: Country::new(0, "ZZ", "Sentinel")
                },
                CountryBlock {
                    ip_range: IpRange::V4(Ipv4Addr::new(54, 36, 84, 0).into(), Ipv4Addr::new(54, 36, 87, 255).into()),
                    country: Country::new(2, "FR", "France")
                },
                CountryBlock {
                    ip_range: IpRange::V4(Ipv4Addr::new(54, 36, 88, 0).into(), Ipv4Addr::new(142, 44, 195, 255).into()),
                    country: Country::new(0, "ZZ", "Sentinel")
                },
                CountryBlock {
                    ip_range: IpRange::V4(Ipv4Addr::new(142, 44, 196, 0).into(), Ipv4Addr::new(142, 44, 196, 255).into()),
                    country: Country::new(3, "IN", "India")
                },
                CountryBlock {
                    ip_range: IpRange::V4(Ipv4Addr::new(142, 44, 197, 0).into(), Ipv4Addr::new(255, 255, 255, 255).into()),
                    country: Country::new(0, "ZZ", "Sentinel")
                },
            ]
        );
        assert_eq!(
            ipv6_country_blocks,
            vec![
                CountryBlock {
                    ip_range: IpRange::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(), Ipv6Addr::new(0x5555,0x5555,0x5555,0x5555,0x5555,0x5554, 0xFFFF, 0xFFFF).into()),
                    country: Country::new(0, "ZZ", "Sentinel")
                },
                CountryBlock {
                    ip_range: IpRange::V6(Ipv6Addr::new(0x5555,0x5555,0x5555,0x5555,0x5555,0x5555, 0, 0).into(), Ipv6Addr::new(0x5555,0x5555,0x5555,0x5555,0x5555,0x5555, 0xFFFF, 0xFFFF).into()),
                    country: Country::new(1, "CZ", "Czechia")
                },
                CountryBlock {
                    ip_range: IpRange::V6(Ipv6Addr::new(0x5555,0x5555,0x5555,0x5555,0x5555,0x5556, 0, 0).into(), Ipv6Addr::new(0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF, 0xFFFF, 0xFFFF).into()),
                    country: Country::new(0, "ZZ", "Sentinel")
                },
            ]
        )
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

    fn to_u64s(mut final_bit_queue: FinalBitQueue) -> (Vec<u64>, usize) {
        let mut result = vec![];
        let len = final_bit_queue.bit_queue.len();
        let mut bits_remaining = len;
        while (bits_remaining > 0) {
            let bits_to_take = min(64, bits_remaining);
            let bits = final_bit_queue.bit_queue.take_bits(bits_to_take).unwrap();
            result.push(bits);
            bits_remaining -= bits_to_take;
        }
        (result, len)
    }
}
