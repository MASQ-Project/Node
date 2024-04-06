use std::net::{Ipv4Addr, Ipv6Addr};
use crate::bit_queue::BitQueue;
use crate::country_block_stream::{Country, CountryBlock, IpRange};

pub struct IpSerializer {
    prev_start_ipv4: Ipv4Addr,
    prev_end_ipv4: Ipv4Addr,
    bit_queue_ipv4: BitQueue,
    prev_start_ipv6: Ipv6Addr,
    prev_end_ipv6: Ipv6Addr,
    bit_queue_ipv6: BitQueue,
}

impl IpSerializer {

    pub fn new() -> Self {
        Self {
            prev_start_ipv4: Ipv4Addr::new(255, 255, 255, 254),
            prev_end_ipv4: Ipv4Addr::new(255, 255, 255, 255),
            bit_queue_ipv4: BitQueue::new(),
            prev_start_ipv6: Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE),
            prev_end_ipv6: Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),
            bit_queue_ipv6: BitQueue::new(),
        }
    }

    pub fn add(&mut self, country_block: CountryBlock) {
        match country_block.ip_range {
            IpRange::V4(start, end) => self.add_ipv4(start, end, country_block.country.index),
            IpRange::V6(start, end) => self.add_ipv6(start, end, country_block.country.index)
        }
    }

    pub fn finish(mut self) -> (BitQueue, BitQueue) {
        self.add_ipv4(Self::plus_one_ipv4(self.prev_end_ipv4), Ipv4Addr::new (0xFF, 0xFF, 0xFF, 0xFF), 0);
        self.add_ipv6(Self::plus_one_ipv6(self.prev_end_ipv6), Ipv6Addr::new (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), 0);
        (self.bit_queue_ipv4, self.bit_queue_ipv6)
    }

    fn add_ipv4(&mut self, start: Ipv4Addr, end: Ipv4Addr, country_index: usize) {
        let expected_start = Self::plus_one_ipv4(self.prev_end_ipv4);
        if start != expected_start {
            self.add_ipv4(expected_start, Self::minus_one_ipv4(start), 0)
        }
        let differences = Self::differences_ipv4(self.prev_start_ipv4, start);
        let difference_count_minus_one = (differences.len() - 1) as u64;
        self.bit_queue_ipv4.add_bits(difference_count_minus_one, 2);
        differences.into_iter().for_each(|difference| {
            self.bit_queue_ipv4.add_bits(difference.index, 2);
            self.bit_queue_ipv4.add_bits(difference.value, 8);
        });
        self.bit_queue_ipv4.add_bits(country_index as u64, 9);
        self.prev_start_ipv4 = start;
        self.prev_end_ipv4 = end;
    }

    fn add_ipv6(&mut self, start: Ipv6Addr, end: Ipv6Addr, country_index: usize) {
        let expected_start = Self::plus_one_ipv6(self.prev_end_ipv6);
        if start != expected_start {
            self.add_ipv6(expected_start, Self::minus_one_ipv6(start), 0)
        }
        let differences = Self::differences_ipv6(self.prev_start_ipv6, start);
        let difference_count_minus_one = (differences.len() - 1) as u64;
        self.bit_queue_ipv6.add_bits(difference_count_minus_one, 3);
        differences.into_iter().for_each(|difference| {
            self.bit_queue_ipv6.add_bits(difference.index, 3);
            self.bit_queue_ipv6.add_bits(difference.value, 16);
        });
        self.bit_queue_ipv6.add_bits(country_index as u64, 9);
        self.prev_start_ipv6 = start;
        self.prev_end_ipv6 = end;
    }

    fn plus_one_ipv4(ip_addr: Ipv4Addr) -> Ipv4Addr {
        let old_data = Self::u32_from_ipv4(ip_addr);
        let new_data = old_data.overflowing_add(1).0;
        Ipv4Addr::from(new_data)
    }

    fn minus_one_ipv4(ip_addr: Ipv4Addr) -> Ipv4Addr {
        let old_data = Self::u32_from_ipv4(ip_addr);
        let new_data = old_data.overflowing_sub(1).0;
        Ipv4Addr::from(new_data)
    }

    fn differences_ipv4(from: Ipv4Addr, to: Ipv4Addr) -> Vec<Difference> {
        let pairs = from.octets().into_iter().zip(to.octets().into_iter());
        pairs.into_iter()
            .enumerate()
            .flat_map(|(index, (from_octet, to_octet))| {
                if to_octet == from_octet {
                    None
                }
                else {
                    Some(Difference {index: index as u64, value: to_octet as u64})
                }
            })
            .collect::<Vec<Difference>>()
    }

    fn u32_from_ipv4(ip_addr: Ipv4Addr) -> u32 {
        let octets = ip_addr.octets();
        let mut bit_data = 0u32;
        octets.into_iter().for_each(|octet| {
            bit_data <<= 8;
            bit_data |= octet as u32;
        });
        bit_data
    }

    fn plus_one_ipv6(ip_addr: Ipv6Addr) -> Ipv6Addr {
        let old_data = Self::u128_from_ipv6(ip_addr);
        let new_data = old_data.overflowing_add(1).0;
        Ipv6Addr::from(new_data)
    }

    fn minus_one_ipv6(ip_addr: Ipv6Addr) -> Ipv6Addr {
        let old_data = Self::u128_from_ipv6(ip_addr);
        let new_data = old_data.overflowing_sub(1).0;
        Ipv6Addr::from(new_data)
    }

    fn differences_ipv6(from: Ipv6Addr, to: Ipv6Addr) -> Vec<Difference> {
        let pairs = from.segments().into_iter().zip(to.segments().into_iter());
        pairs.into_iter()
            .enumerate()
            .flat_map(|(index, (from_segment, to_segment))| {
                if to_segment == from_segment {
                    None
                }
                else {
                    Some(Difference {index: index as u64, value: to_segment as u64})
                }
            })
            .collect::<Vec<Difference>>()
    }

    fn u128_from_ipv6(ip_addr: Ipv6Addr) -> u128 {
        let octets = ip_addr.octets();
        let mut bit_data = 0u128;
        octets.into_iter().for_each(|octet| {
            bit_data <<= 8;
            bit_data |= octet as u128;
        });
        bit_data
    }
}

struct Difference {
    index: u64,
    value: u64
}

mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use crate::country_block_stream::{Country, IpRange};
    use super::*;

    #[test]
    fn add_works_for_ipv4() {
        let first = CountryBlock {
            ip_range: IpRange::V4 (
                Ipv4Addr::from_str("1.2.3.4").unwrap(),
                Ipv4Addr::from_str("1.2.3.5").unwrap()
            ),
            country: Country::try_from("AS").unwrap().clone(),
        };
        let second = CountryBlock {
            ip_range: IpRange::V4 (
                Ipv4Addr::from_str("1.2.3.6").unwrap(),
                Ipv4Addr::from_str("6.7.8.9").unwrap()
            ),
            country: Country::try_from("AD").unwrap().clone(),
        };
        let third = CountryBlock {
            ip_range: IpRange::V4 (
                Ipv4Addr::from_str("10.11.12.13").unwrap(),
                Ipv4Addr::from_str("11.11.12.13").unwrap()
            ),
            country: Country::try_from("AO").unwrap().clone(),
        };
        let mut subject = IpSerializer::new();

        subject.add(first);
        subject.add(second);
        subject.add(third);

        let (mut bit_queue, _) = subject.finish();
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 0));
            assert_eq!((index2, value2), (1, 0));
            assert_eq!((index3, value3), (2, 0));
            assert_eq!((index4, value4), (3, 0));
            assert_eq!(country_index, 0) // sentinel
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 1));
            assert_eq!((index2, value2), (1, 2));
            assert_eq!((index3, value3), (2, 3));
            assert_eq!((index4, value4), (3, 4));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AS".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 0);
            assert_eq!((index1, value1), (3, 6));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AD".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 6));
            assert_eq!((index2, value2), (1, 7));
            assert_eq!((index3, value3), (2, 8));
            assert_eq!((index4, value4), (3, 10));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "ZZ".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 3);
            assert_eq!((index1, value1), (0, 10));
            assert_eq!((index2, value2), (1, 11));
            assert_eq!((index3, value3), (2, 12));
            assert_eq!((index4, value4), (3, 13));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AO".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                country_index
            ) = (
                bit_queue.take_bits(2).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(2).unwrap(), bit_queue.take_bits(8).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 1);
            assert_eq!((index1, value1), (0, 11));
            assert_eq!((index2, value2), (3, 14));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "ZZ".to_string())
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }

    #[test]
    fn add_works_for_ipv6() {
        let first = CountryBlock {
            ip_range: IpRange::V6 (
                Ipv6Addr::from_str("1:2:3:4:5:6:7:8").unwrap(),
                Ipv6Addr::from_str("1:2:3:4:5:6:7:9").unwrap()
            ),
            country: Country::try_from("AS").unwrap().clone(),
        };
        let second = CountryBlock {
            ip_range: IpRange::V6 (
                Ipv6Addr::from_str("1:2:3:4:5:6:7:A").unwrap(),
                Ipv6Addr::from_str("B:C:D:E:F:10:11:12").unwrap()
            ),
            country: Country::try_from("AD").unwrap().clone(),
        };
        let third = CountryBlock {
            ip_range: IpRange::V6 (
                Ipv6Addr::from_str("13:14:15:16:17:18:19:1A").unwrap(),
                Ipv6Addr::from_str("14:14:15:16:17:18:19:1A").unwrap()
            ),
            country: Country::try_from("AO").unwrap().clone(),
        };
        let mut subject = IpSerializer::new();

        subject.add(first);
        subject.add(second);
        subject.add(third);

        let (_, mut bit_queue) = subject.finish();
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                index5, value5,
                index6, value6,
                index7, value7,
                index8, value8,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0));
            assert_eq!((index2, value2), (1, 0));
            assert_eq!((index3, value3), (2, 0));
            assert_eq!((index4, value4), (3, 0));
            assert_eq!((index5, value5), (4, 0));
            assert_eq!((index6, value6), (5, 0));
            assert_eq!((index7, value7), (6, 0));
            assert_eq!((index8, value8), (7, 0));
            assert_eq!(country_index, 0) // sentinel
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                index5, value5,
                index6, value6,
                index7, value7,
                index8, value8,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 1));
            assert_eq!((index2, value2), (1, 2));
            assert_eq!((index3, value3), (2, 3));
            assert_eq!((index4, value4), (3, 4));
            assert_eq!((index5, value5), (4, 5));
            assert_eq!((index6, value6), (5, 6));
            assert_eq!((index7, value7), (6, 7));
            assert_eq!((index8, value8), (7, 8));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AS".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 0);
            assert_eq!((index1, value1), (7, 10));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AD".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                index5, value5,
                index6, value6,
                index7, value7,
                index8, value8,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0xB));
            assert_eq!((index2, value2), (1, 0xC));
            assert_eq!((index3, value3), (2, 0xD));
            assert_eq!((index4, value4), (3, 0xE));
            assert_eq!((index5, value5), (4, 0xF));
            assert_eq!((index6, value6), (5, 0x10));
            assert_eq!((index7, value7), (6, 0x11));
            assert_eq!((index8, value8), (7, 0x13));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "ZZ".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                index3, value3,
                index4, value4,
                index5, value5,
                index6, value6,
                index7, value7,
                index8, value8,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 7);
            assert_eq!((index1, value1), (0, 0x13));
            assert_eq!((index2, value2), (1, 0x14));
            assert_eq!((index3, value3), (2, 0x15));
            assert_eq!((index4, value4), (3, 0x16));
            assert_eq!((index5, value5), (4, 0x17));
            assert_eq!((index6, value6), (5, 0x18));
            assert_eq!((index7, value7), (6, 0x19));
            assert_eq!((index8, value8), (7, 0x1A));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "AO".to_string())
        }
        {
            let (
                difference_count_minus_one,
                index1, value1,
                index2, value2,
                country_index
            ) = (
                bit_queue.take_bits(3).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(3).unwrap(), bit_queue.take_bits(16).unwrap(),
                bit_queue.take_bits(9).unwrap()
            );
            assert_eq!(difference_count_minus_one, 1);
            assert_eq!((index1, value1), (0, 0x14));
            assert_eq!((index2, value2), (7, 0x1B));
            assert_eq!(Country::try_from(country_index).unwrap().iso3166, "ZZ".to_string())
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }
}