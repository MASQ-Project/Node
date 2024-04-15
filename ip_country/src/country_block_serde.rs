use std::net::{Ipv4Addr, Ipv6Addr};
use crate::bit_queue::BitQueue;
use crate::country_block_stream::{Country, CountryBlock, IpRange};

/*

Compressed Data Format

Country IP-address data is stored in compressed format as a literal Vec<u64>. In order to
traverse it, it's fed into a BitQueue and then retrieved as a series of variably-sized bit strings.
IPv4 data is stored in one Vec<u64>, and IPv6 data is stored in a different one.

Conceptually, the compressed data format is a sequence of two-element records:

<IP address at beginning of country block>, <index of country in COUNTRIES list>
<IP address at beginning of country block>, <index of country in COUNTRIES list>
<IP address at beginning of country block>, <index of country in COUNTRIES list>
[...]

Each block is assumed to end at the address immediately before the one where the next block starts.
If the data contains no block starting at the lowest possible address (0.0.0.0 for IPv4,
0:0:0:0:0:0:0:0 for IPv6), the deserializer will invent one starting at that address, ending just
before the first address specified in the data, and having country index 0. The last block ends at
the maximum possible address: 255.255.255.255 for IPv4, FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
for IPv6.

The index of the country in the COUNTRIES list is specified as nine bits. At the time this code was
written, there were 250 countries in ISO3166, so we could have used eight bits; but 250 is close
enough to 256 that we added an extra bit for future-proofing.

The block-start IP addresses are specified in compressed fashion. Only the parts (octets for IPv4,
segments for IPv6) of the start address that are different from the corresponding segments of the
previous address are stored, like this:

<difference count minus one> <differences>

For IPv4, the difference-count-minus-one is stored as two bits, and for IPv6 it's stored as three
bits. Make sure you add 1 to the value before you use it. (The data is stored this way because
there can't be no changes (that'd imply a zero-length block), but it _is_ possible that every part
of the new start address is different, and that number wouldn't fit into the available bit field.)

Each difference is stored as two fields: an index and a value, like this:

<index> <value>

The index refers to the number of the address part that's different, and the value is the new
address part. For IPv4, the index is two bits long and the value is eight bits long. For IPv6,
the index is three bits long and the value is sixteen bits long.

Since every start address is composed of differences from the address before it, the very first
start address is compared against 255.255.255.254 for IPv4 and
FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFE for IPv6.

Examples

Here are two compressed IPv4 records, with whitespace for clarity:

11 00 00000001 01 00000010 10 00000011 11 00000100 011101101
00 00 11111111 011101011

This says:
1. There are 4 (3 + 1) differences. Octet 0 is 1; octet 1 is 2; octet 2 is 3; octet 3 is 4. The
country index is 237, which is "US" in the COUNTRIES list.
2. There is 1 (0 + 1) difference. Octet 0 changes to 255. The country index is 235, which is "GB"
in the COUNTRIES list.

It would deserialize into three CountryBlocks:
CountryBlock { // this block is implied by the fact that the first start address wasn't 0.0.0.0
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("0.0.0.0").unwrap(), Ipv4Addr.from_str("1.2.3.3").unwrap()),
    pub country: Country::try_from("ZZ").unwrap(), // generated blocks are always for ZZ
}
CountryBlock {
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("1.2.3.4").unwrap(), Ipv4Addr.from_str("255.2.3.3").unwrap()),
    pub country: Country::try_from("US").unwrap(),
}
CountryBlock {
    pub ip_range: IpRange::V4(Ipv4Addr.from_str("255.2.3.4").unwrap(), Ipv4Addr.from_str("255.255.255.255").unwrap()),
    pub country: Country::try_from("GB").unwrap(),
}

Here are two compressed IPv6 records, with whitespace for clarity:

111
    000 0000000000000001
    001 0000000000000010
    010 0000000000000011
    011 0000000000000100
    100 0000000000000000
    101 0000000000000000
    110 0000000000000000
    111 0000000000000000
    011101101
000
    000 0000000011111111
    011101011

This says:
1. There are 8 (7 + 1) differences. Segment 0 is 1; segment 1 is 2; segment 2 is 3; segment 3 is 4;
and the other four segments are all 0. The country index is 237, which is "US" in the COUNTRIES
list.
2. There is 1 (0 + 1) difference. Segment 0 changes to 255. The country index is 235, which is "GB"
in the COUNTRIES list.

It would deserialize into three CountryBlocks:
CountryBlock { // this block is implied by the fact that the first start address wasn't 0.0.0.0
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("0:0:0:0:0:0:0:0").unwrap(), Ipv6Addr.from_str("1:2:3:3:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("ZZ").unwrap(), // generated blocks are always for ZZ
}
CountryBlock {
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("1:2:3:4:0:0:0:0").unwrap(), Ipv6Addr.from_str("FF:2:3:3:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("US").unwrap(),
}
CountryBlock {
    pub ip_range: IpRange::V6(Ipv6Addr.from_str("FF:2:3:4:0:0:0:0").unwrap(), Ipv6Addr.from_str("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").unwrap()),
    pub country: Country::try_from("GB").unwrap(),
}

 */

pub struct CountryBlockSerializer {
    prev_start_ipv4: Ipv4Addr,
    prev_end_ipv4: Ipv4Addr,
    bit_queue_ipv4: BitQueue,
    prev_start_ipv6: Ipv6Addr,
    prev_end_ipv6: Ipv6Addr,
    bit_queue_ipv6: BitQueue,
}

impl CountryBlockSerializer {

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
        self.add_ipv4(plus_one_ipv4(self.prev_end_ipv4), Ipv4Addr::new (0xFF, 0xFF, 0xFF, 0xFF), 0);
        self.add_ipv6(plus_one_ipv6(self.prev_end_ipv6), Ipv6Addr::new (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF), 0);
        (self.bit_queue_ipv4, self.bit_queue_ipv6)
    }

    fn add_ipv4(&mut self, start: Ipv4Addr, end: Ipv4Addr, country_index: usize) {
        let expected_start = plus_one_ipv4(self.prev_end_ipv4);
        if start != expected_start {
            self.add_ipv4(expected_start, minus_one_ipv4(start), 0)
        }
        let differences = Self::differences_ipv4(self.prev_start_ipv4, start);
        let difference_count_minus_one = (differences.len() - 1) as u64;
        self.bit_queue_ipv4.add_bits(difference_count_minus_one, 2);
        differences.into_iter().for_each(|difference| {
            self.bit_queue_ipv4.add_bits(difference.index as u64, 2);
            self.bit_queue_ipv4.add_bits(difference.value, 8);
        });
        self.bit_queue_ipv4.add_bits(country_index as u64, 9);
        self.prev_start_ipv4 = start;
        self.prev_end_ipv4 = end;
    }

    fn add_ipv6(&mut self, start: Ipv6Addr, end: Ipv6Addr, country_index: usize) {
        let expected_start = plus_one_ipv6(self.prev_end_ipv6);
        if start != expected_start {
            self.add_ipv6(expected_start, minus_one_ipv6(start), 0)
        }
        let differences = Self::differences_ipv6(self.prev_start_ipv6, start);
        let difference_count_minus_one = (differences.len() - 1) as u64;
        self.bit_queue_ipv6.add_bits(difference_count_minus_one, 3);
        differences.into_iter().for_each(|difference| {
            self.bit_queue_ipv6.add_bits(difference.index as u64, 3);
            self.bit_queue_ipv6.add_bits(difference.value, 16);
        });
        self.bit_queue_ipv6.add_bits(country_index as u64, 9);
        self.prev_start_ipv6 = start;
        self.prev_end_ipv6 = end;
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
                    Some(Difference {index, value: to_octet as u64})
                }
            })
            .collect::<Vec<Difference>>()
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
                    Some(Difference {index, value: to_segment as u64})
                }
            })
            .collect::<Vec<Difference>>()
    }
}

pub trait CountryBlockDeserializer {
    fn next(&mut self) -> Option<CountryBlock>;
}

pub struct CountryBlockDeserializerIpv4 {
    prev_record: StreamRecordIpv4,
    bit_queue: BitQueue,
    empty: bool,
}

impl CountryBlockDeserializer for CountryBlockDeserializerIpv4 {
    fn next(&mut self) -> Option<CountryBlock> {
        if self.empty {return None}
        let next_record_opt = Self::get_record(
            &mut self.bit_queue, self.prev_record.start
        );
        match next_record_opt {
            Some(next_record) => {
                let prev_block = CountryBlock {
                    ip_range: IpRange::V4 (
                        self.prev_record.start,
                        minus_one_ipv4(next_record.start)
                    ),
                    country: Country::from(self.prev_record.country_idx)
                };
                self.prev_record = next_record;
                Some(prev_block)
            },
            None => {
                self.empty = true;
                Some(CountryBlock {
                    ip_range: IpRange::V4(self.prev_record.start, Ipv4Addr::new(255, 255, 255, 255)),
                    country: Country::from(self.prev_record.country_idx)
                })
            }
        }
    }
}

impl CountryBlockDeserializerIpv4 {
    pub fn new (country_data_ipv4: (Vec<u64>, usize)) -> Self {
        let mut bit_queue = bit_queue_from_country_data(country_data_ipv4);
        let prev_record = Self::get_record(
            &mut bit_queue,
            Ipv4Addr::new(255, 255, 255, 254)
        ).expect("Empty BitQueue");
        Self {
            prev_record,
            bit_queue,
            empty: false,
        }
    }

    fn get_record (bit_queue: &mut BitQueue, prev_start: Ipv4Addr) -> Option<StreamRecordIpv4> {
        let mut octets = prev_start.octets();
        let difference_count = (bit_queue.take_bits(2)? + 1) as usize;
        let differences = (0..difference_count).map(|_|
            Some(Difference {
                index: bit_queue.take_bits(2)? as usize,
                value: bit_queue.take_bits(8)?,
            })
        )
            .flatten()
            .collect::<Vec<Difference>>();
        if differences.len() < difference_count {return None}
        differences.into_iter().for_each(|d| octets[d.index] = d.value as u8);
        Some (StreamRecordIpv4 {
            start: Ipv4Addr::from(octets),
            country_idx: bit_queue.take_bits(9)? as usize,
        })
    }
}

pub struct CountryBlockDeserializerIpv6 {
    prev_record: StreamRecordIpv6,
    bit_queue: BitQueue,
    empty: bool,
}

impl CountryBlockDeserializer for CountryBlockDeserializerIpv6 {
    fn next(&mut self) -> Option<CountryBlock> {
        if self.empty {return None}
        let next_record_opt = Self::get_record(
            &mut self.bit_queue, self.prev_record.start
        );
        match next_record_opt {
            Some(next_record) => {
                let prev_block = CountryBlock {
                    ip_range: IpRange::V6 (
                        self.prev_record.start,
                        minus_one_ipv6(next_record.start)
                    ),
                    country: Country::from(self.prev_record.country_idx)
                };
                self.prev_record = next_record;
                Some(prev_block)
            },
            None => {
                self.empty = true;
                Some(CountryBlock {
                    ip_range: IpRange::V6(self.prev_record.start, Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)),
                    country: Country::from(self.prev_record.country_idx)
                })
            }
        }
    }
}

impl CountryBlockDeserializerIpv6 {
    pub fn new (country_data_ipv6: (Vec<u64>, usize)) -> Self {
        let mut bit_queue = bit_queue_from_country_data(country_data_ipv6);
        let prev_record = Self::get_record(
            &mut bit_queue,
            Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFE)
        ).expect("Empty BitQueue");
        Self {
            prev_record,
            bit_queue,
            empty: false,
        }
    }

    fn get_record (bit_queue: &mut BitQueue, prev_start: Ipv6Addr) -> Option<StreamRecordIpv6> {
        let mut segments = prev_start.segments();
        let difference_count = (bit_queue.take_bits(3)? + 1) as usize;
        let differences = (0..difference_count).map(|_|
            Some(Difference {
                index: bit_queue.take_bits(3)? as usize,
                value: bit_queue.take_bits(16)?,
            })
        )
            .flatten()
            .collect::<Vec<Difference>>();
        if differences.len() < difference_count {return None}
        differences.into_iter().for_each(|d| segments[d.index] = d.value as u16);
        Some (StreamRecordIpv6 {
            start: Ipv6Addr::from(segments),
            country_idx: bit_queue.take_bits(9)? as usize,
        })
    }
}

struct StreamRecordIpv4 {
    start: Ipv4Addr,
    country_idx: usize
}

struct StreamRecordIpv6 {
    start: Ipv6Addr,
    country_idx: usize
}

struct Difference {
    index: usize,
    value: u64
}

fn plus_one_ipv4(ip_addr: Ipv4Addr) -> Ipv4Addr {
    let old_data = u32_from_ipv4(ip_addr);
    let new_data = old_data.overflowing_add(1).0;
    Ipv4Addr::from(new_data)
}

fn minus_one_ipv4(ip_addr: Ipv4Addr) -> Ipv4Addr {
    let old_data = u32_from_ipv4(ip_addr);
    let new_data = old_data.overflowing_sub(1).0;
    Ipv4Addr::from(new_data)
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
    let old_data = u128_from_ipv6(ip_addr);
    let new_data = old_data.overflowing_add(1).0;
    Ipv6Addr::from(new_data)
}

fn minus_one_ipv6(ip_addr: Ipv6Addr) -> Ipv6Addr {
    let old_data = u128_from_ipv6(ip_addr);
    let new_data = old_data.overflowing_sub(1).0;
    Ipv6Addr::from(new_data)
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

fn bit_queue_from_country_data(country_data_pair: (Vec<u64>, usize)) -> BitQueue {
    let (mut country_data, mut bit_count) = country_data_pair;
    let mut bit_queue = BitQueue::new();
    while bit_count >= 64 {
        bit_queue.add_bits(country_data.remove(0), 64);
        bit_count -= 64;
    }
    if bit_count > 0 {
        bit_queue.add_bits(country_data.remove(0), bit_count);
    }
    bit_queue
}

mod tests {
    use std::net::{Ipv4Addr};
    use std::str::FromStr;
    use crate::country_block_stream::{Country, IpRange};
    use super::*;

    #[allow(unused)]
    fn ipv4_country_blocks() -> Vec<CountryBlock> {
        vec![
            CountryBlock {
                ip_range: IpRange::V4 (
                    Ipv4Addr::from_str("1.2.3.4").unwrap(),
                    Ipv4Addr::from_str("1.2.3.5").unwrap()
                ),
                country: Country::try_from("AS").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V4 (
                    Ipv4Addr::from_str("1.2.3.6").unwrap(),
                    Ipv4Addr::from_str("6.7.8.9").unwrap()
                ),
                country: Country::try_from("AD").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V4 (
                    Ipv4Addr::from_str("10.11.12.13").unwrap(),
                    Ipv4Addr::from_str("11.11.12.13").unwrap()
                ),
                country: Country::try_from("AO").unwrap().clone(),
            }
        ]
    }

    #[allow(unused)]
    fn ipv6_country_blocks() -> Vec<CountryBlock> {
        vec![
            CountryBlock {
                ip_range: IpRange::V6 (
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:8").unwrap(),
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:9").unwrap()
                ),
                country: Country::try_from("AS").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V6 (
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:A").unwrap(),
                    Ipv6Addr::from_str("B:C:D:E:F:10:11:12").unwrap()
                ),
                country: Country::try_from("AD").unwrap().clone(),
            },
            CountryBlock {
                ip_range: IpRange::V6 (
                    Ipv6Addr::from_str("13:14:15:16:17:18:19:1A").unwrap(),
                    Ipv6Addr::from_str("14:14:15:16:17:18:19:1A").unwrap()
                ),
                country: Country::try_from("AO").unwrap().clone(),
            }
        ]
    }

    #[test]
    fn add_works_for_ipv4() {
        let mut country_blocks = ipv4_country_blocks();
        let mut subject = CountryBlockSerializer::new();

        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));

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
            assert_eq!(Country::from(country_index as usize).iso3166, "AS".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "AD".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "ZZ".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "AO".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "ZZ".to_string())
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }

    #[test]
    fn next_works_for_ipv4() {
        let mut serializer = CountryBlockSerializer::new();
        ipv4_country_blocks().into_iter().for_each (|country_block| serializer.add(country_block));
        let mut bit_queue = serializer.finish().0;
        let bit_queue_len = bit_queue.len();
        let mut bit_data: Vec<u64> = vec![];
        while bit_queue.len() >= 64 {
            let data = bit_queue.take_bits(64).unwrap();
            bit_data.push(data);
        }
        let remaining_bit_count = bit_queue.len();
        let data = bit_queue.take_bits(remaining_bit_count).unwrap();
        bit_data.push(data);
        let mut subject = CountryBlockDeserializerIpv4::new ((
            bit_data, bit_queue_len
        ));

        let country_block1 = subject.next().unwrap();
        let country_block2 = subject.next().unwrap();
        let country_block3 = subject.next().unwrap();
        let country_block4 = subject.next().unwrap();
        let country_block5 = subject.next().unwrap();
        let country_block6 = subject.next().unwrap();
        let result = subject.next();

        let original_country_blocks = ipv4_country_blocks();
        assert_eq!(
            country_block1,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("0.0.0.0").unwrap(),
                    Ipv4Addr::from_str("1.2.3.3").unwrap()
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block2, original_country_blocks[0]);
        assert_eq!(country_block3, original_country_blocks[1]);
        assert_eq!(
            country_block4,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("6.7.8.10").unwrap(),
                    Ipv4Addr::from_str("10.11.12.12").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block5, original_country_blocks[2]);
        assert_eq!(
            country_block6,
            CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("11.11.12.14").unwrap(),
                    Ipv4Addr::from_str("255.255.255.255").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(result, None);
    }

    #[test]
    fn add_works_for_ipv6() {
        let mut country_blocks = ipv6_country_blocks();
        let mut subject = CountryBlockSerializer::new();

        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));
        subject.add(country_blocks.remove(0));

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
            assert_eq!(Country::from(country_index as usize).iso3166, "AS".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "AD".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "ZZ".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "AO".to_string())
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
            assert_eq!(Country::from(country_index as usize).iso3166, "ZZ".to_string())
        }
        assert_eq!(bit_queue.take_bits(1), None);
    }

    #[test]
    fn next_works_for_ipv6() {
        let mut serializer = CountryBlockSerializer::new();
        ipv6_country_blocks().into_iter().for_each (|country_block| serializer.add(country_block));
        let mut bit_queue = serializer.finish().1;
        let bit_queue_len = bit_queue.len();
        let mut bit_data: Vec<u64> = vec![];
        while bit_queue.len() >= 64 {
            let data = bit_queue.take_bits(64).unwrap();
            bit_data.push(data);
        }
        let remaining_bit_count = bit_queue.len();
        let data = bit_queue.take_bits(remaining_bit_count).unwrap();
        bit_data.push(data);
        let mut subject = CountryBlockDeserializerIpv6::new ((
            bit_data, bit_queue_len
        ));

        let country_block1 = subject.next().unwrap();
        let country_block2 = subject.next().unwrap();
        let country_block3 = subject.next().unwrap();
        let country_block4 = subject.next().unwrap();
        let country_block5 = subject.next().unwrap();
        let country_block6 = subject.next().unwrap();
        let result = subject.next();

        let original_country_blocks = ipv6_country_blocks();
        assert_eq!(
            country_block1,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("0:0:0:0:0:0:0:0").unwrap(),
                    Ipv6Addr::from_str("1:2:3:4:5:6:7:7").unwrap()
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block2, original_country_blocks[0]);
        assert_eq!(country_block3, original_country_blocks[1]);
        assert_eq!(
            country_block4,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("B:C:D:E:F:10:11:13").unwrap(),
                    Ipv6Addr::from_str("13:14:15:16:17:18:19:19").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(country_block5, original_country_blocks[2]);
        assert_eq!(
            country_block6,
            CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("14:14:15:16:17:18:19:1B").unwrap(),
                    Ipv6Addr::from_str("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").unwrap(),
                ),
                country: Country::from(0usize) // sentinel
            }
        );
        assert_eq!(result, None);
    }
}
