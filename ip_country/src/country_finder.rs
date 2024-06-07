use crate::country_block_serde::{
    CountryBlockDeserializer, CountryBlockDeserializerIpv4, CountryBlockDeserializerIpv6,
};
use crate::country_block_stream::{Country, CountryBlock};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

static mut SEARCHABLE_COUNTRY_BLOCKS_IPV4: Vec<CountryBlock> = vec![];
static mut SEARCHABLE_COUNTRY_BLOCKS_IPV6: Vec<CountryBlock> = vec![];
pub fn initialize_country_finder<F1, F2>(ipv4_country_data: F1, ipv6_country_data: F2) {

}

pub fn country_finder(
    ip_addr: IpAddr,
) -> Option<Country>
{
    match ip_addr {
        IpAddr::V4(ipv4_addr) => find_country_ipv4(ipv4_addr), //rewrite those functions with binary search in SEARCHABLE_COUNTRY_BLOCKS_IPV4
        IpAddr::V6(ipv6_addr) => find_country_ipv6(ipv6_addr),
    }
}

fn initialize_country_finder_ipv4(data: (Vec<u64>, usize), ip_addr: Ipv4Addr) -> Option<Country> {
    let mut deserializer = CountryBlockDeserializerIpv4::new(data);
    loop {
        match deserializer.next() {
            None => break, // this line isn't really testable, since the deserializer will produce CountryBlocks for every possible address
            Some(country_block) => {
                unsafe {
                    SEARCHABLE_COUNTRY_BLOCKS.push(country_block);
                }
                // if country_block.ip_range.contains(IpAddr::V4(ip_addr)) {
                //     if country_block.country.index == 0 {
                //         return None;
                //     } else {
                //         return Some(country_block.country.clone());
                //     }
                // }
            }
        }
    }
}

fn find_country_ipv6(data: (Vec<u64>, usize), ip_addr: Ipv6Addr) -> Option<Country> {
    let mut deserializer = CountryBlockDeserializerIpv6::new(data);
    loop {
        match deserializer.next() {
            None => return None, // this line isn't really testable, since the deserializer will produce CountryBlocks for every possible address
            Some(country_block) => {
                if country_block.ip_range.contains(IpAddr::V6(ip_addr)) {
                    if country_block.country.index == 0 {
                        return None;
                    } else {
                        return Some(country_block.country.clone());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ipv4_country_data() -> (Vec<u64>, usize) {
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

    fn ipv6_country_data() -> (Vec<u64>, usize) {
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
        let result = country_finder(
            ipv4_country_data,
            ipv6_country_data,
            IpAddr::from_str("1.0.5.0").unwrap(),
        );

        assert_eq!(result, Some(Country::try_from("AU").unwrap()))
    }

    #[test]
    fn does_not_find_ipv4_address_in_zz_block() {
        let result = country_finder(
            ipv4_country_data,
            ipv6_country_data,
            IpAddr::from_str("0.0.5.0").unwrap(),
        );

        assert_eq!(result, None)
    }

    #[test]
    fn finds_ipv6_address_in_fourth_block() {
        let result = country_finder(
            ipv4_country_data,
            ipv6_country_data,
            IpAddr::from_str("1:0:5:0:0:0:0:0").unwrap(),
        );

        assert_eq!(result, Some(Country::try_from("AU").unwrap()))
    }

    #[test]
    fn does_not_find_ipv6_address_in_zz_block() {
        let result = country_finder(
            ipv4_country_data,
            ipv6_country_data,
            IpAddr::from_str("0:0:5:0:0:0:0:0").unwrap(),
        );

        assert_eq!(result, None)
    }

    #[test]
    fn real_test_ipv4_with_google() {
        let result = country_finder(
            crate::dbip_country::ipv4_country_data,
            crate::dbip_country::ipv6_country_data,
            IpAddr::from_str("142.250.191.132").unwrap(), // dig www.google.com A
        )
        .unwrap();

        assert_eq!(result.name, "United States".to_string());
    }

    #[test]
    fn real_test_ipv4_with_cz_isp() {
        let result = country_finder(
            crate::dbip_country::ipv4_country_data,
            crate::dbip_country::ipv6_country_data,
            IpAddr::from_str("77.75.77.222").unwrap(), // dig www.seznam.cz A
        )
        .unwrap();

        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "CZ".to_string());
        assert_eq!(result.name, "Czechia".to_string());
    }

    #[test]
    fn real_test_ipv4_with_sk_isp() {
        let result = country_finder(
            crate::dbip_country::ipv4_country_data,
            crate::dbip_country::ipv6_country_data,
            IpAddr::from_str("213.81.185.100").unwrap(), // dig www.zoznam.sk A
        )
        .unwrap();

        assert_eq!(result.free_world, true);
        assert_eq!(result.iso3166, "SK".to_string());
        assert_eq!(result.name, "Slovakia".to_string());
    }

    #[test]
    fn real_test_ipv6_with_google() {
        let result = country_finder(
            crate::dbip_country::ipv4_country_data,
            crate::dbip_country::ipv6_country_data,
            IpAddr::from_str("2607:f8b0:4009:814::2004").unwrap(), // dig www.google.com AAAA
        )
        .unwrap();

        assert_eq!(result.name, "United States".to_string());
    }
}
