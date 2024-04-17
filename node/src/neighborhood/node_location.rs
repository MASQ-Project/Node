// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use ip_country_lib;
use ip_country_lib::country_finder::country_finder;
use ip_country_lib::dbip_country;

#[derive(Clone, Debug, Default)]
pub struct NodeLocation {
    id: u8,
    locale: String,
    pub(crate) free_world: bool
}

impl PartialEq<Self> for NodeLocation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NodeLocation {}

pub fn get_node_location(ip: Option<IpAddr>) -> Option<NodeLocation> {
    match ip {
        Some(ip_addr) => {
            let country = country_finder(dbip_country::ipv4_country_data, dbip_country::ipv6_country_data, ip_addr);
            match country {
                Some(country) => {
                    Some( NodeLocation { id: country.index as u8, locale: country.iso3166.to_string(), free_world: country.free_world } )
                },
                None => None
            }
        }
        None => None
    }

}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;
    use crate::neighborhood::node_location::{get_node_location, NodeLocation};
    use crate::neighborhood::node_record::NodeRecordMetadata;
    use crate::test_utils::neighborhood_test_utils::make_node_record;

    #[test]
    fn test_node_location() {
        let node_location = get_node_location(Some(IpAddr::V4(Ipv4Addr::new(125, 125, 125, 1)))).unwrap();

        assert_eq!(node_location.locale, "CN");
        assert_eq!(node_location.id, 46);
        assert_eq!(node_location.free_world, false);
    }

    #[test]
    fn construct_node_record_metadata_with_free_world_bit() {
        let metadata = NodeRecordMetadata::new(
            get_node_location(Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))))
        );

        assert_eq!(metadata.node_location.as_ref().unwrap(), &NodeLocation { id: 14, locale: "AU".to_string(), free_world: true });
        assert_eq!(metadata.free_world, metadata.node_location.as_ref().unwrap().free_world);
        assert_eq!(metadata.node_location.as_ref().unwrap().free_world, true);
        assert_eq!(metadata.node_location.as_ref().unwrap().locale, "AU");
        assert_eq!(metadata.node_location.as_ref().unwrap().id, 14);
    }

    #[test]
    fn construct_node_record_for_test() {
        let node_record = make_node_record(1111, true);

        assert_eq!(node_record.metadata.free_world, true);
        assert_eq!(node_record.metadata.node_location, Some(NodeLocation { id: 14, locale: "AU".to_string(), free_world: true }))
    }

    /*#[test]
    fn get_node_location_for_test_with_1000_v4_high_val_ips() {
        let start = 0xFFFF0101u32;
        let timestart = SystemTime::now();
        (start..(start + 1000)).for_each(|num|{
            let address = IpAddr::V4(Ipv4Addr::from(num));
            println!("ip: {}", &address);
            let node_location = get_node_location(Some(address));
            match node_location {
                Some(node_location) => println!("fwb: {}", node_location.free_world),
                None => println!("ip does not exists: {}", address)
            }
        });

        let timeend = SystemTime::now();
        // 2.681 s
        // 2.898 s
        println!("Elapesd time: {}", timeend.duration_since(timestart).unwrap().as_secs());
    }

    #[test]
    fn get_node_location_for_test_with_1000_v4_low_val_ips() {
        let start = 0x00000101u32;
        let timestart = SystemTime::now();
        (start..(start + 1000)).for_each(|num|{
            let address = IpAddr::V4(Ipv4Addr::from(num));
            println!("ip: {}", &address);
            let node_location = get_node_location(Some(address));
            match node_location {
                Some(node_location) => println!("fwb: {}", node_location.free_world),
                None => println!("ip does not exists: {}", address)
            }
        });

        let timeend = SystemTime::now();
        // 1494
        println!("Elapesd time: {}", timeend.duration_since(timestart).unwrap().as_secs());
    }

    #[test]
    fn get_node_location_for_test_with_1000_v6_middle_val_ips() {
        let start = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000u128;
        let timestart = SystemTime::now();
        (start..(start + 1000)).for_each(|num|{
            let address = IpAddr::V6(Ipv6Addr::from(num));
            println!("ip: {}", &address);
            let node_location = get_node_location(Some(address));
            match node_location {
                Some(node_location) => println!("fwb: {}", node_location.free_world),
                None => println!("ip does not exists: {}", address)
            }
        });

        let timeend = SystemTime::now();
        // 3.739
        println!("Elapesd time: {}", timeend.duration_since(timestart).unwrap().as_secs());
    }*/


}
