// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ip_country_lib;
use ip_country_lib::country_finder::{CountryCodeFinder, COUNTRY_CODE_FINDER};
use std::net::IpAddr;

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct NodeLocation {
    pub(crate) country_code: String,
    pub(crate) free_world_bit: bool,
}

impl PartialEq<Self> for NodeLocation {
    fn eq(&self, other: &Self) -> bool {
        self.country_code == other.country_code
    }
}

impl Eq for NodeLocation {}

pub fn get_node_location(ip: Option<IpAddr>) -> Option<NodeLocation> {
    match ip {
        Some(ip_addr) => {
            let country = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, ip_addr);
            match country {
                Some(country) => Some(NodeLocation {
                    country_code: country.iso3166.to_string(),
                    free_world_bit: country.free_world,
                }),
                None => None,
            }
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::neighborhood::gossip::GossipBuilder;
    use crate::neighborhood::node_location::{get_node_location, NodeLocation};
    use crate::neighborhood::node_record::{NodeRecord, NodeRecordMetadata};
    use crate::sub_lib::node_addr::NodeAddr;
    use crate::test_utils::neighborhood_test_utils::{
        db_from_node, make_node_record, pick_country_code_record,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_node_location() {
        let node_location =
            get_node_location(Some(IpAddr::V4(Ipv4Addr::new(125, 125, 125, 1)))).unwrap();

        assert_eq!(node_location.country_code, "CN");
        assert_eq!(node_location.free_world_bit, false);
    }

    #[test]
    fn construct_node_record_metadata_with_free_world_bit() {
        let mut metadata = NodeRecordMetadata::new();
        metadata.node_location_opt = get_node_location(Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert_eq!(
            metadata.node_location_opt.as_ref().unwrap(),
            &NodeLocation {
                country_code: "AU".to_string(),
                free_world_bit: true
            }
        );
        assert_eq!(
            metadata.node_location_opt.as_ref().unwrap().free_world_bit,
            true
        );
        assert_eq!(
            metadata.node_location_opt.as_ref().unwrap().country_code,
            "AU"
        );
    }

    #[test]
    fn construct_node_record_for_test() {
        let mut node_record = make_node_record(1111, true);
        let country_record = pick_country_code_record(3333);
        node_record.metadata.node_location_opt = Some(NodeLocation {
            country_code: country_record.1.clone(),
            free_world_bit: country_record.2,
        });
        node_record.metadata.node_addr_opt =
            Some(NodeAddr::new(&country_record.0, &[8000 % 10000]));
        node_record.inner.country_code = country_record.1;

        assert_eq!(
            node_record.metadata.node_location_opt,
            Some(NodeLocation {
                country_code: "AU".to_string(),
                free_world_bit: true
            })
        )
    }

    #[test]
    fn create_gossip_node_with_addr_and_country_code_reveal_results_in_node_with_addr_adn_free_world_bit(
    ) {
        let mut node = make_node_record(2222, true);
        let country_record = pick_country_code_record(2222);
        println!("node: {:?}", node);
        node.metadata.node_location_opt = Some(NodeLocation {
            country_code: country_record.1.clone(),
            free_world_bit: country_record.2,
        });
        node.metadata.node_addr_opt = Some(NodeAddr::new(&country_record.0, &[8000 % 10000]));
        node.inner.country_code = country_record.1;
        let db = db_from_node(&node);
        let builder = GossipBuilder::new(&db);

        let builder = builder.node(node.public_key(), true);

        let mut gossip = builder.build();
        let gossip_result = gossip.node_records.remove(0);
        let node_record = NodeRecord::try_from(&gossip_result).unwrap();

        println!("node_record: {:?}", node_record);
        assert_eq!(
            gossip_result.node_addr_opt.unwrap(),
            node.node_addr_opt().unwrap()
        );
        assert_eq!(node_record.inner.country_code, "US")
    }
}

#[allow(dead_code, unused_imports)]
#[cfg(not(test))]
mod test_ip_country_performance {
    use crate::neighborhood::node_location::{get_node_location, NodeLocation};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    #[test]
    fn get_node_location_for_test_with_1000_v4_high_val_ips() {
        let mut result_vec: Vec<Option<NodeLocation>> = vec![];
        let start = 0xdfff8000u32;
        let timestart = SystemTime::now();

        (start..(start + 1000)).for_each(|num| {
            let address = IpAddr::V4(Ipv4Addr::from(num));
            result_vec.push(get_node_location(Some(address)));
        });

        let timeend = SystemTime::now();

        println!(
            "get_node_location_for_test_with_1000_v4_high_val_ips Elapesd time: {}",
            timeend.duration_since(timestart).unwrap().as_secs()
        );
        assert!(timeend.duration_since(timestart).unwrap().as_secs() < 20);
        while !result_vec.is_empty() {
            let location = result_vec.remove(0);
            assert_eq!(location.unwrap().free_world_bit, true);
        }
    }

    #[test]
    fn get_node_location_for_test_with_1000_v4_low_val_ips() {
        let mut result_vec: Vec<Option<NodeLocation>> = vec![];
        let start = 0x10100101u32;
        let timestart = SystemTime::now();

        (start..(start + 1000)).for_each(|num| {
            let address = IpAddr::V4(Ipv4Addr::from(num));
            result_vec.push(get_node_location(Some(address)));
        });

        let timeend = SystemTime::now();

        println!(
            "get_node_location_for_test_with_1000_v4_high_val_ips Elapesd time: {}",
            timeend.duration_since(timestart).unwrap().as_secs()
        );
        assert!(timeend.duration_since(timestart).unwrap().as_secs() < 20);
        while !result_vec.is_empty() {
            let location = result_vec.remove(0);
            assert_eq!(location.unwrap().free_world_bit, true);
        }
    }

    #[test]
    fn get_node_location_for_test_with_1000_v6_middle_val_ips() {
        let mut result_vec: Vec<Option<NodeLocation>> = vec![];
        let start = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000u128;
        let timestart = SystemTime::now();

        (start..(start + 1000)).for_each(|num| {
            let address = IpAddr::V6(Ipv6Addr::from(num));
            result_vec.push(get_node_location(Some(address)));
        });

        let timeend = SystemTime::now();

        println!(
            "get_node_location_for_test_with_1000_v4_high_val_ips Elapesd time: {}",
            timeend.duration_since(timestart).unwrap().as_secs()
        );
        assert!(timeend.duration_since(timestart).unwrap().as_secs() < 20);
        while !result_vec.is_empty() {
            let location = result_vec.remove(0);
            assert_eq!(location.unwrap().free_world_bit, true);
        }
    }
}
