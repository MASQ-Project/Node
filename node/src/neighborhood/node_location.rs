// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ip_country_lib;
use ip_country_lib::country_finder::CountryCodeFinder;
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeLocation {
    pub country_code: String,
    pub free_world_bit: bool,
}

pub fn get_node_location(ip_opt: Option<IpAddr>) -> Option<NodeLocation> {
    match ip_opt {
        Some(ip_addr) => {
            let country_opt = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, ip_addr);
            country_opt.map(|country| NodeLocation {
                country_code: country.iso3166.clone(),
                free_world_bit: country.free_world,
            })
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::neighborhood::node_location::{get_node_location, NodeLocation};
    use crate::neighborhood::node_record::NodeRecordMetadata;
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
    }
}
