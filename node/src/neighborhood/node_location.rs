// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ip_country_lib;
use ip_country_lib::country_finder::{CountryCodeFinder, COUNTRY_CODE_FINDER};
use std::net::IpAddr;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeLocation {
    pub country_code: String,
}

pub fn get_node_location(ip_opt: Option<IpAddr>) -> Option<NodeLocation> {
    match ip_opt {
        Some(ip_addr) => {
            let country_opt = CountryCodeFinder::find_country(&COUNTRY_CODE_FINDER, ip_addr);
            country_opt.map(|country| NodeLocation {
                country_code: country.iso3166.clone(),
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
        let node_location = get_node_location(Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))).unwrap();

        assert_eq!(node_location.country_code, "AD");
    }

    #[test]
    fn construct_node_record_metadata_with_free_world_bit() {
        //TODO check in From impl for AGR that construction of metadata contains proper country_code and fwb, then delete this test
        let mut metadata = NodeRecordMetadata::new();
        metadata.node_location_opt = get_node_location(Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(
            metadata.node_location_opt.as_ref().unwrap(),
            &NodeLocation {
                country_code: "AD".to_string(),
            }
        );
    }
}
