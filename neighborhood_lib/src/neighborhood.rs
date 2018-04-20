// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::Ipv4Addr;
use regex::Regex;
use regex::Captures;
use sub_lib::dispatcher::Component;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::neighborhood::NeighborhoodError;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;

pub struct NeighborhoodReal {
}

impl NeighborhoodReal {
    pub fn new() -> Self {
        NeighborhoodReal {}
    }

    fn valid(&self, from_public_key: &Key) -> bool {
        0 != from_public_key.data.len()
    }

    fn num_from_capture(&self, captures: &Captures, idx: usize) -> u8 {
        let string = captures.get(idx).unwrap().as_str();
        string.parse::<u8>().unwrap()
    }
}

impl Neighborhood for NeighborhoodReal {
    fn route_one_way(&self, _destination: &Key, _remote_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn route_round_trip(&self, destination: &Key, _remote_recipient: Component, _local_recipient: Component) -> Result<Route, NeighborhoodError> {
        let cryptde = CryptDENull::new ();
        if self.valid(destination) {
            Ok (Route::new(vec! (
                    RouteSegment::new(vec! (&cryptde.public_key()), Component::ProxyClient),
                    RouteSegment::new(vec!(&cryptde.public_key(), &cryptde.public_key()), Component::ProxyServer)
                ), &cryptde).expect ("Internal error: couldn't construct Route"))
        }
        else {
            Err(NeighborhoodError::InvalidPublicKey)
        }
    }

    fn public_key_from_ip_address(&self, ip_addr: &IpAddr) -> Option<Key> {
        // This is temporary code, and should go away as soon as the Neighborhood offers this service.
        let string = format!("{:?}", ip_addr);
        if string == String::from("V4(0.0.0.0)") { return None; }
        Some(Key::new (&string.into_bytes()[..]))
    }

    fn node_addr_from_public_key(&self, public_key: &[u8]) -> Option<NodeAddr> {
        // This is temporary code, and should go away as soon as the Neighborhood offers this service.
        let regex = match Regex::new("^V4\\((\\d+)\\.(\\d+)\\.(\\d+)\\.(\\d+)\\)$") {
            Ok(x) => x,
            Err(_) => return None
        };
        let string_key = match String::from_utf8(Vec::from(public_key)) {
            Ok(x) => x,
            Err(_) => return None
        };
        match regex.captures (&string_key[..]) {
            Some (captures) => Some (NodeAddr::new (&IpAddr::V4(Ipv4Addr::from([
                self.num_from_capture(&captures, 1),
                self.num_from_capture(&captures, 2),
                self.num_from_capture(&captures, 3),
                self.num_from_capture(&captures, 4),
            ])), &vec! (5678))),
            None => None
        }
    }

    fn node_addr_from_ip_address (&self, _ip_addr: &IpAddr) -> Option<NodeAddr> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sub_lib::hop::Hop;
    use sub_lib::cryptde::CryptData;
    use std::iter;

    #[test]
    fn call_neighborhood_and_ask_for_a_rel_2_route() {
        let cryptde = CryptDENull::new ();
        let neighborhood = NeighborhoodReal::new();

        let mut route = neighborhood.route_round_trip(&cryptde.public_key (),
            Component::Hopper, Component::Hopper).unwrap();

        let next_hop = route.shift(&cryptde.private_key(), &cryptde).unwrap();

        let mut garbage_can: Vec<u8> = iter::repeat (0u8).take (41).collect ();
        cryptde.random (&mut garbage_can[..]);
        assert_eq! (next_hop, Hop::with_key_and_component(&cryptde.public_key(), Component::ProxyClient));
        assert_eq! (route.hops, vec! (
            Hop::with_component (Component::ProxyServer).encode (&cryptde.public_key (), &cryptde).unwrap (),
            CryptData::new (&garbage_can[..])
        ));
    }

    #[test]
    fn call_neighborhood_and_ask_for_a_route_with_an_empty_public_key() {
        let neighborhood = NeighborhoodReal::new();

        let result = neighborhood.route_round_trip(&Key::new ("".as_bytes()),
            Component::Hopper, Component::Hopper).err().unwrap();

        assert_eq!(NeighborhoodError::InvalidPublicKey, result);
    }

    // Temporary
    #[test]
    fn public_key_from_ip_address_can_return_some() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let subject = NeighborhoodReal::new();

        let result = subject.public_key_from_ip_address(&ip_addr).unwrap();

        let string_version = String::from_utf8(result.data).unwrap();
        assert_eq!(string_version, String::from("V4(1.2.3.4)"));
    }

    // Temporary
    #[test]
    fn public_key_from_ip_address_can_return_none() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let subject = NeighborhoodReal::new();

        let result = subject.public_key_from_ip_address(&ip_addr);

        assert_eq!(result, None);
    }

    // Temporary
    #[test]
    fn node_addr_from_public_key_can_return_some() {
        let subject = NeighborhoodReal::new();
        let public_key_string = String::from("V4(1.2.3.4)");
        let public_key = public_key_string.as_bytes();

        let result = subject.node_addr_from_public_key(public_key);

        assert_eq!(result, Some (NodeAddr::new (&IpAddr::from([1, 2, 3, 4]), &vec!(5678))));
    }

    // Temporary
    #[test]
    fn node_addr_from_public_key_can_return_none() {
        let subject = NeighborhoodReal::new();
        let public_key_string = String::from("booga");
        let public_key = public_key_string.as_bytes();

        let result = subject.node_addr_from_public_key(public_key);

        assert_eq!(result.is_none (), true);
    }

    // Temporary
    #[test]
    fn node_addr_is_preserved() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let subject = NeighborhoodReal::new();

        let result = subject.node_addr_from_public_key(&subject.public_key_from_ip_address(&ip_addr).unwrap().data[..]);

        assert_eq!(result, Some (NodeAddr::new (&ip_addr, &vec!(5678))));
    }

    // Temporary
    #[test]
    fn public_key_is_preserved() {
        let public_key = Key::new (b"V4(1.2.3.4)");
        let subject = NeighborhoodReal::new();

        let result = subject.public_key_from_ip_address(&subject.node_addr_from_public_key(&public_key.data[..]).unwrap ().ip_addr ());

        assert_eq!(result, Some(public_key));
    }
}