// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use regex::Regex;
use regex::Captures;
use sub_lib::dispatcher::DispatcherClient;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::PeerClients;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::dispatcher::Component;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::neighborhood::NeighborhoodError;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde_null::CryptDENull;

pub struct NeighborhoodReal {
    bound: bool,
    transmitter_handle: Option<Mutex<Box<TransmitterHandle>>>
}

impl NeighborhoodReal {
    pub fn new() -> Self {
        NeighborhoodReal {
            bound: false,
            transmitter_handle: None
        }
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
    fn route_one_way(&mut self, _destination: &Key, _remote_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn route_round_trip(&mut self, destination: &Key, _remote_recipient: Component, _local_recipient: Component) -> Result<Route, NeighborhoodError> {
        let cryptde = CryptDENull::new ();
        if self.valid(destination) {
            Ok (Route::rel2_from_proxy_server (&cryptde.public_key (), &cryptde).expect ("Internal error"))
        }
        else {
            Err(NeighborhoodError::InvalidPublicKey)
        }
    }

    fn public_key_from_ip_address(&self, ip_addr: &IpAddr) -> Option<Key> {
        // This is temporary code, and should go away as soon as the Neighborhood offers this service.
        if !self.bound { panic!("Call bind() on Neighborhood before asking for public key"); }
        let string = format!("{:?}", ip_addr);
        if string == String::from("V4(0.0.0.0)") { return None; }
        Some(Key::new (&string.into_bytes()[..]))
    }

    fn node_addr_from_public_key(&self, public_key: &[u8]) -> Option<NodeAddr> {
        // This is temporary code, and should go away as soon as the Neighborhood offers this service.
        if !self.bound { panic!("Call bind() on Neighborhood before asking for IP address"); }
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

impl DispatcherClient for NeighborhoodReal {
    fn bind(&mut self, transmitter_handle: Box<TransmitterHandle>, _clients: &PeerClients) {
        self.transmitter_handle = Some(Mutex::new(transmitter_handle));
        self.bound = true;
    }

    fn receive(&mut self, _source: Endpoint, _data: PlainData) {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use sub_lib::hop::Hop;
    use sub_lib::test_utils;
    use sub_lib::test_utils::TransmitterHandleMock;

    #[test]
    fn call_neighborhood_and_ask_for_a_rel_2_route() {
        let cryptde = CryptDENull::new ();
        let mut neighborhood = NeighborhoodReal::new();

        let route = neighborhood.route_round_trip(&cryptde.public_key (),
            Component::Hopper, Component::Hopper).unwrap();

        assert_eq! (route.next_hop (), Hop::with_key_and_component (&cryptde.public_key (), Component::ProxyClient));
    }

    #[test]
    fn call_neighborhood_and_ask_for_a_route_with_an_empty_public_key() {
        let mut neighborhood = NeighborhoodReal::new();

        let result = neighborhood.route_round_trip(&Key::new ("".as_bytes()),
            Component::Hopper, Component::Hopper).err().unwrap();

        assert_eq!(NeighborhoodError::InvalidPublicKey, result);
    }

    // Temporary
    #[test]
    #[should_panic(expected = "Call bind() on Neighborhood before asking for public key")]
    fn public_key_from_ip_address_doesnt_work_until_after_bind() {
        let subject = NeighborhoodReal::new();
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        subject.public_key_from_ip_address(&ip_addr);
    }

    // Temporary
    #[test]
    #[should_panic(expected = "Call bind() on Neighborhood before asking for IP address")]
    fn node_addr_from_public_key_doesnt_work_until_after_bind() {
        let subject = NeighborhoodReal::new();

        subject.node_addr_from_public_key(&[]);
    }

    // Temporary
    #[test]
    fn public_key_from_ip_address_can_return_some() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());

        let result = subject.public_key_from_ip_address(&ip_addr).unwrap();

        let string_version = String::from_utf8(result.data).unwrap();
        assert_eq!(string_version, String::from("V4(1.2.3.4)"));
    }

    // Temporary
    #[test]
    fn public_key_from_ip_address_can_return_none() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());

        let result = subject.public_key_from_ip_address(&ip_addr);

        assert_eq!(result, None);
    }

    // Temporary
    #[test]
    fn node_addr_from_public_key_can_return_some() {
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());
        let public_key_string = String::from("V4(1.2.3.4)");
        let public_key = public_key_string.as_bytes();

        let result = subject.node_addr_from_public_key(public_key);

        assert_eq!(result, Some (NodeAddr::new (&IpAddr::from([1, 2, 3, 4]), &vec!(5678))));
    }

    // Temporary
    #[test]
    fn node_addr_from_public_key_can_return_none() {
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());
        let public_key_string = String::from("booga");
        let public_key = public_key_string.as_bytes();

        let result = subject.node_addr_from_public_key(public_key);

        assert_eq!(result.is_none (), true);
    }

    // Temporary
    #[test]
    fn node_addr_is_preserved() {
        let ip_addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());

        let result = subject.node_addr_from_public_key(&subject.public_key_from_ip_address(&ip_addr).unwrap().data[..]);

        assert_eq!(result, Some (NodeAddr::new (&ip_addr, &vec!(5678))));
    }

    // Temporary
    #[test]
    fn public_key_is_preserved() {
        let public_key = Key::new (b"V4(1.2.3.4)");
        let transmitter_handle = TransmitterHandleMock::new ();
        let mut subject = NeighborhoodReal::new();
        subject.bind(Box::new(transmitter_handle), &test_utils::make_peer_clients_with_mocks());

        let result = subject.public_key_from_ip_address(&subject.node_addr_from_public_key(&public_key.data[..]).unwrap ().ip_addr ());

        assert_eq!(result, Some(public_key));
    }
}