// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::IpAddr;
use sub_lib::dispatcher::Component;
use sub_lib::dispatcher::DispatcherClient;
use sub_lib::dispatcher::Endpoint;
use sub_lib::dispatcher::PeerClients;
use sub_lib::dispatcher::TransmitterHandle;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::neighborhood::NeighborhoodError;
use sub_lib::hopper::HopperClient;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::node_addr::NodeAddr;
use sub_lib::route::Route;
use sub_lib::cryptde::Key;
use sub_lib::cryptde::PlainData;

pub struct TemporaryDispatcherClientReal {
    pub component: Component,
    pub transmitter_handle: Option<Box<TransmitterHandle>>,
}

pub trait TemporaryDispatcherClient: DispatcherClient {}

impl DispatcherClient for TemporaryDispatcherClientReal {
    fn bind(&mut self, transmitter_handle: Box<TransmitterHandle>, _clients: &PeerClients) {
        self.transmitter_handle = Some (transmitter_handle);
    }

    fn receive(&mut self, source: Endpoint, data: PlainData) {
        let mut outgoing = PlainData::new (b"");
        for i in 0..data.data.len () {
            outgoing.data.push (data.data[data.data.len () - i - 1])
        }
        let transmitter_handle = self.transmitter_handle.as_ref ().unwrap ();
        let result = match source {
            Endpoint::Key(key) => transmitter_handle.transmit(&key, outgoing),
            Endpoint::Ip(ip_addr) => transmitter_handle.transmit_to_ip (ip_addr, outgoing),
            Endpoint::Socket(socket_addr) => transmitter_handle.transmit_to_socket_addr(socket_addr, outgoing)
        };
        match result {
            Ok (()) => (),
            Err (e) => eprintln! ("Error: {:?}: Problem: {:?}", self.component, e)
        }
    }
}

impl HopperClient for TemporaryDispatcherClientReal {
    fn receive_cores_package(&mut self, _package: ExpiredCoresPackage) {
        unimplemented!()
    }
}

impl<T: DispatcherClient + TemporaryDispatcherClient + Send + Sync> TemporaryDispatcherClient for T {}

impl TemporaryDispatcherClientReal {
    pub fn new (component: Component) -> TemporaryDispatcherClientReal {
        TemporaryDispatcherClientReal {
            component,
            transmitter_handle: None
        }
    }
}

pub struct TemporaryNeighborhoodReal {
    delegate: TemporaryDispatcherClientReal
}

unsafe impl Send for TemporaryNeighborhoodReal {}

unsafe impl Sync for TemporaryNeighborhoodReal {}

impl DispatcherClient for TemporaryNeighborhoodReal {
    fn bind(&mut self, transmitter_handle: Box<TransmitterHandle>, clients: &PeerClients) {
        self.delegate.bind (transmitter_handle, clients)
    }

    fn receive(&mut self, source: Endpoint, data: PlainData) {
        self.delegate.receive (source, data)
    }
}

impl Neighborhood for TemporaryNeighborhoodReal {
    fn route_one_way(&mut self, _destination: &Key, _remote_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn route_round_trip(&mut self, _destination: &Key, _remote_recipient: Component, _local_recipient: Component) -> Result<Route, NeighborhoodError> {
        Err (NeighborhoodError::NoRouteAvailable)
    }

    fn public_key_from_ip_address(&self, _ip_addr: &IpAddr) -> Option<Key> {
        None
    }

    fn node_addr_from_public_key(&self, _public_key: &[u8]) -> Option<NodeAddr> {
        None
    }

    fn node_addr_from_ip_address(&self, _ip_addr: &IpAddr) -> Option<NodeAddr> {
        None
    }
}

impl TemporaryNeighborhoodReal {
    pub fn new () -> TemporaryNeighborhoodReal {
        TemporaryNeighborhoodReal {
            delegate: TemporaryDispatcherClientReal::new (Component::Neighborhood)
        }
    }
}

#[cfg (test)]
mod tests {

    #[test]
    fn nothing () {

    }
}