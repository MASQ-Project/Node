// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use sub_lib::hopper::IncipientCoresPackage;
use node_lib::json_masquerader::JsonMasquerader;
use hopper_lib::hopper::LiveCoresPackage;
use substratum_client:: SubstratumNodeClient;
use sub_lib::cryptde::CryptDE;
use node_lib::masquerader::Masquerader;
use serde_cbor;

pub struct SubstratumCoresClient<'a> {
    cryptde: &'a CryptDE,
    delegate: SubstratumNodeClient,
}

impl<'a> SubstratumCoresClient<'a> {
    pub fn new(socket_addr: SocketAddr, cryptde: &'a CryptDE) -> SubstratumCoresClient<'a> {
        SubstratumCoresClient {
            cryptde,
            delegate: SubstratumNodeClient::new (socket_addr)
        }
    }

    pub fn transmit_package(&mut self, incipient_cores_package: IncipientCoresPackage, masquerader: &JsonMasquerader) {
        let (live_cores_package, _) =
            LiveCoresPackage::from_incipient (incipient_cores_package, self.cryptde);
        let serialized_lcp = serde_cbor::ser::to_vec (&live_cores_package).expect (format! ("Serializing LCP: {:?}", live_cores_package).as_str ());
        let masquerade = masquerader.mask (&serialized_lcp[..]).expect (format! ("Masquerading {}-byte serialized LCP", serialized_lcp.len ()).as_str ());
        self.delegate.send_chunk (masquerade);
    }
}
