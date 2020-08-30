// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::masq_node_client::MASQNodeClient;
use node_lib::hopper::live_cores_package::LiveCoresPackage;
use node_lib::json_masquerader::JsonMasquerader;
use node_lib::masquerader::Masquerader;
use node_lib::sub_lib::cryptde::CryptDE;
use node_lib::sub_lib::cryptde::PlainData;
use node_lib::sub_lib::cryptde::PublicKey;
use node_lib::sub_lib::hopper::IncipientCoresPackage;
use std::net::SocketAddr;

pub struct MASQCoresClient<'a> {
    cryptde: &'a dyn CryptDE,
    delegate: MASQNodeClient,
}

impl<'a> MASQCoresClient<'a> {
    pub fn new(socket_addr: SocketAddr, cryptde: &'a dyn CryptDE) -> MASQCoresClient<'a> {
        MASQCoresClient {
            cryptde,
            delegate: MASQNodeClient::new(socket_addr),
        }
    }

    pub fn transmit_package(
        &mut self,
        incipient_cores_package: IncipientCoresPackage,
        masquerader: &JsonMasquerader,
        recipient_key: PublicKey,
    ) {
        let (live_cores_package, _) =
            LiveCoresPackage::from_incipient(incipient_cores_package, self.cryptde).unwrap();
        let serialized_lcp = serde_cbor::ser::to_vec(&live_cores_package)
            .unwrap_or_else(|_| panic!("Serializing LCP: {:?}", live_cores_package));
        let encoded_serialized_package = self
            .cryptde
            .encode(&recipient_key, &PlainData::new(&serialized_lcp[..]))
            .unwrap();
        let masqueraded = masquerader
            .mask(encoded_serialized_package.as_slice())
            .unwrap_or_else(|_| {
                panic!("Masquerading {}-byte serialized LCP", serialized_lcp.len())
            });
        self.delegate.send_chunk(&masqueraded);
    }

    pub fn masquerade_live_cores_package(
        live_cores_package: LiveCoresPackage,
        masquerader: &JsonMasquerader,
    ) -> Vec<u8> {
        let serialized_lcp = serde_cbor::ser::to_vec(&live_cores_package)
            .unwrap_or_else(|_| panic!("Serializing LCP: {:?}", live_cores_package));
        masquerader
            .mask(&serialized_lcp[..])
            .unwrap_or_else(|_| panic!("Masquerading {}-byte serialized LCP", serialized_lcp.len()))
    }
}
