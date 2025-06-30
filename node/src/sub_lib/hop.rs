// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::blockchain::payer::Payer;
use crate::sub_lib::cryptde::encodex;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{decodex, CodexError};
use crate::sub_lib::dispatcher::Component;
use serde_derive::{Deserialize, Serialize};

// This structure is the one that will travel from Node to Node in a CORES package.
// There may soon be another version that always stays on the Node and is used to
// remember Routes while they're in use.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LiveHop {
    pub public_key: PublicKey,
    pub payer: Option<Payer>,
    pub component: Component,
}

impl LiveHop {
    pub fn new(key: &PublicKey, payer: Option<Payer>, component: Component) -> Self {
        LiveHop {
            public_key: key.clone(),
            payer,
            component,
        }
    }

    pub fn decode(cryptde: &dyn CryptDE, crypt_data: &CryptData) -> Result<Self, CodexError> {
        decodex::<LiveHop>(cryptde, crypt_data)
    }

    pub fn encode(
        &self,
        public_key: &PublicKey,
        cryptde: &dyn CryptDE,
    ) -> Result<CryptData, CodexError> {
        encodex(cryptde, public_key, &self)
    }

    pub fn payer_owns_secret_key(&self, digest: &dyn AsRef<[u8]>) -> bool {
        match &self.payer {
            Some(p) => p.owns_secret_key(digest),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use super::*;
    use crate::test_utils::{make_paying_wallet};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use crate::bootstrapper::CryptDEPair;

    lazy_static! {
        static ref CRYPTDE_PAIR: CryptDEPair = CryptDEPair::null();
    }

    #[test]
    fn can_construct_hop() {
        let key = PublicKey::new(b"key");

        let subject = LiveHop::new(
            &key,
            Some(make_paying_wallet(b"wallet"))
                .map(|w| w.as_payer(&key, &TEST_DEFAULT_CHAIN.rec().contract)),
            Component::Neighborhood,
        );

        assert_eq!(subject.public_key, key);
        assert_eq!(subject.component, Component::Neighborhood);
    }

    #[test]
    fn decode_can_handle_errors() {
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let encrypted = CryptData::new(&[0]);

        let result = LiveHop::decode(cryptde, &encrypted);

        assert_eq!(
            format!("{:?}", result).contains("DecryptionError(InvalidKey("),
            true,
            "{:?}",
            result
        );
    }

    #[test]
    fn encode_decode() {
        let cryptde = CRYPTDE_PAIR.main.as_ref();
        let paying_wallet = make_paying_wallet(b"wallet");
        let encode_key = cryptde.public_key();
        let contract_address = &TEST_DEFAULT_CHAIN.rec().contract.clone();
        let hopper_hop = LiveHop::new(
            &PublicKey::new(&[4, 3, 2, 1]),
            Some(paying_wallet.clone())
                .map(|w| w.as_payer(&PublicKey::new(&[4, 3, 2, 1]), contract_address)),
            Component::Hopper,
        );
        let neighborhood_hop = LiveHop::new(
            &PublicKey::new(&[1, 2, 3, 4]),
            Some(paying_wallet.clone())
                .map(|w| w.as_payer(&PublicKey::new(&[1, 2, 3, 4]), contract_address)),
            Component::Neighborhood,
        );
        let proxy_server_hop = LiveHop::new(
            &PublicKey::new(&[127, 128]),
            Some(paying_wallet.clone())
                .map(|w| w.as_payer(&PublicKey::new(&[127, 128]), contract_address)),
            Component::ProxyServer,
        );
        let proxy_client_hop = LiveHop::new(
            &PublicKey::new(&[253, 254, 255]),
            Some(paying_wallet.clone())
                .map(|w| w.as_payer(&PublicKey::new(&[253, 254, 255]), contract_address)),
            Component::ProxyClient,
        );
        let relay_hop = LiveHop::new(
            &PublicKey::new(&[123]),
            Some(paying_wallet.clone())
                .map(|w| w.as_payer(&PublicKey::new(&[123]), contract_address)),
            Component::Hopper,
        );

        let hopper_hop_encoded = hopper_hop.encode(&encode_key, cryptde).unwrap();
        let neighborhood_hop_encoded = neighborhood_hop.encode(&encode_key, cryptde).unwrap();
        let proxy_server_hop_encoded = proxy_server_hop.encode(&encode_key, cryptde).unwrap();
        let proxy_client_hop_encoded = proxy_client_hop.encode(&encode_key, cryptde).unwrap();
        let none_hop_encoded = relay_hop.encode(&encode_key, cryptde).unwrap();

        assert_eq!(
            LiveHop::decode(cryptde, &hopper_hop_encoded).unwrap(),
            hopper_hop
        );
        assert_eq!(
            LiveHop::decode(cryptde, &neighborhood_hop_encoded).unwrap(),
            neighborhood_hop
        );
        assert_eq!(
            LiveHop::decode(cryptde, &proxy_server_hop_encoded).unwrap(),
            proxy_server_hop
        );
        assert_eq!(
            LiveHop::decode(cryptde, &proxy_client_hop_encoded).unwrap(),
            proxy_client_hop
        );
        assert_eq!(
            LiveHop::decode(cryptde, &none_hop_encoded).unwrap(),
            relay_hop
        );
    }
}
