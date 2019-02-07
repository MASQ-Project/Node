// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use cryptde::CryptDE;
use cryptde::CryptData;
use cryptde::CryptdecError;
use cryptde::PlainData;
use cryptde::PublicKey;
use dispatcher::Component;
use serde_cbor;
use wallet::Wallet;

// This structure is the one that will travel from Node to Node in a CORES package.
// There may soon be another version that always stays on the Node and is used to
// remember Routes while they're in use.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct LiveHop {
    pub public_key: PublicKey,
    pub consuming_wallet: Option<Wallet>,
    pub component: Component,
}

impl LiveHop {
    pub fn new(key: &PublicKey, consuming_wallet: Option<Wallet>, component: Component) -> Self {
        LiveHop {
            public_key: key.clone(),
            consuming_wallet: consuming_wallet.clone(),
            component,
        }
    }

    pub fn decode(cryptde: &CryptDE, crypt_data: &CryptData) -> Result<Self, CryptdecError> {
        let plain_data = cryptde.decode(crypt_data)?;
        match serde_cbor::de::from_slice::<LiveHop>(plain_data.as_slice()) {
            Ok(hop) => Ok(hop),
            // crashpoint - need to figure out how to return deserialize error
            Err(_) => unimplemented!("failed to deserialize hop"),
        }
    }

    pub fn encode(
        &self,
        public_key: &PublicKey,
        cryptde: &CryptDE,
    ) -> Result<CryptData, CryptdecError> {
        let plain_data = match serde_cbor::ser::to_vec(&self) {
            Ok(data) => PlainData::new(&data[..]),
            // crashpoint - need to figure out how to return serialize error
            Err(_) => unimplemented!(),
        };
        cryptde.encode(public_key, &plain_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde_null::CryptDENull;

    #[test]
    fn can_construct_hop() {
        let subject = LiveHop::new(
            &PublicKey::new("key".as_bytes()),
            Some(Wallet::new("wallet")),
            Component::Neighborhood,
        );

        assert_eq!(subject.public_key, PublicKey::new("key".as_bytes()));
        assert_eq!(subject.component, Component::Neighborhood);
    }

    #[test]
    fn encode_decode() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let encode_key = cryptde.public_key();
        let hopper_hop = LiveHop::new(
            &&PublicKey::new(&[4, 3, 2, 1]),
            Some(consuming_wallet.clone()),
            Component::Hopper,
        );
        let neighborhood_hop = LiveHop::new(
            &PublicKey::new(&[1, 2, 3, 4]),
            Some(consuming_wallet.clone()),
            Component::Neighborhood,
        );
        let proxy_server_hop = LiveHop::new(
            &PublicKey::new(&[127, 128]),
            Some(consuming_wallet.clone()),
            Component::ProxyServer,
        );
        let proxy_client_hop = LiveHop::new(
            &PublicKey::new(&[253, 254, 255]),
            Some(consuming_wallet.clone()),
            Component::ProxyClient,
        );
        let relay_hop = LiveHop::new(
            &PublicKey::new(&[123]),
            Some(consuming_wallet.clone()),
            Component::Hopper,
        );

        let hopper_hop_encoded = hopper_hop.encode(&encode_key, &cryptde).unwrap();
        let neighborhood_hop_encoded = neighborhood_hop.encode(&encode_key, &cryptde).unwrap();
        let proxy_server_hop_encoded = proxy_server_hop.encode(&encode_key, &cryptde).unwrap();
        let proxy_client_hop_encoded = proxy_client_hop.encode(&encode_key, &cryptde).unwrap();
        let none_hop_encoded = relay_hop.encode(&encode_key, &cryptde).unwrap();

        assert_eq!(
            LiveHop::decode(&cryptde, &hopper_hop_encoded).unwrap(),
            hopper_hop
        );
        assert_eq!(
            LiveHop::decode(&cryptde, &neighborhood_hop_encoded).unwrap(),
            neighborhood_hop
        );
        assert_eq!(
            LiveHop::decode(&cryptde, &proxy_server_hop_encoded).unwrap(),
            proxy_server_hop
        );
        assert_eq!(
            LiveHop::decode(&cryptde, &proxy_client_hop_encoded).unwrap(),
            proxy_client_hop
        );
        assert_eq!(
            LiveHop::decode(&cryptde, &none_hop_encoded).unwrap(),
            relay_hop
        );
    }
}
