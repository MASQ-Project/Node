// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use cryptde::CryptDE;
use cryptde::CryptData;
use cryptde::CryptdecError;
use cryptde::Key;
use cryptde::PlainData;
use dispatcher::Component;
use serde_cbor;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Hop {
    pub public_key: Key,
    pub component: Component,
}

impl Hop {
    pub fn new(key: &Key, component: Component) -> Self {
        Hop {
            public_key: key.clone(),
            component,
        }
    }

    pub fn decode(cryptde: &CryptDE, crypt_data: &CryptData) -> Result<Self, CryptdecError> {
        let plain_data = cryptde.decode(crypt_data)?;
        match serde_cbor::de::from_slice::<Hop>(&plain_data.data[..]) {
            Ok(hop) => Ok(hop),
            // crashpoint - need to figure out how to return deserialize error
            Err(_) => unimplemented!("failed to deserialize hop"),
        }
    }

    pub fn encode(&self, public_key: &Key, cryptde: &CryptDE) -> Result<CryptData, CryptdecError> {
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
        let subject = Hop::new(&Key::new("key".as_bytes()), Component::Neighborhood);

        assert_eq!(subject.public_key, Key::new("key".as_bytes()));
        assert_eq!(subject.component, Component::Neighborhood);
    }

    #[test]
    fn encode_decode() {
        let cryptde = CryptDENull::new();
        let encode_key = cryptde.public_key();
        let hopper_hop = Hop::new(&&Key::new(&[4, 3, 2, 1]), Component::Hopper);
        let neighborhood_hop = Hop::new(&Key::new(&[1, 2, 3, 4]), Component::Neighborhood);
        let proxy_server_hop = Hop::new(&Key::new(&[127, 128]), Component::ProxyServer);
        let proxy_client_hop = Hop::new(&Key::new(&[253, 254, 255]), Component::ProxyClient);
        let relay_hop = Hop::new(&Key::new(&[123]), Component::Hopper);

        let hopper_hop_encoded = hopper_hop.encode(&encode_key, &cryptde).unwrap();
        let neighborhood_hop_encoded = neighborhood_hop.encode(&encode_key, &cryptde).unwrap();
        let proxy_server_hop_encoded = proxy_server_hop.encode(&encode_key, &cryptde).unwrap();
        let proxy_client_hop_encoded = proxy_client_hop.encode(&encode_key, &cryptde).unwrap();
        let none_hop_encoded = relay_hop.encode(&encode_key, &cryptde).unwrap();

        assert_eq!(
            Hop::decode(&cryptde, &hopper_hop_encoded).unwrap(),
            hopper_hop
        );
        assert_eq!(
            Hop::decode(&cryptde, &neighborhood_hop_encoded).unwrap(),
            neighborhood_hop
        );
        assert_eq!(
            Hop::decode(&cryptde, &proxy_server_hop_encoded).unwrap(),
            proxy_server_hop
        );
        assert_eq!(
            Hop::decode(&cryptde, &proxy_client_hop_encoded).unwrap(),
            proxy_client_hop
        );
        assert_eq!(Hop::decode(&cryptde, &none_hop_encoded).unwrap(), relay_hop);
    }
}
