// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use dispatcher::Component;
use cryptde::Key;
use cryptde::CryptDE;
use cryptde::CryptData;
use cryptde::PlainData;
use cryptde::CryptdecError;
use serde_cbor;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Hop {
    pub public_key: Option<Key>,
    pub component: Option<Component>
}

impl Hop {
    pub fn with_key(key: &Key) -> Self {
        Hop {
            public_key: Some(key.clone ()),
            component: None
        }
    }

    pub fn with_key_and_component(key: &Key, component: Component) -> Self {
        Hop {
            public_key: Some(key.clone ()),
            component: Some(component)
        }
    }

    pub fn with_component (component: Component) -> Self {
        Hop {
            public_key: None,
            component: Some (component)
        }
    }

    pub fn decode (key: &Key, cryptde: &CryptDE, crypt_data: &CryptData) -> Result<Self, CryptdecError> {
        let plain_data = cryptde.decode (key, crypt_data)?;
        match serde_cbor::de::from_slice::<Hop> (&plain_data.data[..]) {
            Ok (hop) => Ok (hop),
            // crashpoint - need to figure out how to return deserialize error
            Err (_) => unimplemented!()
        }
    }

    pub fn encode (&self, key: &Key, cryptde: &CryptDE) -> Result<CryptData, CryptdecError> {
        let plain_data = match serde_cbor::ser::to_vec (&self) {
            Ok (data) => PlainData::new (&data[..]),
            // crashpoint - need to figure out how to return serialize error
            Err (_) => unimplemented!()
        };
        cryptde.encode (key, &plain_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde_null::CryptDENull;

    #[test]
    fn with_key() {
        let subject = Hop::with_key(&Key::new ("key".as_bytes()));

        assert_eq!(subject.component, None);
        assert_eq!(subject.public_key, Some(Key::new ("key".as_bytes())));
    }

    #[test]
    fn with_key_and_component() {
        let subject = Hop::with_key_and_component(&Key::new ("key".as_bytes()), Component::Neighborhood);

        assert_eq!(subject.public_key, Some(Key::new("key".as_bytes())));
        assert_eq!(subject.component, Some(Component::Neighborhood));
    }

    #[test]
    fn with_component () {
        let subject = Hop::with_component (Component::Hopper);

        assert_eq! (subject.public_key, None);
        assert_eq! (subject.component, Some (Component::Hopper));
    }

    #[test]
    fn encode_decode () {
        let cryptde = CryptDENull::new ();
        let encode_key = Key::new (b"waffle");
        let decode_key = CryptDENull::other_key (&encode_key);
        let hopper_hop = Hop::with_component (Component::Hopper);
        let neighborhood_hop = Hop::with_key_and_component (&Key::new (&[1, 2, 3, 4]), Component::Neighborhood);
        let proxy_server_hop = Hop::with_key_and_component (&Key::new (&[127, 128]), Component::ProxyServer);
        let proxy_client_hop = Hop::with_key_and_component (&Key::new (&[253, 254, 255]), Component::ProxyClient);
        let none_hop = Hop::with_key (&Key::new (&[123]));

        let hopper_hop_encoded = hopper_hop.encode (&encode_key, &cryptde).unwrap ();
        let neighborhood_hop_encoded = neighborhood_hop.encode (&encode_key, &cryptde).unwrap ();
        let proxy_server_hop_encoded = proxy_server_hop.encode (&encode_key, &cryptde).unwrap ();
        let proxy_client_hop_encoded = proxy_client_hop.encode (&encode_key, &cryptde).unwrap ();
        let none_hop_encoded = none_hop.encode (&encode_key, &cryptde).unwrap ();

        assert_eq! (Hop::decode (&decode_key, &cryptde, &hopper_hop_encoded).unwrap (), hopper_hop);
        assert_eq! (Hop::decode (&decode_key, &cryptde, &neighborhood_hop_encoded).unwrap (), neighborhood_hop);
        assert_eq! (Hop::decode (&decode_key, &cryptde, &proxy_server_hop_encoded).unwrap (), proxy_server_hop);
        assert_eq! (Hop::decode (&decode_key, &cryptde, &proxy_client_hop_encoded).unwrap (), proxy_client_hop);
        assert_eq! (Hop::decode (&decode_key, &cryptde, &none_hop_encoded).unwrap (), none_hop);
    }
}
