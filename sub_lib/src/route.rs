// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::cryptde::decodex;
use crate::cryptde::encodex;
use crate::cryptde::CryptDE;
use crate::cryptde::CryptData;
use crate::cryptde::PublicKey;
use crate::dispatcher::Component;
use crate::hop::LiveHop;
use crate::wallet::Wallet;
use serde_derive::{Deserialize, Serialize};
use std::iter;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Route {
    pub hops: Vec<CryptData>,
}

impl Route {
    pub fn one_way(
        route_segment: RouteSegment,
        cryptde: &dyn CryptDE, // Any CryptDE can go here; it's only used to encrypt to public keys.
        consuming_wallet: Option<Wallet>,
    ) -> Result<Route, RouteError> {
        Self::construct(vec![route_segment], cryptde, consuming_wallet, None)
    }

    pub fn round_trip(
        route_segment_over: RouteSegment,
        route_segment_back: RouteSegment,
        cryptde: &dyn CryptDE, // Any CryptDE can go here; it's only used to encrypt to public keys.
        consuming_wallet: Option<Wallet>,
        return_route_id: u32,
    ) -> Result<Route, RouteError> {
        Self::construct(
            vec![route_segment_over, route_segment_back],
            cryptde,
            consuming_wallet,
            Some(return_route_id),
        )
    }

    pub fn id(&self, cryptde: &dyn CryptDE) -> Result<u32, String> {
        if let Some(first) = self.hops.first() {
            decodex(cryptde, first)
        } else {
            return Err("Response route did not contain a return route ID".to_string());
        }
    }

    // This cryptde must be the CryptDE of the next hop to come off the Route.
    pub fn next_hop(&self, cryptde: &dyn CryptDE) -> Result<LiveHop, RouteError> {
        match self.hops.first() {
            None => Err(RouteError::EmptyRoute),
            Some(first) => Route::decode_hop(cryptde, &first.clone()),
        }
    }

    pub fn shift(&mut self, cryptde: &dyn CryptDE) -> Result<LiveHop, RouteError> {
        if self.hops.is_empty() {
            return Err(RouteError::EmptyRoute);
        }
        let top_hop = self.hops.remove(0);
        let top_hop_len = top_hop.len();
        let next_hop = Route::decode_hop(cryptde, &top_hop)?;

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        self.hops.push(CryptData::new(&garbage_can[..]));

        return Ok(next_hop);
    }

    fn construct(
        route_segments: Vec<RouteSegment>,
        cryptde: &dyn CryptDE,
        consuming_wallet: Option<Wallet>,
        return_route_id_opt: Option<u32>,
    ) -> Result<Route, RouteError> {
        if route_segments.is_empty() {
            return Err(RouteError::NoRouteSegments);
        }
        let mut hops: Vec<LiveHop> = Vec::new();
        let mut pending_recipient: Option<Component> = None;
        for segment_index in 0..route_segments.len() {
            let route_segment = &route_segments[segment_index];
            if route_segment.keys.len() < 1 {
                return Err(RouteError::TooFewKeysInRouteSegment);
            }
            for hop_index in 0..route_segment.keys.len() {
                let key = &route_segment.keys[hop_index];
                if (segment_index > 0) && (hop_index == 0) {
                    let last_segment = &route_segments[segment_index - 1];
                    let last_segment_last_key = &last_segment.keys[last_segment.keys.len() - 1];
                    if key != last_segment_last_key {
                        return Err(RouteError::DisjointRouteSegments);
                    }
                    continue;
                }
                hops.push(match pending_recipient {
                    Some(recipient) => LiveHop::new(key, consuming_wallet.clone(), recipient),
                    None => LiveHop::new(key, consuming_wallet.clone(), Component::Hopper),
                });
                pending_recipient = None;
                if (hop_index + 1) == route_segment.keys.len() {
                    pending_recipient = Some(route_segment.recipient);
                }
            }
        }
        hops.push(LiveHop::new(
            &PublicKey::new(b""),
            consuming_wallet,
            pending_recipient.expect("Route segment without recipient"),
        ));
        Route::hops_to_route(
            hops[1..].to_vec(),
            &route_segments[0].keys[0],
            return_route_id_opt,
            cryptde,
        )
    }

    fn decode_hop(cryptde: &dyn CryptDE, hop_enc: &CryptData) -> Result<LiveHop, RouteError> {
        match LiveHop::decode(cryptde, hop_enc) {
            Err(e) => Err(RouteError::HopDecodeProblem(e)),
            Ok(h) => Ok(h),
        }
    }

    fn hops_to_route(
        hops: Vec<LiveHop>,
        top_hop_key: &PublicKey,
        return_route_id_opt: Option<u32>,
        cryptde: &dyn CryptDE,
    ) -> Result<Route, RouteError> {
        let mut hops_enc: Vec<CryptData> = Vec::new();
        let mut hop_key = top_hop_key;
        for hop_index in 0..hops.len() {
            let data_hop = &hops[hop_index];
            // crashpoint - should not be possible, can this be restructured to remove Option?
            hops_enc.push(match data_hop.encode(hop_key, cryptde) {
                Ok(crypt_data) => crypt_data,
                Err(_) => panic!("Couldn't encode hop"),
            });
            hop_key = &data_hop.public_key;
        }
        if let Some(return_route_id) = return_route_id_opt {
            let return_route_id_enc = Self::encrypt_return_route_id(return_route_id, cryptde);
            hops_enc.push(return_route_id_enc);
        }
        Ok(Route { hops: hops_enc })
    }

    fn encrypt_return_route_id(return_route_id: u32, cryptde: &CryptDE) -> CryptData {
        encodex(cryptde, &cryptde.public_key(), &return_route_id)
            .expect("Internal error encrypting u32 return_route_id")
    }
}

#[derive(Debug)]
pub struct RouteSegment {
    pub keys: Vec<PublicKey>,
    pub recipient: Component,
}

impl RouteSegment {
    pub fn new(keys: Vec<&PublicKey>, recipient: Component) -> RouteSegment {
        RouteSegment {
            keys: keys.iter().map(|k| (*k).clone()).collect(),
            recipient,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RouteError {
    HopDecodeProblem(String),
    EmptyRoute,
    NoRouteSegments,
    TooFewKeysInRouteSegment,
    DisjointRouteSegments,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptde_null::CryptDENull;
    use serde_cbor;

    #[test]
    fn id_decodes_return_route_id() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();

        let subject = Route {
            hops: vec![Route::encrypt_return_route_id(42, &cryptde)],
        };

        assert_eq!(subject.id(&cryptde), Ok(42));
    }

    #[test]
    fn id_returns_empty_route_error_when_the_route_is_empty() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();

        let subject = Route { hops: vec![] };

        assert_eq!(
            subject.id(&cryptde),
            Err("Response route did not contain a return route ID".to_string())
        );
    }

    #[test]
    fn id_returns_error_when_the_id_fails_to_decrypt() {
        let cryptde1 = CryptDENull::from(&PublicKey::new(b"key a"));
        let cryptde2 = CryptDENull::from(&PublicKey::new(b"key b"));

        let subject = Route {
            hops: vec![Route::encrypt_return_route_id(42, &cryptde1)],
        };

        assert_eq!(subject.id(&cryptde2), Err("Decryption error: InvalidKey(\"Could not decrypt with [235, 229, 249, 160, 226] data beginning with [235, 229, 249, 160, 225]\")".to_string()));
    }

    #[test]
    fn construct_does_not_like_route_segments_with_too_few_keys() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let result = Route::one_way(
            RouteSegment::new(vec![], Component::ProxyClient),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .err()
        .unwrap();

        assert_eq!(result, RouteError::TooFewKeysInRouteSegment)
    }

    #[test]
    fn construct_does_not_like_route_segments_that_start_where_the_previous_segment_didnt_end() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let mut cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        cryptde.generate_key_pair();

        let result = Route::round_trip(
            RouteSegment::new(vec![&a_key, &b_key], Component::ProxyClient),
            RouteSegment::new(vec![&c_key, &d_key], Component::ProxyServer),
            &cryptde,
            Some(consuming_wallet.clone()),
            0,
        )
        .err()
        .unwrap();

        assert_eq!(result, RouteError::DisjointRouteSegments)
    }

    #[test]
    fn construct_can_make_long_multistop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let e_key = PublicKey::new(&[69, 69, 69]);
        let f_key = PublicKey::new(&[70, 70, 70]);
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");
        let return_route_id = 4321;

        let subject = Route::round_trip(
            RouteSegment::new(vec![&a_key, &b_key, &c_key, &d_key], Component::ProxyClient),
            RouteSegment::new(vec![&d_key, &e_key, &f_key, &a_key], Component::ProxyServer),
            &cryptde,
            Some(consuming_wallet.clone()),
            return_route_id,
        )
        .unwrap();

        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&b_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&a_key, &cryptde)
                    .unwrap(),
                LiveHop::new(&c_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&b_key, &cryptde)
                    .unwrap(),
                LiveHop::new(&d_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&c_key, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &e_key,
                    Some(consuming_wallet.clone()),
                    Component::ProxyClient
                )
                .encode(&d_key, &cryptde)
                .unwrap(),
                LiveHop::new(&f_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&e_key, &cryptde)
                    .unwrap(),
                LiveHop::new(&a_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&f_key, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &PublicKey::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::ProxyServer
                )
                .encode(&a_key, &cryptde)
                .unwrap(),
                Route::encrypt_return_route_id(return_route_id, &cryptde),
            )
        );
    }

    #[test]
    fn construct_can_make_short_single_stop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");

        let subject = Route::one_way(
            RouteSegment::new(vec![&a_key, &b_key], Component::Neighborhood),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();

        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&b_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&a_key, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &PublicKey::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&b_key, &cryptde)
                .unwrap(),
            )
        );
    }

    #[test]
    fn next_hop_decodes_top_hop() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let subject = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::Neighborhood),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();

        let next_hop = subject.next_hop(&cryptde).unwrap();

        assert_eq!(
            next_hop,
            LiveHop::new(&key34, Some(consuming_wallet.clone()), Component::Hopper)
        );
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key34, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&key12, &cryptde)
                    .unwrap(),
                LiveHop::new(&key56, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &PublicKey::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&key56, &cryptde)
                .unwrap(),
            )
        );
    }

    #[test]
    fn shift_returns_next_hop_and_adds_garbage_at_the_bottom() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let mut subject = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::Neighborhood),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();
        let top_hop_len = subject.hops.first().unwrap().len();

        let next_hop = subject.shift(&cryptde).unwrap();

        assert_eq!(
            next_hop,
            LiveHop::new(&key34, Some(consuming_wallet.clone()), Component::Hopper)
        );
        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key56, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &PublicKey::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&key56, &cryptde)
                .unwrap(),
                CryptData::new(&garbage_can[..])
            )
        )
    }

    #[test]
    fn empty_route_says_none_when_asked_for_next_hop() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let subject = Route { hops: Vec::new() };

        let result = subject.next_hop(&cryptde).err().unwrap();

        assert_eq!(result, RouteError::EmptyRoute);
    }

    #[test]
    fn shift_says_none_when_asked_for_next_hop_on_empty_route() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let mut subject = Route { hops: Vec::new() };

        let result = subject.shift(&cryptde).err().unwrap();

        assert_eq!(result, RouteError::EmptyRoute);
    }

    #[test]
    fn route_serialization_deserialization() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[4, 3, 2, 1]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let original = Route::round_trip(
            RouteSegment::new(vec![&key1, &key2], Component::ProxyClient),
            RouteSegment::new(vec![&key2, &key1], Component::ProxyServer),
            &cryptde,
            Some(consuming_wallet),
            1234,
        )
        .unwrap();

        let serialized = serde_cbor::ser::to_vec(&original).unwrap();

        let deserialized = serde_cbor::de::from_slice::<Route>(&serialized[..]).unwrap();

        assert_eq!(deserialized, original);
    }
}
