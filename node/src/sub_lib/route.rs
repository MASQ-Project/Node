// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::decodex;
use crate::sub_lib::cryptde::encodex;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::hop::LiveHop;
use crate::sub_lib::wallet::Wallet;
use serde_derive::{Deserialize, Serialize};
use std::cmp::min;
use std::iter;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Route {
    pub hops: Vec<CryptData>,
}

impl Route {
    pub fn single_hop(
        destination: &PublicKey,
        cryptde: &dyn CryptDE, // The CryptDE of the beginning of this Route must go here.
    ) -> Result<Route, String> {
        Self::construct(
            RouteSegment::new(
                vec![&cryptde.public_key(), destination],
                Component::Neighborhood,
            ),
            None,
            cryptde,
            None,
            None,
        )
    }

    pub fn one_way(
        route_segment: RouteSegment,
        cryptde: &dyn CryptDE, // Any CryptDE can go here; it's only used to encrypt to public keys.
        consuming_wallet: Option<Wallet>,
    ) -> Result<Route, String> {
        Self::construct(route_segment, None, cryptde, consuming_wallet, None)
    }

    pub fn round_trip(
        route_segment_over: RouteSegment,
        route_segment_back: RouteSegment,
        cryptde: &dyn CryptDE, // Must be the CryptDE of the originating Node: used to encrypt return_route_id.
        consuming_wallet: Option<Wallet>,
        return_route_id: u32,
    ) -> Result<Route, String> {
        Self::construct(
            route_segment_over,
            Some(route_segment_back),
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

    pub fn to_string(&self, cryptdes: Vec<&CryptDE>) -> String {
        let item_count = min(cryptdes.len(), self.hops.len());
        if item_count == 0 {
            return String::from("\n");
        }
        let mut most_hops_enc: Vec<CryptData> =
            self.hops[0..item_count].iter().map(|x| x.clone()).collect();
        let mut most_cryptdes: Vec<&CryptDE> = cryptdes[0..item_count].to_vec();
        let last_hop_enc = most_hops_enc.remove(item_count - 1);
        let last_cryptde = most_cryptdes.remove(item_count - 1);
        let most_strings = (0..(item_count - 1))
            .into_iter()
            .fold(String::new(), |sofar, index| {
                let hop_enc = &most_hops_enc[index];
                let cryptde = most_cryptdes[index];
                let live_hop_str = match decodex::<LiveHop>(cryptde, hop_enc) {
                    Ok(live_hop) => {
                        format!("Encrypted with {}: {:?}", cryptde.public_key(), live_hop)
                    }
                    Err(e) => format!("Error: {}", e),
                };
                format!("{}\n{}", sofar, live_hop_str)
            });
        match decodex::<LiveHop>(last_cryptde, &last_hop_enc) {
            Ok(live_hop) => format!(
                "{}\nEncrypted with {}: {:?}\n",
                most_strings,
                last_cryptde.public_key(),
                live_hop
            ),
            Err(outside) => match decodex::<u32>(last_cryptde, &last_hop_enc) {
                Ok(return_route_id) => format!(
                    "{}\nEncrypted with {}: Return Route ID: {}\n",
                    most_strings,
                    last_cryptde.public_key(),
                    return_route_id
                ),
                Err(inside) => format!("{}\nError: {:?} / {}", most_strings, outside, inside),
            },
        }
    }

    fn construct(
        over: RouteSegment,
        back: Option<RouteSegment>,
        cryptde: &dyn CryptDE,
        consuming_wallet: Option<Wallet>,
        return_route_id_opt: Option<u32>,
    ) -> Result<Route, String> {
        if let Some(error) = Route::validate_route_segments(&over, &back) {
            return Err(format!("{:?}", error));
        }
        let over_component = over.recipient;
        let over_keys = over.keys.iter().skip(1);

        let mut hops = Route::over_segment(
            back.is_none(),
            consuming_wallet.clone(),
            over_keys,
            over_component,
        );

        Route::back_segment(&back, consuming_wallet.clone(), over_component, &mut hops);

        Route::hops_to_route(
            hops[0..].to_vec(),
            &over.keys[0],
            return_route_id_opt,
            cryptde,
        )
    }

    fn over_segment<'a>(
        one_way: bool,
        consuming_wallet: Option<Wallet>,
        over_keys: impl Iterator<Item = &'a PublicKey>,
        over_component: Component,
    ) -> Vec<LiveHop> {
        let mut hops: Vec<LiveHop> = over_keys
            .map(|key| LiveHop::new(key, consuming_wallet.clone(), Component::Hopper))
            .collect();
        if one_way {
            hops.push(LiveHop::new(
                &PublicKey::new(b""),
                consuming_wallet.clone(),
                over_component,
            ));
        };
        hops
    }

    fn back_segment(
        back_option: &Option<RouteSegment>,
        consuming_wallet: Option<Wallet>,
        over_component: Component,
        hops: &mut Vec<LiveHop>,
    ) {
        if let Some(back) = back_option {
            let back_component = back.recipient;
            let back_keys: Vec<&PublicKey> = back.keys.iter().skip(1).collect();
            for (key_index, key) in back_keys.iter().enumerate() {
                let component = if key_index == 0 {
                    over_component
                } else {
                    Component::Hopper
                };

                hops.push(LiveHop::new(key, consuming_wallet.clone(), component))
            }

            hops.push(LiveHop::new(
                &PublicKey::new(b""),
                consuming_wallet.clone(),
                back_component,
            ));
        }
    }

    fn validate_route_segments(
        over: &RouteSegment,
        back: &Option<RouteSegment>,
    ) -> Option<RouteError> {
        if over.keys.is_empty() {
            return Some(RouteError::TooFewKeysInRouteSegment);
        }

        if let Some(b) = back {
            if b.keys.is_empty() {
                return Some(RouteError::TooFewKeysInRouteSegment);
            }
            let over_segment_last_key = &over.keys[over.keys.len() - 1];
            let back_segment_first_key = &b.keys[0];
            if back_segment_first_key != over_segment_last_key {
                return Some(RouteError::DisjointRouteSegments);
            }
        };
        None
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
    ) -> Result<Route, String> {
        let mut hops_enc: Vec<CryptData> = Vec::new();
        let mut hop_key = top_hop_key;
        for hop_index in 0..hops.len() {
            let data_hop = &hops[hop_index];
            // crashpoint - should not be possible, can this be restructured to remove Option?
            hops_enc.push(match data_hop.encode(hop_key, cryptde) {
                Ok(crypt_data) => crypt_data,
                Err(e) => return Err(format!("Couldn't encode hop: {}", e)),
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
    TooFewKeysInRouteSegment,
    DisjointRouteSegments,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde_null::CryptDENull;
    use crate::test_utils::test_utils::make_wallet;
    use serde_cbor;

    #[test]
    fn id_decodes_return_route_id() {
        let cryptde = CryptDENull::new();

        let subject = Route {
            hops: vec![Route::encrypt_return_route_id(42, &cryptde)],
        };

        assert_eq!(subject.id(&cryptde), Ok(42));
    }

    #[test]
    fn id_returns_empty_route_error_when_the_route_is_empty() {
        let cryptde = CryptDENull::new();

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
        let consuming_wallet = make_wallet("wallet");
        let result = Route::one_way(
            RouteSegment::new(vec![], Component::ProxyClient),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .err()
        .unwrap();

        assert_eq!(String::from("TooFewKeysInRouteSegment"), result)
    }

    #[test]
    fn construct_does_not_like_route_segments_that_start_where_the_previous_segment_didnt_end() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");

        let result = Route::round_trip(
            RouteSegment::new(vec![&a_key, &b_key], Component::ProxyClient),
            RouteSegment::new(vec![&c_key, &d_key], Component::ProxyServer),
            &cryptde,
            Some(consuming_wallet.clone()),
            0,
        )
        .err()
        .unwrap();

        assert_eq!(String::from("DisjointRouteSegments"), result)
    }

    #[test]
    fn construct_can_make_single_hop_route() {
        let target_key = PublicKey::new(&[65, 65, 65]);
        let cryptde = CryptDENull::new();

        let subject = Route::single_hop(&target_key, &cryptde).unwrap();

        assert_eq!(
            LiveHop::new(&target_key, None, Component::Hopper)
                .encode(&cryptde.public_key(), &cryptde)
                .unwrap(),
            subject.hops[0]
        );
        assert_eq!(
            LiveHop::new(&PublicKey::new(b""), None, Component::Neighborhood)
                .encode(&target_key, &cryptde)
                .unwrap(),
            subject.hops[1]
        );
        assert_eq!(2, subject.hops.len());
    }

    #[test]
    fn construct_can_make_long_multistop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let e_key = PublicKey::new(&[69, 69, 69]);
        let f_key = PublicKey::new(&[70, 70, 70]);

        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");
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
            LiveHop::new(&b_key, Some(consuming_wallet.clone()), Component::Hopper)
                .encode(&a_key, &cryptde)
                .unwrap(),
            subject.hops[0],
            "first hop"
        );

        assert_eq!(
            LiveHop::new(&c_key, Some(consuming_wallet.clone()), Component::Hopper)
                .encode(&b_key, &cryptde)
                .unwrap(),
            subject.hops[1],
            "second hop"
        );

        assert_eq!(
            LiveHop::new(&d_key, Some(consuming_wallet.clone()), Component::Hopper)
                .encode(&c_key, &cryptde)
                .unwrap(),
            subject.hops[2],
            "third hop"
        );

        assert_eq!(
            LiveHop::new(
                &e_key,
                Some(consuming_wallet.clone()),
                Component::ProxyClient
            )
            .encode(&d_key, &cryptde)
            .unwrap(),
            subject.hops[3],
            "fourth hop"
        );

        assert_eq!(
            LiveHop::new(&f_key, Some(consuming_wallet.clone()), Component::Hopper)
                .encode(&e_key, &cryptde)
                .unwrap(),
            subject.hops[4],
            "fifth hop"
        );

        assert_eq!(
            LiveHop::new(&a_key, Some(consuming_wallet.clone()), Component::Hopper)
                .encode(&f_key, &cryptde)
                .unwrap(),
            subject.hops[5],
            "sixth hop"
        );

        assert_eq!(
            LiveHop::new(
                &PublicKey::new(b""),
                Some(consuming_wallet.clone()),
                Component::ProxyServer,
            )
            .encode(&a_key, &cryptde)
            .unwrap(),
            subject.hops[6],
            "seventh hop"
        );

        assert_eq!(
            Route::encrypt_return_route_id(return_route_id, &cryptde),
            subject.hops[7],
            "eighth hop"
        );
    }

    #[test]
    fn construct_can_make_short_single_stop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");

        let subject = Route::one_way(
            RouteSegment::new(vec![&a_key, &b_key], Component::Neighborhood),
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();

        assert_eq!(
            vec!(
                LiveHop::new(&b_key, Some(consuming_wallet.clone()), Component::Hopper)
                    .encode(&a_key, &cryptde)
                    .unwrap(),
                LiveHop::new(
                    &PublicKey::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood,
                )
                .encode(&b_key, &cryptde)
                .unwrap(),
            ),
            subject.hops,
        );
    }

    #[test]
    fn next_hop_decodes_top_hop() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");
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
                    Component::Neighborhood,
                )
                .encode(&key56, &cryptde)
                .unwrap(),
            )
        );
    }

    #[test]
    fn shift_returns_next_hop_and_adds_garbage_at_the_bottom() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");
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
                    Component::Neighborhood,
                )
                .encode(&key56, &cryptde)
                .unwrap(),
                CryptData::new(&garbage_can[..])
            )
        )
    }

    #[test]
    fn empty_route_says_none_when_asked_for_next_hop() {
        let cryptde = CryptDENull::new();
        let subject = Route { hops: Vec::new() };

        let result = subject.next_hop(&cryptde).err().unwrap();

        assert_eq!(result, RouteError::EmptyRoute);
    }

    #[test]
    fn shift_says_none_when_asked_for_next_hop_on_empty_route() {
        let cryptde = CryptDENull::new();
        let mut subject = Route { hops: Vec::new() };

        let result = subject.shift(&cryptde).err().unwrap();

        assert_eq!(result, RouteError::EmptyRoute);
    }

    #[test]
    fn route_serialization_deserialization() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[4, 3, 2, 1]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = make_wallet("wallet");
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

    #[test]
    fn to_string_works_with_one_way_route() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[2, 3, 4, 5]);
        let key3 = PublicKey::new(&[3, 4, 5, 6]);
        let consuming_wallet = Wallet::new("wallet");
        let subject = Route::one_way(
            RouteSegment::new(vec![&key1, &key2, &key3], Component::Neighborhood),
            &CryptDENull::new(),
            Some(consuming_wallet),
        )
        .unwrap();

        let result = subject.to_string(vec![
            &CryptDENull::from(&key1),
            &CryptDENull::from(&key2),
            &CryptDENull::from(&key3),
        ]);

        assert_eq!(result, String::from("
Encrypted with AQIDBA: LiveHop { public_key: AgMEBQ, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Hopper }
Encrypted with AgMEBQ: LiveHop { public_key: AwQFBg, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Hopper }
Encrypted with AwQFBg: LiveHop { public_key: , consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Neighborhood }
"));
    }

    #[test]
    fn to_string_works_with_round_trip_route() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[2, 3, 4, 5]);
        let key3 = PublicKey::new(&[3, 4, 5, 6]);
        let consuming_wallet = Wallet::new("wallet");
        let subject = Route::round_trip(
            RouteSegment::new(vec![&key1, &key2, &key3], Component::ProxyClient),
            RouteSegment::new(vec![&key3, &key2, &key1], Component::ProxyServer),
            &CryptDENull::from(&key1),
            Some(consuming_wallet),
            1234,
        )
        .unwrap();

        let result = subject.to_string(vec![
            &CryptDENull::from(&key1),
            &CryptDENull::from(&key2),
            &CryptDENull::from(&key3),
            &CryptDENull::from(&key2),
            &CryptDENull::from(&key1),
            &CryptDENull::from(&key1),
        ]);

        assert_eq!(result, String::from("
Encrypted with AQIDBA: LiveHop { public_key: AgMEBQ, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Hopper }
Encrypted with AgMEBQ: LiveHop { public_key: AwQFBg, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Hopper }
Encrypted with AwQFBg: LiveHop { public_key: AgMEBQ, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: ProxyClient }
Encrypted with AgMEBQ: LiveHop { public_key: AQIDBA, consuming_wallet: Some(Wallet { kind: Uninitialized }), component: Hopper }
Encrypted with AQIDBA: LiveHop { public_key: , consuming_wallet: Some(Wallet { kind: Uninitialized }), component: ProxyServer }
Encrypted with AQIDBA: Return Route ID: 1234
"));
    }

    #[test]
    fn to_string_works_with_zero_length_data() {
        let subject = Route { hops: vec![] };

        let result = subject.to_string(vec![]);

        assert_eq!(result, String::from("\n"));
    }
}
