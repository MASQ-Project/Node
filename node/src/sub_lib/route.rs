// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::cryptde::encodex;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde::{decodex, CodexError};
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::hop::LiveHop;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::Address;
use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};
use std::cmp::min;
use std::iter;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Route {
    pub hops: Vec<CryptData>,
}

impl Route {
    pub fn single_hop(
        destination: &PublicKey,
        cryptde: &dyn CryptDE, // The CryptDE of the beginning of this Route must go here.
    ) -> Result<Route, CodexError> {
        Self::construct(
            RouteSegment::new(
                vec![cryptde.public_key(), destination],
                Component::Neighborhood,
            ),
            None,
            cryptde,
            None,
            None,
            None,
        )
    }

    pub fn one_way(
        route_segment: RouteSegment,
        cryptde: &dyn CryptDE, // Any CryptDE can go here; it's only used to encrypt to public keys.
        consuming_wallet: Option<Wallet>,
        contract_address: Option<Address>,
    ) -> Result<Route, CodexError> {
        Self::construct(
            route_segment,
            None,
            cryptde,
            consuming_wallet,
            None,
            contract_address,
        )
    }

    pub fn round_trip(
        route_segment_over: RouteSegment,
        route_segment_back: RouteSegment,
        cryptde: &dyn CryptDE, // Must be the CryptDE of the originating Node: used to encrypt return_route_id.
        consuming_wallet: Option<Wallet>,
        return_route_id: u32,
        contract_address: Option<Address>,
    ) -> Result<Route, CodexError> {
        Self::construct(
            route_segment_over,
            Some(route_segment_back),
            cryptde,
            consuming_wallet,
            Some(return_route_id),
            contract_address,
        )
    }

    pub fn id(&self, cryptde: &dyn CryptDE) -> Result<u32, String> {
        if let Some(first) = self.hops.first() {
            match decodex(cryptde, first) {
                Ok(n) => Ok(n),
                Err(e) => Err(format!("{:?}", e)),
            }
        } else {
            Err("Response route did not contain a return route ID".to_string())
        }
    }

    // This cryptde must be the CryptDE of the next hop to come off the Route.
    pub fn next_hop(&self, cryptde: &dyn CryptDE) -> Result<LiveHop, CodexError> {
        match self.hops.first() {
            None => Err(CodexError::RoutingError(RouteError::EmptyRoute)),
            Some(first) => LiveHop::decode(cryptde, &first.clone()),
        }
    }

    pub fn shift(&mut self, cryptde: &dyn CryptDE) -> Result<LiveHop, CodexError> {
        if self.hops.is_empty() {
            return Err(CodexError::RoutingError(RouteError::EmptyRoute));
        }
        let top_hop = self.hops.remove(0);
        let top_hop_len = top_hop.len();
        let next_hop = LiveHop::decode(cryptde, &top_hop)?;

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        self.hops.push(CryptData::new(&garbage_can[..]));

        Ok(next_hop)
    }

    pub fn to_string(&self, cryptdes: Vec<&dyn CryptDE>) -> String {
        let item_count = min(cryptdes.len(), self.hops.len());
        if item_count == 0 {
            return String::from("\n");
        }
        let mut most_hops_enc: Vec<CryptData> = self.hops[0..item_count].to_vec();
        let mut most_cryptdes: Vec<&dyn CryptDE> = cryptdes[0..item_count].to_vec();
        let last_hop_enc = most_hops_enc.remove(item_count - 1);
        let last_cryptde = most_cryptdes.remove(item_count - 1);
        let most_strings = (0..(item_count - 1)).fold(String::new(), |sofar, index| {
            let hop_enc = &most_hops_enc[index];
            let cryptde = most_cryptdes[index];
            let live_hop_str = match decodex::<LiveHop>(cryptde, hop_enc) {
                Ok(live_hop) => {
                    format!("Encrypted with {:?}: {:?}", cryptde.public_key(), live_hop)
                }
                Err(e) => format!("Error: {:?}", e),
            };
            format!("{}\n{}", sofar, live_hop_str)
        });
        match decodex::<LiveHop>(last_cryptde, &last_hop_enc) {
            Ok(live_hop) => format!(
                "{}\nEncrypted with {:?}: {:?}\n",
                most_strings,
                last_cryptde.public_key(),
                live_hop
            ),
            Err(outside) => match decodex::<u32>(last_cryptde, &last_hop_enc) {
                Ok(return_route_id) => format!(
                    "{}\nEncrypted with {:?}: Return Route ID: {}\n",
                    most_strings,
                    last_cryptde.public_key(),
                    return_route_id
                ),
                Err(inside) => format!("{}\nError: {:?} / {:?}", most_strings, outside, inside),
            },
        }
    }

    fn construct(
        over: RouteSegment,
        back: Option<RouteSegment>,
        cryptde: &dyn CryptDE,
        consuming_wallet: Option<Wallet>,
        return_route_id_opt: Option<u32>,
        contract_address: Option<Address>,
    ) -> Result<Route, CodexError> {
        if let Some(error) = Route::validate_route_segments(&over, &back) {
            return Err(CodexError::RoutingError(error));
        }
        let over_component = over.recipient;
        let over_keys = over.keys.iter();

        let mut hops = Route::over_segment(
            back.is_none(),
            consuming_wallet.clone(),
            over_keys,
            over_component,
            contract_address,
        );

        Route::back_segment(
            &back,
            consuming_wallet,
            over_component,
            &mut hops,
            contract_address,
        );

        Route::hops_to_route(
            hops[0..].to_vec(),
            &over.keys[0],
            return_route_id_opt,
            cryptde,
        )
    }

    fn over_segment<'a>(
        one_way: bool,
        consuming_wallet_opt: Option<Wallet>,
        over_keys: impl Iterator<Item = &'a PublicKey>,
        over_component: Component,
        contract_address_opt: Option<Address>,
    ) -> Vec<LiveHop> {
        let mut last_key: Option<PublicKey> = None;
        let mut hops: Vec<LiveHop> = over_keys
            .tuple_windows()
            .map(|(current_key, next_key)| {
                last_key = Some(next_key.clone());
                LiveHop::new(
                    next_key,
                    consuming_wallet_opt.as_ref().map(|w| {
                        w.as_payer(
                            &current_key,
                            &contract_address_opt.unwrap_or_else(Address::zero),
                        )
                    }),
                    Component::Hopper,
                )
            })
            .collect();
        if one_way {
            let key = PublicKey::new(b"");
            match last_key {
                Some(last_hop_key) => {
                    hops.push(LiveHop::new(
                        &key,
                        consuming_wallet_opt.map(|w| {
                            w.as_payer(
                                &last_hop_key,
                                &contract_address_opt.unwrap_or_else(Address::zero),
                            )
                        }),
                        over_component,
                    ));
                }
                None => hops.push(LiveHop::new(&key, None, over_component)),
            }
        };
        hops
    }

    fn back_segment(
        back_option: &Option<RouteSegment>,
        consuming_wallet: Option<Wallet>,
        over_component: Component,
        hops: &mut Vec<LiveHop>,
        contract_address: Option<Address>,
    ) {
        if let Some(back) = back_option {
            let back_component = back.recipient;
            let back_keys: Vec<&PublicKey> = back.keys.iter().collect();
            for (key_index, (current_key, next_key)) in back_keys.iter().tuple_windows().enumerate()
            {
                let component = if key_index == 0 {
                    over_component
                } else {
                    Component::Hopper
                };

                hops.push(LiveHop::new(
                    next_key,
                    consuming_wallet.clone().map(|w| {
                        w.as_payer(
                            &current_key,
                            &contract_address.unwrap_or_else(Address::zero),
                        )
                    }),
                    component,
                ))
            }
            let next_key = PublicKey::new(b"");
            match back_keys.last() {
                Some(current_key) => {
                    hops.push(LiveHop::new(
                        &next_key,
                        consuming_wallet.map(|w| {
                            w.as_payer(current_key, &contract_address.unwrap_or_else(Address::zero))
                        }),
                        back_component,
                    ));
                }
                None => hops.push(LiveHop::new(&next_key, None, back_component)),
            }
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

    fn hops_to_route(
        hops: Vec<LiveHop>,
        top_hop_key: &PublicKey,
        return_route_id_opt: Option<u32>,
        cryptde: &dyn CryptDE,
    ) -> Result<Route, CodexError> {
        let mut hops_enc: Vec<CryptData> = Vec::new();
        let mut hop_key = top_hop_key;
        for data_hop in &hops {
            hops_enc.push(match data_hop.encode(hop_key, cryptde) {
                Ok(crypt_data) => crypt_data,
                Err(e) => return Err(e),
            });
            hop_key = &data_hop.public_key;
        }
        if let Some(return_route_id) = return_route_id_opt {
            let return_route_id_enc = Self::encrypt_return_route_id(return_route_id, cryptde);
            hops_enc.push(return_route_id_enc);
        }
        Ok(Route { hops: hops_enc })
    }

    fn encrypt_return_route_id(return_route_id: u32, cryptde: &dyn CryptDE) -> CryptData {
        encodex(cryptde, cryptde.public_key(), &return_route_id)
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

#[derive(Debug, PartialEq, Eq)]
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
    use crate::test_utils::make_wallet;
    use crate::test_utils::{main_cryptde, make_paying_wallet};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use serde_cbor;

    #[test]
    fn id_decodes_return_route_id() {
        let cryptde = main_cryptde();

        let subject = Route {
            hops: vec![Route::encrypt_return_route_id(42, cryptde)],
        };

        assert_eq!(subject.id(cryptde), Ok(42));
    }

    #[test]
    fn id_returns_empty_route_error_when_the_route_is_empty() {
        let cryptde = main_cryptde();

        let subject = Route { hops: vec![] };

        assert_eq!(
            subject.id(cryptde),
            Err("Response route did not contain a return route ID".to_string())
        );
    }

    #[test]
    #[should_panic(expected = "Could not decrypt with ebe5f9a0e2 data beginning with ebe5f9a0e1")]
    fn id_returns_error_when_the_id_fails_to_decrypt() {
        let cryptde1 = CryptDENull::from(&PublicKey::new(b"key a"), TEST_DEFAULT_CHAIN);
        let cryptde2 = CryptDENull::from(&PublicKey::new(b"key b"), TEST_DEFAULT_CHAIN);
        let subject = Route {
            hops: vec![Route::encrypt_return_route_id(42, &cryptde1)],
        };

        let _ = subject.id(&cryptde2);
    }

    #[test]
    fn construct_does_not_like_route_segments_with_too_few_keys() {
        let cryptde = main_cryptde();
        let paying_wallet = make_wallet("wallet");
        let result = Route::one_way(
            RouteSegment::new(vec![], Component::ProxyClient),
            cryptde,
            Some(paying_wallet.clone()),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .err()
        .unwrap();

        assert_eq!(
            result,
            CodexError::RoutingError(RouteError::TooFewKeysInRouteSegment)
        );
    }

    #[test]
    fn construct_does_not_like_route_segments_that_start_where_the_previous_segment_didnt_end() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");

        let result = Route::round_trip(
            RouteSegment::new(vec![&a_key, &b_key], Component::ProxyClient),
            RouteSegment::new(vec![&c_key, &d_key], Component::ProxyServer),
            cryptde,
            Some(paying_wallet.clone()),
            0,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .err()
        .unwrap();

        assert_eq!(
            result,
            CodexError::RoutingError(RouteError::DisjointRouteSegments)
        );
    }

    #[test]
    fn construct_can_make_single_hop_route() {
        let target_key = PublicKey::new(&[65, 65, 65]);
        let cryptde = main_cryptde();

        let subject = Route::single_hop(&target_key, cryptde).unwrap();

        assert_eq!(2, subject.hops.len());
        assert_eq!(
            subject.hops[0],
            LiveHop::new(&target_key, None, Component::Hopper)
                .encode(&cryptde.public_key(), cryptde)
                .unwrap()
        );
        assert_eq!(
            subject.hops[1],
            LiveHop::new(&PublicKey::new(b""), None, Component::Neighborhood)
                .encode(&target_key, cryptde)
                .unwrap()
        );
    }

    #[test]
    fn construct_can_make_long_multistop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let c_key = PublicKey::new(&[67, 67, 67]);
        let d_key = PublicKey::new(&[68, 68, 68]);
        let e_key = PublicKey::new(&[69, 69, 69]);
        let f_key = PublicKey::new(&[70, 70, 70]);
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let return_route_id = 4321;
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;

        let subject = Route::round_trip(
            RouteSegment::new(vec![&a_key, &b_key, &c_key, &d_key], Component::ProxyClient),
            RouteSegment::new(vec![&d_key, &e_key, &f_key, &a_key], Component::ProxyServer),
            cryptde,
            Some(paying_wallet.clone()),
            return_route_id,
            Some(contract_address.clone()),
        )
        .unwrap();

        assert_eq!(
            subject.hops[0],
            LiveHop::new(
                &b_key,
                Some(paying_wallet.as_payer(&a_key, &contract_address)),
                Component::Hopper
            )
            .encode(&a_key, cryptde)
            .unwrap(),
            "first hop"
        );

        assert_eq!(
            subject.hops[1],
            LiveHop::new(
                &c_key,
                Some(paying_wallet.as_payer(&b_key, &contract_address)),
                Component::Hopper
            )
            .encode(&b_key, cryptde)
            .unwrap(),
            "second hop"
        );

        assert_eq!(
            subject.hops[2],
            LiveHop::new(
                &d_key,
                Some(paying_wallet.as_payer(&c_key, &contract_address)),
                Component::Hopper
            )
            .encode(&c_key, cryptde)
            .unwrap(),
            "third hop"
        );

        assert_eq!(
            subject.hops[3],
            LiveHop::new(
                &e_key,
                Some(paying_wallet.as_payer(&d_key, &contract_address)),
                Component::ProxyClient
            )
            .encode(&d_key, cryptde)
            .unwrap(),
            "fourth hop"
        );

        assert_eq!(
            subject.hops[4],
            LiveHop::new(
                &f_key,
                Some(paying_wallet.as_payer(&e_key, &contract_address)),
                Component::Hopper
            )
            .encode(&e_key, cryptde)
            .unwrap(),
            "fifth hop"
        );

        assert_eq!(
            subject.hops[5],
            LiveHop::new(
                &a_key,
                Some(paying_wallet.as_payer(&f_key, &contract_address)),
                Component::Hopper
            )
            .encode(&f_key, cryptde)
            .unwrap(),
            "sixth hop"
        );

        let empty_public_key = PublicKey::new(b"");
        assert_eq!(
            subject.hops[6],
            LiveHop::new(
                &empty_public_key,
                Some(paying_wallet.as_payer(&a_key, &contract_address)),
                Component::ProxyServer,
            )
            .encode(&a_key, cryptde)
            .unwrap(),
            "seventh hop"
        );

        assert_eq!(
            subject.hops[7],
            Route::encrypt_return_route_id(return_route_id, cryptde),
            "eighth hop"
        );
    }

    #[test]
    fn construct_can_make_short_single_stop_route() {
        let a_key = PublicKey::new(&[65, 65, 65]);
        let b_key = PublicKey::new(&[66, 66, 66]);
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;

        let subject = Route::one_way(
            RouteSegment::new(vec![&a_key, &b_key], Component::Neighborhood),
            cryptde,
            Some(paying_wallet.clone()),
            Some(contract_address.clone()),
        )
        .unwrap();
        let empty_public_key = PublicKey::new(b"");

        assert_eq!(
            vec!(
                LiveHop::new(
                    &b_key,
                    Some(paying_wallet.as_payer(&a_key, &contract_address)),
                    Component::Hopper
                )
                .encode(&a_key, cryptde)
                .unwrap(),
                LiveHop::new(
                    &empty_public_key,
                    Some(paying_wallet.as_payer(&b_key, &contract_address)),
                    Component::Neighborhood,
                )
                .encode(&b_key, cryptde)
                .unwrap(),
            ),
            subject.hops,
        );
    }

    #[test]
    fn next_hop_decodes_top_hop() {
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let subject = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::Neighborhood),
            cryptde,
            Some(paying_wallet.clone()),
            Some(contract_address),
        )
        .unwrap();

        let next_hop = subject.next_hop(cryptde).unwrap();

        assert_eq!(
            next_hop,
            LiveHop::new(
                &key34,
                Some(paying_wallet.as_payer(&key12, &contract_address)),
                Component::Hopper
            )
        );
        let empty_public_key = PublicKey::new(b"");
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(
                    &key34,
                    Some(paying_wallet.as_payer(&key12, &contract_address)),
                    Component::Hopper
                )
                .encode(&key12, cryptde)
                .unwrap(),
                LiveHop::new(
                    &key56,
                    Some(paying_wallet.as_payer(&key34, &contract_address)),
                    Component::Hopper
                )
                .encode(&key34, cryptde)
                .unwrap(),
                LiveHop::new(
                    &empty_public_key,
                    Some(paying_wallet.as_payer(&key56, &contract_address)),
                    Component::Neighborhood,
                )
                .encode(&key56, cryptde)
                .unwrap(),
            )
        );
    }

    #[test]
    fn shift_returns_next_hop_and_adds_garbage_at_the_bottom() {
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let key12 = cryptde.public_key();
        let key34 = PublicKey::new(&[3, 4]);
        let key56 = PublicKey::new(&[5, 6]);
        let contract_address = TEST_DEFAULT_CHAIN.rec().contract;
        let mut subject = Route::one_way(
            RouteSegment::new(vec![&key12, &key34, &key56], Component::Neighborhood),
            cryptde,
            Some(paying_wallet.clone()),
            Some(contract_address),
        )
        .unwrap();
        let top_hop_len = subject.hops.first().unwrap().len();

        let next_hop = subject.shift(cryptde).unwrap();

        assert_eq!(
            next_hop,
            LiveHop::new(
                &key34,
                Some(paying_wallet.as_payer(&key12, &contract_address)),
                Component::Hopper
            )
        );
        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        let empty_public_key = PublicKey::new(b"");
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(
                    &key56,
                    Some(paying_wallet.as_payer(&key34, &contract_address)),
                    Component::Hopper
                )
                .encode(&key34, cryptde)
                .unwrap(),
                LiveHop::new(
                    &empty_public_key,
                    Some(paying_wallet.as_payer(&key56, &contract_address)),
                    Component::Neighborhood,
                )
                .encode(&key56, cryptde)
                .unwrap(),
                CryptData::new(&garbage_can[..])
            )
        )
    }

    #[test]
    fn empty_route_says_none_when_asked_for_next_hop() {
        let cryptde = main_cryptde();
        let subject = Route { hops: Vec::new() };

        let result = subject.next_hop(cryptde).err().unwrap();

        assert_eq!(result, CodexError::RoutingError(RouteError::EmptyRoute));
    }

    #[test]
    fn shift_says_none_when_asked_for_next_hop_on_empty_route() {
        let cryptde = main_cryptde();
        let mut subject = Route { hops: Vec::new() };

        let result = subject.shift(cryptde).err().unwrap();

        assert_eq!(result, CodexError::RoutingError(RouteError::EmptyRoute));
    }

    #[test]
    fn route_serialization_deserialization() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[4, 3, 2, 1]);
        let cryptde = main_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let original = Route::round_trip(
            RouteSegment::new(vec![&key1, &key2], Component::ProxyClient),
            RouteSegment::new(vec![&key2, &key1], Component::ProxyServer),
            cryptde,
            Some(paying_wallet),
            1234,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
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
        let paying_wallet = make_paying_wallet(b"wallet");
        let subject = Route::one_way(
            RouteSegment::new(vec![&key1, &key2, &key3], Component::Neighborhood),
            main_cryptde(),
            Some(paying_wallet),
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();

        let result = subject.to_string(vec![
            &CryptDENull::from(&key1, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key2, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key3, TEST_DEFAULT_CHAIN),
        ]);

        assert_eq!(
            result,
            String::from(
                r#"
Encrypted with 0x01020304: LiveHop { public_key: 0x02030405, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d", s: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d" } }), component: Hopper }
Encrypted with 0x02030405: LiveHop { public_key: 0x03040506, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a", s: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a" } }), component: Hopper }
Encrypted with 0x03040506: LiveHop { public_key: 0x, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 1, r: "8649b8f6db6232cb1e4f1f04786ad4ef33488c968e64bec74ecd893d6d05c1b9", s: "8649b8f6db6232cb1e4f1f04786ad4ef33488c968e64bec74ecd893d6d05c1b9" } }), component: Neighborhood }
"#
            )
        );
    }

    #[test]
    fn to_string_works_with_round_trip_route() {
        let key1 = PublicKey::new(&[1, 2, 3, 4]);
        let key2 = PublicKey::new(&[2, 3, 4, 5]);
        let key3 = PublicKey::new(&[3, 4, 5, 6]);
        let paying_wallet = make_paying_wallet(b"wallet");
        let subject = Route::round_trip(
            RouteSegment::new(vec![&key1, &key2, &key3], Component::ProxyClient),
            RouteSegment::new(vec![&key3, &key2, &key1], Component::ProxyServer),
            &CryptDENull::from(&key1, TEST_DEFAULT_CHAIN),
            Some(paying_wallet),
            1234,
            Some(TEST_DEFAULT_CHAIN.rec().contract),
        )
        .unwrap();

        let result = subject.to_string(vec![
            &CryptDENull::from(&key1, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key2, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key3, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key2, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key1, TEST_DEFAULT_CHAIN),
            &CryptDENull::from(&key1, TEST_DEFAULT_CHAIN),
        ]);

        assert_eq!(
            result,
            String::from(
                r#"
Encrypted with 0x01020304: LiveHop { public_key: 0x02030405, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d", s: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d" } }), component: Hopper }
Encrypted with 0x02030405: LiveHop { public_key: 0x03040506, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a", s: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a" } }), component: Hopper }
Encrypted with 0x03040506: LiveHop { public_key: 0x02030405, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 1, r: "8649b8f6db6232cb1e4f1f04786ad4ef33488c968e64bec74ecd893d6d05c1b9", s: "8649b8f6db6232cb1e4f1f04786ad4ef33488c968e64bec74ecd893d6d05c1b9" } }), component: ProxyClient }
Encrypted with 0x02030405: LiveHop { public_key: 0x01020304, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a", s: "4324a40295bb36ef2b927fb24250fe42397a57b861ea152bbbe4f84150d4ff5a" } }), component: Hopper }
Encrypted with 0x01020304: LiveHop { public_key: 0x, payer: Some(Payer { wallet: Wallet { kind: Address(0x71d0fc7d1c570b1ed786382b551a09391c91e33d) }, proof: Signature { v: 0, r: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d", s: "3e3a92d7284c2c2ff7119e9f7a7e183b062a335a598e965a47c36a2f288b6f8d" } }), component: ProxyServer }
Encrypted with 0x01020304: Return Route ID: 1234
"#
            )
        );
    }

    #[test]
    fn to_string_works_with_zero_length_data() {
        let subject = Route { hops: vec![] };

        let result = subject.to_string(vec![]);

        assert_eq!(result, String::from("\n"));
    }
}
