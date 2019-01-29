// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use cryptde::CryptDE;
use cryptde::CryptData;
use cryptde::CryptdecError;
use cryptde::Key;
use dispatcher::Component;
use hop::LiveHop;
use std::iter;
use wallet::Wallet;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Route {
    pub hops: Vec<CryptData>,
}

impl Route {
    pub fn new(
        route_segments: Vec<RouteSegment>,
        cryptde: &CryptDE, // Any CryptDE can go here; it's only used to encrypt to public keys.
        consuming_wallet: Option<Wallet>,
    ) -> Result<Route, RouteError> {
        if route_segments.is_empty() {
            return Err(RouteError::NoRouteSegments);
        }
        let mut hops: Vec<LiveHop> = Vec::new();
        let mut pending_recipient: Option<Component> = None;
        for segment_index in 0..route_segments.len() {
            let route_segment = &route_segments[segment_index];
            // TODO each route segment must have at least 2 keys, unless we keep Zero-Hop Routes
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
        // crashpoint - should not be possible, can we restructure to remove the Option?
        hops.push(LiveHop::new(
            &Key::new(b""),
            consuming_wallet,
            pending_recipient.expect("Route segment without recipient"),
        ));
        Route::hops_to_route(hops[1..].to_vec(), &route_segments[0].keys[0], cryptde)
    }

    // This cryptde must be the CryptDE of the next hop to come off the Route.
    pub fn next_hop(&self, cryptde: &CryptDE) -> Result<LiveHop, RouteError> {
        match self.hops.first() {
            None => Err(RouteError::EmptyRoute),
            Some(first) => Route::decode_hop(cryptde, &first.clone()),
        }
    }

    pub fn shift(&mut self, cryptde: &CryptDE) -> Result<LiveHop, RouteError> {
        if self.hops.is_empty() {
            return Err(RouteError::EmptyRoute);
        }
        let top_hop = self.hops.remove(0);
        let top_hop_len = top_hop.data.len();
        let next_hop = Route::decode_hop(cryptde, &top_hop)?;

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        self.hops.push(CryptData::new(&garbage_can[..]));

        return Ok(next_hop);
    }

    fn decode_hop(cryptde: &CryptDE, hop_enc: &CryptData) -> Result<LiveHop, RouteError> {
        match LiveHop::decode(cryptde, hop_enc) {
            Err(e) => Err(RouteError::HopDecodeProblem(e)),
            Ok(h) => Ok(h),
        }
    }

    fn hops_to_route(
        hops: Vec<LiveHop>,
        top_hop_key: &Key,
        cryptde: &CryptDE,
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
        Ok(Route { hops: hops_enc })
    }
}

#[derive(Debug)]
pub struct RouteSegment {
    pub keys: Vec<Key>,
    pub recipient: Component,
}

impl RouteSegment {
    pub fn new(keys: Vec<&Key>, recipient: Component) -> RouteSegment {
        RouteSegment {
            keys: keys.iter().map(|k| (*k).clone()).collect(),
            recipient,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RouteError {
    HopDecodeProblem(CryptdecError),
    EmptyRoute,
    NoRouteSegments,
    TooFewKeysInRouteSegment,
    DisjointRouteSegments,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde_null::CryptDENull;
    use serde_cbor;

    #[test]
    fn new_does_not_like_empty_segment_lists() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let result = Route::new(vec![], &cryptde, Some(consuming_wallet.clone()))
            .err()
            .unwrap();

        assert_eq!(result, RouteError::NoRouteSegments)
    }

    #[test]
    fn new_does_not_like_route_segments_with_too_few_keys() {
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let result = Route::new(
            vec![RouteSegment::new(vec![], Component::ProxyClient)],
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .err()
        .unwrap();

        assert_eq!(result, RouteError::TooFewKeysInRouteSegment)
    }

    #[test]
    fn new_does_not_like_route_segments_that_start_where_the_previous_segment_didnt_end() {
        let a_key = Key::new(&[65, 65, 65]);
        let b_key = Key::new(&[66, 66, 66]);
        let c_key = Key::new(&[67, 67, 67]);
        let d_key = Key::new(&[68, 68, 68]);
        let mut cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        cryptde.generate_key_pair();

        let result = Route::new(
            vec![
                RouteSegment::new(vec![&a_key, &b_key], Component::ProxyClient),
                RouteSegment::new(vec![&c_key, &d_key], Component::ProxyServer),
            ],
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .err()
        .unwrap();

        assert_eq!(result, RouteError::DisjointRouteSegments)
    }

    #[test]
    fn new_can_make_long_multistop_route() {
        let a_key = Key::new(&[65, 65, 65]);
        let b_key = Key::new(&[66, 66, 66]);
        let c_key = Key::new(&[67, 67, 67]);
        let d_key = Key::new(&[68, 68, 68]);
        let e_key = Key::new(&[69, 69, 69]);
        let f_key = Key::new(&[70, 70, 70]);
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");

        let subject = Route::new(
            vec![
                RouteSegment::new(vec![&a_key, &b_key, &c_key, &d_key], Component::ProxyClient),
                RouteSegment::new(vec![&d_key, &e_key, &f_key, &a_key], Component::ProxyServer),
            ],
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
                    &Key::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::ProxyServer
                )
                .encode(&a_key, &cryptde)
                .unwrap()
            )
        );
    }

    #[test]
    fn new_can_make_short_single_stop_route() {
        let a_key = Key::new(&[65, 65, 65]);
        let b_key = Key::new(&[66, 66, 66]);
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");

        let subject = Route::new(
            vec![RouteSegment::new(
                vec![&a_key, &b_key],
                Component::Neighborhood,
            )],
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
                    &Key::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&b_key, &cryptde)
                .unwrap()
            )
        );
    }

    #[test]
    fn next_hop_decodes_top_hop() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let subject = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();
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
                    &Key::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&key56, &cryptde)
                .unwrap()
            )
        );

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
                    &Key::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&key56, &cryptde)
                .unwrap()
            )
        );
    }

    #[test]
    fn shift_returns_next_hop_and_adds_garbage_at_the_bottom() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let mut subject = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            &cryptde,
            Some(consuming_wallet.clone()),
        )
        .unwrap();
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
                    &Key::new(b""),
                    Some(consuming_wallet.clone()),
                    Component::Neighborhood
                )
                .encode(&key56, &cryptde)
                .unwrap()
            )
        );
        let top_hop_len = subject.hops.first().unwrap().data.len();

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
                    &Key::new(b""),
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
        let key1 = Key::new(&[1, 2, 3, 4]);
        let key2 = Key::new(&[4, 3, 2, 1]);
        let cryptde = CryptDENull::new();
        let consuming_wallet = Wallet::new("wallet");
        let original = Route::new(
            vec![
                RouteSegment::new(vec![&key1, &key2], Component::ProxyClient),
                RouteSegment::new(vec![&key2, &key1], Component::ProxyServer),
            ],
            &cryptde,
            Some(consuming_wallet),
        )
        .unwrap();

        let serialized = serde_cbor::ser::to_vec(&original).unwrap();

        let deserialized = serde_cbor::de::from_slice::<Route>(&serialized[..]).unwrap();

        assert_eq!(deserialized, original);
    }
}
