// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use cryptde::CryptDE;
use cryptde::CryptData;
use cryptde::Key;
use dispatcher::Component;
use hop::Hop;
use std::iter;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Route {
    pub hops: Vec<CryptData>,
}

impl Route {
    // TODO: Drive out panic!s.
    pub fn new(route_segments: Vec<RouteSegment>, cryptde: &CryptDE) -> Result<Route, RouteError> {
        // crashpoint - send back a RouteError
        if route_segments.is_empty() {
            panic!("A route must have at least one segment")
        }
        let mut hops: Vec<Hop> = Vec::new();
        let mut pending_recipient: Option<Component> = None;
        for segment_index in 0..route_segments.len() {
            let route_segment = &route_segments[segment_index];
            // crashpoint - send back a RouteError
            // TODO each route segment must have at least 2 keys
            if route_segment.keys.len() < 1 {
                panic!(
                    "Degenerate {}-element route segment",
                    route_segment.keys.len()
                )
            }
            for hop_index in 0..route_segment.keys.len() {
                let key = &route_segment.keys[hop_index];
                if (segment_index > 0) && (hop_index == 0) {
                    let last_segment = &route_segments[segment_index - 1];
                    let last_segment_last_key = &last_segment.keys[last_segment.keys.len() - 1];
                    // crashpoint - send back a RouteError
                    if key != last_segment_last_key {
                        panic!(
                            "Route segment {} ({:?}) must begin where segment {} ({:?}) left off",
                            segment_index,
                            route_segment,
                            segment_index - 1,
                            last_segment
                        )
                    }
                    continue;
                }
                hops.push(match pending_recipient {
                    Some(recipient) => Hop::new(key, recipient),
                    None => Hop::new(key, Component::Hopper),
                });
                pending_recipient = None;
                if (hop_index + 1) == route_segment.keys.len() {
                    pending_recipient = Some(route_segment.recipient);
                }
            }
        }
        // crashpoint - should not be possible, can we restructure to remove the Option?
        hops.push(Hop::new(
            &Key::new(b""),
            pending_recipient.expect("Route segment without recipient"),
        ));
        Route::hops_to_route(hops[1..].to_vec(), &route_segments[0].keys[0], cryptde)
    }

    // TODO: We should probably either have access to a Logger here, or return a Result instead of an Option.
    pub fn next_hop(&self, cryptde: &CryptDE) -> Option<Hop> {
        match self.hops.first() {
            None => None,
            Some(first) => Route::decode_hop(cryptde, &first.clone()),
        }
    }

    // TODO: We should probably either have access to a Logger here, or return a Result instead of an Option.
    pub fn shift(&mut self, cryptde: &CryptDE) -> Option<Hop> {
        if self.hops.is_empty() {
            return None;
        }
        let top_hop = self.hops.remove(0);
        let top_hop_len = top_hop.data.len();
        let next_hop = match Route::decode_hop(cryptde, &top_hop) {
            None => return None,
            Some(h) => h,
        };

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        self.hops.push(CryptData::new(&garbage_can[..]));

        return Some(next_hop);
    }

    // TODO: We should probably either have access to a Logger here, or return a Result instead of an Option.
    fn decode_hop(cryptde: &CryptDE, hop_enc: &CryptData) -> Option<Hop> {
        match Hop::decode(cryptde, hop_enc) {
            Err(_) => None,
            Ok(h) => Some(h),
        }
    }

    fn hops_to_route(
        hops: Vec<Hop>,
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

#[derive(Debug)]
pub enum RouteError {
    GenericRouteError, // TODO: replace this when we drive out the panic!s
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde_null::CryptDENull;
    use serde_cbor;

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

        let subject = Route::new(
            vec![
                RouteSegment::new(vec![&a_key, &b_key, &c_key, &d_key], Component::ProxyClient),
                RouteSegment::new(vec![&d_key, &e_key, &f_key, &a_key], Component::ProxyServer),
            ],
            &cryptde,
        )
        .unwrap();

        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&b_key, Component::Hopper)
                    .encode(&a_key, &cryptde)
                    .unwrap(),
                Hop::new(&c_key, Component::Hopper)
                    .encode(&b_key, &cryptde)
                    .unwrap(),
                Hop::new(&d_key, Component::Hopper)
                    .encode(&c_key, &cryptde)
                    .unwrap(),
                Hop::new(&e_key, Component::ProxyClient)
                    .encode(&d_key, &cryptde)
                    .unwrap(),
                Hop::new(&f_key, Component::Hopper)
                    .encode(&e_key, &cryptde)
                    .unwrap(),
                Hop::new(&a_key, Component::Hopper)
                    .encode(&f_key, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::ProxyServer)
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

        let subject = Route::new(
            vec![RouteSegment::new(
                vec![&a_key, &b_key],
                Component::Neighborhood,
            )],
            &cryptde,
        )
        .unwrap();

        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&b_key, Component::Hopper)
                    .encode(&a_key, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::Neighborhood)
                    .encode(&b_key, &cryptde)
                    .unwrap()
            )
        );
    }

    #[test]
    fn next_hop_decodes_top_hop() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let subject = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            &cryptde,
        )
        .unwrap();
        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&key34, Component::Hopper)
                    .encode(&key12, &cryptde)
                    .unwrap(),
                Hop::new(&key56, Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::Neighborhood)
                    .encode(&key56, &cryptde)
                    .unwrap()
            )
        );

        let next_hop = subject.next_hop(&cryptde).unwrap();

        assert_eq!(next_hop, Hop::new(&key34, Component::Hopper));
        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&key34, Component::Hopper)
                    .encode(&key12, &cryptde)
                    .unwrap(),
                Hop::new(&key56, Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::Neighborhood)
                    .encode(&key56, &cryptde)
                    .unwrap()
            )
        );
    }

    #[test]
    fn shift_returns_next_hop_and_adds_garbage_at_the_bottom() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let mut subject = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            &cryptde,
        )
        .unwrap();
        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&key34, Component::Hopper)
                    .encode(&key12, &cryptde)
                    .unwrap(),
                Hop::new(&key56, Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::Neighborhood)
                    .encode(&key56, &cryptde)
                    .unwrap()
            )
        );
        let top_hop_len = subject.hops.first().unwrap().data.len();

        let next_hop = subject.shift(&cryptde).unwrap();

        assert_eq!(next_hop, Hop::new(&key34, Component::Hopper));
        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(top_hop_len).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                Hop::new(&key56, Component::Hopper)
                    .encode(&key34, &cryptde)
                    .unwrap(),
                Hop::new(&Key::new(b""), Component::Neighborhood)
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

        let result = subject.next_hop(&cryptde);

        assert_eq!(result, None);
    }

    #[test]
    fn shift_says_none_when_asked_for_next_hop() {
        let mut cryptde = CryptDENull::new();
        cryptde.generate_key_pair();
        let mut subject = Route { hops: Vec::new() };

        let result = subject.shift(&cryptde);

        assert_eq!(result, None);
    }

    #[test]
    fn route_serialization_deserialization() {
        let key1 = Key::new(&[1, 2, 3, 4]);
        let key2 = Key::new(&[4, 3, 2, 1]);
        let cryptde = CryptDENull::new();
        let original = Route::new(
            vec![
                RouteSegment::new(vec![&key1, &key2], Component::ProxyClient),
                RouteSegment::new(vec![&key2, &key1], Component::ProxyServer),
            ],
            &cryptde,
        )
        .unwrap();

        let serialized = serde_cbor::ser::to_vec(&original).unwrap();

        let deserialized = serde_cbor::de::from_slice::<Route>(&serialized[..]).unwrap();

        assert_eq!(deserialized, original);
    }
}
