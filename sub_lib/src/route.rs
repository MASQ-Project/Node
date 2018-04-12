// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use dispatcher::Component;
use hop::Hop;
use cryptde::Key;
use cryptde::CryptDE;
use cryptde::CryptData;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Route {
    next_hop: Hop,
    tail: Vec<CryptData>
}

impl Route {

    // TODO: Drive out panic!s.
    pub fn new(route_segments: Vec<RouteSegment>, cryptde: &CryptDE) -> Result<Route, RouteError> {
        if route_segments.is_empty () {panic! ("A route must have at least one segment")}
        let mut hops: Vec<Hop> = Vec::new ();
        let mut pending_recipient: Option<Component> = None;
        for segment_index in 0..route_segments.len () {
            let route_segment = &route_segments[segment_index];
            if route_segment.keys.len () < 1 {panic! ("Degenerate {}-element route segment", route_segment.keys.len ())}
            for hop_index in 0..route_segment.keys.len () {
                let key = &route_segment.keys[hop_index];
                if (segment_index > 0) && (hop_index == 0) {
                    let last_segment = &route_segments[segment_index - 1];
                    let last_segment_last_key = &last_segment.keys[last_segment.keys.len () - 1];
                    if key != last_segment_last_key {panic! ("Route segment {} ({:?}) must begin where segment {} ({:?}) left off", segment_index, route_segment, segment_index - 1, last_segment)}
                    continue
                }
                hops.push (match pending_recipient {
                    Some (recipient) => Hop::with_key_and_component (key, recipient),
                    None => Hop::with_key (key)
                });
                pending_recipient = None;
                if (hop_index + 1) == route_segment.keys.len () {
                    pending_recipient = Some (route_segment.recipient);
                }
            }
        }
        hops.push (Hop::with_component (pending_recipient.expect ("Route segment without recipient")));
        Route::hops_to_route (hops, cryptde)
    }

    pub fn next_hop (&self) -> Hop {
        self.next_hop.clone ()
    }

    pub fn construct (next_hop: Hop, tail: Vec<CryptData>) -> Route {
        Route {next_hop, tail}
    }

    pub fn deconstruct (self) -> (Hop, Vec<CryptData>) {
        (self.next_hop, self.tail)
    }

    pub fn shift (mut self, new_bottom: Hop, new_bottom_key: &Key, cryptde: &CryptDE) -> (Key, Vec<CryptData>) {
        self.tail.push (match new_bottom.encode (new_bottom_key, cryptde) {
            Ok (crypt_data) => crypt_data,
            Err (_) => unimplemented! ()
        });
        let key = match self.next_hop.public_key {
            Some (key) => key,
            None => unimplemented! ()
        };
        match self.next_hop.component {
            Some (_) => unimplemented! (),
            None => (key, self.tail)
        }
    }

    fn hops_to_route (hops: Vec<Hop>, cryptde: &CryptDE) -> Result<Route, RouteError> {
        let mut tail: Vec<CryptData> = Vec::new ();
        for hop_index in 1..hops.len () {
            let key_hop_index = hop_index - 1;
            let key_hop = &hops[key_hop_index];
            let data_hop = &hops[hop_index];
            tail.push (match data_hop.encode (key_hop.public_key.as_ref ().expect ("Hop without source key"), cryptde) {
                Ok (crypt_data) => crypt_data,
                // TODO FIXME don't panic!
                Err (_) => panic! ("Couldn't encode hop")
            });
        }
        Ok (Route {next_hop: hops[0].clone (), tail})
    }
}

#[derive (Debug)]
pub struct RouteSegment {
    pub keys: Vec<Key>,
    pub recipient: Component
}

impl RouteSegment {
    pub fn new (keys: Vec<&Key>, recipient: Component) -> RouteSegment {
        RouteSegment {keys: keys.iter ().map (|k| {(*k).clone ()}).collect (), recipient}
    }
}

#[derive (Debug)]
pub enum RouteError {
    GenericRouteError // TODO: replace this when we drive out the panic!s
}

#[cfg (test)]
mod tests {
    use super::*;
    use cryptde_null::CryptDENull;

    #[test]
    fn construct_and_deconstruct_communicate () {
        let next_hop = Hop::with_key_and_component(&Key::new (&[1, 2]), Component::Hopper);
        let tail = vec! (CryptData::new (&[3, 4]), CryptData::new (&[5, 6]));
        let subject = Route::construct (next_hop.clone (), tail.clone ());

        let (actual_next_hop, actual_tail) = subject.deconstruct ();

        assert_eq! (actual_next_hop, next_hop);
        assert_eq! (actual_tail, tail);
    }

    #[test]
    fn new_can_make_long_multistop_route () {
        let a_key = Key::new (&[65, 65, 65]);
        let b_key = Key::new (&[66, 66, 66]);
        let c_key = Key::new (&[67, 67, 67]);
        let d_key = Key::new (&[68, 68, 68]);
        let e_key = Key::new (&[69, 69, 69]);
        let f_key = Key::new (&[70, 70, 70]);
        let cryptde = CryptDENull::new ();
        let subject = Route::new(vec! (
            RouteSegment::new (vec! (&b_key, &c_key, &d_key), Component::ProxyClient),
            RouteSegment::new (vec! (&d_key, &e_key, &f_key, &a_key), Component::ProxyServer)
        ), &cryptde).unwrap ();

        let (next_hop, tail) = subject.deconstruct ();

        assert_eq! (next_hop, Hop::with_key (&b_key));
        assert_eq! (tail, vec! (
            Hop::with_key (&c_key).encode (&b_key, &cryptde).unwrap (),
            Hop::with_key (&d_key).encode (&c_key, &cryptde).unwrap (),
            Hop::with_key_and_component (&e_key, Component::ProxyClient).encode (&d_key, &cryptde).unwrap (),
            Hop::with_key (&f_key).encode (&e_key, &cryptde).unwrap (),
            Hop::with_key (&a_key).encode (&f_key, &cryptde).unwrap (),
            Hop::with_component (Component::ProxyServer).encode (&a_key, &cryptde).unwrap ()
        ));
    }

    #[test]
    fn new_can_make_short_single_stop_route () {
        let a_key = Key::new (&[65, 65, 65]);
        let b_key = Key::new (&[66, 66, 66]);
        let cryptde = CryptDENull::new ();
        let subject = Route::new(vec! (
            RouteSegment::new (vec! (&a_key, &b_key), Component::Neighborhood)
        ), &cryptde).unwrap ();

        let (next_hop, tail) = subject.deconstruct ();

        assert_eq! (next_hop, Hop::with_key (&a_key));
        assert_eq! (tail, vec! (
            Hop::with_key (&b_key).encode (&a_key, &cryptde).unwrap (),
            Hop::with_component (Component::Neighborhood).encode (&b_key, &cryptde).unwrap ()
        ));
    }

    #[test]
    fn shift_returns_next_hop_and_tail_of_route_integrated_with_new_bottom () {
        let cryptde = CryptDENull::new ();
        let key12 = Key::new (&[1, 2]);
        let key34 = Key::new (&[3, 4]);
        let key56 = Key::new (&[5, 6]);
        let new_bottom = Hop::with_key_and_component (&key56, Component::Hopper);
        let subject = Route::new (vec! (
            RouteSegment::new (vec! (&key12, &key34), Component::Neighborhood)
        ), &cryptde).unwrap ();

        let (next_stop_key, crypt_hops) = subject.shift (new_bottom.clone (), &key34, &cryptde);

        assert_eq! (next_stop_key, key12);
        assert_eq! (crypt_hops, vec! (
            Hop::with_key (&key34).encode (&key12, &cryptde).unwrap (),
            Hop::with_component (Component::Neighborhood).encode (&key34, &cryptde).unwrap (),
            new_bottom.encode (&key34, &cryptde).unwrap ()
        ))
    }
}
