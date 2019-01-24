// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::CryptdecError;
use sub_lib::cryptde::Key;
use sub_lib::hop::Hop;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::route::Route;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LiveCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

impl LiveCoresPackage {
    pub fn new(route: Route, payload: CryptData) -> LiveCoresPackage {
        LiveCoresPackage { route, payload }
    }

    pub fn from_incipient(
        incipient: IncipientCoresPackage,
        cryptde: &CryptDE,
    ) -> (LiveCoresPackage, Key) {
        // crashpoint - should discuss as a team
        let encrypted_payload = cryptde
            .encode(&incipient.payload_destination_key, &incipient.payload)
            .expect("Encode error");
        let mut route = incipient.route.clone();
        let next_hop = match route.shift(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!("no next_hop shifted out of route"),
            Some(h) => h,
        };

        (
            LiveCoresPackage::new(route, encrypted_payload),
            next_hop.public_key,
        )
    }

    pub fn to_expired(self, cryptde: &CryptDE) -> ExpiredCoresPackage {
        let payload = match cryptde.decode(&self.payload) {
            Ok(payload) => payload,
            // crashpoint - should discuss as a team
            Err(e) => panic!("{:?}", e),
        };
        ExpiredCoresPackage::new(self.route, payload)
    }

    pub fn to_next_live(
        mut self,
        cryptde: &CryptDE,
    ) -> Result<(Key, LiveCoresPackage), CryptdecError> {
        let next_hop = match self.route.shift(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!(),
            Some(h) => h,
        };
        let next_key = next_hop.public_key;
        let next_live = LiveCoresPackage::new(self.route, self.payload);
        Ok((next_key, next_live))
    }

    pub fn next_hop(&self, cryptde: &CryptDE) -> Hop {
        match self.route.next_hop(cryptde) {
            // crashpoint - should discuss as a team
            None => unimplemented!(),
            Some(h) => h,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use test_utils::test_utils::PayloadMock;

    #[test]
    fn live_cores_package_can_be_constructed_from_scratch() {
        let payload = CryptData::new(&[5, 6]);
        let cryptde = cryptde();
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&Key::new(&[1, 2]), &Key::new(&[3, 4])],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();

        let subject = LiveCoresPackage::new(route.clone(), payload.clone());

        assert_eq!(subject.route, route);
        assert_eq!(subject.payload, payload);
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_incipient_cores_package() {
        let cryptde = cryptde();
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let mut route = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            cryptde,
        )
        .unwrap();
        let payload = PayloadMock::new();
        let incipient = IncipientCoresPackage::new(route.clone(), payload.clone(), &key56);

        let (subject, next_stop) = LiveCoresPackage::from_incipient(incipient, cryptde);

        assert_eq!(next_stop, key34);
        route.shift(cryptde).unwrap();
        assert_eq!(subject.route, route);
        assert_eq!(
            subject.payload,
            cryptde
                .encode(
                    &key56,
                    &PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap())
                )
                .unwrap()
        );
    }

    #[test]
    fn live_cores_package_serialization_deserialization() {
        let original = LiveCoresPackage {
            route: make_meaningless_route(),
            payload: CryptData::new(&[1, 2, 3, 4]),
        };

        let serialized = serde_cbor::ser::to_vec(&original).unwrap();

        let deserialized = serde_cbor::de::from_slice::<LiveCoresPackage>(&serialized[..]).unwrap();

        assert_eq!(deserialized, original);
    }
}
