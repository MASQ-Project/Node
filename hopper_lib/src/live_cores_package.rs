// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::CryptData;
use sub_lib::cryptde::CryptdecError;
use sub_lib::cryptde::Key;
use sub_lib::hop::LiveHop;
use sub_lib::hopper::ExpiredCoresPackage;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::route::Route;
use sub_lib::route::RouteError;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LiveCoresPackage {
    pub route: Route,
    pub payload: CryptData,
}

impl LiveCoresPackage {
    pub fn new(route: Route, payload: CryptData) -> LiveCoresPackage {
        LiveCoresPackage { route, payload }
    }

    pub fn to_next_live(
        mut self,
        cryptde: &CryptDE, // must be the CryptDE of the Node to which the top hop is encrypted
    ) -> Result<(LiveHop, LiveCoresPackage), RouteError> {
        let next_hop = self.route.shift(cryptde)?;
        let next_live = LiveCoresPackage::new(self.route, self.payload);
        Ok((next_hop, next_live))
    }

    pub fn from_incipient(
        incipient: IncipientCoresPackage,
        cryptde: &CryptDE, // must be the CryptDE of the Node to which the top hop is encrypted
    ) -> Result<(LiveCoresPackage, Key), String> {
        let encrypted_payload =
            match cryptde.encode(&incipient.payload_destination_key, &incipient.payload) {
                Ok(p) => p,
                Err(e) => return Err(format!("Could not encrypt payload: {:?}", e)),
            };
        let mut route = incipient.route.clone();
        let next_hop = match route.shift(cryptde) {
            Ok(h) => h,
            Err(e) => return Err(format!("Could not decrypt next hop: {:?}", e)),
        };

        Ok((
            LiveCoresPackage::new(route, encrypted_payload),
            next_hop.public_key,
        ))
    }

    // cryptde must be the CryptDE of the Node for which the payload is intended.
    pub fn to_expired(
        self,
        immediate_neighbor_ip: IpAddr,
        cryptde: &CryptDE,
    ) -> Result<ExpiredCoresPackage, CryptdecError> {
        let payload = cryptde.decode(&self.payload)?;
        Ok(ExpiredCoresPackage::new(
            immediate_neighbor_ip,
            self.route,
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use sub_lib::cryptde::Key;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use sub_lib::wallet::Wallet;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::make_meaningless_route;
    use test_utils::test_utils::PayloadMock;

    #[test]
    fn live_cores_package_can_be_constructed_from_scratch() {
        let payload = CryptData::new(&[5, 6]);
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&Key::new(&[1, 2]), &Key::new(&[3, 4])],
                Component::Neighborhood,
            )],
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();

        let subject = LiveCoresPackage::new(route.clone(), payload.clone());

        assert_eq!(subject.route, route);
        assert_eq!(subject.payload, payload);
    }

    #[test]
    fn live_cores_package_can_be_produced_from_older_live_cores_package() {
        let payload = PayloadMock::new();
        let destination_key = Key::new(&[3, 4]);
        let destination_cryptde = CryptDENull::from(&destination_key);
        let relay_key = Key::new(&[1, 2]);
        let relay_cryptde = CryptDENull::from(&relay_key);
        let cryptde = cryptde();
        let serialized_payload = serde_cbor::ser::to_vec(&payload).unwrap();
        let encrypted_payload = cryptde
            .encode(&destination_key, &PlainData::new(&serialized_payload))
            .unwrap();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&relay_key, &destination_key],
                Component::Neighborhood,
            )],
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        let subject = LiveCoresPackage::new(route.clone(), encrypted_payload.clone());

        let (next_hop, next_pkg) = subject.to_next_live(&relay_cryptde).unwrap();

        assert_eq!(
            next_hop,
            LiveHop::new(
                &destination_key,
                Some(Wallet::new("wallet")),
                Component::Hopper
            )
        );
        assert_eq!(next_pkg.payload, encrypted_payload);
        let mut route = next_pkg.route.clone();
        assert_eq!(
            route.shift(&destination_cryptde).unwrap(),
            LiveHop::new(
                &Key::new(&[]),
                Some(Wallet::new("wallet")),
                Component::Neighborhood
            )
        );
        assert_eq!(&route.hops[0].data[..8], &[52, 52, 52, 52, 52, 52, 52, 52]); // garbage
    }

    #[test]
    fn to_next_live_complains_about_bad_input() {
        let subject = LiveCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]));

        let result = subject.to_next_live(cryptde());

        assert_eq!(result, Err(RouteError::EmptyRoute));
    }

    #[test]
    fn live_cores_package_can_be_constructed_from_incipient_cores_package() {
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let key12 = cryptde.public_key();
        let key34 = Key::new(&[3, 4]);
        let key56 = Key::new(&[5, 6]);
        let mut route = Route::new(
            vec![RouteSegment::new(
                vec![&key12, &key34, &key56],
                Component::Neighborhood,
            )],
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        let payload = PayloadMock::new();
        let incipient = IncipientCoresPackage::new(route.clone(), payload.clone(), &key56);

        let (subject, next_stop) = LiveCoresPackage::from_incipient(incipient, cryptde).unwrap();

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
    fn from_incipient_complains_about_problems_encrypting_payload() {
        let incipient =
            IncipientCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]), &Key::new(&[]));

        let result = LiveCoresPackage::from_incipient(incipient, cryptde());

        assert_eq!(
            result,
            Err(String::from("Could not encrypt payload: EmptyKey"))
        );
    }

    #[test]
    fn from_incipient_complains_about_problems_decrypting_next_hop() {
        let incipient = IncipientCoresPackage::new(
            Route { hops: vec![] },
            String::from("booga"),
            &Key::new(&[3, 4]),
        );

        let result = LiveCoresPackage::from_incipient(incipient, cryptde());

        assert_eq!(
            result,
            Err(String::from("Could not decrypt next hop: EmptyRoute"))
        );
    }

    #[test]
    fn expired_cores_package_can_be_constructed_from_live_cores_package() {
        let immediate_neighbor_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let payload = PayloadMock::new();
        let destination_key = Key::new(&[3, 4]);
        let destination_cryptde = CryptDENull::from(&destination_key);
        let relay_key = Key::new(&[1, 2]);
        let relay_cryptde = CryptDENull::from(&relay_key);
        let cryptde = cryptde();
        let serialized_payload = serde_cbor::ser::to_vec(&payload).unwrap();
        let encrypted_payload = cryptde
            .encode(&destination_key, &PlainData::new(&serialized_payload))
            .unwrap();
        let consuming_wallet = Wallet::new("wallet");
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&relay_key, &destination_key],
                Component::Neighborhood,
            )],
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        let subject = LiveCoresPackage::new(route.clone(), encrypted_payload.clone());

        let result = subject
            .to_expired(immediate_neighbor_ip, &destination_cryptde)
            .unwrap();

        assert_eq!(result.immediate_neighbor_ip, immediate_neighbor_ip);
        assert_eq!(
            result.payload,
            PlainData::new(&serde_cbor::ser::to_vec(&payload).unwrap())
        );
        let mut route = result.remaining_route.clone();
        assert_eq!(
            route.shift(&relay_cryptde).unwrap(),
            LiveHop::new(
                &destination_key,
                Some(Wallet::new("wallet")),
                Component::Hopper
            )
        );
        assert_eq!(
            route.shift(&destination_cryptde).unwrap(),
            LiveHop::new(
                &Key::new(&[]),
                Some(Wallet::new("wallet")),
                Component::Neighborhood
            )
        );
        assert_eq!(&route.hops[0].data[..8], &[52, 52, 52, 52, 52, 52, 52, 52]); // garbage
    }

    #[test]
    fn to_expired_complains_about_bad_input() {
        let subject = LiveCoresPackage::new(Route { hops: vec![] }, CryptData::new(&[]));

        let result = subject.to_expired(IpAddr::from_str("1.2.3.4").unwrap(), cryptde());

        assert_eq!(result, Err(CryptdecError::EmptyData));
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
