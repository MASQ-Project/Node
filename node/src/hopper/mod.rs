// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod consuming_service;
pub mod live_cores_package;
mod routing_service;

use crate::hopper::routing_service::RoutingServiceSubs;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::hopper::IncipientCoresPackage;
use crate::sub_lib::hopper::{HopperConfig, NoLookupIncipientCoresPackage};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use consuming_service::ConsumingService;
use routing_service::RoutingService;

pub const CRASH_KEY: &str = "HOPPER";

pub struct Hopper {
    main_cryptde: &'static dyn CryptDE,
    alias_cryptde: &'static dyn CryptDE,
    consuming_service: Option<ConsumingService>,
    routing_service: Option<RoutingService>,
    per_routing_service: u64,
    per_routing_byte: u64,
    is_decentralized: bool,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.consuming_service = Some(ConsumingService::new(
            self.main_cryptde,
            msg.peer_actors.dispatcher.from_dispatcher_client.clone(),
            msg.peer_actors.hopper.from_dispatcher.clone(),
        ));
        self.routing_service = Some(RoutingService::new(
            self.main_cryptde,
            self.alias_cryptde,
            RoutingServiceSubs {
                proxy_client_subs: msg.peer_actors.proxy_client,
                proxy_server_subs: msg.peer_actors.proxy_server,
                neighborhood_subs: msg.peer_actors.neighborhood,
                hopper_subs: msg.peer_actors.hopper,
                to_dispatcher: msg.peer_actors.dispatcher.from_dispatcher_client,
                to_accountant_routing: msg.peer_actors.accountant.report_routing_service_provided,
            },
            self.per_routing_service,
            self.per_routing_byte,
            self.is_decentralized,
        ));
    }
}

// TODO: Make this message return a Future, so that the Neighborhood can tell if its
// message didn't go through.
impl Handler<NoLookupIncipientCoresPackage> for Hopper {
    type Result = ();

    fn handle(
        &mut self,
        msg: NoLookupIncipientCoresPackage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.consuming_service
            .as_ref()
            .expect("Hopper unbound: no ConsumingService")
            .consume_no_lookup(msg);
    }
}

// TODO: Make this message return a Future, so that the ProxyServer (or whatever) can tell if its
// message didn't go through.
impl Handler<IncipientCoresPackage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        self.consuming_service
            .as_ref()
            .expect("Hopper unbound: no ConsumingService")
            .consume(msg);
    }
}

impl Handler<InboundClientData> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        self.routing_service
            .as_ref()
            .expect("Hopper unbound: no RoutingService")
            .route(msg);
    }
}

impl Hopper {
    pub fn new(config: HopperConfig) -> Hopper {
        Hopper {
            main_cryptde: config.main_cryptde,
            alias_cryptde: config.alias_cryptde,
            consuming_service: None,
            routing_service: None,
            per_routing_service: config.per_routing_service,
            per_routing_byte: config.per_routing_byte,
            is_decentralized: config.is_decentralized,
        }
    }

    pub fn make_subs_from(addr: &Addr<Hopper>) -> HopperSubs {
        HopperSubs {
            bind: recipient!(addr, BindMessage),
            from_hopper_client: recipient!(addr, IncipientCoresPackage),
            from_hopper_client_no_lookup: recipient!(addr, NoLookupIncipientCoresPackage),
            from_dispatcher: recipient!(addr, InboundClientData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::live_cores_package::LiveCoresPackage;
    use super::*;
    use crate::blockchain::blockchain_interface::contract_address;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::test_utils::{
        alias_cryptde, main_cryptde, make_meaningless_message_type, make_paying_wallet,
        route_to_proxy_client,
    };
    use actix::Actor;
    use actix::System;
    use masq_lib::test_utils::utils::DEFAULT_CHAIN_ID;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    #[should_panic(expected = "Hopper unbound: no RoutingService")]
    fn panics_if_routing_service_is_unbound() {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_client(&main_cryptde.public_key(), main_cryptde);
        let serialized_payload = serde_cbor::ser::to_vec(&make_meaningless_message_type()).unwrap();
        let data = main_cryptde
            .encode(
                &main_cryptde.public_key(),
                &PlainData::new(&serialized_payload[..]),
            )
            .unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec(&live_package).unwrap()[..]);
        let encrypted_package = main_cryptde
            .encode(&main_cryptde.public_key(), &live_data)
            .unwrap()
            .into();

        let inbound_client_data = InboundClientData {
            peer_addr,
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: encrypted_package,
        };
        let system = System::new("panics_if_routing_service_is_unbound");
        let subject = Hopper::new(HopperConfig {
            main_cryptde,
            alias_cryptde,
            per_routing_service: 100,
            per_routing_byte: 200,
            is_decentralized: false,
        });
        let subject_addr: Addr<Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(expected = "Hopper unbound: no ConsumingService")]
    fn panics_if_consuming_service_is_unbound() {
        let main_cryptde = main_cryptde();
        let alias_cryptde = alias_cryptde();
        let paying_wallet = make_paying_wallet(b"wallet");
        let next_key = PublicKey::new(&[65, 65, 65]);
        let route = Route::one_way(
            RouteSegment::new(
                vec![&main_cryptde.public_key(), &next_key],
                Component::Neighborhood,
            ),
            main_cryptde,
            Some(paying_wallet),
            Some(contract_address(DEFAULT_CHAIN_ID)),
        )
        .unwrap();
        let incipient_package = IncipientCoresPackage::new(
            main_cryptde,
            route,
            make_meaningless_message_type(),
            &main_cryptde.public_key(),
        )
        .unwrap();
        let system = System::new("panics_if_consuming_service_is_unbound");
        let subject = Hopper::new(HopperConfig {
            main_cryptde,
            alias_cryptde,
            per_routing_service: 100,
            per_routing_byte: 200,
            is_decentralized: false,
        });
        let subject_addr: Addr<Hopper> = subject.start();

        subject_addr.try_send(incipient_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }
}
