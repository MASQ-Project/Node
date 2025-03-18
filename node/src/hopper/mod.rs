// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

mod consuming_service;
pub mod live_cores_package;
mod routing_service;

use crate::bootstrapper::CryptDEPair;
use crate::hopper::routing_service::RoutingServiceSubs;
use crate::sub_lib::dispatcher::InboundClientData;
use crate::sub_lib::hopper::HopperSubs;
use crate::sub_lib::hopper::IncipientCoresPackage;
use crate::sub_lib::hopper::{HopperConfig, NoLookupIncipientCoresPackage};
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::{handle_ui_crash_request, NODE_MAILBOX_CAPACITY};
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use consuming_service::ConsumingService;
use masq_lib::logger::Logger;
use masq_lib::ui_gateway::NodeFromUiMessage;
use routing_service::RoutingService;

pub const CRASH_KEY: &str = "HOPPER";

pub struct Hopper {
    cryptdes: CryptDEPair,
    consuming_service: Option<ConsumingService>,
    routing_service: Option<RoutingService>,
    per_routing_service: u64,
    per_routing_byte: u64,
    is_decentralized: bool,
    logger: Logger,
    crashable: bool,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.consuming_service = Some(ConsumingService::new(
            self.cryptdes.main,
            msg.peer_actors.dispatcher.from_dispatcher_client.clone(),
            msg.peer_actors.hopper.from_dispatcher.clone(),
        ));
        self.routing_service = Some(RoutingService::new(
            self.cryptdes,
            RoutingServiceSubs {
                proxy_client_subs_opt: msg.peer_actors.proxy_client_opt,
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

impl Handler<NodeFromUiMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        handle_ui_crash_request(msg, &self.logger, self.crashable, CRASH_KEY)
    }
}

impl Hopper {
    pub fn new(config: HopperConfig) -> Hopper {
        Hopper {
            cryptdes: config.cryptdes,
            consuming_service: None,
            routing_service: None,
            crashable: config.crashable,
            per_routing_service: config.per_routing_service,
            per_routing_byte: config.per_routing_byte,
            is_decentralized: config.is_decentralized,
            logger: Logger::new("Hopper"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Hopper>) -> HopperSubs {
        HopperSubs {
            bind: recipient!(addr, BindMessage),
            from_hopper_client: recipient!(addr, IncipientCoresPackage),
            from_hopper_client_no_lookup: recipient!(addr, NoLookupIncipientCoresPackage),
            from_dispatcher: recipient!(addr, InboundClientData),
            node_from_ui: recipient!(addr, NodeFromUiMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::live_cores_package::LiveCoresPackage;
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use crate::sub_lib::cryptde::PublicKey;
    use crate::sub_lib::dispatcher::Component;
    use crate::sub_lib::hopper::IncipientCoresPackage;
    use crate::sub_lib::route::Route;
    use crate::sub_lib::route::RouteSegment;
    use crate::test_utils::unshared_test_utils::{
        make_meaningless_message_type, prove_that_crash_request_handler_is_hooked_up,
    };
    use crate::test_utils::{
        alias_cryptde, main_cryptde, make_cryptde_pair, make_paying_wallet, route_to_proxy_client,
    };
    use actix::Actor;
    use actix::System;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::SystemTime;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(CRASH_KEY, "HOPPER");
    }

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
            timestamp: SystemTime::now(),
            peer_addr,
            reception_port: None,
            last_data: false,
            is_clandestine: false,
            sequence_number: None,
            data: encrypted_package,
        };
        let system = System::new("panics_if_routing_service_is_unbound");
        let subject = Hopper::new(HopperConfig {
            cryptdes: CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            per_routing_service: 100,
            per_routing_byte: 200,
            is_decentralized: false,
            crashable: false,
        });
        let subject_addr = subject.start();

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
            Some(TEST_DEFAULT_CHAIN.rec().contract),
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
            cryptdes: CryptDEPair {
                main: main_cryptde,
                alias: alias_cryptde,
            },
            per_routing_service: 100,
            per_routing_byte: 200,
            is_decentralized: false,
            crashable: false,
        });
        let subject_addr = subject.start();

        subject_addr.try_send(incipient_package).unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[test]
    #[should_panic(
        expected = "panic message (processed with: node_lib::sub_lib::utils::crash_request_analyzer)"
    )]
    fn hopper_can_be_crashed_properly_but_not_improperly() {
        let hopper = Hopper::new(HopperConfig {
            cryptdes: make_cryptde_pair(),
            per_routing_service: 100,
            per_routing_byte: 200,
            is_decentralized: false,
            crashable: true,
        });

        prove_that_crash_request_handler_is_hooked_up(hopper, CRASH_KEY);
    }
}
