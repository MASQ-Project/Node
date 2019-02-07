// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;
use consuming_service::ConsumingService;
use routing_service::RoutingService;
use sub_lib::cryptde::CryptDE;
use sub_lib::dispatcher::InboundClientData;
use sub_lib::hopper::HopperSubs;
use sub_lib::hopper::IncipientCoresPackage;
use sub_lib::peer_actors::BindMessage;
use sub_lib::utils::NODE_MAILBOX_CAPACITY;

pub struct Hopper {
    cryptde: &'static CryptDE,
    is_bootstrap_node: bool,
    consuming_service: Option<ConsumingService>,
    routing_service: Option<RoutingService>,
}

impl Actor for Hopper {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        self.consuming_service = Some(ConsumingService::new(
            self.cryptde,
            self.is_bootstrap_node,
            msg.peer_actors.dispatcher.from_dispatcher_client.clone(),
            msg.peer_actors.hopper.from_dispatcher,
        ));
        self.routing_service = Some(RoutingService::new(
            self.cryptde,
            self.is_bootstrap_node,
            msg.peer_actors.proxy_client.from_hopper,
            msg.peer_actors.proxy_server.from_hopper,
            msg.peer_actors.neighborhood.from_hopper,
            msg.peer_actors.dispatcher.from_dispatcher_client,
            msg.peer_actors.accountant.report_routing_service,
        ));
        ()
    }
}

// TODO: Make this message return a Future, so that the Proxy Server (or whatever) can tell if its
// message didn't go through.
impl Handler<IncipientCoresPackage> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackage, _ctx: &mut Self::Context) -> Self::Result {
        self.consuming_service
            .as_ref()
            .expect("Hopper unbound: no ConsumingService")
            .consume(msg);
        ()
    }
}

impl Handler<InboundClientData> for Hopper {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        self.routing_service
            .as_ref()
            .expect("Hopper unbound: no RoutingService")
            .route(msg);
        ()
    }
}

impl Hopper {
    pub fn new(cryptde: &'static CryptDE, is_bootstrap_node: bool) -> Hopper {
        Hopper {
            cryptde,
            is_bootstrap_node,
            consuming_service: None,
            routing_service: None,
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, Hopper>) -> HopperSubs {
        HopperSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            from_hopper_client: addr.clone().recipient::<IncipientCoresPackage>(),
            from_dispatcher: addr.clone().recipient::<InboundClientData>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Actor;
    use actix::Arbiter;
    use actix::System;
    use live_cores_package::LiveCoresPackage;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use sub_lib::cryptde::PlainData;
    use sub_lib::cryptde::PublicKey;
    use sub_lib::dispatcher::Component;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::route::Route;
    use sub_lib::route::RouteSegment;
    use sub_lib::wallet::Wallet;
    use test_utils::test_utils::cryptde;
    use test_utils::test_utils::route_to_proxy_client;
    use test_utils::test_utils::PayloadMock;

    #[test]
    #[should_panic(expected = "Hopper unbound: no RoutingService")]
    fn panics_if_routing_service_is_unbound() {
        let cryptde = cryptde();
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
        let route = route_to_proxy_client(&cryptde.public_key(), cryptde);
        let serialized_payload = serde_cbor::ser::to_vec(&PayloadMock::new()).unwrap();
        let data = cryptde
            .encode(
                &cryptde.public_key(),
                &PlainData::new(&serialized_payload[..]),
            )
            .unwrap();
        let live_package = LiveCoresPackage::new(route, data);
        let live_data = PlainData::new(&serde_cbor::ser::to_vec(&live_package).unwrap()[..]);
        let encrypted_package = cryptde
            .encode(&cryptde.public_key(), &live_data)
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
        let subject = Hopper::new(cryptde, false);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(inbound_client_data).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }

    #[test]
    #[should_panic(expected = "Hopper unbound: no ConsumingService")]
    fn panics_if_consuming_service_is_unbound() {
        let cryptde = cryptde();
        let consuming_wallet = Wallet::new("wallet");
        let next_key = PublicKey::new(&[65, 65, 65]);
        let route = Route::new(
            vec![RouteSegment::new(
                vec![&cryptde.public_key(), &next_key],
                Component::Neighborhood,
            )],
            cryptde,
            Some(consuming_wallet),
        )
        .unwrap();
        let incipient_package =
            IncipientCoresPackage::new(route, PayloadMock::new(), &cryptde.public_key());
        let system = System::new("panics_if_consuming_service_is_unbound");
        let subject = Hopper::new(cryptde, false);
        let subject_addr: Addr<Syn, Hopper> = subject.start();

        subject_addr.try_send(incipient_package).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
    }
}
