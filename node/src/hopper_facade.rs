// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::actor_messages::BindMessage;
use sub_lib::actor_messages::IncipientCoresPackageMessage;
use sub_lib::hopper::Hopper;
use sub_lib::hopper::HopperSubs;
use actix::SyncAddress;
use actix::Actor;
use actix::Context;
use actix::Handler;
use std::sync::Arc;
use std::sync::Mutex;

pub struct HopperFacade {
    hopper: Arc<Mutex<Hopper>>
}

impl Actor for HopperFacade {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for HopperFacade {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        // TODO implement once Hopper is actorized
        ()
    }
}

impl Handler<IncipientCoresPackageMessage> for HopperFacade {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.hopper.lock().expect("Hopper is Poisoned").transmit_cores_package(msg.pkg);
        ()
    }
}

impl HopperFacade {
    pub fn new(hopper: Arc<Mutex<Hopper>>) -> HopperFacade {
        HopperFacade { hopper }
    }

    pub fn make_subs_from(addr: &SyncAddress<HopperFacade>) -> HopperSubs {
        HopperSubs {
            bind: addr.subscriber::<BindMessage>(),
            from_hopper_client: addr.subscriber::<IncipientCoresPackageMessage>(),
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use sub_lib::actor_messages::IncipientCoresPackageMessage;
    use sub_lib::hopper::IncipientCoresPackage;
    use sub_lib::test_utils::HopperMock;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::cryptde::CryptDE;
    use sub_lib::route::Route;
    use sub_lib::cryptde::PlainData;

    #[test]
    fn forwards_incipient_cores_message_to_hopper() {
        let system = System::new ("forwards_incipient_cores_message_to_hopper");
        let hopper = HopperMock::new();
        let cryptde = CryptDENull::new ();
        let actual_packages_arc = hopper.transmit_cores_package_parameters.clone ();
        let subject = HopperFacade::new(Arc::new(Mutex::new(hopper)));
        let subject_addr: SyncAddress<_> = subject.start();
        let expected_pkg = IncipientCoresPackage {
            route: Route::rel2_to_proxy_client(&cryptde.public_key (), &cryptde).unwrap(),
            payload: PlainData::new(b"blah don't care"),
            payload_destination_key: cryptde.public_key(),
        };

        subject_addr.send(IncipientCoresPackageMessage { pkg: expected_pkg.clone() });

        Arbiter::system().send(msgs::SystemExit(0));
        system.run ();

        let actual_pkgs_mutex = actual_packages_arc.lock().unwrap();
        let actual_pkgs: &Vec<IncipientCoresPackage> = actual_pkgs_mutex.as_ref();

        assert_eq!(actual_pkgs[0], expected_pkg);
    }
}