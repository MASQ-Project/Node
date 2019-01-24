// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;
use sub_lib::accountant::AccountantConfig;
use sub_lib::accountant::AccountantSubs;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;

pub struct Accountant {
    logger: Logger,
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, _msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.logger.info(String::from("Accountant bound"));
        ()
    }
}

impl Accountant {
    pub fn new(_config: AccountantConfig) -> Accountant {
        Accountant {
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: addr.clone().recipient::<BindMessage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_peer_actors;

    #[test]
    fn bind_message_is_received() {
        init_test_logging();
        // TODO: This test can be removed once behavior dependent on the reception of the BindMessage
        // is driven in
        let config = AccountantConfig {
            replace_me: String::new(),
        };
        let system = System::new("bind_message_is_received");
        let subject = Accountant::new(config);
        let subject_addr: Addr<Syn, Accountant> = subject.start();
        let peer_actors = make_peer_actors();

        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing("INFO: Accountant: Accountant bound");
    }
}
