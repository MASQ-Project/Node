// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Syn;
use sub_lib::accountant::AccountantConfig;
use sub_lib::accountant::AccountantSubs;
use sub_lib::accountant::ReportExitServiceConsumedMessage;
use sub_lib::accountant::ReportExitServiceProvidedMessage;
use sub_lib::accountant::ReportRoutingServiceProvidedMessage;
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

impl Handler<ReportRoutingServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.info(format!(
            "Charging routing of {} bytes to wallet {}",
            msg.payload_size, msg.consuming_wallet.address
        ));
        ()
    }
}

impl Handler<ReportExitServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.info(format!(
            "Charging exit service for {} bytes to wallet {}",
            msg.payload_size, msg.consuming_wallet.address
        ));
        ()
    }
}

impl Handler<ReportExitServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        _msg: ReportExitServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        unimplemented!()
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
            report_routing_service_provided: addr
                .clone()
                .recipient::<ReportRoutingServiceProvidedMessage>(),
            report_exit_service_provided: addr
                .clone()
                .recipient::<ReportExitServiceProvidedMessage>(),
            report_exit_service_consumed: addr
                .clone()
                .recipient::<ReportExitServiceConsumedMessage>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::msgs;
    use actix::Arbiter;
    use actix::System;
    use sub_lib::wallet::Wallet;
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

    #[test]
    fn report_routing_service_message_is_received() {
        init_test_logging();
        // TODO: This test can be removed once behavior dependent on the reception of the ReportRoutingServiceMessage
        // is driven in
        let config = AccountantConfig {
            replace_me: String::new(),
        };
        let system = System::new("report_routing_service_message_is_received");
        let subject = Accountant::new(config);
        let subject_addr: Addr<Syn, Accountant> = subject.start();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                consuming_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 1,
                byte_rate: 1,
            })
            .unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "INFO: Accountant: Charging routing of 1234 bytes to wallet booga",
        );
    }

    #[test]
    fn report_exit_service_message_is_received() {
        init_test_logging();
        // TODO: This test can be removed once behavior dependent on the reception of the ReportExitServiceMessage
        // is driven in
        let config = AccountantConfig {
            replace_me: String::new(),
        };
        let system = System::new("report_routing_service_message_is_received");
        let subject = Accountant::new(config);
        let subject_addr: Addr<Syn, Accountant> = subject.start();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                consuming_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 1,
                byte_rate: 1,
            })
            .unwrap();

        Arbiter::system().try_send(msgs::SystemExit(0)).unwrap();
        system.run();
        TestLogHandler::new().exists_log_containing(
            "INFO: Accountant: Charging exit service for 1234 bytes to wallet booga",
        );
    }
}
