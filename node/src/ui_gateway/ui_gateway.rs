// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::ui_gateway::shutdown_supervisor::ShutdownSupervisor;
use crate::ui_gateway::shutdown_supervisor::ShutdownSupervisorReal;
use crate::ui_gateway::ui_traffic_converter::UiTrafficConverter;
use crate::ui_gateway::ui_traffic_converter::UiTrafficConverterReal;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisor;
use crate::ui_gateway::websocket_supervisor::WebSocketSupervisorReal;
use actix::Actor;
use actix::Addr;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use actix::Syn;
use sub_lib::logger::Logger;
use sub_lib::peer_actors::BindMessage;
use sub_lib::ui_gateway::FromUiMessage;
use sub_lib::ui_gateway::UiGatewayConfig;
use sub_lib::ui_gateway::UiGatewaySubs;
use sub_lib::ui_gateway::UiMessage;

pub struct UiGateway {
    port: u16,
    converter: Box<dyn UiTrafficConverter>,
    ui_message_sub: Option<Recipient<Syn, UiMessage>>,
    websocket_supervisor: Option<Box<dyn WebSocketSupervisor>>,
    shutdown_supervisor: Box<dyn ShutdownSupervisor>,
    logger: Logger,
}

impl UiGateway {
    pub fn new(config: &UiGatewayConfig) -> UiGateway {
        UiGateway {
            port: config.ui_port,
            converter: Box::new(UiTrafficConverterReal::new()),
            ui_message_sub: None,
            websocket_supervisor: None,
            shutdown_supervisor: Box::new(ShutdownSupervisorReal::new()),
            logger: Logger::new("UiGateway"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Syn, UiGateway>) -> UiGatewaySubs {
        UiGatewaySubs {
            bind: addr.clone().recipient::<BindMessage>(),
            ui_message_sub: addr.clone().recipient::<UiMessage>(),
            from_ui_message_sub: addr.clone().recipient::<FromUiMessage>(),
        }
    }
}

impl Actor for UiGateway {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for UiGateway {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        //        ctx.set_mailbox_capacity(?);
        self.ui_message_sub = Some(msg.peer_actors.ui_gateway.ui_message_sub.clone());
        self.websocket_supervisor = Some(Box::new(WebSocketSupervisorReal::new(
            self.port,
            msg.peer_actors.ui_gateway.from_ui_message_sub.clone(),
        )));
        ()
    }
}

impl Handler<UiMessage> for UiGateway {
    type Result = ();

    // All UI messages, both inbound and outbound, come through here
    fn handle(&mut self, _msg: UiMessage, _ctx: &mut Self::Context) -> Self::Result {
        // TODO: The assumption here is that every UiMessage means, "Shut down!" This assumption is only temporarily valid.
        self.logger.info(String::from("Received shutdown order"));
        self.shutdown_supervisor.shutdown();
        ()
    }
}

impl Handler<FromUiMessage> for UiGateway {
    type Result = ();

    // JSON messages from external UIs come in here, are translated to UiMessages, and sent to the handler above
    fn handle(&mut self, msg: FromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        match self.converter.unmarshal(&msg.json) {
            Err(e) => self.logger.warning(format!(
                "Error unmarshalling message from UI - ignoring: '{}'",
                e
            )),
            Ok(ui_message) => self
                .ui_message_sub
                .as_ref()
                .expect("UiGateway is unbound")
                .try_send(ui_message)
                .expect("UiGateway is dead"),
        };
        ()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix::System;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use sub_lib::ui_gateway::DEFAULT_UI_PORT;
    use test_utils::logging::init_test_logging;
    use test_utils::logging::TestLogHandler;
    use test_utils::recorder::make_recorder;
    use test_utils::test_utils::find_free_port;
    use test_utils::test_utils::wait_for;
    use test_utils::recorder::peer_actors_builder;

    pub struct UiTrafficConverterMock {
        marshal_parameters: Arc<Mutex<Vec<UiMessage>>>,
        marshal_results: RefCell<Vec<Result<String, String>>>,
        unmarshal_parameters: Arc<Mutex<Vec<String>>>,
        unmarshal_results: RefCell<Vec<Result<UiMessage, String>>>,
    }

    impl UiTrafficConverter for UiTrafficConverterMock {
        fn marshal(&self, ui_message: UiMessage) -> Result<String, String> {
            self.marshal_parameters.lock().unwrap().push(ui_message);
            self.marshal_results.borrow_mut().remove(0)
        }

        fn unmarshal(&self, json: &str) -> Result<UiMessage, String> {
            self.unmarshal_parameters
                .lock()
                .unwrap()
                .push(String::from(json));
            self.unmarshal_results.borrow_mut().remove(0)
        }
    }

    impl UiTrafficConverterMock {
        fn new() -> UiTrafficConverterMock {
            UiTrafficConverterMock {
                marshal_parameters: Arc::new(Mutex::new(vec![])),
                marshal_results: RefCell::new(vec![]),
                unmarshal_parameters: Arc::new(Mutex::new(vec![])),
                unmarshal_results: RefCell::new(vec![]),
            }
        }

        #[allow(dead_code)]
        fn marshal_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<UiMessage>>>,
        ) -> UiTrafficConverterMock {
            self.marshal_parameters = parameters.clone();
            self
        }

        #[allow(dead_code)]
        fn marshal_result(self, result: Result<String, String>) -> UiTrafficConverterMock {
            self.marshal_results.borrow_mut().push(result);
            self
        }

        fn unmarshal_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<String>>>,
        ) -> UiTrafficConverterMock {
            self.unmarshal_parameters = parameters.clone();
            self
        }

        fn unmarshal_result(self, result: Result<UiMessage, String>) -> UiTrafficConverterMock {
            self.unmarshal_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Default)]
    struct WebSocketSupervisorMock {
        receive_results: RefCell<Vec<()>>,
        receive_parameters: Arc<Mutex<Vec<(u64, String)>>>,
    }

    impl WebSocketSupervisor for WebSocketSupervisorMock {
        fn receive(&self, client_id: u64, message_json: &str) {
            self.receive_parameters
                .lock()
                .unwrap()
                .push((client_id, String::from(message_json)));
            self.receive_results.borrow_mut().remove(0)
        }
    }

    #[allow(dead_code)]
    impl WebSocketSupervisorMock {
        fn new() -> WebSocketSupervisorMock {
            Default::default()
        }
    }

    pub struct ShutdownSupervisorMock {
        shutdown_parameters: Arc<Mutex<Vec<()>>>,
    }

    impl ShutdownSupervisor for ShutdownSupervisorMock {
        fn shutdown(&self) {
            self.shutdown_parameters.lock().unwrap().push(());
        }
    }

    impl ShutdownSupervisorMock {
        fn new() -> ShutdownSupervisorMock {
            ShutdownSupervisorMock {
                shutdown_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        fn shutdown_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<()>>>,
        ) -> ShutdownSupervisorMock {
            self.shutdown_parameters = parameters.clone();
            self
        }
    }

    #[test]
    fn receiving_a_shutdown_message_triggers_the_shutdown_supervisor() {
        let shutdown_parameters = Arc::new(Mutex::new(vec![]));
        let shutdown_parameters_inside = shutdown_parameters.clone();

        thread::spawn(move || {
            let supervisor =
                ShutdownSupervisorMock::new().shutdown_parameters(&shutdown_parameters_inside);
            let mut subject = UiGateway::new(&UiGatewayConfig {
                ui_port: find_free_port(),
            });
            subject.shutdown_supervisor = Box::new(supervisor);
            let system =
                System::new("receiving_a_shutdown_message_triggers_the_shutdown_supervisor");
            let addr: Addr<Syn, UiGateway> = subject.start();
            let mut peer_actors = peer_actors_builder ().build ();
            peer_actors.ui_gateway = UiGateway::make_subs_from(&addr);
            addr.try_send(BindMessage { peer_actors }).unwrap();

            addr.try_send(UiMessage::ShutdownMessage).unwrap();

            system.run();
        });
        wait_for(None, None, || shutdown_parameters.lock().unwrap().len() > 0)
    }

    #[test]
    fn good_from_ui_message_is_unmarshalled_and_resent() {
        let unmarshal_parameters = Arc::new(Mutex::new(vec![]));
        let handler = UiTrafficConverterMock::new()
            .unmarshal_parameters(&unmarshal_parameters)
            .unmarshal_result(Ok(UiMessage::ShutdownMessage));
        let (ui_gateway, ui_gateway_awaiter, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let mut subject = UiGateway::new(&UiGatewayConfig {
                ui_port: find_free_port(),
            });
            subject.converter = Box::new(handler);
            let system = System::new("good_from_ui_message_is_unmarshalled_and_resent");
            let addr: Addr<Syn, UiGateway> = subject.start();
            let peer_actors = peer_actors_builder ().ui_gateway (ui_gateway).build ();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            addr.try_send(FromUiMessage {
                json: String::from("pretend I'm JSON"),
            })
            .unwrap();

            system.run();
        });
        ui_gateway_awaiter.await_message_count(1);
        let unmarshal_parameters_locked = unmarshal_parameters.lock().unwrap();
        assert_eq!(
            unmarshal_parameters_locked[0],
            String::from("pretend I'm JSON")
        );
        assert_eq!(unmarshal_parameters_locked.len(), 1);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(
            ui_gateway_recording.get_record::<UiMessage>(0),
            &UiMessage::ShutdownMessage
        );
    }

    #[test]
    fn bad_from_ui_message_is_logged_and_ignored() {
        init_test_logging();
        let handler =
            UiTrafficConverterMock::new().unmarshal_result(Err(String::from("I have a tummyache")));
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();

        thread::spawn(move || {
            let mut subject = UiGateway::new(&UiGatewayConfig {
                ui_port: DEFAULT_UI_PORT,
            });
            subject.converter = Box::new(handler);
            let system = System::new("bad_from_ui_message_is_logged_and_ignored");
            let addr: Addr<Syn, UiGateway> = subject.start();
            let peer_actors = peer_actors_builder ().ui_gateway (ui_gateway).build ();
            addr.try_send(BindMessage { peer_actors }).unwrap();

            addr.try_send(FromUiMessage {
                json: String::from("pretend I'm JSON"),
            })
            .unwrap();

            system.run();
        });
        TestLogHandler::new().await_log_containing(
            "Error unmarshalling message from UI - ignoring: 'I have a tummyache'",
            1000,
        );
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.len(), 0);
    }
}
