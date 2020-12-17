use std::cell::RefCell;
use std::path::PathBuf;

use actix::{Actor, Context, Handler, Message, Recipient};

use masq_lib::messages::{FromMessageBody, ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse, UiCheckPasswordRequest, UiCheckPasswordResponse, UiNewPasswordBroadcast};
use masq_lib::ui_gateway::{MessageBody, MessagePath, MessageTarget, NodeFromUiMessage, NodeToUiMessage};
use masq_lib::ui_gateway::MessageTarget::ClientId;

use crate::db_config::config_dao::ConfigDaoReal;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;

pub const CONFIGURATOR_PREFIX: u64 = 0x0001_0000_0000_0000;
pub const CONFIGURATOR_WRITE_ERROR: u64 = CONFIGURATOR_PREFIX | 1;

pub struct Configurator {
    persistent_config: Box<dyn PersistentConfiguration>,
    node_to_ui_sub: Option<Recipient<NodeToUiMessage>>,
    configuration_change_subs: Option<Vec<Recipient<NodeFromUiMessage>>>,
    logger: Logger,
}

impl Actor for Configurator {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.node_to_ui_sub = Some (msg.peer_actors.ui_gateway.node_to_ui_message_sub.clone());
        self.configuration_change_subs = Some (vec![
            msg.peer_actors.neighborhood.from_ui_message_sub.clone(),
        ])
    }
}

impl Handler<NodeFromUiMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Ok((body, context_id)) = UiCheckPasswordRequest::fmb(msg.clone().body) {     //hmm I don't like that clone.
            let response = self.handle_check_password(body, context_id);
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        } else if let Ok((body, context_id)) = UiChangePasswordRequest::fmb(msg.body) {
            let response = self.handle_change_password(body, msg.client_id, context_id);
            self.send_to_ui_gateway(ClientId(msg.client_id), response);
        }
    }
}

impl From<Box<dyn PersistentConfiguration>> for Configurator {
    fn from(persistent_config: Box<dyn PersistentConfiguration>) -> Self {
        Configurator {
            persistent_config,
            node_to_ui_sub: None,
            configuration_change_subs: None,
            logger: Logger::new ("Configurator"),
        }
    }
}

impl Configurator {
    pub fn new (data_directory: PathBuf, chain_id: u8) -> Self {
        unimplemented!();
        // let initializer = DbInitializerReal::new();
        // let conn = initializer.initialize(
        //     &data_directory,
        //     chain_id,
        //     false,
        // ).expect ("Couldn't initialize database");
        // let config_dao = ConfigDaoReal::new(conn);
        // let persistent_config: Box<dyn PersistentConfiguration> = Box::new (PersistentConfigurationReal::new (Box::new (config_dao)));
        // Configurator::from (persistent_config)
    }

    fn handle_check_password(&mut self, msg: UiCheckPasswordRequest, context_id: u64) -> MessageBody {
        match self.persistent_config.check_password(msg.db_password_opt.clone()) {
            Ok(matches) => { UiCheckPasswordResponse { matches }.tmb(context_id) }
            ,
            Err(e) => {
                warning!(self.logger, "Failed to check password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, format!("{:?}", e))),
                }
            }
        }
    }

    fn handle_change_password(&mut self, msg: UiChangePasswordRequest, client_id: u64, context_id: u64) -> MessageBody {
        match self.persistent_config.change_password(msg.old_password_opt.clone(),&msg.new_password) {
            Ok(_) => {
                let broadcast = UiNewPasswordBroadcast {
                    new_password: msg.new_password
                }.tmb(0);
                self.send_configuration_changes(broadcast.clone());
                self.send_to_ui_gateway (MessageTarget::AllExcept(client_id), broadcast);
                UiChangePasswordResponse {}.tmb(context_id)
            },

            Err(e) => {
                warning!(self.logger, "Failed to change password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, format!("{:?}", e))),
                }
            }
        }
    }

    fn send_to_ui_gateway (&self, target: MessageTarget, body: MessageBody) {
        let msg = NodeToUiMessage {
            target,
            body,
        };
        self.node_to_ui_sub
            .as_ref().expect("Configurator is unbound")
            .try_send (msg).expect ("UiGateway is dead");
    }

    fn send_configuration_changes (&self, body: MessageBody) {
        let msg = NodeFromUiMessage {
            client_id: 0,
            body,
        };
        self.configuration_change_subs
            .as_ref().expect("Configurator is unbound")
            .iter().for_each (|sub|
                sub.try_send (msg.clone()).expect ("Configuration change recipient is dead")
            );
    }
}

#[cfg (test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use actix::System;

    use masq_lib::messages::{ToMessageBody, UiChangePasswordResponse, UiCheckPasswordRequest, UiCheckPasswordResponse, UiNewPasswordBroadcast, UiStartOrder};
    use masq_lib::ui_gateway::{MessagePath, MessageTarget};

    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::db_config::persistent_configuration::PersistentConfigError::DatabaseError;
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, peer_actors_builder};

    use super::*;

    #[test]
    fn ignores_unexpected_message () {
        let system = System::new("test");
        let subject = make_subject (None);
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording) = make_recorder ();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(NodeFromUiMessage {
            client_id: 1234,
            body: UiStartOrder{}.tmb (4321),
        }).unwrap();

        System::current().stop();
        system.run();
        let recording = ui_gateway_recording.lock().unwrap();
        assert_eq! (recording.len(), 0);
    }

    #[test]
    fn check_password_works () {
        let system = System::new("test");
        let check_password_params_arc = Arc::new (Mutex::new (vec![]));
        let persistent_config = PersistentConfigurationMock::new ()
            .check_password_params (&check_password_params_arc)
            .check_password_result (Ok(false));
        let subject = make_subject (Some (persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder ();
        let peer_actors = peer_actors_builder().ui_gateway(ui_gateway).build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(NodeFromUiMessage {
            client_id: 1234,
            body: UiCheckPasswordRequest{
                db_password_opt: Some ("password".to_string())
            }.tmb (4321),
        }).unwrap();

        System::current().stop();
        system.run();
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq! (*check_password_params, vec![Some ("password".to_string())]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq! (ui_gateway_recording.get_record::<NodeToUiMessage>(0), &NodeToUiMessage {
            target: MessageTarget::ClientId(1234), 
            body: UiCheckPasswordResponse {
                matches: false
            }.tmb(4321)
        });
        assert_eq! (ui_gateway_recording.len(), 1);
    }

    #[test]
    fn handle_check_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result (Err(PersistentConfigError::NotPresent));
        let mut subject = make_subject (Some(persistent_config));
        let msg = UiCheckPasswordRequest {db_password_opt: None};

        let result = subject.handle_check_password (msg, 4321);

        assert_eq! (result, MessageBody {
            opcode: "checkPassword".to_string(),
            path: MessagePath::Conversation(4321),
            payload: Err ((CONFIGURATOR_WRITE_ERROR, "NotPresent".to_string()))
        });
        TestLogHandler::new().exists_log_containing("WARN: Configurator: Failed to check password: NotPresent");
    }

    #[test]
    fn change_password_works() {
        let system = System::new("test");
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let persistent_config = PersistentConfigurationMock::new()
            .change_password_params(&change_password_params_arc)
            .change_password_result(Ok(()));
        let subject = make_subject(Some(persistent_config));
        let subject_addr = subject.start();
        let (ui_gateway, _, ui_gateway_recording_arc) = make_recorder();
        let (neighborhood, _, neighborhood_recording_arc) = make_recorder();
        let peer_actors = peer_actors_builder()
            .ui_gateway(ui_gateway)
            .neighborhood(neighborhood)
            .build();
        subject_addr.try_send(BindMessage { peer_actors }).unwrap();

        subject_addr.try_send(NodeFromUiMessage {
            client_id: 1234,
            body: UiChangePasswordRequest {
                old_password_opt: Some("old_password".to_string()),
                new_password: "new_password".to_string()
            }.tmb(4321),
        }).unwrap();

        System::current().stop();
        system.run();
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(*change_password_params, vec![(Some("old_password".to_string()), "new_password".to_string())]);
        let ui_gateway_recording = ui_gateway_recording_arc.lock().unwrap();
        assert_eq!(ui_gateway_recording.get_record::<NodeToUiMessage>(0), &NodeToUiMessage {
            target: MessageTarget::AllExcept(1234),
            body: UiNewPasswordBroadcast {
                new_password: "new_password".to_string(),
            }.tmb(0)
        });
        assert_eq!(ui_gateway_recording.get_record::<NodeToUiMessage>(1), &NodeToUiMessage {
            target: MessageTarget::ClientId(1234),
            body: UiChangePasswordResponse {}.tmb(4321)
        });
        let neighborhood_recording = neighborhood_recording_arc.lock().unwrap();
        assert_eq!(neighborhood_recording.get_record::<NodeFromUiMessage>(0), &NodeFromUiMessage {
            client_id: 0,
            body: UiNewPasswordBroadcast {
                new_password: "new_password".to_string(),
            }.tmb(0)
        });
        assert_eq!(neighborhood_recording.len(), 1);
    }

    #[test]
    fn handle_change_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .change_password_result(Err(PersistentConfigError::DatabaseError("Didn't work good".to_string())));
        let mut subject = make_subject(Some(persistent_config));
        let msg = UiChangePasswordRequest { old_password_opt: None, new_password: "".to_string() };

        let result = subject.handle_change_password(msg, 1234, 4321);

        assert_eq!(result, MessageBody {
            opcode: "changePassword".to_string(),
            path: MessagePath::Conversation(4321),
            payload: Err((CONFIGURATOR_WRITE_ERROR, r#"DatabaseError("Didn\'t work good")"#.to_string())),
        });
        TestLogHandler::new().exists_log_containing(r#"WARN: Configurator: Failed to change password: DatabaseError("Didn\'t work good")"#);
    }

    fn make_subject(persistent_config_opt: Option<PersistentConfigurationMock>) -> Configurator {
        let persistent_config: Box<dyn PersistentConfiguration> = Box::new(persistent_config_opt.unwrap_or(PersistentConfigurationMock::new()));
        Configurator::from(persistent_config)
        }
    }