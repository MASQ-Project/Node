use actix::{Handler, Actor, Context, Recipient};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage, MessageTarget, MessageBody, MessagePath};
use crate::sub_lib::peer_actors::BindMessage;
use crate::db_config::persistent_configuration::{PersistentConfiguration, PersistentConfigurationReal};
use crate::database::db_initializer::{DbInitializerReal, DbInitializer};
use std::path::PathBuf;
use crate::db_config::config_dao::ConfigDaoReal;
use masq_lib::messages::{UiChangePasswordRequest, FromMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse, ToMessageBody};
use masq_lib::ui_gateway::MessageTarget::ClientId;
use crate::sub_lib::logger::Logger;

pub const CONFIGURATOR_PREFIX: u64 = 0x0001_0000_0000_0000;
pub const CONFIGURATOR_WRITE_ERROR: u64 = CONFIGURATOR_PREFIX | 1;

pub struct Configurator {
    persistent_config: Box<dyn PersistentConfiguration>,
    node_to_ui_sub: Option<Recipient<NodeToUiMessage>>,
    logger: Logger,
}

impl Actor for Configurator {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.node_to_ui_sub = Some (msg.peer_actors.ui_gateway.node_to_ui_message_sub.clone());
    }
}

impl Handler<NodeFromUiMessage> for Configurator {
    type Result = ();

    fn handle(&mut self, msg: NodeFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        if let Ok((body, context_id)) = UiCheckPasswordRequest::fmb(msg.body) {
            self.reply (ClientId(msg.client_id), self.handle_check_password (body, context_id));
        }
    }
}

impl From<Box<dyn PersistentConfiguration>> for Configurator {
    fn from(persistent_config: Box<dyn PersistentConfiguration>) -> Self {
        Configurator {
            persistent_config,
            node_to_ui_sub: None,
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

    fn handle_check_password (&self, msg: UiCheckPasswordRequest, context_id: u64) -> MessageBody {
        match self.persistent_config.check_password(msg.db_password_opt.clone()) {
            Ok(matches) => UiCheckPasswordResponse { matches }.tmb (context_id),
            Err(e) => {
                warning! (self.logger, "Failed to check password: {:?}", e);
                MessageBody {
                    opcode: msg.opcode().to_string(),
                    path: MessagePath::Conversation(context_id),
                    payload: Err((CONFIGURATOR_WRITE_ERROR, format!("{:?}", e))),
                }
            },
        }
    }

    fn reply (&self, target: MessageTarget, body: MessageBody) {
        let msg = NodeToUiMessage {
            target,
            body
        };
        self.node_to_ui_sub
            .as_ref().expect ("Configurator is unbound")
            .try_send(msg).expect ("UiGateway is dead");
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use actix::{System};
    use crate::test_utils::recorder::{peer_actors_builder, make_recorder};
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use masq_lib::messages::{UiStartOrder, ToMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse};
    use std::sync::{Arc, Mutex};
    use masq_lib::ui_gateway::{MessageTarget, MessagePath};
    use crate::test_utils::logging::{init_test_logging, TestLogHandler};
    use crate::db_config::persistent_configuration::PersistentConfigError;

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
        let (ui_gateway, _, ui_gateway_recording) = make_recorder ();
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
        let recording = ui_gateway_recording.lock().unwrap();
        assert_eq! (recording.get_record::<NodeToUiMessage>(0), &NodeToUiMessage {
            target: MessageTarget::ClientId(1234), 
            body: UiCheckPasswordResponse {
                matches: false
            }.tmb(4321)
        });
        assert_eq! (recording.len(), 1);
    }

    #[test]
    fn handle_check_password_handles_error() {
        init_test_logging();
        let persistent_config = PersistentConfigurationMock::new()
            .check_password_result (Err(PersistentConfigError::NotPresent));
        let subject = make_subject (Some(persistent_config));
        let msg = UiCheckPasswordRequest {db_password_opt: None};

        let result = subject.handle_check_password (msg, 4321);

        assert_eq! (result, MessageBody {
            opcode: "checkPassword".to_string(),
            path: MessagePath::Conversation(4321),
            payload: Err ((CONFIGURATOR_WRITE_ERROR, "NotPresent".to_string()))
        });
        TestLogHandler::new().exists_log_containing("WARN: Configurator: Failed to check password: NotPresent");
    }

    fn make_subject (persistent_config_opt: Option<PersistentConfigurationMock>) -> Configurator {
        let persistent_config: Box<dyn PersistentConfiguration> = Box::new (persistent_config_opt.unwrap_or (PersistentConfigurationMock::new()));
        Configurator::from (persistent_config)
    }
}