// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::CommandError::{
    ConnectionDropped, Payload, Transmission, UnexpectedResponse,
};
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::fmt::Debug;

#[derive(Debug, PartialEq)]
pub enum CommandError {
    ConnectionRefused(String),
    ConnectionDropped(String),
    Transmission(String),
    Reception(String),
    UnexpectedResponse(UiMessageError),
    Payload(u64, String),
    Other(String),
}

pub trait Command: Debug {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError>;
}

pub fn transaction<I, O>(input: I, context: &mut dyn CommandContext) -> Result<O, CommandError>
where
    I: ToMessageBody,
    O: FromMessageBody,
{
    let ntum: NodeToUiMessage = match context.transact(NodeFromUiMessage {
        client_id: 0,
        body: input.tmb(0),
    }) {
        Ok(ntum) => ntum,
        Err(ContextError::ConnectionRefused(s)) => unimplemented!("{}", s),
        Err(ContextError::ConnectionDropped(s)) => return Err(ConnectionDropped(s)),
        Err(ContextError::PayloadError(code, message)) => return Err(Payload(code, message)),
        Err(ContextError::RedirectFailure(e)) => panic!("Couldn't redirect to Node: {:?}", e),
        Err(ContextError::Other(msg)) => return Err(Transmission(msg)),
    };
    let response: O = match O::fmb(ntum.body) {
        Ok((r, _)) => r,
        Err(e) => {
            writeln!(
                context.stderr(),
                "Node or Daemon is acting erratically: {}",
                e
            )
            .expect("write! failed");
            return Err(UnexpectedResponse(e));
        }
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::commands::commands_common::CommandError::{
        Payload, Transmission, UnexpectedResponse,
    };
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{UiStartOrder, UiStartResponse};
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use masq_lib::ui_gateway::{MessageBody, NodeToUiMessage};

    #[test]
    fn two_way_transaction_passes_dropped_connection_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context);

        assert_eq!(result, Err(ConnectionDropped("booga".to_string())));
    }

    #[test]
    fn two_way_transaction_passes_payload_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::PayloadError(10, "booga".to_string())));

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context);

        assert_eq!(result, Err(Payload(10, "booga".to_string())));
    }

    #[test]
    fn two_way_transaction_passes_other_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::Other("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context);

        assert_eq!(result, Err(Transmission("booga".to_string())));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn two_way_transaction_handles_deserialization_error() {
        let mut context = CommandContextMock::new().transact_result(Ok(NodeToUiMessage {
            target: ClientId(0),
            body: MessageBody {
                opcode: "booga".to_string(),
                path: Conversation(1234),
                payload: Ok("unparseable".to_string()),
            },
        }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context);

        assert_eq!(
            result,
            Err(UnexpectedResponse(UiMessageError::UnexpectedMessage(
                "booga".to_string(),
                Conversation(1234)
            )))
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(), "Node or Daemon is acting erratically: Unexpected two-way message from context 1234 with opcode 'booga'\n".to_string());
    }
}
