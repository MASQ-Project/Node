// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::CommandError::{
    ConnectionProblem, Other, Payload, Reception, Transmission, UnexpectedResponse,
};
use masq_lib::intentionally_blank;
use masq_lib::messages::{FromMessageBody, ToMessageBody, UiMessageError};
use masq_lib::short_writeln;
use masq_lib::ui_gateway::MessageBody;
use std::any::Any;
use std::fmt::Debug;
use std::fmt::Display;
use std::io::Write;

pub const STANDARD_COMMAND_TIMEOUT_MILLIS: u64 = 1000;
pub const STANDARD_COLUMN_WIDTH: usize = 33;

#[derive(Debug, PartialEq, Eq)]
pub enum CommandError {
    ConnectionProblem(String),
    Transmission(String),
    Reception(String),
    UnexpectedResponse(UiMessageError),
    Payload(u64, String),
    Other(String),
}

impl Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            ConnectionProblem(s) => format!("Connection problem: {}", s),
            Transmission(s) => format!("Transmission problem: {}", s),
            Reception(s) => format!("Reception problem: {}", s),
            UnexpectedResponse(e) => format!("{}", e),
            Payload(code, s) => {
                let pure_hex_string = format!("{:016X}", code);
                let expanded_hex_string = format!(
                    "{}_{}_{}_{}",
                    &pure_hex_string[0..4],
                    &pure_hex_string[4..8],
                    &pure_hex_string[8..12],
                    &pure_hex_string[12..16]
                );
                format!("{} (Code {})", s, expanded_hex_string)
            }
            Other(s) => s.to_string(),
        };
        write!(f, "{}", msg)
    }
}

pub trait Command: Debug {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError>;

    fn as_any(&self) -> &dyn Any {
        intentionally_blank!()
    }
}

pub fn send<I>(input: I, context: &mut dyn CommandContext) -> Result<(), CommandError>
where
    I: ToMessageBody,
{
    match context.send(input.tmb(0)) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn transaction<I, O>(
    input: I,
    context: &mut dyn CommandContext,
    timeout_millis: u64,
) -> Result<O, CommandError>
where
    I: ToMessageBody,
    O: FromMessageBody,
{
    let message: MessageBody = match context.transact(input.tmb(0), timeout_millis) {
        Ok(ntum) => ntum,
        Err(e) => return Err(e.into()),
    };
    let response: O = match O::fmb(message) {
        Ok((r, _)) => r,
        Err(e) => {
            short_writeln!(
                context.stderr(),
                "Node or Daemon is acting erratically: {}",
                e
            );
            return Err(UnexpectedResponse(e));
        }
    };
    Ok(response)
}

impl From<ContextError> for CommandError {
    fn from(context_error: ContextError) -> Self {
        match context_error {
            ContextError::ConnectionRefused(s) => ConnectionProblem(s),
            ContextError::ConnectionDropped(s) => ConnectionProblem(s),
            ContextError::PayloadError(code, message) => Payload(code, message),
            ContextError::RedirectFailure(e) => panic!("Couldn't redirect to Node: {:?}", e),
            ContextError::Other(msg) => Transmission(msg),
        }
    }
}

pub(in crate::commands) fn dump_parameter_line(stream: &mut dyn Write, name: &str, value: &str) {
    short_writeln!(
        stream,
        "{:width$} {}",
        name,
        value,
        width = STANDARD_COLUMN_WIDTH
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::commands::commands_common::CommandError::{
        Other, Payload, Reception, Transmission, UnexpectedResponse,
    };
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{UiStartOrder, UiStartResponse};
    use masq_lib::ui_gateway::MessagePath::Conversation;
    use masq_lib::ui_gateway::{MessageBody, MessagePath};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(STANDARD_COMMAND_TIMEOUT_MILLIS, 1000);
        assert_eq!(STANDARD_COLUMN_WIDTH, 33)
    }

    #[test]
    fn two_way_transaction_passes_dropped_connection_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context, 1000);

        assert_eq!(result, Err(ConnectionProblem("booga".to_string())));
    }

    #[test]
    fn two_way_transaction_passes_payload_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::PayloadError(10, "booga".to_string())));

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context, 1000);

        assert_eq!(result, Err(Payload(10, "booga".to_string())));
    }

    #[test]
    fn two_way_transaction_passes_other_error() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::Other("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context, 1000);

        assert_eq!(result, Err(Transmission("booga".to_string())));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn two_way_transaction_handles_deserialization_error() {
        let message_body = MessageBody {
            opcode: "booga".to_string(),
            path: Conversation(1234),
            payload: Ok("unparseable".to_string()),
        };
        let mut context = CommandContextMock::new().transact_result(Ok(message_body.clone()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result: Result<UiStartResponse, CommandError> =
            transaction(UiStartOrder {}, &mut context, 1000);

        assert_eq!(
            result,
            Err(UnexpectedResponse(UiMessageError::UnexpectedMessage(
                message_body
            )))
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq! (stderr_arc.lock().unwrap().get_string(),
                    "Node or Daemon is acting erratically: Unexpected two-way message from context 1234 with opcode 'booga'\nOk(\"unparseable\")\n".to_string());
    }

    #[test]
    fn context_error_converter_happy() {
        check_conversion(
            ContextError::ConnectionDropped("message".to_string()),
            CommandError::ConnectionProblem("message".to_string()),
        );
        check_conversion(
            ContextError::ConnectionRefused("message".to_string()),
            CommandError::ConnectionProblem("message".to_string()),
        );
        check_conversion(
            ContextError::Other("message".to_string()),
            CommandError::Transmission("message".to_string()),
        );
        check_conversion(
            ContextError::PayloadError(1234, "message".to_string()),
            CommandError::Payload(1234, "message".to_string()),
        );
    }

    fn check_conversion(from: ContextError, expected_into: CommandError) {
        let actual_into: CommandError = from.into();
        assert_eq!(actual_into, expected_into);
    }

    #[test]
    fn command_error_displays_properly() {
        assert_eq!(
            format!("{}", ConnectionProblem("string".to_string())),
            "Connection problem: string".to_string()
        );
        assert_eq!(
            format!("{}", Transmission("string".to_string())),
            "Transmission problem: string".to_string()
        );
        assert_eq!(
            format!("{}", Reception("string".to_string())),
            "Reception problem: string".to_string()
        );
        let message_body = MessageBody {
            opcode: "opcode".to_string(),
            path: MessagePath::FireAndForget,
            payload: Err((1234, "booga".to_string())),
        };
        assert_eq!(
            format!(
                "{}",
                UnexpectedResponse(UiMessageError::DeserializationError(
                    "string".to_string(),
                    message_body
                ))
            ),
            "Could not deserialize message from Daemon or Node: string\nErr((1234, \"booga\"))"
                .to_string()
        );
        assert_eq!(
            format!("{}", Payload(1234, "string".to_string())),
            "string (Code 0000_0000_0000_04D2)".to_string()
        );
        assert_eq!(
            format!("{}", Other("string".to_string())),
            "string".to_string()
        );
    }

    #[test]
    #[should_panic(expected = "Couldn't redirect to Node: \"message\"")]
    fn context_error_converter_sad() {
        let _: CommandError = ContextError::RedirectFailure("message".to_string()).into();
    }
}
