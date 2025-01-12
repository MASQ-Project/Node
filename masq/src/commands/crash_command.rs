// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{send_non_conversational_msg, Command, CommandError};
use crate::terminal::WTermInterface;
use async_trait::async_trait;
use clap::builder::PossibleValuesParser;
use clap::{Arg, Command as ClapCommand};
use masq_lib::messages::UiCrashRequest;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug)]
pub struct CrashCommand {
    actor: String,
    panic_message: String,
}

const CRASH_COMMAND_ABOUT: &str =
    "Causes an element of the Node to crash with a specified message. \
     Only valid if the Node has been started with '--crash-point message'.";
const ACTOR_ARG_HELP: &str = "Name of actor inside the Node that should be made to crash.";
const MESSAGE_ARG_HELP: &str = "Panic message that should be produced by the crash.";
const ACTOR_ARG_POSSIBLE_VALUES: [&str; 5] = [
    "BlockchainBridge",
    "Dispatcher",
    "Accountant",
    "Configurator",
    // "Hopper",
    "Neighborhood",
    // "ProxyClient",
    // "ProxyServer",
    // "UiGateway", // This should be the default, when it comes in
    // "StreamHandlerPool",
];
const ACTOR_ARG_DEFAULT_VALUE: &str = "BlockchainBridge";
const MESSAGE_ARG_DEFAULT_VALUE: &str = "Intentional crash";

pub fn crash_subcommand() -> ClapCommand {
    ClapCommand::new("crash")
        .about(CRASH_COMMAND_ABOUT)
        .arg(
            Arg::new("actor")
                .help(ACTOR_ARG_HELP)
                .index(1)
                .value_parser(PossibleValuesParser::new(&ACTOR_ARG_POSSIBLE_VALUES))
                .ignore_case(true)
                .default_value(ACTOR_ARG_DEFAULT_VALUE),
        )
        .arg(
            Arg::new("message")
                .help(MESSAGE_ARG_HELP)
                .index(2)
                .default_value(MESSAGE_ARG_DEFAULT_VALUE),
        )
}

#[async_trait(?Send)]
impl Command for CrashCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        _term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let input = UiCrashRequest {
            actor: self.actor.clone(),
            panic_message: self.panic_message.clone(),
        };
        let result = send_non_conversational_msg(input, context).await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl CrashCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match crash_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            actor: matches
                .get_one::<String>("actor")
                .expect("actor parameter is not properly defaulted")
                .to_uppercase(),
            panic_message: matches
                .get_one::<String>("message")
                .expect("message parameter is not properly defaulted")
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::{CommandContextMock, MockTerminalMode, TermInterfaceMock};
    use masq_lib::messages::ToMessageBody;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CRASH_COMMAND_ABOUT,
            "Causes an element of the Node to crash with a specified message. \
             Only valid if the Node has been started with '--crash-point message'."
        );
        assert_eq!(
            ACTOR_ARG_HELP,
            "Name of actor inside the Node that should be made to crash."
        );
        assert_eq!(
            MESSAGE_ARG_HELP,
            "Panic message that should be produced by the crash."
        );
        assert_eq!(
            ACTOR_ARG_POSSIBLE_VALUES,
            [
                "BlockchainBridge",
                "Dispatcher",
                "Accountant",
                "Configurator",
                "Neighborhood",
            ]
        );
        assert_eq!(ACTOR_ARG_DEFAULT_VALUE, "BlockchainBridge");
        assert_eq!(MESSAGE_ARG_DEFAULT_VALUE, "Intentional crash");
    }

    #[tokio::test]
    async fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().send_one_way_result(Ok(()));
        let (mut term_interface, stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let subject = factory
            .make(&[
                "crash".to_string(),
                "Dispatcher".to_string(),
                "panic message".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn crash_command_with_a_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_one_way_params(&send_params_arc)
            .send_one_way_result(Ok(()));
        let (mut term_interface, stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "crash".to_string(),
                "blocKChainbRidge".to_string(),
                "These are the times".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        stream_handles.assert_empty_stdout();
        stream_handles.assert_empty_stderr();
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(
            *send_params,
            vec![UiCrashRequest {
                actor: "BLOCKCHAINBRIDGE".to_string(),
                panic_message: "These are the times".to_string()
            }
            .tmb(0)]
        )
    }

    #[tokio::test]
    async fn crash_command_without_actor_or_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_one_way_params(&send_params_arc)
            .send_one_way_result(Ok(()));
        let (mut term_interface, stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["crash".to_string()]).unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        stream_handles.assert_empty_stdout();
        stream_handles.assert_empty_stderr();
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(
            *send_params,
            vec![UiCrashRequest {
                actor: "BLOCKCHAINBRIDGE".to_string(),
                panic_message: "Intentional crash".to_string()
            }
            .tmb(0)]
        )
    }

    #[tokio::test]
    async fn crash_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .send_one_way_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let (mut term_interface, stream_handles) =
            TermInterfaceMock::new_non_interactive();
        let subject = CrashCommand::new(&[
            "crash".to_string(),
            "BlockchainBridge".to_string(),
            "message".to_string(),
        ])
        .unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
