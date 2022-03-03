// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{send, Command, CommandError};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::UiCrashRequest;
use std::fmt::Debug;

#[derive(Debug)]
pub struct CrashCommand {
    actor: String,
    panic_message: String,
}

const CRASH_COMMAND_ABOUT: &str =
    "Causes an element of the Node to crash with a specified message. \
     Only valid if the Node has been started with '--crash-point message'";
const ACTOR_ARG_HELP: &str = "Name of actor inside the Node that should be made to crash";
const MESSAGE_ARG_HELP: &str = "Panic message that should be produced by the crash";
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

pub fn crash_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("crash")
        .about(CRASH_COMMAND_ABOUT)
        .arg(
            Arg::with_name("actor")
                .help(ACTOR_ARG_HELP)
                .index(1)
                .possible_values(&ACTOR_ARG_POSSIBLE_VALUES)
                .case_insensitive(true)
                .default_value(ACTOR_ARG_DEFAULT_VALUE),
        )
        .arg(
            Arg::with_name("message")
                .help(MESSAGE_ARG_HELP)
                .index(2)
                .default_value(MESSAGE_ARG_DEFAULT_VALUE),
        )
}

impl Command for CrashCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiCrashRequest {
            actor: self.actor.clone(),
            panic_message: self.panic_message.clone(),
        };
        let result = send(input, context);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl CrashCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match crash_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            actor: matches
                .value_of("actor")
                .expect("actor parameter is not properly defaulted")
                .to_uppercase(),
            panic_message: matches
                .value_of("message")
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
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::ToMessageBody;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CRASH_COMMAND_ABOUT,
            "Causes an element of the Node to crash with a specified message. \
             Only valid if the Node has been started with '--crash-point message'"
        );
        assert_eq!(
            ACTOR_ARG_HELP,
            "Name of actor inside the Node that should be made to crash"
        );
        assert_eq!(
            MESSAGE_ARG_HELP,
            "Panic message that should be produced by the crash"
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

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().send_result(Ok(()));
        let subject = factory
            .make(&[
                "crash".to_string(),
                "Dispatcher".to_string(),
                "panic message".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn crash_command_with_a_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "crash".to_string(),
                "blocKChainbRidge".to_string(),
                "These are the times".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
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

    #[test]
    fn crash_command_without_actor_or_message() {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["crash".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
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

    #[test]
    fn crash_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .send_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = CrashCommand::new(&[
            "crash".to_string(),
            "BlockchainBridge".to_string(),
            "message".to_string(),
        ])
        .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
