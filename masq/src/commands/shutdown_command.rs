// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::{
    ConnectionDropped, Other, Payload, Transmission,
};
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, SubCommand};
use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse, NODE_NOT_RUNNING_ERROR};
use std::fmt::Debug;
use std::thread;
use std::time::Duration;

const DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL: u64 = 250; // milliseconds
const DEFAULT_SHUTDOWN_ATTEMPT_LIMIT: u64 = 4;

#[derive(Debug, PartialEq)]
pub struct ShutdownCommand {
    attempt_interval: u64,
    attempt_limit: u64,
}

pub fn shutdown_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("shutdown")
        .about("Shuts down the running MASQNode. Only valid if Node is already running.")
}

impl Command for ShutdownCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let mut attempts_remaining = self.attempt_limit;
        let input = UiShutdownRequest {};
        loop {
            let output: Result<UiShutdownResponse, CommandError> =
                transaction(input.clone(), context);
            match output {
                Ok(_) => (),
                Err(ConnectionDropped) => {
                    writeln!(
                        context.stdout(),
                        "MASQNode was instructed to shut down and has broken its connection"
                    )
                    .expect("write! failed");
                    return Ok(());
                }
                Err(Transmission(msg)) => return Err(Transmission(msg)),
                Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                    writeln!(
                        context.stderr(),
                        "MASQNode is not running; therefore it cannot be shut down."
                    )
                    .expect("write! failed");
                    return Err(Payload(code, message));
                }
                Err(impossible) => panic!("Never happen: {:?}", impossible),
            }
            thread::sleep(Duration::from_millis(self.attempt_interval));
            attempts_remaining -= 1;
            if attempts_remaining == 0 {
                writeln!(
                    context.stderr(),
                    "MASQNode ignored the instruction to shut down and is still running"
                )
                .expect("write! failed");
                return Err(Other("Shutdown failed".to_string()));
            }
        }
    }
}

impl Default for ShutdownCommand {
    fn default() -> Self {
        Self {
            attempt_interval: DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL,
            attempt_limit: DEFAULT_SHUTDOWN_ATTEMPT_LIMIT,
        }
    }
}

impl ShutdownCommand {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::Other;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse, NODE_NOT_RUNNING_ERROR};
    use masq_lib::ui_gateway::MessageTarget::ClientId;
    use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    #[test]
    fn shutdown_command_defaults_parameters() {
        let subject = ShutdownCommand::new();

        assert_eq!(subject.attempt_interval, DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL);
        assert_eq!(subject.attempt_limit, DEFAULT_SHUTDOWN_ATTEMPT_LIMIT);
    }

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));
        let subject = factory.make(vec!["shutdown".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn shutdown_command_doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ShutdownCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode is not running; therefore it cannot be shut down.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn shutdown_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let msg = NodeToUiMessage {
            target: ClientId(0),
            body: UiShutdownResponse {}.tmb(0),
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(msg.clone()))
            .transact_result(Ok(msg.clone()))
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let mut subject = ShutdownCommand::new();
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![
                NodeFromUiMessage {
                    client_id: 0,
                    body: UiShutdownRequest {}.tmb(0)
                },
                NodeFromUiMessage {
                    client_id: 0,
                    body: UiShutdownRequest {}.tmb(0)
                },
                NodeFromUiMessage {
                    client_id: 0,
                    body: UiShutdownRequest {}.tmb(0)
                },
            ]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode was instructed to shut down and has broken its connection\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn shutdown_command_uses_interval() {
        let mut context = CommandContextMock::new().transact_result(Ok(NodeToUiMessage {
            target: ClientId(0),
            body: UiShutdownResponse {}.tmb(0),
        }));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let mut subject = ShutdownCommand::new();
        subject.attempt_interval = 100;
        subject.attempt_limit = 1;
        let before = SystemTime::now();

        let result = subject.execute(&mut context);

        let after = SystemTime::now();
        assert_eq!(result, Err(Other("Shutdown failed".to_string())));
        let interval = after.duration_since(before).unwrap().as_millis();
        assert!(
            interval >= subject.attempt_interval as u128,
            "Not waiting long enough per attempt: {} < {}",
            interval,
            subject.attempt_interval
        );
        assert!(
            interval < (subject.attempt_interval as u128 * 5),
            "Waiting too long per attempt: {} >> {}",
            interval,
            subject.attempt_interval
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode ignored the instruction to shut down and is still running\n"
        );
    }
}
