// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::terminal::terminal_interface::WTermInterface;
use async_trait::async_trait;
use clap::Command as ClapCommand;
use masq_lib::messages::{UiStartOrder, UiStartResponse};
use masq_lib::short_writeln;
use std::default::Default;
use std::fmt::Debug;
use std::sync::Arc;

const START_COMMAND_TIMEOUT_MILLIS: u64 = 15000;
const START_SUBCOMMAND_ABOUT: &str =
    "Starts a MASQNode with the parameters that have been established by 'setup.' \
     Only valid if Node is not already running.";

pub fn start_subcommand() -> ClapCommand {
    ClapCommand::new("start").about(START_SUBCOMMAND_ABOUT)
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct StartCommand {}

#[async_trait]
impl Command for StartCommand {
    async fn execute(
        self: Box<Self>,
        context: &mut dyn CommandContext,
        term_interface: &mut dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let out_message = UiStartOrder {};
        let result: Result<UiStartResponse, CommandError> =
            transaction(out_message, context, stderr, START_COMMAND_TIMEOUT_MILLIS).await;
        match result {
            Ok(response) => {
                short_writeln!(
                    stdout,
                    "MASQNode successfully started in process {} on port {}",
                    response.new_process_id,
                    response.redirect_ui_port
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl StartCommand {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::start_command::{START_COMMAND_TIMEOUT_MILLIS, START_SUBCOMMAND_ABOUT};
    use crate::test_utils::mocks::{CommandContextMock, WTermInterfaceMock};
    use masq_lib::test_utils::fake_stream_holder::ByteArrayHelperMethods;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiStartOrder, UiStartResponse};
    use std::string::ToString;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(START_COMMAND_TIMEOUT_MILLIS, 15000);
        assert_eq!(
            START_SUBCOMMAND_ABOUT,
            "Starts a MASQNode with the parameters that have been established by 'setup.' \
             Only valid if Node is not already running."
        );
    }

    #[tokio::test]
    async fn start_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiStartResponse {
                new_process_id: 1234,
                redirect_ui_port: 4321,
            }
            .tmb(0)));
        let mut term_interface = WTermInterfaceMock::default();
        let stdout_arc = term_interface.stdout_arc().clone();
        let stderr_arc = term_interface.stderr_arc().clone();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["start".to_string()]).unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiStartOrder {}.tmb(0), START_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode successfully started in process 1234 on port 4321\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }
}
