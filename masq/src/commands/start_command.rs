// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::masq_short_writeln;
use crate::terminal::WTermInterface;
use async_trait::async_trait;
use clap::Command as ClapCommand;
use masq_lib::messages::{UiStartOrder, UiStartResponse};
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

#[async_trait(?Send)]
impl Command for StartCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let out_message = UiStartOrder {};
        let result: Result<UiStartResponse, CommandError> =
            transaction(out_message, context, &stderr, START_COMMAND_TIMEOUT_MILLIS).await;
        match result {
            Ok(response) => {
                masq_short_writeln!(
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
    use crate::test_utils::mocks::{CommandContextMock, MockTerminalMode, TermInterfaceMock};
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
        let (mut term_interface, stream_handles) =
            TermInterfaceMock::new_non_interactive();
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
            stream_handles.stdout_all_in_one(),
            "MASQNode successfully started in process 1234 on port 4321\n"
        );
        stream_handles.assert_empty_stderr()
    }
}
