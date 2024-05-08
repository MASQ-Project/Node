// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::Command as ClapCommand;
use masq_lib::messages::{UiStartOrder, UiStartResponse};
use masq_lib::short_writeln;
use std::default::Default;
use std::fmt::Debug;

const START_COMMAND_TIMEOUT_MILLIS: u64 = 15000;
const START_SUBCOMMAND_ABOUT: &str =
    "Starts a MASQNode with the parameters that have been established by 'setup.' \
     Only valid if Node is not already running.";

pub fn start_subcommand() -> ClapCommand {
    ClapCommand::new("start").about(START_SUBCOMMAND_ABOUT)
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct StartCommand {}

impl Command for StartCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiStartOrder {};
        let result: Result<UiStartResponse, CommandError> =
            transaction(out_message, context, START_COMMAND_TIMEOUT_MILLIS);
        match result {
            Ok(response) => {
                short_writeln!(
                    context.stdout(),
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
    use crate::test_utils::mocks::CommandContextMock;
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

    #[test]
    fn start_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiStartResponse {
                new_process_id: 1234,
                redirect_ui_port: 4321,
            }
            .tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["start".to_string()]).unwrap();

        let result = subject.execute(&mut context);

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
