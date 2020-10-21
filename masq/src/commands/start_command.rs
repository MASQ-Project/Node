// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, SubCommand};
use masq_lib::messages::{UiStartOrder, UiStartResponse};
use std::default::Default;
use std::fmt::Debug;

pub fn start_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("start")
        .about("Starts a MASQNode with the parameters that have been established by 'setup.' Only valid if Node is not already running.")
}

#[derive(Debug, PartialEq, Default)]
pub struct StartCommand {}

impl Command for StartCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiStartOrder {};
        let result: Result<UiStartResponse, CommandError> =
            transaction(out_message, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match result {
            Ok(response) => {
                writeln!(
                    context.stdout(),
                    "MASQNode successfully started in process {} on port {}",
                    response.new_process_id,
                    response.redirect_ui_port,
                )
                .expect("write! failed");
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
    // use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::STANDARD_COMMAND_TIMEOUT_MILLIS;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiStartOrder, UiStartResponse};
    use std::string::ToString;
    use std::sync::{Arc, Mutex};

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
        let subject = factory.make(vec!["start".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiStartOrder {}.tmb(0), STANDARD_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode successfully started in process 1234 on port 4321\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }
}
