// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{UiSetMinHopsRequest, UiSetMinHopsResponse};
use std::fmt::Debug;

#[derive(Debug)]
pub struct MinHopsSubCommand {
    value: u8,
}

const MIN_HOPS_ABOUT: &str = "Sets the value of the minimum hops count in Node.";
const MIN_HOPS_HELP: &str = "Enter the count as an argument. 3-hops is required for anonymity.";

pub fn min_hops_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("min-hops").about(MIN_HOPS_ABOUT).arg(
        Arg::with_name("value")
            .help(MIN_HOPS_HELP)
            .index(1)
            .possible_values(&["1", "2", "3", "4", "5", "6"])
            .required(true),
    )
}

impl Command for MinHopsSubCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiSetMinHopsRequest {
            min_hops_count: self.value,
        };
        let result = transaction::<UiSetMinHopsRequest, UiSetMinHopsResponse>(
            input,
            context,
            STANDARD_COMMAND_TIMEOUT_MILLIS,
        );
        match result {
            Ok(_response) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl MinHopsSubCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match min_hops_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        let input_string = matches
            .value_of("value")
            .expect("value parameter is not properly required");
        let value: u8 = match input_string {
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            "5" => 5,
            "6" => 6,
            _ => panic!("Invalid input string!"),
        };

        Ok(Self { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiSetMinHopsResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            MIN_HOPS_ABOUT,
            "Sets the value of the minimum hops count in Node."
        );
        assert_eq!(
            MIN_HOPS_HELP,
            "Enter the count as an argument. 3-hops is required for anonymity."
        );
    }

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context =
            CommandContextMock::new().transact_result(Ok(UiSetMinHopsResponse {}.tmb(0)));
        let subject = factory
            .make(&["min-hops".to_string(), "3".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn min_hops_subcommand_works() {
        min_hops_subcommand_works_for_value(1);
        min_hops_subcommand_works_for_value(2);
        min_hops_subcommand_works_for_value(3);
        min_hops_subcommand_works_for_value(4);
        min_hops_subcommand_works_for_value(5);
        min_hops_subcommand_works_for_value(6);
    }

    fn min_hops_subcommand_works_for_value(value: u8) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetMinHopsResponse {}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["min-hops".to_string(), value.to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetMinHopsRequest {
                    min_hops_count: value
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        )
    }

    #[test]
    fn scan_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = MinHopsSubCommand::new(&["min-hops".to_string(), "3".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
