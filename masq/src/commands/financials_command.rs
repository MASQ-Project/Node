// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, SubCommand};
use masq_lib::messages::{UiFinancialsRequest, UiFinancialsResponse};
use masq_lib::short_writeln;
use std::fmt::Debug;

const FINANCIALS_SUBCOMMAND_ABOUT: &str =
    "Displays financial statistics of this Node. Only valid if Node is already running.";

#[derive(Debug)]
pub struct FinancialsCommand {}

pub fn financials_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("financials").about(FINANCIALS_SUBCOMMAND_ABOUT)
}

impl Command for FinancialsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiFinancialsRequest {};
        let output: Result<UiFinancialsResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                let stdout = context.stdout();
                short_writeln!(stdout, "Financial status totals in Gwei\n");
                dump_parameter_line(
                    stdout,
                    "Unpaid and pending payable:",
                    &response.total_unpaid_and_pending_payable.to_string(),
                );
                dump_parameter_line(
                    stdout,
                    "Paid payable:",
                    &response.total_paid_payable.to_string(),
                );
                dump_parameter_line(
                    stdout,
                    "Unpaid receivable:",
                    &response.total_unpaid_receivable.to_string(),
                );
                dump_parameter_line(
                    stdout,
                    "Paid receivable:",
                    &response.total_paid_receivable.to_string(),
                );
                Ok(())
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Financials retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }
}

impl Default for FinancialsCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl FinancialsCommand {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiFinancialsResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            FINANCIALS_SUBCOMMAND_ABOUT,
            "Displays financial statistics of this Node. Only valid if Node is already running."
        );
    }

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiFinancialsResponse {
            total_unpaid_and_pending_payable: 0,
            total_paid_payable: 1111,
            total_unpaid_receivable: 2222,
            total_paid_receivable: 3333,
        }
        .tmb(0)));
        let subject = factory.make(&["financials".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn financials_command_happy_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiFinancialsResponse {
            total_unpaid_and_pending_payable: 116688,
            total_paid_payable: 55555,
            total_unpaid_receivable: 221144,
            total_paid_receivable: 66555,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(31)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\
                Financial status totals in Gwei\n\
                \n\
                Unpaid and pending payable:       116688\n\
                Paid payable:                     55555\n\
                Unpaid receivable:                221144\n\
                Paid receivable:                  66555\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn financials_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = FinancialsCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiFinancialsRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Financials retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
