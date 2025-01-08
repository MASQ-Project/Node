// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::terminal::WTermInterface;
use async_trait::async_trait;
use clap::builder::PossibleValuesParser;
use clap::{Arg, Command as ClapCommand};
use masq_lib::messages::{ScanType, UiScanRequest, UiScanResponse};
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;

pub const SCAN_COMMAND_TIMEOUT_MILLIS: u64 = 10000;

#[derive(Debug)]
pub struct ScanCommand {
    name: String,
}

const SCAN_SUBCOMMAND_ABOUT: &str =
    "Orders the Node to perform an immediate scan of the indicated type.";
const SCAN_SUBCOMMAND_HELP: &str = "Type of the scan that should be triggered.";

pub fn scan_subcommand() -> ClapCommand {
    ClapCommand::new("scan").about(SCAN_SUBCOMMAND_ABOUT).arg(
        Arg::new("name")
            .help(SCAN_SUBCOMMAND_HELP)
            .index(1)
            .value_parser(PossibleValuesParser::new(&[
                "payables",
                "receivables",
                "pendingpayables",
            ]))
            .required(true)
            .ignore_case(true),
    )
}

#[async_trait(?Send)]
impl Command for ScanCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let input = UiScanRequest {
            scan_type: match ScanType::from_str(&self.name) {
                Ok(st) => st,
                Err(s) => panic!("clap schema does not restrict scan type properly: {}", s),
            },
        };
        let result: Result<UiScanResponse, CommandError> =
            transaction(input, context, &stderr, SCAN_COMMAND_TIMEOUT_MILLIS).await;
        match result {
            Ok(_response) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ScanCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match scan_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            name: matches
                .get_one::<String>("name")
                .expect("name parameter is not properly required")
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
    use masq_lib::messages::{ToMessageBody, UiScanRequest};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            SCAN_SUBCOMMAND_ABOUT,
            "Orders the Node to perform an immediate scan of the indicated type."
        );
        assert_eq!(
            SCAN_SUBCOMMAND_HELP,
            "Type of the scan that should be triggered."
        );
    }

    #[tokio::test]
    async fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiScanResponse {}.tmb(0)));
        let subject = factory
            .make(&["scan".to_string(), "payables".to_string()])
            .unwrap();
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn scan_command_works() {
        scan_command_for_name("payables", ScanType::Payables);
        scan_command_for_name("receivables", ScanType::Receivables);
        scan_command_for_name("pendingpayables", ScanType::PendingPayables);
    }

    async fn scan_command_for_name(name: &str, scan_type: ScanType) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiScanResponse {}.tmb(0)));
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["scan".to_string(), name.to_string()])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        stream_handles.assert_empty_stdout();
        stream_handles.assert_empty_stderr();
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiScanRequest { scan_type }.tmb(0),
                SCAN_COMMAND_TIMEOUT_MILLIS
            )]
        )
    }

    #[tokio::test]
    async fn scan_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = ScanCommand::new(&["scan".to_string(), "payables".to_string()]).unwrap();
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
