// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{CommendableScanType, UiScanRequest, UiScanResponse};
use std::fmt::Debug;
use std::str::FromStr;

pub const SCAN_COMMAND_TIMEOUT_MILLIS: u64 = 10000;

#[derive(Debug)]
pub struct ScanCommand {
    name: String,
}

const SCAN_SUBCOMMAND_ABOUT: &str =
    "Orders the Node to perform an immediate scan of the indicated type.";
const SCAN_SUBCOMMAND_HELP: &str = "Type of the scan that should be triggered.";

pub fn scan_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("scan")
        .about(SCAN_SUBCOMMAND_ABOUT)
        .arg(
            Arg::with_name("name")
                .help(SCAN_SUBCOMMAND_HELP)
                .index(1)
                .possible_values(&["payables", "receivables", "pendingpayables"])
                .required(true)
                .case_insensitive(true),
        )
}

impl Command for ScanCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiScanRequest {
            scan_type: match CommendableScanType::from_str(&self.name) {
                Ok(st) => st,
                Err(s) => panic!("clap schema does not restrict scan type properly: {}", s),
            },
        };
        let result = transaction::<UiScanRequest, UiScanResponse>(
            input,
            context,
            SCAN_COMMAND_TIMEOUT_MILLIS,
        );
        match result {
            Ok(_response) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl ScanCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match scan_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            name: matches
                .value_of("name")
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
    use crate::test_utils::mocks::CommandContextMock;
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

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiScanResponse {}.tmb(0)));
        let subject = factory
            .make(&["scan".to_string(), "payables".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn scan_command_works() {
        scan_command_for_name("payables", CommendableScanType::Payables);
        scan_command_for_name("receivables", CommendableScanType::Receivables);
        scan_command_for_name("pendingpayables", CommendableScanType::PendingPayables);
    }

    fn scan_command_for_name(name: &str, scan_type: CommendableScanType) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiScanResponse {}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["scan".to_string(), name.to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiScanRequest { scan_type }.tmb(0),
                SCAN_COMMAND_TIMEOUT_MILLIS
            )]
        )
    }

    #[test]
    fn scan_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = ScanCommand::new(&["scan".to_string(), "payables".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
