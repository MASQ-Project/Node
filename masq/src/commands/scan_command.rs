// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{send, Command, CommandError};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{UiScanRequest};
use std::fmt::Debug;

#[derive(Debug)]
pub struct ScanCommand {
    name: String,
}

pub fn scan_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("scan")
        .about("Orders the Node to perform an immediate scan of the indicated type")
        .arg(
            Arg::with_name("name")
                .help("Type of the scan that should be triggered")
                .index(1)
                .possible_values(&["payables", "receivables"])
                .required(true)
                .case_insensitive(true),
        )
}

impl Command for ScanCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiScanRequest {
            name: self.name.clone(),
        };
        let result = send(input, context);
        match result {
            Ok(_) => Ok(()),
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
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().send_result(Ok(()));
        let subject = factory
            .make(&["scan".to_string(), "payables".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn scan_command_works() {
        scan_command_for_name("payables");
        scan_command_for_name("receivables");
    }

    fn scan_command_for_name(name: &str) {
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .send_params(&send_params_arc)
            .send_result(Ok(()));
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
        let send_params = send_params_arc.lock().unwrap();
        assert_eq!(
            *send_params,
            vec![UiScanRequest {
                name: name.to_string(),
            }
            .tmb(0)]
        )
    }

    #[test]
    fn scan_command_handles_send_failure() {
        let mut context = CommandContextMock::new()
            .send_result(Err(ContextError::ConnectionDropped("blah".to_string())));
        let subject = ScanCommand::new(&["scan".to_string(), "payables".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("blah".to_string()))
        )
    }
}
