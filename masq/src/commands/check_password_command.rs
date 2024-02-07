// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::as_any_ref_in_trait_impl;
use masq_lib::messages::{UiCheckPasswordRequest, UiCheckPasswordResponse};
use masq_lib::short_writeln;
use masq_lib::utils::to_string;

#[derive(Debug, PartialEq, Eq)]
pub struct CheckPasswordCommand {
    pub db_password_opt: Option<String>,
}

const CHECK_PASSWORD_ABOUT: &str =
    "Checks whether the supplied db-password (if any) is the correct password for the Node's database.";
const DB_PASSWORD_ARG_HELP: &str =
    "Password to check--leave it out if you think the database doesn't have a password yet.";

pub fn check_password_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("check-password")
        .about(CHECK_PASSWORD_ABOUT)
        .arg(
            Arg::with_name("db-password")
                .help(DB_PASSWORD_ARG_HELP)
                .index(1)
                .required(false)
                .case_insensitive(false),
        )
}

impl Command for CheckPasswordCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiCheckPasswordRequest {
            db_password_opt: self.db_password_opt.clone(),
        };
        let msg: UiCheckPasswordResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        short_writeln!(
            context.stdout(),
            "{}",
            if msg.matches {
                "Password is correct"
            } else {
                "Password is incorrect"
            }
        );
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

impl CheckPasswordCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match check_password_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            db_password_opt: matches.value_of("db-password").map(to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::commands::commands_common::{Command, CommandError};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiCheckPasswordRequest, UiCheckPasswordResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CHECK_PASSWORD_ABOUT,
            "Checks whether the supplied db-password (if any) is the correct password for the Node's database."
        );
        assert_eq!(
            DB_PASSWORD_ARG_HELP,
            "Password to check--leave it out if you think the database doesn't have a password yet."
        );
    }

    #[test]
    fn testing_command_factory_with_good_command() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&["check-password".to_string(), "bonkers".to_string()])
            .unwrap();

        let check_password_command: &CheckPasswordCommand = result.as_any().downcast_ref().unwrap();
        assert_eq!(
            check_password_command,
            &CheckPasswordCommand {
                db_password_opt: Some("bonkers".to_string()),
            }
        );
    }

    #[test]
    fn testing_command_factory_with_bad_command() {
        let subject = CommandFactoryReal::new();

        let result = subject.make(&[
            "check-password".to_string(),
            "bonkers".to_string(),
            "invalid".to_string(),
        ]);

        match result {
            Err(CommandFactoryError::CommandSyntax(msg)) => {
                // Note: when run with MASQ/Node/ci/all.sh, msg contains escape sequences for color.
                assert_eq!(
                    msg.contains("which wasn't expected, or isn't valid in this context"),
                    true,
                    "{}",
                    msg
                )
            }
            x => panic!("Expected CommandSyntax error, got {:?}", x),
        }
    }

    #[test]
    fn check_password_command_with_a_password_right() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiCheckPasswordResponse { matches: true }.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["check-password".to_string(), "bonkers".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Password is correct\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiCheckPasswordRequest {
                    db_password_opt: Some("bonkers".to_string()),
                }
                .tmb(0),
                1000
            )]
        )
    }

    #[test]
    fn check_password_command_with_no_password_wrong() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiCheckPasswordResponse { matches: false }.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["check-password".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Password is incorrect\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiCheckPasswordRequest {
                    db_password_opt: None,
                }
                .tmb(0),
                1000
            )]
        )
    }

    #[test]
    fn check_password_command_handles_send_failure() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::ConnectionDropped("tummyache".to_string()),
        ));
        let subject =
            CheckPasswordCommand::new(&["check-password".to_string(), "bonkers".to_string()])
                .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("tummyache".to_string()))
        )
    }
}
