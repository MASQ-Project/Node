// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::masq_short_writeln;
use crate::terminal::WTermInterface;
use async_trait::async_trait;
use clap::{Arg, Command as ClapCommand};
use masq_lib::implement_as_any;
use masq_lib::messages::{UiCheckPasswordRequest, UiCheckPasswordResponse};
#[cfg(test)]
use std::any::Any;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub struct CheckPasswordCommand {
    pub db_password_opt: Option<String>,
}

const CHECK_PASSWORD_ABOUT: &str =
    "Checks whether the supplied db-password (if any) is the correct password for the Node's database.";
const DB_PASSWORD_ARG_HELP: &str =
    "Password to check--leave it out if you think the database doesn't have a password yet.";

pub fn check_password_subcommand() -> ClapCommand {
    ClapCommand::new("check-password")
        .about(CHECK_PASSWORD_ABOUT)
        .arg(
            Arg::new("db-password")
                .help(DB_PASSWORD_ARG_HELP)
                .index(1)
                .required(false)
                .ignore_case(false),
        )
}

#[async_trait(?Send)]
impl Command for CheckPasswordCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();

        let input = UiCheckPasswordRequest {
            db_password_opt: self.db_password_opt.clone(),
        };
        let msg: UiCheckPasswordResponse =
            transaction(input, context, &stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await?;
        masq_short_writeln!(
            stdout,
            "{}",
            if msg.matches {
                "Password is correct"
            } else {
                "Password is incorrect"
            }
        );
        Ok(())
    }

    implement_as_any!();
}

impl CheckPasswordCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match check_password_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self {
            db_password_opt: matches.get_one::<String>("db-password").map(|r| r.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::commands::commands_common::{Command, CommandError};
    use crate::terminal::test_utils::allow_spawned_tasks_to_finish;
    use crate::test_utils::mocks::{CommandContextMock, MockTerminalMode, TermInterfaceMock};
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
                assert_eq!(msg.contains("unexpected argument"), true, "{}", msg)
            }
            x => panic!("Expected CommandSyntax error, got {:?}", x),
        }
    }

    #[tokio::test]
    async fn check_password_command_with_a_password_right() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiCheckPasswordResponse { matches: true }.tmb(0)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&["check-password".to_string(), "bonkers".to_string()])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        allow_spawned_tasks_to_finish().await;
        assert_eq!(result, Ok(()));
        assert_eq!(stream_handles.stdout_all_in_one(), "Password is correct\n");
        stream_handles.assert_empty_stderr();
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

    #[tokio::test]
    async fn check_password_command_with_no_password_wrong() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiCheckPasswordResponse { matches: false }.tmb(0)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let factory = CommandFactoryReal::new();
        let subject = factory.make(&["check-password".to_string()]).unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        allow_spawned_tasks_to_finish().await;
        assert_eq!(result, Ok(()));
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            "Password is incorrect\n"
        );
        stream_handles.assert_empty_stderr();
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

    #[tokio::test]
    async fn check_password_command_handles_send_failure() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::ConnectionDropped("tummyache".to_string()),
        ));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let subject =
            CheckPasswordCommand::new(&["check-password".to_string(), "bonkers".to_string()])
                .unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        assert_eq!(
            result,
            Err(CommandError::ConnectionProblem("tummyache".to_string()))
        )
    }
}
