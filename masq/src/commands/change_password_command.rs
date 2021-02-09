use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{UiChangePasswordRequest, UiChangePasswordResponse};
use std::any::Any;
use std::io::Write;

#[derive(Debug, PartialEq)]
pub struct ChangePasswordCommand {
    pub old_password: Option<String>,
    pub new_password: String,
}

impl ChangePasswordCommand {
    pub fn new_set(pieces: Vec<String>) -> Result<Self, String> {
        match set_password_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => Ok(Self {
                old_password: None,
                new_password: matches
                    .value_of("new-db-password")
                    .expect("new-db-password is not properly required")
                    .to_string(),
            }),
            Err(e) => Err(format!("{}", e)),
        }
    }

    pub fn new_change(pieces: Vec<String>) -> Result<Self, String> {
        match change_password_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => Ok(Self {
                old_password: Some(
                    matches
                        .value_of("old-db-password")
                        .expect("old-db-password is not properly required")
                        .to_string(),
                ),
                new_password: matches
                    .value_of("new-db-password")
                    .expect("new-db-password is not properly required")
                    .to_string(),
            }),
            Err(e) => Err(format!("{}", e)),
        }
    }

    pub fn handle_broadcast(stdout: &mut dyn Write) {
        write!(
            stdout,
            "\nThe Node's database password has changed.\n\nmasq> "
        )
        .expect("write! failed");
    }
}

impl Command for ChangePasswordCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiChangePasswordRequest {
            old_password_opt: self.old_password.clone(),
            new_password: self.new_password.clone(),
        };
        let _: UiChangePasswordResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        writeln!(context.stdout(), "Database password has been changed").expect("writeln! failed");
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn change_password_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("change-password")
        .about("Changes the existing password on the Node database")
        .arg(
            Arg::with_name("old-db-password")
                .help("The existing password")
                .value_name("OLD-DB-PASSWORD")
                .index(1)
                .required(true)
                .case_insensitive(false),
        )
        .arg(
            Arg::with_name("new-db-password")
                .help("The new password to set")
                .value_name("NEW-DB-PASSWORD")
                .index(2)
                .required(true)
                .case_insensitive(false),
        )
}

pub fn set_password_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("set-password")
        .about("Sets an initial password on the Node database")
        .arg(
            Arg::with_name("new-db-password")
                .help("Password to be set; must not already exist")
                .index(1)
                .required(true)
                .case_insensitive(false),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn set_password_command_works_when_changing_from_no_password() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiChangePasswordResponse {}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["set-password".to_string(), "abracadabra".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Database password has been changed\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiChangePasswordRequest {
                    old_password_opt: None,
                    new_password: "abracadabra".to_string()
                }
                .tmb(0), // there is hard-coded 0
                1000
            )]
        )
    }

    #[test]
    fn change_password_command_changed_db_password_successfully_with_both_parameters_supplied() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiChangePasswordResponse {}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec![
                "change-password".to_string(),
                "abracadabra".to_string(),
                "boringPassword".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Database password has been changed\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiChangePasswordRequest {
                    old_password_opt: Some("abracadabra".to_string()),
                    new_password: "boringPassword".to_string()
                }
                .tmb(0),
                1000
            )]
        )
    }

    #[test]
    fn change_password_command_fails_if_only_one_argument_supplied() {
        let factory = CommandFactoryReal::new();

        let result = factory.make(vec![
            "change-password".to_string(),
            "abracadabra".to_string(),
        ]);

        let msg = match result {
            Err(CommandFactoryError::CommandSyntax(s)) => s,
            x => panic!("Expected CommandSyntax error, found {:?}", x),
        };
        assert_eq!(
            msg.contains("The following required arguments were not provided"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn change_password_new_set_handles_error_of_missing_both_arguments() {
        let result = ChangePasswordCommand::new_set(vec!["set-password".to_string()]);

        let msg = match result {
            Err(s) => s,
            x => panic!("Expected string, found {:?}", x),
        };
        assert_eq!(
            msg.contains("The following required arguments were not provided"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn change_password_new_change_handles_error_of_missing_both_arguments() {
        let result = ChangePasswordCommand::new_change(vec!["change-password".to_string()]);

        let msg = match result {
            Err(s) => s,
            x => panic!("Expected string, found {:?}", x),
        };
        assert_eq!(
            msg.contains("The following required arguments were not provided"),
            true,
            "{}",
            msg
        );
    }
}
