use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{
    ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse,
    UiNewPasswordBroadcast,
};
use std::io::Write;

#[derive(Debug, PartialEq)]
pub struct ChangePasswordCommand {
    old_password: Option<String>,
    new_password: String,
}

impl ChangePasswordCommand {
    pub(crate) fn new(pieces: Vec<String>) -> Result<Self, String> {
        match pieces.len() {
            3 => match change_password_subcommand().get_matches_from_safe(pieces) {
                Ok(matches) => Ok(Self {
                    old_password: Some(
                        matches
                            .value_of("old-db-password")
                            .expect("change password: Clipy: internal error")
                            .to_string(),
                    ),
                    new_password: matches
                        .value_of("new-db-password")
                        .expect("change password: Clipy: internal error")
                        .to_string(),
                }),
                Err(e) => Err(format!("{}", e)),
            },
            2 => match set_password_subcommand().get_matches_from_safe(pieces) {
                Ok(matches) => Ok(Self {
                    old_password: None,
                    new_password: matches
                        .value_of("new-db-password")
                        .expect("change-password: Clipy: internal error")
                        .to_string(),
                }),
                Err(e) => Err(format!("{}", e)),
            },

            _ => Err("change-password: Invalid number of arguments".to_string()),
        }
    }

    pub fn handle_broadcast(
        _msg: UiNewPasswordBroadcast,
        stdout: &mut dyn Write,
        _stderr: &mut dyn Write,
    ) {
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
        let _: UiChangePasswordResponse = transaction(input, context, 1000)?;
        writeln!(context.stdout(), "Database password has been changed").expect("writeln! failed");
        Ok(())
    }
}

pub fn change_password_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("change-password")
        .about("Changes the existing password on the Node database")
        .arg(
            Arg::with_name("old-db-password")
                .help("The existing password")
                .index(1)
                .required(true)
                .case_insensitive(false),
        )
        .arg(
            Arg::with_name("new-db-password")
                .help("The new password to set")
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
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context =
            CommandContextMock::new().transact_result(Ok(UiChangePasswordResponse {}.tmb(1230)));
        let subject = factory
            .make(vec![
                "change-password".to_string(),
                "abracadabra".to_string(),
                "boringPassword".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

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
    fn change_password_new_handles_error_of_missing_both_arguments() {
        let result = ChangePasswordCommand::new(vec!["change-password".to_string()]);

        assert_eq!(
            result,
            Err("change-password: Invalid number of arguments".to_string())
        )
    }
}
