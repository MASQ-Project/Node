use clap::{SubCommand, Arg, App, AppSettings};
use crate::commands::commands_common::{Command, CommandError, transaction};
use crate::command_context::CommandContext;
use masq_lib::messages::{UiChangePasswordRequest, UiChangePasswordResponse, UiNewPasswordBroadcast};
use std::io::Write;

#[derive(Debug,PartialEq)]
pub struct ChangePasswordCommand {
    old_password: Option<String>,
    new_password: String
}

impl ChangePasswordCommand{
    pub(crate) fn new(pieces: Vec<String>)->Result<Self,String>{
        match pieces.len(){
                3 => match change_password_subcommand().get_matches_from_safe(pieces) {
                            Ok(matches) => {
                                    return Ok(Self{
                                    old_password: Some(matches.value_of("old-db-password")
                                        .expect("change password: Clipy: internal error").to_string()),
                                    new_password: matches.value_of("new-db-password")
                                        .expect("change password: Clipy: internal error").to_string(),
                            })},
                            Err(e) => return Err(format!("{}", e))},
                2 => match change_password_subcommand_initial().get_matches_from_safe(pieces) {
                            Ok(matches) => {
                                    return Ok(Self {
                                    old_password: None,
                                    new_password: matches.value_of("new-db-password")
                                        .expect("change-password: Clipy: internal error").to_string(),
                                })},
                            Err(e) => return Err(format!("{}", e))},

                _ => return Err("change-password: Invalid number of arguments".to_string())
        }
    }

    pub fn handle_broadcast (_msg: UiNewPasswordBroadcast, stdout: &mut dyn Write, _stderr: &mut dyn Write) {
        write! (stdout, "\nThe Node's database password has changed.\n\nmasq> ").expect ("write! failed");
    }
}

impl Command for ChangePasswordCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiChangePasswordRequest {
            old_password_opt: self.old_password.clone(),
            new_password: self.new_password.clone(),
        };
        let _: UiChangePasswordResponse = transaction(input, context, 1000)?;
        writeln!(
            context.stdout(),
            "Database password has been changed"
        )
            .expect("writeln! failed");
        Ok(())
    }
}

pub fn change_password_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("change-password")
        .about("XXXXXXXXXXXXXXXX")                  //TODO write info
        .arg(Arg::with_name ("old-db-password")
            .help ("XXXXXXXXXXXXXXXXXX")         //TODO
            .index (1)
            .required (true)
            .case_insensitive(false))
        .arg(Arg::with_name("new-db-password")
            .help ("XXXXXXXXXXXXXXXXXX")        //TODO
            .index (2)
            .required (true)
            .case_insensitive(false))
}

pub fn change_password_subcommand_initial() -> App<'static, 'static> {
    SubCommand::with_name("change-password")
        .about("XXXXXXXXXXXXXXXX")                    //TODO write info
        .arg(Arg::with_name("new-db-password")
            .help("XXXXXXXXXXXXXXXXXX")       //TODO
            .index(1)
            .required(true)
            .case_insensitive(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse};
    use std::sync::{Arc, Mutex};
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::Other;
    use crate::commands::commands_common::CommandError;

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Ok(UiChangePasswordResponse {}.tmb(1230)));
        let subject = factory
            .make(vec!["change-password".to_string(), "abracadabra".to_string(), "boringPassword".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn change_password_command_works_when_changing_from_no_password() {

        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiChangePasswordResponse{}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["change-password".to_string(), "abracadabra".to_string()])
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
                    .tmb(0),  // there is hard-coded 0 as irrelevant in configurator, nothing else can come back
                1000
            )]
        )
    }

    #[test]
    fn change_password_command_changed_db_password_successfully_with_both_parameters_supplied() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiChangePasswordResponse{}.tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["change-password".to_string(), "abracadabra".to_string(), "boringPassword".to_string()])
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

    // #[test]
    // fn clipy_argues_about_typo_in_arguments_for_short_command() {
    //     let result:Result<ChangePasswordCommand,String> = ChangePasswordCommand::new(
    //         vec!["cha-word".to_string(),"myIdeas".to_string(),"yourIdeas".to_string()]);
    //
    //     assert_eq!(result, Err("change-password: Invalid number of arguments".to_string()))
    // }

    #[test]
    fn change_password_new_handles_error_of_missing_both_arguments() {
        let result = ChangePasswordCommand::new(
            vec!["change-password".to_string()]);

        assert_eq!(result, Err("change-password: Invalid number of arguments".to_string()))
    }

    #[test]
    fn change_password_command_with_one_arg_causes_error_when_password_already_exists() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(Other("Database password already exists".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["change-password".to_string(), "abracadabra".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(CommandError::Transmission("Database password already exists".to_string())));   // TODO error type transmission?

        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiChangePasswordRequest {
                    old_password_opt: None,
                    new_password: "abracadabra".to_string()
                }
                    .tmb(0),
                1000
            )]
        )
    }

    #[test]
    fn change_password_command_with_two_args_causes_error_when_no_password_exists() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(Other("There is no password to be changed".to_string())));    // TODO..is there a proper reaction on the side of Deamon?
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec!["change-password".to_string(),"boring*** password".to_string(), "abracadabra".to_string()])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(CommandError::Transmission("There is no password to be changed".to_string())));   // TODO really error type transmission?

        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiChangePasswordRequest {
                    old_password_opt: Some("boring*** password".to_string()),
                    new_password: "abracadabra".to_string()
                }
                    .tmb(0),
                1000
            )]
        )
    }
}



