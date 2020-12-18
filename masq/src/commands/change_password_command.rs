use clap::{SubCommand, Arg, App};
use crate::commands::commands_common::{Command, CommandError, transaction};
use crate::command_context::CommandContext;
use masq_lib::messages::{UiChangePasswordRequest, UiChangePasswordResponse};

#[derive(Debug)]
pub struct ChangePasswordCommand {
    old_password: Option<String>,
    new_password: String
}

impl ChangePasswordCommand{
    pub(crate) fn new(pieces: Vec<String>)->Result<Self,String>{
        let matches = match change_password_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        Ok(Self{
            old_password: matches.value_of("old-db-password")
                .map(|r| r.to_string()),
            new_password: matches.value_of("new-db-password")
                .expect("New password was omitted while required").to_string(),  // I suppose Clap will take care of that; edit: now also tested
        })
    }
}

impl Command for ChangePasswordCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiChangePasswordRequest {
            old_password_opt: self.old_password.clone(),
            new_password: self.new_password.clone(),
        };
        let msg:UiChangePasswordResponse = transaction(input, context, 1000)?;
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
        .about("XXXXXXXXXXXXXXXX")    //TODO write info
        .arg(Arg::with_name ("old-db-password")
            .help ("XXXXXXXXXXXXXXXXXX")  //TODO
            .index (1)
            .required (true)
            .case_insensitive(false))
        .arg(Arg::with_name("new-db-password")
            .help ("XXXXXXXXXXXXXXXXXX")  //TODO
            .index (2)
            .required (true)
            .case_insensitive(false))

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal, CommandFactoryError};
    use crate::commands::commands_common::{Command, CommandError};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse};
    use std::sync::{Arc, Mutex};

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
    fn change_password_command_changed_db_password_successfully_with_both_parameters_supplied() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiChangePasswordResponse {}.tmb(0)));
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
                    .tmb(0),  // there is hard-coded 0 as irrelevant in configurator, nothing else can come back
                1000
            )]
        )
    }

    #[test]
    fn change_password_new_handles_error_of_missing_second_argument() {
        let result:Result<(),String> = if let Err(e) = ChangePasswordCommand::new(
            vec!["change-password"
                .to_string(),"abracadabra"
                .to_string()])
        {Err(e)} else {Ok(())};

        assert!(result.is_err())     //error message is too long (chained) and messy, try later, could be more clear
    }
}


