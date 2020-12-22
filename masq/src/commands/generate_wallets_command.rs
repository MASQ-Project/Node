use masq_lib::messages::{UiGenerateWalletsRequest, UiGenerateWalletsResponse};
use crate::commands::commands_common::{transaction, CommandError, Command};
use crate::command_context::CommandContext;
use clap::{SubCommand, App, Arg};
use std::any::Any;

#[derive(Debug, PartialEq)]
pub struct GenerateWalletsCommand {
    db_password: String,
    word_count: usize,
    language: String,
    passphrase_opt: Option<String>,
    consuming_path: String,
    earning_path: String,
}

impl GenerateWalletsCommand {
    pub fn new(pieces: Vec<String>) -> Result<Self, String> {
        let matches = match generate_wallets_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => unimplemented!(),
            Err(e) => unimplemented!(),
        };

        Ok(
            GenerateWalletsCommand {
                db_password: "".to_string(),
                word_count: 0,
                language: "".to_string(),
                passphrase_opt: None,
                consuming_path: "".to_string(),
                earning_path: "".to_string(),
            }
        )
    }
}

impl Command for GenerateWalletsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiGenerateWalletsRequest {
            db_password: self.db_password.clone(),
            mnemonic_phrase_size: self.word_count,
            mnemonic_phrase_language: self.language.clone(),
            mnemonic_passphrase_opt: self.passphrase_opt.clone(),
            consuming_derivation_path: self.consuming_path.clone(),
            earning_derivation_path: self.earning_path.clone(),
        };
        let _: UiGenerateWalletsResponse = transaction(input, context, 1000)?;
        unimplemented!();
        //writeln!(context.stdout(), "Database password has been changed").expect("writeln! failed");
        //Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}


pub fn generate_wallets_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("generate-wallets")
        .about("Generate a pair of wallets (consuming and earning) for the Node if they haven't been generated already")
        .arg(Arg::with_name ("db-password")
            .help ("XXX")
            .index (1)
            .required (false)
            .case_insensitive(false)
    )
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse, UiGenerateWalletsRequest, UiGenerateWalletsResponse};
    use std::sync::{Arc, Mutex};
    use std::any::Any;

    #[test]
    fn testing_command_factory_here() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "generate-wallets".to_string(),
                "--db-password".to_string(), "password".to_string(),
                "--word-count".to_string(), "21".to_string(),
                "--language".to_string(), "Korean".to_string(),
                "--passphrase".to_string(), "booga".to_string(),
                "--consuming-path".to_string(), "m/60'/44'/0'/100/0/200".to_string(),
                "--earning-path".to_string(), "m/60'/44'/0'/100/0/201".to_string(),
            ])
            .unwrap();

        let generate_wallets_command: &GenerateWalletsCommand = result.as_any().downcast_ref().unwrap();
        assert_eq! (generate_wallets_command, &GenerateWalletsCommand {
            db_password: "password".to_string(),
            word_count: 21,
            language: "Korean".to_string(),
            passphrase_opt: Some ("booga".to_string()),
            consuming_path: "m/60'/44'/0'/100/0/200".to_string(),
            earning_path: "m/60'/44'/0'/100/0/201".to_string()
        })
    }
}


