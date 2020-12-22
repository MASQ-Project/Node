use masq_lib::messages::{UiGenerateWalletsRequest, UiGenerateWalletsResponse};
use crate::commands::commands_common::{transaction, CommandError, Command};
use crate::command_context::CommandContext;
use clap::{SubCommand, App};

#[derive(Debug, PartialEq)]
pub struct GenerateWalletsCommand{
    db_password: String,
    mnemonic_phrase_size: usize,
    mnemonic_phrase_language: String,
    mnemonic_passphrase_opt: Option<String>,
    consuming_derivation_path: String,
    earning_derivation_path: String,
}

impl GenerateWalletsCommand{
    pub fn new(pieces:Vec<String>)->Result<Self,String>{

    let matches = match generate_wallets_subcommand().get_matches_from_safe(pieces){
        Ok(matches) => unimplemented!(),
        Err(e) => unimplemented!(),
    };

    Ok(
        GenerateWalletsCommand{
        db_password: "".to_string(),
        mnemonic_phrase_size: 0,
        mnemonic_phrase_language: "".to_string(),
        mnemonic_passphrase_opt: None,
        consuming_derivation_path: "".to_string(),
        earning_derivation_path: "".to_string()
        }
      )
    }
}

impl Command for GenerateWalletsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiGenerateWalletsRequest {
            db_password: self.db_password.clone(),
            mnemonic_phrase_size: self.mnemonic_phrase_size,
            mnemonic_phrase_language: self.mnemonic_phrase_language.clone(),
            mnemonic_passphrase_opt: self.mnemonic_passphrase_opt.clone(),
            consuming_derivation_path: self.consuming_derivation_path.clone(),
            earning_derivation_path: self.earning_derivation_path.clone()
        };
        let _: UiGenerateWalletsResponse = transaction(input, context, 1000)?;
        unimplemented!();
        //writeln!(context.stdout(), "Database password has been changed").expect("writeln! failed");
        //Ok(())
    }
}


pub fn generate_wallets_subcommand() -> App<'static, 'static> {
    unimplemented!();
    // SubCommand::with_name("check-password")
    //     .about("XX")
    //     .arg(Arg::with_name ("db-password")
    //         .help ("XXX")
    //         .index (1)
    //         .required (false)
    //         .case_insensitive(false)
    // )
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiChangePasswordRequest, UiChangePasswordResponse, UiGenerateWalletsRequest, UiGenerateWalletsResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context =
            CommandContextMock::new().transact_result(Ok(UiGenerateWalletsResponse {
                mnemonic_phrase: vec![],
                consuming_wallet_address: "".to_string(),
                earning_wallet_address: "".to_string()
            }.tmb(1230)));
        let subject = factory
            .make(vec![
                 "generate-wallets".to_string(),
                // "abracadabra".to_string(),
                // "boringPassword".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }
}


