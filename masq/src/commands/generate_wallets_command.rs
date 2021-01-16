use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{App, Arg, SubCommand};
use masq_lib::messages::{UiGenerateWalletsRequest, UiGenerateWalletsResponse};
use masq_lib::utils::DEFAULT_CONSUMING_DERIVATION_PATH;
use masq_lib::utils::DEFAULT_EARNING_DERIVATION_PATH;
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
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        Ok(GenerateWalletsCommand {
            db_password: matches
                .value_of("db-password")
                .expect("db-password not properly required")
                .to_string(),
            word_count: matches
                .value_of("word-count")
                .expect("word-count not properly defaulted")
                .to_string()
                .parse::<usize>()
                .expect("word-count allowable values are wrong"),
            language: matches
                .value_of("language")
                .expect("language not properly defaulted")
                .to_string(),
            passphrase_opt: matches.value_of("passphrase").map(|s| s.to_string()),
            consuming_path: matches
                .value_of("consuming-path")
                .expect("consuming-path not properly defaulted")
                .to_string(),
            earning_path: matches
                .value_of("earning-path")
                .expect("earning-path not properly defaulted")
                .to_string(),
        })
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
        let response: UiGenerateWalletsResponse = transaction(input, context, 1000)?;
        writeln!(
            context.stdout(),
            "Copy this phrase down and keep it safe; you'll need it to restore your wallet:"
        )
        .expect("writeln! failed");
        writeln!(context.stdout(), "'{}'", response.mnemonic_phrase.join(" "))
            .expect("writeln! failed");
        writeln!(
            context.stdout(),
            "Address of consuming wallet: {}",
            response.consuming_wallet_address
        )
        .expect("writeln! failed");
        writeln!(
            context.stdout(),
            "Address of   earning wallet: {}",
            response.earning_wallet_address
        )
        .expect("writeln! failed");
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        //for testing
        self
    }
}

pub fn generate_wallets_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("generate-wallets")
        .about("Generate a pair of wallets (consuming and earning) for the Node if they haven't been generated already")
        .arg(Arg::with_name("db-password")
            .help("The current database password (a password must be set to use this command)")
            .long("db-password")
            .value_name("DB-PASSWORD")
            .required(true)
            .case_insensitive(false)
            .takes_value(true)
        )
        .arg(Arg::with_name ("word-count")
            .help("The number of words that should be generated for the wallets' mnemonic phrase")
            .long("word-count")
            .value_name("WORD-COUNT")
            .required(false)
            .default_value("24")
            .takes_value(true)
            .possible_values(&["12", "15", "18", "21", "24"])
        )
        .arg(Arg::with_name("language")
            .help("The language in which the wallets' mnemonic phrase should be generated")
            .long("language")
            .value_name("LANGUAGE")
            .required(false)
            .default_value("English")
            .takes_value(true)
            .possible_values(&["English", "Chinese", "Traditional Chinese", "French",
                "Italian", "Japanese", "Korean", "Spanish"])
        )
        .arg(Arg::with_name("passphrase")
            .help("An optional additional word(it can be any word) that the wallet-recovery process should require at the end of the mnemonic phrase")
            .long("passphrase")
            .value_name("PASSPHRASE")
            .required(false)
            .takes_value(true)
        )
        .arg(Arg::with_name ("consuming-path")
            .help ("Derivation path from which to generate the consuming wallet from which your bills will be paid. Remember to put it in double quotes; otherwise the single quotes will cause problems")
            .long ("consuming-path")
            .value_name ("CONSUMING-PATH")
            .required (false)
            .default_value(DEFAULT_CONSUMING_DERIVATION_PATH.as_str())
            .takes_value (true)
        )
        .arg(Arg::with_name ("earning-path")
            .help ("Derivation path from which to generate the earning wallet from which your bills will be paid. Can be the same as consuming-path. Remember to put it in double quotes; otherwise the single quotes will cause problems")
            .long ("earning-path")
            .value_name ("EARNING-PATH")
            .required (false)
            .default_value(DEFAULT_EARNING_DERIVATION_PATH.as_str())
            .takes_value (true)
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiGenerateWalletsRequest, UiGenerateWalletsResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn testing_command_factory_here() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--word-count".to_string(),
                "21".to_string(),
                "--language".to_string(),
                "Korean".to_string(),
                "--passphrase".to_string(),
                "booga".to_string(),
                "--consuming-path".to_string(),
                "m/44'/60'/0'/100/0/200".to_string(),
                "--earning-path".to_string(),
                "m/44'/60'/0'/100/0/201".to_string(),
            ])
            .unwrap();

        let generate_wallets_command: &GenerateWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            generate_wallets_command,
            &GenerateWalletsCommand {
                db_password: "password".to_string(),
                word_count: 21,
                language: "Korean".to_string(),
                passphrase_opt: Some("booga".to_string()),
                consuming_path: "m/44'/60'/0'/100/0/200".to_string(),
                earning_path: "m/44'/60'/0'/100/0/201".to_string()
            }
        )
    }

    #[test]
    fn constructor_handles_bad_syntax() {
        let result = GenerateWalletsCommand::new(vec![
            "bipplety".to_string(),
            "bopplety".to_string(),
            "boop".to_string(),
        ]);

        let msg = result.err().unwrap();
        assert_eq!(
            msg.contains("or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn defaults_work() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
            ])
            .unwrap();

        let generate_wallets_command: &GenerateWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            generate_wallets_command,
            &GenerateWalletsCommand {
                db_password: "password".to_string(),
                word_count: 24,
                language: "English".to_string(),
                passphrase_opt: None,
                consuming_path: DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
                earning_path: DEFAULT_EARNING_DERIVATION_PATH.to_string()
            }
        )
    }

    #[test]
    fn successful_result_is_printed() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiGenerateWalletsResponse {
                mnemonic_phrase: vec![
                    "taxation".to_string(),
                    "is".to_string(),
                    "theft".to_string(),
                ],
                consuming_wallet_address: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
                earning_wallet_address: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
            }
            .tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = GenerateWalletsCommand {
            db_password: "password".to_string(),
            word_count: 21,
            language: "Korean".to_string(),
            passphrase_opt: Some("booga".to_string()),
            consuming_path: "m/44'/60'/0'/100/0/200".to_string(),
            earning_path: "m/44'/60'/0'/100/0/201".to_string(),
        };

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiGenerateWalletsRequest {
                    db_password: "password".to_string(),
                    mnemonic_phrase_size: 21,
                    mnemonic_phrase_language: "Korean".to_string(),
                    mnemonic_passphrase_opt: Some("booga".to_string()),
                    consuming_derivation_path: "m/44'/60'/0'/100/0/200".to_string(),
                    earning_derivation_path: "m/44'/60'/0'/100/0/201".to_string()
                }
                .tmb(0),
                1000
            )]
        );
        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(*stderr.get_string(), String::new());
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(
            &stdout.get_string(),
            "Copy this phrase down and keep it safe; you'll need it to restore your wallet:\n\
'taxation is theft'\n\
Address of consuming wallet: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n\
Address of   earning wallet: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n\
"
        );
    }
}
