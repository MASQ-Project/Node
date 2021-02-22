// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, ArgGroup, SubCommand};
use masq_lib::messages::{UiRecoverWalletsRequest, UiRecoverWalletsResponse};
use masq_lib::short_writeln;
use std::any::Any;

#[derive(Debug, PartialEq)]
pub struct RecoverWalletsCommand {
    db_password: String,
    mnemonic_phrase: Vec<String>,
    passphrase_opt: Option<String>,
    language: String,
    consuming_path: String,
    earning_wallet: String,
}

impl RecoverWalletsCommand {
    pub fn new(pieces: Vec<String>) -> Result<Self, String> {
        let matches = match recover_wallets_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        let mnemonic_phrase_str = matches
            .value_of("mnemonic-phrase")
            .expect("mnemonic-phrase not properly required")
            .to_string();
        let mnemonic_phrase = mnemonic_phrase_str
            .split(' ')
            .map(|x| x.to_string())
            .collect();
        let earning_wallet_derivation_path = matches.value_of("earning-path");
        let earning_wallet_address = matches.value_of("earning-address");
        let earning_wallet: String = match (earning_wallet_derivation_path, earning_wallet_address)
        {
            (Some(ewdp), None) => ewdp.to_string(),
            (None, Some(ewa)) => ewa.to_string(),
            x => panic!(
                "Earning-wallet parameters are not properly required by clap: {:?}",
                x
            ),
        };

        Ok(RecoverWalletsCommand {
            db_password: matches
                .value_of("db-password")
                .expect("db-password not properly required")
                .to_string(),
            mnemonic_phrase,
            language: matches
                .value_of("language")
                .expect("language not properly defaulted")
                .to_string(),
            passphrase_opt: matches.value_of("passphrase").map(|s| s.to_string()),
            consuming_path: matches
                .value_of("consuming-path")
                .expect("consuming-path not properly defaulted")
                .to_string(),
            earning_wallet,
        })
    }
}

impl Command for RecoverWalletsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiRecoverWalletsRequest {
            db_password: self.db_password.clone(),
            mnemonic_phrase: self.mnemonic_phrase.clone(),
            mnemonic_passphrase_opt: self.passphrase_opt.clone(),
            mnemonic_phrase_language: self.language.clone(),
            consuming_derivation_path: self.consuming_path.clone(),
            earning_wallet: self.earning_wallet.clone(),
        };
        let _: UiRecoverWalletsResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        short_writeln!(context.stdout(), "Wallets were successfully recovered");
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        //for testing
        self
    }
}

pub fn recover_wallets_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("recover-wallets")
        .about("Recovers a pair of wallets (consuming and earning) for the Node if they haven't been recovered already")
        .arg(Arg::with_name ("db-password")
            .help ("The current database password (a password must be set to use this command)")
            .long ("db-password")
            .value_name ("DB-PASSWORD")
            .required (true)
            .case_insensitive(false)
            .takes_value (true)
        )
        .arg(Arg::with_name ("mnemonic-phrase")
            .help ("The mnemonic phrase upon which the consuming wallet (and possibly the earning wallet) is based. Surround with double quotes.")
            .long ("mnemonic-phrase")
            .value_name ("MNEMONIC-PHRASE")
            .required (true)
            .takes_value (true)
        )
        .arg(Arg::with_name ("passphrase")
            .help ("An additional word--any word--to place at the end of the mnemonic phrase to recover the wallet pair")
            .long ("passphrase")
            .value_name ("PASSPHRASE")
            .required (false)
            .takes_value (true)
        )
        .arg(Arg::with_name ("language")
            .help ("The language in which the wallets' mnemonic phrase should be generated")
            .long ("language")
            .value_name ("LANGUAGE")
            .required (false)
            .default_value("English")
            .takes_value (true)
            .possible_values(&["English", "Chinese", "Traditional Chinese", "French",
                "Italian", "Japanese", "Korean", "Spanish"])
        )
        .arg(Arg::with_name ("consuming-path")
            .help ("Derivation path from which to generate the consuming wallet from which your bills will be paid. Remember to put it in double quotes; otherwise the single quotes will cause problems")
            .long ("consuming-path")
            .value_name ("CONSUMING-PATH")
            .required (true)
            .takes_value (true)
        )
        .arg(Arg::with_name ("earning-path")
            .help ("Derivation path from which to generate the earning wallet from which your bills will be paid. Can be the same as consuming-path. Remember to put it in double quotes; otherwise the single quotes will cause problems")
            .long ("earning-path")
            .value_name ("EARNING-PATH")
            .required (false)
            .takes_value (true)
        )
        .arg(Arg::with_name ("earning-address")
            .help ("Address of earning wallet. Supply this instead of --earning-path if the earning wallet is not derived from the mnemonic phrase")
            .long ("earning-address")
            .value_name ("EARNING-ADDRESS")
            .required (false)
            .takes_value (true)
        )
        .group (
            ArgGroup::with_name("earning")
                .arg ("earning-path")
                .arg ("earning-address")
                .required (true)
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryError, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::{ToMessageBody, UiRecoverWalletsRequest, UiRecoverWalletsResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn testing_command_factory_with_derivation_path() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--mnemonic-phrase".to_string(),
                "river message view churn potato cabbage craft luggage tape month observe obvious"
                    .to_string(),
                "--passphrase".to_string(),
                "booga".to_string(),
                "--language".to_string(),
                "English".to_string(),
                "--consuming-path".to_string(),
                "m/60'/44'/0'/100/0/200".to_string(),
                "--earning-path".to_string(),
                "m/60'/44'/0'/100/0/201".to_string(),
            ])
            .unwrap();

        let recover_wallets_command: &RecoverWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            recover_wallets_command,
            &RecoverWalletsCommand {
                db_password: "password".to_string(),
                mnemonic_phrase: "river message view churn potato cabbage craft luggage tape month observe obvious"
                    .split (" ").into_iter ().map(|x| x.to_string()).collect(),
                passphrase_opt: Some("booga".to_string()),
                language: "English".to_string(),
                consuming_path: "m/60'/44'/0'/100/0/200".to_string(),
                earning_wallet: "m/60'/44'/0'/100/0/201".to_string()
            }
        )
    }

    #[test]
    fn testing_command_factory_with_address() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--mnemonic-phrase".to_string(),
                "river message view churn potato cabbage craft luggage tape month observe obvious"
                    .to_string(),
                "--passphrase".to_string(),
                "booga".to_string(),
                "--language".to_string(),
                "English".to_string(),
                "--consuming-path".to_string(),
                "m/60'/44'/0'/100/0/200".to_string(),
                "--earning-address".to_string(),
                "0x0123456789012345678901234567890123456789".to_string(),
            ])
            .unwrap();

        let recover_wallets_command: &RecoverWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            recover_wallets_command,
            &RecoverWalletsCommand {
                db_password: "password".to_string(),
                mnemonic_phrase: "river message view churn potato cabbage craft luggage tape month observe obvious"
                    .split (" ").into_iter ().map(|x| x.to_string()).collect(),
                passphrase_opt: Some("booga".to_string()),
                language: "English".to_string(),
                consuming_path: "m/60'/44'/0'/100/0/200".to_string(),
                earning_wallet: "0x0123456789012345678901234567890123456789".to_string()
            }
        )
    }

    #[test]
    fn constructor_handles_bad_syntax() {
        let result = RecoverWalletsCommand::new(vec![
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
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--mnemonic-phrase".to_string(),
                "word".to_string(),
                "--consuming-path".to_string(),
                "ooga".to_string(),
                "--earning-path".to_string(),
                "booga".to_string(),
            ])
            .unwrap();

        let generate_wallets_command: &RecoverWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            generate_wallets_command,
            &RecoverWalletsCommand {
                db_password: "password".to_string(),
                mnemonic_phrase: vec!["word".to_string()],
                language: "English".to_string(),
                passphrase_opt: None,
                consuming_path: "ooga".to_string(),
                earning_wallet: "booga".to_string()
            }
        )
    }

    #[test]
    fn earning_wallet_must_be_specified_somehow() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--mnemonic-phrase".to_string(),
                "word".to_string(),
                "--consuming-path".to_string(),
                "ooga".to_string(),
            ])
            .err()
            .unwrap();

        let msg = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("Expected CommandSyntax, but got {:?}", x),
        };
        assert_eq!(
            msg.contains("The following required arguments were not provided:"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn earning_wallet_must_be_specified_only_one_way() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(vec![
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--mnemonic-phrase".to_string(),
                "word".to_string(),
                "--consuming-path".to_string(),
                "bipplety".to_string(),
                "--earning-path".to_string(),
                "bopplety".to_string(),
                "--earning-address".to_string(),
                "boop".to_string(),
            ])
            .err()
            .unwrap();

        let msg = match result {
            CommandFactoryError::CommandSyntax(msg) => msg,
            x => panic!("Expected CommandSyntax, but got {:?}", x),
        };
        assert_eq!(
            msg.contains("cannot be used with one or more of the other specified arguments"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn successful_result_is_printed() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiRecoverWalletsResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = RecoverWalletsCommand {
            db_password: "password".to_string(),
            mnemonic_phrase: vec!["word".to_string()],
            language: "English".to_string(),
            passphrase_opt: Some("booga".to_string()),
            consuming_path: "consuming path".to_string(),
            earning_wallet: "earning wallet".to_string(),
        };

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiRecoverWalletsRequest {
                    db_password: "password".to_string(),
                    mnemonic_phrase: vec!["word".to_string()],
                    mnemonic_passphrase_opt: Some("booga".to_string()),
                    mnemonic_phrase_language: "English".to_string(),
                    consuming_derivation_path: "consuming path".to_string(),
                    earning_wallet: "earning wallet".to_string()
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
            "Wallets were successfully recovered\n"
        );
    }
}
