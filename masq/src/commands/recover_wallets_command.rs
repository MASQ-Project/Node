// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::builder::{PossibleValuesParser, ValueRange};
use clap::{Arg, ArgGroup, Command as ClapCommand};
use itertools::Either;
use masq_lib::implement_as_any;
use masq_lib::messages::{UiRecoverSeedSpec, UiRecoverWalletsRequest, UiRecoverWalletsResponse};
use masq_lib::short_writeln;
#[cfg(test)]
use std::any::Any;
use async_trait::async_trait;
use crate::terminal::terminal_interface::WTermInterface;

#[derive(Debug, PartialEq, Eq)]
pub struct SeedSpec {
    mnemonic_phrase: Vec<String>,
    language: String,
    passphrase_opt: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RecoverWalletsCommand {
    db_password: String,
    seed_spec_opt: Option<SeedSpec>,
    consuming: Either<String, String>,
    earning: Either<String, String>,
}

impl RecoverWalletsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match recover_wallets_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        let mnemonic_phrase_opt = matches.get_one::<String>("mnemonic-phrase").map(|mpv| {
            mpv.split(' ')
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
        });
        let language = matches
            .get_one::<String>("language")
            .expect("language is not properly defaulted by clap")
            .to_string();
        let passphrase_opt = matches
            .get_one::<String>("passphrase")
            .map(|mp| mp.to_string());
        let seed_spec_opt = mnemonic_phrase_opt.map(|mnemonic_phrase| SeedSpec {
            mnemonic_phrase,
            language,
            passphrase_opt,
        });
        let earning_wallet_derivation_path_opt = matches.get_one::<String>("earning-path");
        let earning_wallet_address_opt = matches.get_one::<String>("earning-address");
        let earning = match (
            earning_wallet_derivation_path_opt,
            earning_wallet_address_opt,
        ) {
            (Some(ewdp), None) => Either::Right(ewdp.to_string()),
            (None, Some(ewa)) => Either::Left(ewa.to_string()),
            x => panic!(
                "Earning-wallet parameters are not properly required by clap: {:?}",
                x
            ),
        };
        let consuming_wallet_derivation_path_opt = matches.get_one::<String>("consuming-path");
        let consuming_wallet_key_opt = matches.get_one::<String>("consuming-key");
        let consuming = match (
            consuming_wallet_derivation_path_opt,
            consuming_wallet_key_opt,
        ) {
            (Some(cwdp), None) => Either::Right(cwdp.to_string()),
            (None, Some(ewpk)) => Either::Left(ewpk.to_string()),
            x => panic!(
                "Consuming-wallet parameters are not properly required by clap: {:?}",
                x
            ),
        };

        Ok(RecoverWalletsCommand {
            db_password: matches
                .get_one::<String>("db-password")
                .expect("db-password not properly required")
                .to_string(),
            seed_spec_opt,
            consuming,
            earning,
        })
    }
}

#[async_trait]
impl Command for RecoverWalletsCommand {
    async fn execute(&self, context: &mut dyn CommandContext, term_interface: &mut dyn WTermInterface) -> Result<(), CommandError> {
        let input = UiRecoverWalletsRequest {
            db_password: self.db_password.clone(),
            seed_spec_opt: self
                .seed_spec_opt
                .as_ref()
                .map(|seed_spec| UiRecoverSeedSpec {
                    mnemonic_phrase: seed_spec.mnemonic_phrase.clone(),
                    mnemonic_phrase_language_opt: Some(seed_spec.language.clone()),
                    mnemonic_passphrase_opt: seed_spec.passphrase_opt.clone(),
                }),
            consuming_derivation_path_opt: match &self.consuming {
                Either::Left(_) => None,
                Either::Right(path) => Some(path.clone()),
            },
            consuming_private_key_opt: match &self.consuming {
                Either::Left(key) => Some(key.clone()),
                Either::Right(_) => None,
            },
            earning_derivation_path_opt: match &self.earning {
                Either::Left(_) => None,
                Either::Right(path) => Some(path.clone()),
            },
            earning_address_opt: match &self.earning {
                Either::Left(address) => Some(address.clone()),
                Either::Right(_) => None,
            },
        };
        let _: UiRecoverWalletsResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        short_writeln!(context.stdout(), "Wallets were successfully recovered");
        Ok(())
    }

    implement_as_any!();
}

const RECOVER_WALLETS_ABOUT: &str =
    "Recovers a pair of wallets (consuming and earning) for the Node if they haven't been recovered already.";
const DB_PASSWORD_ARG_HELP: &str =
    "The current database password (a password must be set to use this command).";
const MNEMONIC_PHRASE_ARG_HELP: &str =
    "The mnemonic phrase upon which the consuming wallet (and possibly the earning wallet) is based. \
     Surround with double quotes.";
const PASSPHRASE_ARG_HELP: &str =
    "An additional word--any word--to place at the end of the mnemonic phrase to recover the wallet pair.";
const LANGUAGE_ARG_HELP: &str = "The language in which the wallets' mnemonic phrase is written.";
const CONSUMING_PATH_ARG_HELP: &str =
    "Derivation that was used to generate the consuming wallet from which your bills will be paid. \
     Remember to put it in double quotes; otherwise the single quotes will cause problems.";
const CONSUMING_KEY_ARG_HELP: &str =
    "The private key of the consuming wallet. Represent it as a 64-character string of hexadecimal digits.";
const EARNING_PATH_ARG_HELP: &str =
    "Derivation path that was used to generate the earning wallet from which your bills will be paid. \
     Can be the same as consuming-path. Remember to put it in double quotes; otherwise the single \
     quotes will cause problems.";
const EARNING_ADDRESS_ARG_HELP: &str =
    "The address of the earning wallet. Represent it as '0x' followed by 40 hexadecimal digits.";
const LANGUAGE_ARG_POSSIBLE_VALUES: [&str; 8] = [
    "English",
    "Chinese",
    "Traditional Chinese",
    "French",
    "Italian",
    "Japanese",
    "Korean",
    "Spanish",
];
const LANGUAGE_ARG_DEFAULT_VALUE: &str = "English";

pub fn recover_wallets_subcommand() -> ClapCommand {
    ClapCommand::new("recover-wallets")
        .about(RECOVER_WALLETS_ABOUT)
        .arg(
            Arg::new("db-password")
                .help(DB_PASSWORD_ARG_HELP)
                .long("db-password")
                .value_name("DB-PASSWORD")
                .required(true)
                .ignore_case(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("mnemonic-phrase")
                .help(MNEMONIC_PHRASE_ARG_HELP)
                .long("mnemonic-phrase")
                .value_name("MNEMONIC-PHRASE")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("passphrase")
                .help(PASSPHRASE_ARG_HELP)
                .long("passphrase")
                .value_name("PASSPHRASE")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("language")
                .help(LANGUAGE_ARG_HELP)
                .long("language")
                .value_name("LANGUAGE")
                .required(false)
                .default_value(LANGUAGE_ARG_DEFAULT_VALUE)
                .num_args(ValueRange::new(1..=1))
                .value_parser(PossibleValuesParser::new(&LANGUAGE_ARG_POSSIBLE_VALUES)),
        )
        .arg(
            Arg::new("consuming-path")
                .help(CONSUMING_PATH_ARG_HELP)
                .long("consuming-path")
                .value_name("CONSUMING-PATH")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("consuming-key")
                .help(CONSUMING_KEY_ARG_HELP)
                .long("consuming-key")
                .value_name("CONSUMING-KEY")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("earning-path")
                .help(EARNING_PATH_ARG_HELP)
                .long("earning-path")
                .value_name("EARNING-PATH")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .arg(
            Arg::new("earning-address")
                .help(EARNING_ADDRESS_ARG_HELP)
                .long("earning-address")
                .value_name("EARNING-ADDRESS")
                .required(false)
                .num_args(ValueRange::new(1..=1)),
        )
        .group(
            ArgGroup::new("consuming")
                .arg("consuming-path")
                .arg("consuming-key")
                .required(true),
        )
        .group(
            ArgGroup::new("earning")
                .arg("earning-path")
                .arg("earning-address")
                .required(true),
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
    fn constants_have_correct_values() {
        assert_eq!(
            RECOVER_WALLETS_ABOUT,
            "Recovers a pair of wallets (consuming and earning) for the Node if they haven't been \
             recovered already."
        );
        assert_eq!(
            DB_PASSWORD_ARG_HELP,
            "The current database password (a password must be set to use this command)."
        );
        assert_eq!(
            MNEMONIC_PHRASE_ARG_HELP,
            "The mnemonic phrase upon which the consuming wallet (and possibly the earning wallet) \
             is based. Surround with double quotes.");
        assert_eq!(
            PASSPHRASE_ARG_HELP,
            "An additional word--any word--to place at the end of the mnemonic phrase to recover \
             the wallet pair."
        );
        assert_eq!(
            LANGUAGE_ARG_HELP,
            "The language in which the wallets' mnemonic phrase is written."
        );
        assert_eq!(
            CONSUMING_PATH_ARG_HELP,
            "Derivation that was used to generate the consuming wallet from which your bills will \
             be paid. Remember to put it in double quotes; otherwise the single quotes will cause problems."
        );
        assert_eq!(
            CONSUMING_KEY_ARG_HELP,
            "The private key of the consuming wallet. Represent it as a 64-character string of \
             hexadecimal digits."
        );
        assert_eq!(
            EARNING_PATH_ARG_HELP,
            "Derivation path that was used to generate the earning wallet from which your bills \
             will be paid. Can be the same as consuming-path. Remember to put it in double quotes; \
             otherwise the single quotes will cause problems."
        );
        assert_eq!(
            EARNING_ADDRESS_ARG_HELP,
            "The address of the earning wallet. Represent it as '0x' followed by 40 hexadecimal digits."
        );
        assert_eq!(
            LANGUAGE_ARG_POSSIBLE_VALUES,
            [
                "English",
                "Chinese",
                "Traditional Chinese",
                "French",
                "Italian",
                "Japanese",
                "Korean",
                "Spanish",
            ]
        );
        assert_eq!(LANGUAGE_ARG_DEFAULT_VALUE, "English")
    }

    #[test]
    fn testing_command_factory_with_derivation_paths() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
                seed_spec_opt: Some (SeedSpec {
                    mnemonic_phrase: "river message view churn potato cabbage craft luggage tape month observe obvious"
                        .split(" ").into_iter().map(|x| x.to_string()).collect(),
                    passphrase_opt: Some("booga".to_string()),
                    language: "English".to_string(),
                }),
                consuming: Either::Right ("m/60'/44'/0'/100/0/200".to_string()),
                earning: Either::Right ("m/60'/44'/0'/100/0/201".to_string())
            }
        )
    }

    #[test]
    fn testing_command_factory_with_key_and_address() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "recover-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--consuming-key".to_string(),
                "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string(),
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
                seed_spec_opt: None,
                consuming: Either::Left(
                    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF".to_string()
                ),
                earning: Either::Left("0x0123456789012345678901234567890123456789".to_string()),
            }
        )
    }

    #[test]
    fn constructor_handles_bad_syntax() {
        let result = RecoverWalletsCommand::new(&[
            "bipplety".to_string(),
            "bopplety".to_string(),
            "boop".to_string(),
        ]);

        let msg = result.err().unwrap();
        assert_eq!(msg.contains("unexpected argument"), true, "{}", msg);
    }

    #[test]
    fn defaults_work() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
                seed_spec_opt: Some(SeedSpec {
                    mnemonic_phrase: vec!["word".to_string()],
                    language: "English".to_string(),
                    passphrase_opt: None,
                }),
                consuming: Either::Right("ooga".to_string()),
                earning: Either::Right("booga".to_string()),
            }
        )
    }

    #[test]
    fn earning_wallet_must_be_specified_somehow() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
            msg.contains("the following required arguments were not provided:"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn earning_wallet_must_be_specified_only_one_way() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
        assert_eq!(msg.contains("cannot be used with"), true, "{}", msg);
    }

    #[test]
    fn execute_works_with_derivation_paths() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiRecoverWalletsResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = RecoverWalletsCommand {
            db_password: "password".to_string(),
            seed_spec_opt: Some(SeedSpec {
                mnemonic_phrase: vec!["word".to_string()],
                language: "English".to_string(),
                passphrase_opt: Some("booga".to_string()),
            }),
            consuming: Either::Right("consuming path".to_string()),
            earning: Either::Right("earning path".to_string()),
        };

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiRecoverWalletsRequest {
                    db_password: "password".to_string(),
                    seed_spec_opt: Some(UiRecoverSeedSpec {
                        mnemonic_phrase: vec!["word".to_string()],
                        mnemonic_passphrase_opt: Some("booga".to_string()),
                        mnemonic_phrase_language_opt: Some("English".to_string()),
                    }),
                    consuming_derivation_path_opt: Some("consuming path".to_string()),
                    consuming_private_key_opt: None,
                    earning_derivation_path_opt: Some("earning path".to_string()),
                    earning_address_opt: None,
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

    #[test]
    fn execute_works_with_key_and_address() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiRecoverWalletsResponse {}.tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = RecoverWalletsCommand {
            db_password: "password".to_string(),
            seed_spec_opt: None,
            consuming: Either::Left("consuming private key".to_string()),
            earning: Either::Left("earning address".to_string()),
        };

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiRecoverWalletsRequest {
                    db_password: "password".to_string(),
                    seed_spec_opt: None,
                    consuming_derivation_path_opt: None,
                    consuming_private_key_opt: Some("consuming private key".to_string()),
                    earning_derivation_path_opt: None,
                    earning_address_opt: Some("earning address".to_string()),
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
