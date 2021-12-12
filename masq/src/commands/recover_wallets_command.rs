// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, ArgGroup, SubCommand};
use itertools::{Either, Itertools};
use masq_lib::as_any_impl;
use masq_lib::messages::{UiRecoverSeedSpec, UiRecoverWalletsRequest, UiRecoverWalletsResponse};
use masq_lib::short_writeln;
#[cfg(test)]
use std::any::Any;

#[derive(Debug, PartialEq)]
pub struct SeedSpec {
    mnemonic_phrase: Vec<String>,
    language: String,
    passphrase_opt: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct RecoverWalletsCommand {
    db_password: String,
    seed_spec_opt: Option<SeedSpec>,
    consuming: Either<String, String>,
    earning: Either<String, String>,
}

impl RecoverWalletsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match recover_wallets_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        let mnemonic_phrase_opt = matches
            .value_of("mnemonic-phrase")
            .map(|mpv| mpv.split(' ').map(|x| x.to_string()).collect_vec());
        let language = matches
            .value_of("language")
            .expect("language is not properly defaulted by clap")
            .to_string();
        let passphrase_opt = matches.value_of("passphrase").map(|mp| mp.to_string());
        let seed_spec_opt = mnemonic_phrase_opt.map(|mnemonic_phrase| SeedSpec {
            mnemonic_phrase,
            language,
            passphrase_opt,
        });
        let earning_wallet_derivation_path_opt = matches.value_of("earning-path");
        let earning_wallet_address_opt = matches.value_of("earning-address");
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
        let consuming_wallet_derivation_path_opt = matches.value_of("consuming-path");
        let consuming_wallet_key_opt = matches.value_of("consuming-key");
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
                .value_of("db-password")
                .expect("db-password not properly required")
                .to_string(),
            seed_spec_opt,
            consuming,
            earning,
        })
    }
}

impl Command for RecoverWalletsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiRecoverWalletsRequest {
            db_password: self.db_password.clone(),
            seed_spec_opt: self.seed_spec_opt.as_ref().map(|ss| UiRecoverSeedSpec {
                mnemonic_phrase: ss.mnemonic_phrase.clone(),
                mnemonic_phrase_language: ss.language.clone(),
                mnemonic_passphrase_opt: ss.passphrase_opt.clone(),
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

    as_any_impl!();
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
            .required (false)
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
            .help ("The language in which the wallets' mnemonic phrase is written")
            .long ("language")
            .value_name ("LANGUAGE")
            .required (false)
            .default_value("English")
            .takes_value (true)
            .possible_values(&["English", "Chinese", "Traditional Chinese", "French",
                "Italian", "Japanese", "Korean", "Spanish"])
        )
        .arg(Arg::with_name ("consuming-path")
            .help ("Derivation path from which the consuming wallet from which your bills will be paid was generated. Remember to put it in double quotes; otherwise the single quotes will cause problems")
            .long ("consuming-path")
            .value_name ("CONSUMING-PATH")
            .required (false)
            .takes_value (true)
        )
        .arg(Arg::with_name ("consuming-key")
            .help ("The private key of the consuming wallet. Represent it as a 64-character string of hexadecimal digits.")
            .long ("consuming-key")
            .value_name ("CONSUMING-KEY")
            .required (false)
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
            .help ("The address of the earning wallet. Represent it as '0x' followed by 40 hexadecimal digits.")
            .long ("earning-address")
            .value_name ("EARNING-ADDRESS")
            .required (false)
            .takes_value (true)
        )
        .group (
            ArgGroup::with_name("consuming")
                .arg ("consuming-path")
                .arg ("consuming-key")
                .required (true)
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
        assert_eq!(
            msg.contains("cannot be used with one or more of the other specified arguments"),
            true,
            "{}",
            msg
        );
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
            earning: Either::Right("earning wallet".to_string()),
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
                        mnemonic_phrase_language: "English".to_string(),
                    }),
                    consuming_derivation_path_opt: Some("consuming path".to_string()),
                    consuming_private_key_opt: None,
                    earning_derivation_path_opt: Some("earning wallet".to_string()),
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
