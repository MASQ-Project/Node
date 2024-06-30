// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use lazy_static::lazy_static;
use masq_lib::as_any_ref_in_trait_impl;
use masq_lib::messages::{UiGenerateSeedSpec, UiGenerateWalletsRequest, UiGenerateWalletsResponse};
use masq_lib::short_writeln;
use masq_lib::utils::DEFAULT_EARNING_DERIVATION_PATH;
use masq_lib::utils::{to_string, DEFAULT_CONSUMING_DERIVATION_PATH};

lazy_static! {
    static ref CONSUMING_PATH_HELP: String = format!(
        "Derivation path from which to generate the \
            consuming wallet from which your bills will be paid. Remember to put it in double \
            quotes; otherwise the single quotes will cause problems. (Use \"{}\" if you don't have \
            a different value.) Leave this out to generate a consuming private key instead.",
        DEFAULT_CONSUMING_DERIVATION_PATH.as_str()
    );
    static ref EARNING_PATH_HELP: String = format!(
        "Derivation path from which to generate the \
            earning wallet from which your bills will be paid. Can be the same as consuming-path. \
            Remember to put it in double quotes; otherwise the single quotes will cause problems. \
            (Use \"{}\" if you don't have a different value.)  Leave this out to generate an \
            earning address instead.",
        DEFAULT_EARNING_DERIVATION_PATH.as_str()
    );
}

#[derive(Debug, PartialEq, Eq)]
pub struct SeedSpec {
    word_count: usize,
    language: String,
    passphrase_opt: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GenerateWalletsCommand {
    db_password: String,
    seed_spec_opt: Option<SeedSpec>,
    consuming_path_opt: Option<String>,
    earning_path_opt: Option<String>,
}

const GENERATE_WALLET_SUBCOMMAND_ABOUT: &str =
    "Generates a pair of wallets (consuming and earning) for the Node if they haven't \
         been generated already.";
const DB_PASSWORD_ARG_HELP: &str =
    "The current database password (a password must be set to use this command).";
const WORD_COUNT_ARG_HELP: &str =
    "The number of words that should be generated for the wallets' mnemonic phrase, \
             if you're supplying a derivation path.";
const LANGUAGE_ARG_HELP: &str =
    "The language in which the wallets' mnemonic phrase should be generated, \
             if you're supplying a derivation path.";
const PASSPHRASE_ARG_HELP: &str =
    "An optional additional word (it can be any word) that the wallet-recovery \
             process should require at the end of the mnemonic phrase, if you're supplying a \
             derivation path.";

const WORD_COUNT_ARG_POSSIBLE_VALUES: [&str; 5] = ["12", "15", "18", "21", "24"];
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
const WORD_COUNT_ARG_DEFAULT_VALUE: &str = "12";
const LANGUAGE_ARG_DEFAULT_VALUE: &str = "English";

impl GenerateWalletsCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match generate_wallets_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        let consuming_path_opt = matches.value_of("consuming-path").map(to_string);
        let earning_path_opt = matches.value_of("earning-path").map(to_string);
        let seed_spec_opt = if consuming_path_opt.is_some() || earning_path_opt.is_some() {
            Some(SeedSpec {
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
                passphrase_opt: matches.value_of("passphrase").map(to_string),
            })
        } else {
            None
        };

        Ok(GenerateWalletsCommand {
            db_password: matches
                .value_of("db-password")
                .expect("db-password not properly required")
                .to_string(),
            seed_spec_opt,
            consuming_path_opt,
            earning_path_opt,
        })
    }

    fn process_response(response: UiGenerateWalletsResponse, context: &mut dyn CommandContext) {
        if let Some(mnemonic_phrase) = response.mnemonic_phrase_opt {
            short_writeln!(
                context.stdout(),
                "Copy this phrase down and keep it safe; you'll need it to restore your wallet:"
            );
            short_writeln!(context.stdout(), "'{}'", mnemonic_phrase.join(" "));
        }
        short_writeln!(
            context.stdout(),
            "Address of     consuming wallet: {}",
            response.consuming_wallet_address
        );
        short_writeln!(
            context.stdout(),
            "Private key of consuming wallet: {}",
            response.consuming_wallet_private_key
        );
        short_writeln!(
            context.stdout(),
            "Address of       earning wallet: {}",
            response.earning_wallet_address
        );
        short_writeln!(
            context.stdout(),
            "Private key of   earning wallet: {}",
            response.earning_wallet_private_key
        );
    }
}

impl Command for GenerateWalletsCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiGenerateWalletsRequest {
            db_password: self.db_password.clone(),
            seed_spec_opt: self
                .seed_spec_opt
                .as_ref()
                .map(|seed_spec| UiGenerateSeedSpec {
                    mnemonic_phrase_size_opt: Some(seed_spec.word_count),
                    mnemonic_phrase_language_opt: Some(seed_spec.language.clone()),
                    mnemonic_passphrase_opt: seed_spec.passphrase_opt.clone(),
                }),
            consuming_derivation_path_opt: self.consuming_path_opt.as_ref().cloned(),
            earning_derivation_path_opt: self.earning_path_opt.as_ref().cloned(),
        };
        let response: UiGenerateWalletsResponse =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS)?;
        Self::process_response(response, context);
        Ok(())
    }

    as_any_ref_in_trait_impl!();
}

pub fn generate_wallets_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("generate-wallets")
        .about(GENERATE_WALLET_SUBCOMMAND_ABOUT)
        .arg(
            Arg::with_name("db-password")
                .help(DB_PASSWORD_ARG_HELP)
                .long("db-password")
                .value_name("DB-PASSWORD")
                .required(true)
                .case_insensitive(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("word-count")
                .help(WORD_COUNT_ARG_HELP)
                .long("word-count")
                .value_name("WORD-COUNT")
                .required(false)
                .default_value(WORD_COUNT_ARG_DEFAULT_VALUE)
                .takes_value(true)
                .possible_values(&WORD_COUNT_ARG_POSSIBLE_VALUES),
        )
        .arg(
            Arg::with_name("language")
                .help(LANGUAGE_ARG_HELP)
                .long("language")
                .value_name("LANGUAGE")
                .required(false)
                .default_value(LANGUAGE_ARG_DEFAULT_VALUE)
                .takes_value(true)
                .possible_values(&LANGUAGE_ARG_POSSIBLE_VALUES),
        )
        .arg(
            Arg::with_name("passphrase")
                .help(PASSPHRASE_ARG_HELP)
                .long("passphrase")
                .value_name("PASSPHRASE")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("consuming-path")
                .help(CONSUMING_PATH_HELP.as_str())
                .long("consuming-path")
                .value_name("CONSUMING-PATH")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("earning-path")
                .help(EARNING_PATH_HELP.as_str())
                .long("earning-path")
                .value_name("EARNING-PATH")
                .required(false)
                .takes_value(true),
        )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use masq_lib::messages::{
        ToMessageBody, UiGenerateSeedSpec, UiGenerateWalletsRequest, UiGenerateWalletsResponse,
    };

    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;

    use super::*;
    use crate::command_context::ContextError;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONSUMING_PATH_HELP.to_string(),
            format!(
                "Derivation path from which to generate the \
                 consuming wallet from which your bills will be paid. Remember to put it in double \
                 quotes; otherwise the single quotes will cause problems. (Use \"{}\" if you don't have \
                 a different value.) Leave this out to generate a consuming private key instead.",
                DEFAULT_CONSUMING_DERIVATION_PATH.as_str()
            )
        );
        assert_eq!(
            EARNING_PATH_HELP.to_string(),
            format!(
                "Derivation path from which to generate the \
                 earning wallet from which your bills will be paid. Can be the same as consuming-path. \
                 Remember to put it in double quotes; otherwise the single quotes will cause problems. \
                 (Use \"{}\" if you don't have a different value.)  Leave this out to generate an \
                 earning address instead.",
                DEFAULT_EARNING_DERIVATION_PATH.as_str()
            )
        );
        assert_eq!(
            GENERATE_WALLET_SUBCOMMAND_ABOUT,
            "Generates a pair of wallets (consuming and earning) for the Node if they haven't \
         been generated already."
        );
        assert_eq!(
            DB_PASSWORD_ARG_HELP,
            "The current database password (a password must be set to use this command)."
        );
        assert_eq!(
            WORD_COUNT_ARG_HELP,
            "The number of words that should be generated for the wallets' mnemonic phrase, \
             if you're supplying a derivation path."
        );
        assert_eq!(
            LANGUAGE_ARG_HELP,
            "The language in which the wallets' mnemonic phrase should be generated, \
             if you're supplying a derivation path."
        );
        assert_eq!(
            PASSPHRASE_ARG_HELP,
            "An optional additional word (it can be any word) that the wallet-recovery \
             process should require at the end of the mnemonic phrase, if you're supplying a \
             derivation path."
        );

        assert_eq!(
            WORD_COUNT_ARG_POSSIBLE_VALUES,
            ["12", "15", "18", "21", "24"]
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
        assert_eq!(WORD_COUNT_ARG_DEFAULT_VALUE, "12");
        assert_eq!(LANGUAGE_ARG_DEFAULT_VALUE, "English");
    }

    #[test]
    fn command_factory_works_with_earning_path_and_consuming_path_with_no_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
                seed_spec_opt: Some(SeedSpec {
                    word_count: 21,
                    language: "Korean".to_string(),
                    passphrase_opt: Some("booga".to_string()),
                }),
                consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_path_and_consuming_path_with_all_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
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
                seed_spec_opt: Some(SeedSpec {
                    word_count: 12,
                    language: "English".to_string(),
                    passphrase_opt: None,
                }),
                consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_path_and_consuming_private_key_no_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--word-count".to_string(),
                "21".to_string(),
                "--language".to_string(),
                "Korean".to_string(),
                "--passphrase".to_string(),
                "booga".to_string(),
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
                seed_spec_opt: Some(SeedSpec {
                    word_count: 21,
                    language: "Korean".to_string(),
                    passphrase_opt: Some("booga".to_string()),
                }),
                consuming_path_opt: None,
                earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_path_and_consuming_private_key_all_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
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
                seed_spec_opt: Some(SeedSpec {
                    word_count: 12,
                    language: "English".to_string(),
                    passphrase_opt: None,
                }),
                consuming_path_opt: None,
                earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_address_and_consuming_path_with_no_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
            ])
            .unwrap();

        let generate_wallets_command: &GenerateWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            generate_wallets_command,
            &GenerateWalletsCommand {
                db_password: "password".to_string(),
                seed_spec_opt: Some(SeedSpec {
                    word_count: 21,
                    language: "Korean".to_string(),
                    passphrase_opt: Some("booga".to_string()),
                }),
                consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                earning_path_opt: None
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_address_and_consuming_path_with_all_defaults() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
                "generate-wallets".to_string(),
                "--db-password".to_string(),
                "password".to_string(),
                "--consuming-path".to_string(),
                "m/44'/60'/0'/100/0/200".to_string(),
            ])
            .unwrap();

        let generate_wallets_command: &GenerateWalletsCommand =
            result.as_any().downcast_ref().unwrap();
        assert_eq!(
            generate_wallets_command,
            &GenerateWalletsCommand {
                db_password: "password".to_string(),
                seed_spec_opt: Some(SeedSpec {
                    word_count: 12,
                    language: "English".to_string(),
                    passphrase_opt: None,
                }),
                consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                earning_path_opt: None
            }
        )
    }

    #[test]
    fn command_factory_works_with_earning_address_and_consuming_private_key() {
        let subject = CommandFactoryReal::new();

        let result = subject
            .make(&[
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
                seed_spec_opt: None,
                consuming_path_opt: None,
                earning_path_opt: None
            }
        )
    }

    #[test]
    fn constructor_handles_bad_syntax() {
        let result = GenerateWalletsCommand::new(&[
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
    fn command_with_both_paths_is_correctly_translated() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ContextError::Other("booga".to_string())));
        let subject = GenerateWalletsCommand {
            db_password: "password".to_string(),
            seed_spec_opt: Some(SeedSpec {
                word_count: 21,
                language: "Korean".to_string(),
                passphrase_opt: Some("booga".to_string()),
            }),
            consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
            earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string()),
        };

        subject.execute(&mut context).err().unwrap(); // don't need success, just request translation

        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiGenerateWalletsRequest {
                    db_password: "password".to_string(),
                    seed_spec_opt: Some(UiGenerateSeedSpec {
                        mnemonic_phrase_size_opt: Some(21),
                        mnemonic_phrase_language_opt: Some("Korean".to_string()),
                        mnemonic_passphrase_opt: Some("booga".to_string()),
                    }),
                    consuming_derivation_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                    earning_derivation_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
                }
                .tmb(0),
                1000
            )]
        );
    }

    #[test]
    fn command_with_neither_path_is_correctly_translated() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ContextError::Other("booga".to_string())));
        let subject = GenerateWalletsCommand {
            db_password: "password".to_string(),
            seed_spec_opt: None,
            consuming_path_opt: None,
            earning_path_opt: None,
        };

        subject.execute(&mut context).err().unwrap(); // don't need success, just request translation

        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiGenerateWalletsRequest {
                    db_password: "password".to_string(),
                    seed_spec_opt: None,
                    consuming_derivation_path_opt: None,
                    earning_derivation_path_opt: None
                }
                .tmb(0),
                1000
            )]
        );
    }

    #[test]
    fn response_with_mnemonic_phrase_is_processed() {
        let mut context = CommandContextMock::new();
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let response = UiGenerateWalletsResponse {
            mnemonic_phrase_opt: Some(vec![
                "taxation".to_string(),
                "is".to_string(),
                "theft".to_string(),
            ]),
            consuming_wallet_address: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            consuming_wallet_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            earning_wallet_address: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
            earning_wallet_private_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        };

        GenerateWalletsCommand::process_response(response, &mut context);

        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(*stderr.get_string(), String::new());
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(
            &stdout.get_string(),
            "Copy this phrase down and keep it safe; you'll need it to restore your wallet:\n\
'taxation is theft'\n\
Address of     consuming wallet: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n\
Private key of consuming wallet: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
Address of       earning wallet: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n\
Private key of   earning wallet: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
"
        );
    }

    #[test]
    fn response_without_mnemonic_phrase_is_processed() {
        let mut context = CommandContextMock::new();
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let response = UiGenerateWalletsResponse {
            mnemonic_phrase_opt: None,
            consuming_wallet_address: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
            consuming_wallet_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            earning_wallet_address: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
            earning_wallet_private_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        };

        GenerateWalletsCommand::process_response(response, &mut context);

        let stderr = stderr_arc.lock().unwrap();
        assert_eq!(*stderr.get_string(), String::new());
        let stdout = stdout_arc.lock().unwrap();
        assert_eq!(
            &stdout.get_string(),
            "\
Address of     consuming wallet: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n\
Private key of consuming wallet: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
Address of       earning wallet: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n\
Private key of   earning wallet: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
"
        );
    }

    #[test]
    fn successful_result_is_printed() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiGenerateWalletsResponse {
                mnemonic_phrase_opt: Some(vec![
                    "taxation".to_string(),
                    "is".to_string(),
                    "theft".to_string(),
                ]),
                consuming_wallet_address: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
                consuming_wallet_private_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
                earning_wallet_address: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
                earning_wallet_private_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            }
            .tmb(4321)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = GenerateWalletsCommand {
            db_password: "password".to_string(),
            seed_spec_opt: Some(SeedSpec {
                word_count: 21,
                language: "Korean".to_string(),
                passphrase_opt: Some("booga".to_string()),
            }),
            consuming_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
            earning_path_opt: Some("m/44'/60'/0'/100/0/201".to_string()),
        };

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiGenerateWalletsRequest {
                    db_password: "password".to_string(),
                    seed_spec_opt: Some(UiGenerateSeedSpec {
                        mnemonic_phrase_size_opt: Some(21),
                        mnemonic_phrase_language_opt: Some("Korean".to_string()),
                        mnemonic_passphrase_opt: Some("booga".to_string()),
                    }),
                    consuming_derivation_path_opt: Some("m/44'/60'/0'/100/0/200".to_string()),
                    earning_derivation_path_opt: Some("m/44'/60'/0'/100/0/201".to_string())
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
Address of     consuming wallet: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n\
Private key of consuming wallet: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
Address of       earning wallet: EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\n\
Private key of   earning wallet: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n\
"
        );
    }
}
