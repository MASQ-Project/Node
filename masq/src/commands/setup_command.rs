// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::terminal::terminal_interface::TerminalWrapper;
use clap::{value_t, App, SubCommand};
use masq_lib::constants::SETUP_ERROR;
use masq_lib::implement_as_any;
use masq_lib::messages::{UiSetupBroadcast, UiSetupInner, UiSetupRequest, UiSetupRequestValue, UiSetupResponse, UiSetupResponseValue, UiSetupResponseValueStatus};
use masq_lib::shared_schema::shared_app;
use masq_lib::short_writeln;
use masq_lib::utils::{add_chain_specific_directories, add_chain_specific_directory, index_of_from};
use std::iter::Iterator;
#[cfg(test)]
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Write;
use std::path::PathBuf;
use masq_lib::blockchains::chains::Chain;

pub const SETUP_COMMAND_TIMEOUT_MILLIS: u64 = 30000;

const SETUP_COMMAND_ABOUT: &str =
    "Establishes (if Node is not already running) and displays startup parameters for MASQNode.";

pub fn setup_subcommand() -> App<'static, 'static> {
    shared_app(SubCommand::with_name("setup").about(SETUP_COMMAND_ABOUT))
}

#[derive(Debug, PartialEq, Eq)]
pub struct SetupCommand {
    pub values: Vec<UiSetupRequestValue>,
}

impl Command for SetupCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiSetupRequest {
            values: self.values.clone(),
        };
        let result: Result<UiSetupResponse, CommandError> =
            transaction(out_message, context, SETUP_COMMAND_TIMEOUT_MILLIS);
        match result {
            Ok(response) => {
                Self::dump_setup(UiSetupInner::from(response), context.stdout());
                Ok(())
            }
            Err(CommandError::Payload(err, msg)) if err == SETUP_ERROR => {
                short_writeln!(context.stderr(), "{}", msg);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    implement_as_any!();
}

impl SetupCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match setup_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        let mut values = pieces
            .iter()
            .filter(|piece| (*piece).starts_with("--"))
            .map(|piece| piece[2..].to_string())
            .map(|key| {
                if Self::has_value(pieces, &key) {
                    let value = value_t!(matches, &key, String).expect("Value disappeared!");
                    UiSetupRequestValue::new(&key, &value)
                } else {
                    UiSetupRequestValue::clear(&key)
                }
            })
            .collect::<Vec<UiSetupRequestValue>>();
        values.sort_by(|a, b| {
            a.name
                .partial_cmp(&b.name)
                .expect("String comparison failed")
        });
        Ok(Self { values })
    }

    pub fn handle_broadcast(
        response: UiSetupBroadcast,
        stdout: &mut dyn Write,
        term_interface: &TerminalWrapper,
    ) {
        let _lock = term_interface.lock();
        short_writeln!(stdout, "\nDaemon setup has changed:\n");
        Self::dump_setup(UiSetupInner::from(response), stdout);
        stdout.flush().expect("flush failed");
    }

    fn has_value(pieces: &[String], piece: &str) -> bool {
        let dash_dash_piece = format!("--{}", piece);
        match index_of_from(pieces, &dash_dash_piece, 0) {
            None => false,
            Some(idx) if idx == pieces.len() - 1 => false,
            Some(idx) => !pieces[idx + 1].starts_with("--"),
        }
    }

    fn dump_setup(mut inner: UiSetupInner, stdout: &mut dyn Write) {
        inner.values.sort_by(|a, b| {
            a.name
                .partial_cmp(&b.name)
                .expect("String comparison failed")
        });
        short_writeln!(stdout, "{:29} {:64} {}", "NAME", "VALUE", "STATUS");

        let mut chain_and_data_dir = inner.values.iter().flat_map(|p| {
            match p.name.as_str() {
                "chain" => Some((p.name.to_owned(), (p.value.clone(), p.status))),
                "data-directory" => Some((p.name.to_owned(), (p.value.clone(), p.status))),
                _ => None
            }
        } ).collect::<HashMap<String, (String, UiSetupResponseValueStatus)>>();
        let (chain_name, chain_param_status) = chain_and_data_dir.remove("chain").expect("Chain name is missing in setup cluster");
        let (_, data_directory_param_status) = chain_and_data_dir.remove("data-directory").expect("data-directory is missing in setup cluster");

        inner.values.into_iter().for_each(|value| {
            let value_value = Self::match_value_value(value.clone(), &chain_name);
            short_writeln!(
                stdout,
                "{:29} {:64} {:?}",
                value.name,
                value_value,
                value.status
            );
        });
        short_writeln!(stdout);
        if !inner.errors.is_empty() {
            short_writeln!(stdout, "ERRORS:");
            inner.errors.into_iter().for_each(|(parameter, reason)| {
                short_writeln!(stdout, "{:29} {}", parameter, reason)
            });
            short_writeln!(stdout);
        }
        if inner.running {
            short_writeln!(
                stdout,
                "NOTE: no changes were made to the setup because the Node is currently running.\n"
            );
        }
        if chain_param_status != UiSetupResponseValueStatus::Default || data_directory_param_status != UiSetupResponseValueStatus::Default {
            short_writeln!(
                stdout,
                "NOTE: your data directory was modified to match chain parameter.\n"
            );
        }
        //TODO write tests for different statuses
        //TODO write integration test to ensure this will be workind properly after change of daemon in new integration test file in "test"
    }
    fn match_value_value(value: UiSetupResponseValue, chain_name: &str) -> String {
        let value_tmp = match value.name.as_str() {
            "data-directory" => {
                let path = PathBuf::from(value.value.clone());
                let checked_dir_path = match value.status {
                    UiSetupResponseValueStatus::Default => add_chain_specific_directories(
                        Chain::from(chain_name),
                        path.as_path()
                    ),
                    UiSetupResponseValueStatus::Set => add_chain_specific_directory(
                        Chain::from(chain_name),
                        path.as_path()
                    ),
                    UiSetupResponseValueStatus::Configured => add_chain_specific_directory(
                        Chain::from(chain_name),
                        path.as_path()
                    ),
                    _ => path
                };
                checked_dir_path.as_path().to_string_lossy().to_string()
            },
            _ => value.value.to_string()
        };
        value_tmp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::communications::broadcast_handler::StreamFactory;
    use crate::test_utils::mocks::{CommandContextMock, TerminalPassiveMock, TestStreamFactory};
    use masq_lib::constants::ETH_ROPSTEN_FULL_IDENTIFIER;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiSetupResponseValueStatus::{Configured, Default, Set};
    use masq_lib::messages::{UiSetupRequest, UiSetupResponse, UiSetupResponseValue};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(SETUP_COMMAND_TIMEOUT_MILLIS, 30000);
        assert_eq!(
            SETUP_COMMAND_ABOUT,
            "Establishes (if Node is not already running) and displays startup parameters for MASQNode."
         );
    }

    #[test]
    fn setup_command_with_syntax_error() {
        let msg = SetupCommand::new(&["setup".to_string(), "--booga".to_string()])
            .err()
            .unwrap();

        assert_eq!(msg.contains("Found argument '"), true, "{}", msg);
        assert_eq!(msg.contains("--booga"), true, "{}", msg);
        assert_eq!(
            msg.contains("which wasn't expected, or isn't valid in this context"),
            true,
            "{}",
            msg
        );
    }

    #[test]
    fn setup_command_happy_path_with_node_not_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetupResponse {
                running: false,
                values: vec![
                    UiSetupResponseValue::new("chain", "eth-ropsten", Configured),
                    UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
                    UiSetupResponseValue::new(
                        "neighbors",
                        "masq://eth-mainnet:95VjByq5tEUUpDcczA__zXWGE6-7YFEvzN4CDVoPbWw@13.23.13.23:4545",
                        Set,
                    ),
                    UiSetupResponseValue::new("scans", "off", Set),
                    UiSetupResponseValue::new("scan-intervals","123|111|228",Set)
                ],
                errors: vec![],
            }
            .tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--log-level".to_string(),
                "--chain".to_string(),
                "eth-ropsten".to_string(),
                "--scan-intervals".to_string(),
                "123|111|228".to_string(),
                "--scans".to_string(),
                "off".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new(
                            "chain",
                            TEST_DEFAULT_CHAIN.rec().literal_identifier
                        ),
                        UiSetupRequestValue::clear("log-level"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                        UiSetupRequestValue::new("scan-intervals", "123|111|228"),
                        UiSetupRequestValue::new("scans", "off"),
                    ]
                }
                .tmb(0),
                SETUP_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                          VALUE                                                            STATUS\n\
chain                         eth-ropsten                                                      Configured\n\
neighborhood-mode             zero-hop                                                         Set\n\
neighbors                     masq://eth-mainnet:95VjByq5tEUUpDcczA__zXWGE6-7YFEvzN4CDVoPbWw@13.23.13.23:4545 Set\n\
scan-intervals                123|111|228                                                      Set\n\
scans                         off                                                              Set\n\
\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn setup_command_happy_path_with_node_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetupResponse {
                running: true,
                values: vec![
                    UiSetupResponseValue::new("chain", ETH_ROPSTEN_FULL_IDENTIFIER, Set),
                    UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Configured),
                    UiSetupResponseValue::new("clandestine-port", "8534", Default),
                ],
                errors: vec![("ip".to_string(), "Nosir, I don't like it.".to_string())],
            }
            .tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--chain".to_string(),
                "eth-ropsten".to_string(),
                "--clandestine-port".to_string(),
                "8534".to_string(),
                "--log-level".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "eth-ropsten"),
                        UiSetupRequestValue::new("clandestine-port", "8534"),
                        UiSetupRequestValue::clear("log-level"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0),
                SETUP_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                          VALUE                                                            STATUS\n\
chain                         eth-ropsten                                                      Set\n\
clandestine-port              8534                                                             Default\n\
neighborhood-mode             zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                            Nosir, I don't like it.\n\
\n\
NOTE: no changes were made to the setup because the Node is currently running.\n\
\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn handle_broadcast_works() {
        let message = UiSetupBroadcast {
            running: false,
            values: vec![
                UiSetupResponseValue::new("chain", "eth-ropsten", Set),
                UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Configured),
                UiSetupResponseValue::new("clandestine-port", "8534", Default),
            ],
            errors: vec![("ip".to_string(), "No sir, I don't like it.".to_string())],
        };
        let (stream_factory, handle) = TestStreamFactory::new();
        let (mut stdout, _) = stream_factory.make();
        let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));

        SetupCommand::handle_broadcast(message, &mut stdout, &term_interface);

        assert_eq! (handle.stdout_so_far(),
"\n\
Daemon setup has changed:\n\
\n\
NAME                          VALUE                                                            STATUS\n\
chain                         eth-ropsten                                                      Set\n\
clandestine-port              8534                                                             Default\n\
neighborhood-mode             zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                            No sir, I don't like it.\n\
\n");
    }

    #[test]
    fn setup_command_with_data_directory_shows_right_path() {
        vec![
            (None, None, Some("polygon-mainnet"), Some("/home/cooga/.local/MASQ/polygon-mainnet"), Some(None), UiSetupResponseValueStatus::Default, UiSetupResponseValueStatus::Default),
            (Some("polygon-mumbai"), None, Some("polygon-mumbai"), Some("/home/cooga/.local/MASQ/polygon-mumbai"), Some(None), UiSetupResponseValueStatus::Default, UiSetupResponseValueStatus::Default),
            (None, Some("booga"), Some("polygon-mainnet"), Some("booga/polygon-mainnet"), Some(Some("\nNOTE: your data directory was modified to match chain parameter.\n")), UiSetupResponseValueStatus::Default, UiSetupResponseValueStatus::Set),
            (Some("polygon-mumbai"), Some("booga"), Some("polygon-mumbai"), Some("booga/polygon-mumbai"), Some(Some("\nNOTE: your data directory was modified to match chain parameter.\n")), UiSetupResponseValueStatus::Set, UiSetupResponseValueStatus::Set),
            (None, Some("booga/polygon-mumbai"), Some("polygon-mainnet"), Some("booga/polygon-mumbai/polygon-mainnet"), Some(Some("\nNOTE: your data directory was modified to match chain parameter.\n")), UiSetupResponseValueStatus::Default, UiSetupResponseValueStatus::Set),
            (None, Some("booga/polygon-mumbai/polygon-mainnet"), Some("polygon-mainnet"), Some("booga/polygon-mumbai/polygon-mainnet/polygon-mainnet"), Some(Some("\nNOTE: your data directory was modified to match chain parameter.\n")), UiSetupResponseValueStatus::Default, UiSetupResponseValueStatus::Set),
            (Some("polygon-mumbai"), Some("booga/polygon-mumbai"), Some("polygon-mumbai"), Some("booga/polygon-mumbai/polygon-mumbai"), Some(Some("\nNOTE: your data directory was modified to match chain parameter.\n")), UiSetupResponseValueStatus::Set, UiSetupResponseValueStatus::Set),
        ].iter().for_each(|
            (chain_opt,
             data_directory_opt,
             chain_name_expected,
             data_directory_expected,
             note_expected,
             status_chain,
             status_data_dir)| {
            let note_expected_real = match &*note_expected {
                Some(..) => { match note_expected.unwrap() { Some(..) => note_expected.unwrap().unwrap(), None => "" } },
                _ => ""
            };
            let status_data_dir_str = match *status_data_dir { Default => "Default", Set => "Set", Configured => "Configured", UiSetupResponseValueStatus::Blank => "Blank", UiSetupResponseValueStatus::Required => "Required" };
            let status_chain_str = match *status_chain { Default => "Default", Set => "Set", Configured => "Configured", UiSetupResponseValueStatus::Blank => "Blank", UiSetupResponseValueStatus::Required => "Required" };
            let expected = format!("\
NAME                          VALUE                                                            STATUS\n\
{:29} {:64} {}\n{:29} {:64} {}\n{}\n", "chain", &*chain_name_expected.unwrap(), status_chain_str, "data-directory", &*data_directory_expected.unwrap(), status_data_dir_str, note_expected_real );
            let chain_opt_real = match &*chain_opt { Some(..) => &*chain_opt.unwrap(), _ => "polygon-mainnet" };
            let data_directory_opt_real = match &*data_directory_opt { Some(..) => &*data_directory_opt.unwrap(), _ => "/home/cooga/.local" };
            process_setup_command_for_given_attributes(chain_opt_real, data_directory_opt_real, &expected, *status_chain, *status_data_dir);
        });
    }
    fn process_setup_command_for_given_attributes(chain: &str, data_directory: &str, expected: &str,
                                                  status_chain: UiSetupResponseValueStatus,
                                                  status_data_dir: UiSetupResponseValueStatus ) {
        let message = UiSetupResponse {
            running: false,
            values: vec![
                UiSetupResponseValue::new("chain", chain, status_chain),
                UiSetupResponseValue::new("data-directory", data_directory, status_data_dir),
            ],
            errors: vec![],
        };
        let (stream_factory, handle) = TestStreamFactory::new();
        let (mut stdout, _) = stream_factory.make();

        SetupCommand::dump_setup(UiSetupInner::from(message), &mut stdout);

        assert_eq! (handle.stdout_so_far(), expected);
    }
}

