// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::terminal::terminal_interface::{TerminalWriter, WTermInterface};
use async_trait::async_trait;
use clap::Command as ClapCommand;
use futures::future::join_all;
use itertools::Itertools;
use masq_lib::constants::SETUP_ERROR;
use masq_lib::implement_as_any;
use masq_lib::messages::{
    UiSetupBroadcast, UiSetupInner, UiSetupRequest, UiSetupRequestValue, UiSetupResponse,
    UiSetupResponseValue, UiSetupResponseValueStatus,
};
use masq_lib::shared_schema::{data_directory_arg, shared_app};
use masq_lib::short_writeln;
use masq_lib::utils::{get_argument_value_as_string, index_of_from, DATA_DIRECTORY_DAEMON_HELP};
#[cfg(test)]
use std::any::Any;
use std::fmt::Debug;
use std::io::Write;
use std::iter::Iterator;
use std::sync::Arc;

pub const SETUP_COMMAND_TIMEOUT_MILLIS: u64 = 30000;

const SETUP_COMMAND_ABOUT: &str =
    "Establishes (if Node is not already running) and displays startup parameters for MASQNode.";

pub fn setup_subcommand() -> ClapCommand {
    let command_with_old_data_directory =
        shared_app(ClapCommand::new("setup").about(SETUP_COMMAND_ABOUT));
    let args_except_data_directory = command_with_old_data_directory
        .get_arguments()
        .filter(|arg| arg.get_long() != Some("data-directory"))
        .collect_vec();
    let command_with_new_data_directory = ClapCommand::new("setup")
        .about(SETUP_COMMAND_ABOUT)
        .args(args_except_data_directory)
        .arg(data_directory_arg(DATA_DIRECTORY_DAEMON_HELP.clone()));
    command_with_new_data_directory
}

#[derive(Debug, PartialEq, Eq)]
pub struct SetupCommand {
    pub values: Vec<UiSetupRequestValue>,
}

#[async_trait(?Send)]
impl Command for SetupCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let out_message = UiSetupRequest {
            values: self.values.clone(),
        };
        let result: Result<UiSetupResponse, CommandError> =
            transaction(out_message, context, stderr, SETUP_COMMAND_TIMEOUT_MILLIS).await;
        match result {
            Ok(response) => {
                Self::dump_setup(UiSetupInner::from(response), stdout).await;
                Ok(())
            }
            Err(CommandError::Payload(err, msg)) if err == SETUP_ERROR => {
                short_writeln!(stderr, "{}", msg);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    implement_as_any!();
}

impl SetupCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let subcommand = setup_subcommand();
        let matches = match subcommand.try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        let mut values = pieces
            .iter()
            .filter(|piece| (*piece).starts_with("--"))
            .map(|piece| piece[2..].to_string())
            .map(|key| {
                if Self::has_value(pieces, &key) {
                    let value =
                        get_argument_value_as_string(&matches, &key).expect("Value disappeared");
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

    pub async fn handle_broadcast(
        response: UiSetupBroadcast,
        stdout: &TerminalWriter,
        _stderr: &TerminalWriter,
    ) {
        short_writeln!(stdout, "\nDaemon setup has changed:\n");
        Self::dump_setup(UiSetupInner::from(response), stdout).await;
    }

    fn has_value(pieces: &[String], piece: &str) -> bool {
        let dash_dash_piece = format!("--{}", piece);
        match index_of_from(pieces, &dash_dash_piece, 0) {
            None => false,
            Some(idx) if idx == pieces.len() - 1 => false,
            Some(idx) => !pieces[idx + 1].starts_with("--"),
        }
    }

    async fn dump_setup(mut inner: UiSetupInner, stdout: &TerminalWriter) {
        inner.values.sort_by(|a, b| {
            a.name
                .partial_cmp(&b.name)
                .expect("String comparison failed")
        });
        short_writeln!(stdout, "{:29} {:64} {}", "NAME", "VALUE", "STATUS");
        let chain_and_data_dir =
            |p: &UiSetupResponseValue| (p.name.to_owned(), (p.value.clone(), p.status));
        let chain = inner
            .values
            .iter()
            .find(|&p| p.name.as_str() == "chain")
            .map(chain_and_data_dir)
            .expect("Chain name is missing in setup cluster!");
        let data_directory = inner
            .values
            .iter()
            .find(|&p| p.name.as_str() == "data-directory")
            .map(chain_and_data_dir)
            .expect("data-directory is missing in setup cluster!");

        join_all(inner.values.into_iter().map(|value| async move {
            short_writeln!(
                stdout,
                "{:29} {:64} {:?}",
                value.name,
                value.value,
                value.status
            );
        }))
        .await;
        short_writeln!(stdout);
        if !inner.errors.is_empty() {
            short_writeln!(stdout, "ERRORS:");
            join_all(
                inner
                    .errors
                    .into_iter()
                    .map(|(parameter, reason)| async move {
                        short_writeln!(stdout, "{:29} {}", parameter, reason)
                    }),
            )
            .await;
            short_writeln!(stdout);
        }
        if inner.running {
            short_writeln!(
                stdout,
                "NOTE: no changes were made to the setup because the Node is currently running.\n"
            );
        }
        if chain.1 .1 != UiSetupResponseValueStatus::Default
            || data_directory.1 .1 != UiSetupResponseValueStatus::Default
        {
            short_writeln!(
                stdout,
                "NOTE: your data directory was modified to match the chain parameter.\n"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::{
        make_terminal_writer, CommandContextMock, TermInterfaceMock, TestStreamFactory,
    };
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiSetupResponseValueStatus::{
        Configured, Default as DefaultStatus, Set,
    };
    use masq_lib::messages::{UiSetupRequest, UiSetupResponse, UiSetupResponseValue};
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

        assert_eq!(msg.contains("unexpected argument '"), true, "{}", msg);
    }

    #[tokio::test]
    async fn setup_command_happy_path_with_node_not_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetupResponse {
                running: false,
                values: vec![
                    UiSetupResponseValue::new("chain", "eth-mainnet", Configured),
                    UiSetupResponseValue::new("data-directory", "/home/booga/eth-mainnet", UiSetupResponseValueStatus::Default),
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
        let (mut term_interface, stream_handles) = TermInterfaceMock::new(None).await;
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--log-level".to_string(),
                "--chain".to_string(),
                "polygon-mainnet".to_string(),
                "--scan-intervals".to_string(),
                "123|111|228".to_string(),
                "--scans".to_string(),
                "off".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", DEFAULT_CHAIN.rec().literal_identifier),
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
        assert_eq! (stream_handles.stdout_flushed_strings().await,
vec!["NAME                          VALUE                                                            STATUS\n\
chain                         eth-mainnet                                                      Configured\n\
data-directory                /home/booga/eth-mainnet                                          Default\n\
neighborhood-mode             zero-hop                                                         Set\n\
neighbors                     masq://eth-mainnet:95VjByq5tEUUpDcczA__zXWGE6-7YFEvzN4CDVoPbWw@13.23.13.23:4545 Set\n\
scan-intervals                123|111|228                                                      Set\n\
scans                         off                                                              Set\n\
\nNOTE: your data directory was modified to match the chain parameter.\n\n".to_string()]);
        stream_handles.assert_empty_stderr().await;
    }

    #[tokio::test]
    async fn setup_command_happy_path_with_node_running() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(UiSetupResponse {
                running: true,
                values: vec![
                    UiSetupResponseValue::new("chain", "eth-mainnet", Set),
                    UiSetupResponseValue::new("data-directory", "/home/booga/eth-mainnet", Set),
                    UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Configured),
                    UiSetupResponseValue::new(
                        "clandestine-port",
                        "8534",
                        UiSetupResponseValueStatus::Default,
                    ),
                ],
                errors: vec![("ip".to_string(), "Nosir, I don't like it.".to_string())],
            }
            .tmb(0)));
        let (mut term_interface, stream_handles) = TermInterfaceMock::new(None).await;
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(&[
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--chain".to_string(),
                "eth-mainnet".to_string(),
                "--clandestine-port".to_string(),
                "8534".to_string(),
                "--log-level".to_string(),
            ])
            .unwrap();

        let result = subject.execute(&mut context, &mut term_interface).await;

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiSetupRequest {
                    values: vec![
                        UiSetupRequestValue::new("chain", "eth-mainnet"),
                        UiSetupRequestValue::new("clandestine-port", "8534"),
                        UiSetupRequestValue::clear("log-level"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0),
                SETUP_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq! (stream_handles.stdout_flushed_strings().await,
vec!["NAME                          VALUE                                                            STATUS\n\
chain                         eth-mainnet                                                      Set\n\
clandestine-port              8534                                                             Default\n\
data-directory                /home/booga/eth-mainnet                                          Set\n\
neighborhood-mode             zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                            Nosir, I don't like it.\n\
\n\
NOTE: no changes were made to the setup because the Node is currently running.\n\
\nNOTE: your data directory was modified to match the chain parameter.\n\n"]);
        stream_handles.assert_empty_stderr().await;
    }

    #[test]
    fn handle_broadcast_works() {
        todo!("fix me")
        //         let message = UiSetupBroadcast {
        //             running: false,
        //             values: vec![
        //                 UiSetupResponseValue::new("chain", "eth-mainnet", Set),
        //                 UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Configured),
        //                 UiSetupResponseValue::new("clandestine-port", "8534", DefaultStatus),
        //                 UiSetupResponseValue::new("data-directory", "/home/booga/eth-mainnet", Set),
        //             ],
        //             errors: vec![("ip".to_string(), "No sir, I don't like it.".to_string())],
        //         };
        //         let (stream_factory, handle) = TestStreamFactory::new();
        //         let (mut stdout, _) = stream_factory.make();
        //         let term_interface = TerminalWrapper::new(Arc::new(TerminalPassiveMock::new()));
        //
        //         SetupCommand::handle_broadcast(message, &mut stdout, &term_interface);
        //
        //         assert_eq! (handle.stdout_so_far(),
        // "\n\
        // Daemon setup has changed:\n\
        // \n\
        // NAME                          VALUE                                                            STATUS\n\
        // chain                         eth-mainnet                                                      Set\n\
        // clandestine-port              8534                                                             Default\n\
        // data-directory                /home/booga/eth-mainnet                                          Set\n\
        // neighborhood-mode             zero-hop                                                         Configured\n\
        // \n\
        // ERRORS:
        // ip                            No sir, I don't like it.\n\
        // \nNOTE: your data directory was modified to match the chain parameter.\n\n");
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct SetupCommandData {
        chain_str: Option<String>,
        data_directory: Option<String>,
        chain_name_expected: Option<&'static str>,
        data_directory_expected: Option<&'static str>,
        note_expected: bool,
        status_chain: UiSetupResponseValueStatus,
        status_data_dir: UiSetupResponseValueStatus,
    }

    #[tokio::test]
    async fn setup_command_with_data_directory_shows_right_path() {
        #[rustfmt::skip]
        let setup_commands = vec![
            SetupCommandData {
                chain_str: None,
                data_directory: None,
                chain_name_expected: Some("polygon-mainnet"),
                data_directory_expected: Some("/home/cooga/.local/MASQ/polygon-mainnet"),
                note_expected: false,
                status_chain: UiSetupResponseValueStatus::Default,
                status_data_dir: UiSetupResponseValueStatus::Default,
            },
            SetupCommandData {
                chain_str: Some("polygon-mumbai".to_owned()),
                data_directory: None,
                chain_name_expected: Some("polygon-mumbai"),
                data_directory_expected: Some("/home/cooga/.local/MASQ/polygon-mumbai"),
                note_expected: true,
                status_chain: UiSetupResponseValueStatus::Set,
                status_data_dir: UiSetupResponseValueStatus::Default,
            },
            SetupCommandData {
                chain_str: None,
                data_directory: Some("booga".to_owned()),
                chain_name_expected: Some("polygon-mainnet"),
                data_directory_expected: Some("booga/polygon-mainnet"),
                note_expected: true,
                status_chain: UiSetupResponseValueStatus::Default,
                status_data_dir: UiSetupResponseValueStatus::Set,
            },
            SetupCommandData {
                chain_str: Some("polygon-mumbai".to_owned()),
                data_directory: Some("booga/polygon-mumbai".to_owned()),
                chain_name_expected: Some("polygon-mumbai"),
                data_directory_expected: Some("booga/polygon-mumbai/polygon-mumbai"),
                note_expected: true,
                status_chain: UiSetupResponseValueStatus::Set,
                status_data_dir: UiSetupResponseValueStatus::Set,
            },
        ];

        join_all(setup_commands.iter().map(|
            data| async move {
            let note_expected_real = match data.note_expected {
                true => "\nNOTE: your data directory was modified to match the chain parameter.\n",
                _ => ""
            };
            let status_data_dir_str = match data.status_data_dir {
                UiSetupResponseValueStatus::Default => "Default",
                Set => "Set",
                Configured => "Configured",
                UiSetupResponseValueStatus::Blank => "Blank",
                UiSetupResponseValueStatus::Required => "Required"
            };
            let status_chain_str = match data.status_chain {
                UiSetupResponseValueStatus::Default => "Default",
                Set => "Set",
                Configured => "Configured",
                UiSetupResponseValueStatus::Blank => "Blank",
                UiSetupResponseValueStatus::Required => "Required"
            };
            let expected = format!("\
NAME                          VALUE                                                            STATUS\n\
{:29} {:64} {}\n{:29} {:64} {}\n{}\n",
                                   "chain",
                                   data.chain_name_expected.unwrap(),
                                   status_chain_str,
                                   "data-directory",
                                   data.data_directory_expected.unwrap(),
                                   status_data_dir_str,
                                   note_expected_real
            );
            let chain_real = match &data.chain_str { Some(chain) => chain, _ => "polygon-mainnet" };
            let data_directory_real = match &data.data_directory {
                Some(dir) => format!("{}/{}", dir, chain_real),
                _ => format!("/home/cooga/.local/MASQ/{}", chain_real)
            };
            process_setup_command_for_given_attributes(
                chain_real,
                &data_directory_real,
                &expected,
                data.status_chain,
                data.status_data_dir
            ).await;
        })).await;
    }

    async fn process_setup_command_for_given_attributes(
        chain: &str,
        data_directory: &str,
        expected: &str,
        status_chain: UiSetupResponseValueStatus,
        status_data_dir: UiSetupResponseValueStatus,
    ) {
        let message = UiSetupResponse {
            running: false,
            values: vec![
                UiSetupResponseValue::new("chain", chain, status_chain),
                UiSetupResponseValue::new("data-directory", data_directory, status_data_dir),
            ],
            errors: vec![],
        };
        let (stream_factory, handle) = TestStreamFactory::new();
        let (stdout, stdout_arc) = make_terminal_writer();

        SetupCommand::dump_setup(UiSetupInner::from(message), &stdout).await;

        assert_eq!(stdout_arc.lock().unwrap().get_string(), expected);
    }
}
