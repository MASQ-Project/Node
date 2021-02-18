// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{value_t, App, SubCommand};
use masq_lib::messages::{
    UiSetupBroadcast, UiSetupInner, UiSetupRequest, UiSetupRequestValue, UiSetupResponse,
    SETUP_ERROR,
};
use masq_lib::shared_schema::shared_app;
use masq_lib::short_writeln;
use masq_lib::utils::index_of_from;
use std::fmt::Debug;
use std::io::Write;

pub fn setup_subcommand() -> App<'static, 'static> {
    shared_app(SubCommand::with_name("setup")
        .about("Establishes (if Node is not already running) and displays startup parameters for MASQNode."))
}

#[derive(Debug, PartialEq)]
pub struct SetupCommand {
    pub values: Vec<UiSetupRequestValue>,
}

impl Command for SetupCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let out_message = UiSetupRequest {
            values: self.values.clone(),
        };
        let result: Result<UiSetupResponse, CommandError> =
            transaction(out_message, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
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
}

impl SetupCommand {
    pub fn new(pieces: Vec<String>) -> Result<Self, String> {
        let matches = match setup_subcommand().get_matches_from_safe(&pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };
        let mut values = pieces
            .iter()
            .filter(|piece| (*piece).starts_with("--"))
            .map(|piece| piece[2..].to_string())
            .map(|key| {
                if Self::has_value(&pieces, &key) {
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

    pub fn handle_broadcast(response: UiSetupBroadcast, stdout: &mut dyn Write) {
        short_writeln!(stdout, "\nDaemon setup has changed:\n");
        Self::dump_setup(UiSetupInner::from(response), stdout);
        write!(stdout, "masq> ").expect("write! failed");
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
        short_writeln!(
            stdout,
            "NAME                   VALUE                                                            STATUS"
        );
        inner.values.into_iter().for_each(|value| {
            short_writeln!(
                stdout,
                "{:23}{:65}{:?}",
                value.name,
                value.value,
                value.status
            );
        });
        short_writeln!(stdout);
        if !inner.errors.is_empty() {
            short_writeln!(stdout, "ERRORS:");
            inner.errors.into_iter().for_each(|(parameter, reason)| {
                short_writeln!(stdout, "{:23}{}", parameter, reason)
            });
            short_writeln!(stdout);
        }
        if inner.running {
            short_writeln!(
                stdout,
                "NOTE: no changes were made to the setup because the Node is currently running.\n"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::communications::broadcast_handler::StreamFactory;
    use crate::test_utils::mocks::{CommandContextMock, TestStreamFactory};
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiSetupResponseValueStatus::{Configured, Default, Set};
    use masq_lib::messages::{UiSetupRequest, UiSetupResponse, UiSetupResponseValue};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN_NAME;
    use std::sync::{Arc, Mutex};

    #[test]
    fn setup_command_with_syntax_error() {
        let msg = SetupCommand::new(vec!["setup".to_string(), "--booga".to_string()])
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
                    UiSetupResponseValue::new("chain", "ropsten", Configured),
                    UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Set),
                ],
                errors: vec![],
            }
            .tmb(0)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let factory = CommandFactoryReal::new();
        let subject = factory
            .make(vec![
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--log-level".to_string(),
                "--chain".to_string(),
                "ropsten".to_string(),
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
                        UiSetupRequestValue::new("chain", TEST_DEFAULT_CHAIN_NAME),
                        UiSetupRequestValue::clear("log-level"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                   VALUE                                                            STATUS\n\
chain                  ropsten                                                          Configured\n\
neighborhood-mode      zero-hop                                                         Set\n\
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
                    UiSetupResponseValue::new("chain", "ropsten", Set),
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
            .make(vec![
                "setup".to_string(),
                "--neighborhood-mode".to_string(),
                "zero-hop".to_string(),
                "--chain".to_string(),
                "ropsten".to_string(),
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
                        UiSetupRequestValue::new("chain", "ropsten"),
                        UiSetupRequestValue::new("clandestine-port", "8534"),
                        UiSetupRequestValue::clear("log-level"),
                        UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                    ]
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                   VALUE                                                            STATUS\n\
chain                  ropsten                                                          Set\n\
clandestine-port       8534                                                             Default\n\
neighborhood-mode      zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                     Nosir, I don't like it.\n\
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
                UiSetupResponseValue::new("chain", "ropsten", Set),
                UiSetupResponseValue::new("neighborhood-mode", "zero-hop", Configured),
                UiSetupResponseValue::new("clandestine-port", "8534", Default),
            ],
            errors: vec![("ip".to_string(), "Nosir, I don't like it.".to_string())],
        };
        let (stream_factory, handle) = TestStreamFactory::new();
        let (mut stdout, _) = stream_factory.make();

        SetupCommand::handle_broadcast(message, &mut stdout);

        assert_eq! (handle.stdout_so_far(),
"\n\
Daemon setup has changed:\n\
\n\
NAME                   VALUE                                                            STATUS\n\
chain                  ropsten                                                          Set\n\
clandestine-port       8534                                                             Default\n\
neighborhood-mode      zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                     Nosir, I don't like it.\n\
\n\
masq> ");
    }
}
