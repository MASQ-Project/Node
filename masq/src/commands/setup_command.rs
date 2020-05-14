// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::{value_t, App, SubCommand};
use masq_lib::messages::{UiSetupRequest, UiSetupRequestValue, UiSetupResponse, SETUP_ERROR};
use masq_lib::shared_schema::shared_app;
use masq_lib::utils::index_of_from;
use std::fmt::Debug;

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
        let result: Result<UiSetupResponse, CommandError> = transaction(out_message, context);
        match result {
            Ok(mut response) => {
                response.values.sort_by(|a, b| {
                    a.name
                        .partial_cmp(&b.name)
                        .expect("String comparison failed")
                });
                writeln!(
                    context.stdout(),
                    "NAME                      VALUE                                                            STATUS"
                )
                .expect("writeln! failed");
                response.values.into_iter().for_each(|value| {
                    writeln!(
                        context.stdout(),
                        "{:26}{:65}{:?}",
                        value.name,
                        value.value,
                        value.status
                    )
                    .expect("writeln! failed")
                });
                if !response.errors.is_empty() {
                    writeln!(context.stdout(), "\nERRORS:").expect("writeln! failed");
                    response.errors.into_iter().for_each(|(parameter, reason)| {
                        writeln!(context.stdout(), "{:26}{}", parameter, reason)
                            .expect("writeln! failed")
                    })
                }
                if response.running {
                    writeln!(context.stdout(), "\nNOTE: no changes were made to the setup because the Node is currently running.")
                        .expect ("writeln! failed");
                }
                Ok(())
            }
            Err(CommandError::Payload(err, msg)) if err == SETUP_ERROR => {
                writeln!(context.stderr(), "{}", msg).expect("writeln! failed");
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

    fn has_value(pieces: &[String], piece: &str) -> bool {
        let dash_dash_piece = format!("--{}", piece);
        match index_of_from(pieces, &dash_dash_piece, 0) {
            None => false,
            Some(idx) if idx == pieces.len() - 1 => false,
            Some(idx) => !pieces[idx + 1].starts_with("--"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiSetupResponseValueStatus::{Configured, Default, Set};
    use masq_lib::messages::{UiSetupRequest, UiSetupResponse, UiSetupResponseValue};
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
            vec![UiSetupRequest {
                values: vec![
                    UiSetupRequestValue::new("chain", "ropsten"),
                    UiSetupRequestValue::clear("log-level"),
                    UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                ]
            }
            .tmb(0)]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                      VALUE                                                            STATUS\n\
chain                     ropsten                                                          Configured\n\
neighborhood-mode         zero-hop                                                         Set\n");
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
            vec![UiSetupRequest {
                values: vec![
                    UiSetupRequestValue::new("chain", "ropsten"),
                    UiSetupRequestValue::new("clandestine-port", "8534"),
                    UiSetupRequestValue::clear("log-level"),
                    UiSetupRequestValue::new("neighborhood-mode", "zero-hop"),
                ]
            }
            .tmb(0)]
        );
        assert_eq! (stdout_arc.lock().unwrap().get_string(),
"NAME                      VALUE                                                            STATUS\n\
chain                     ropsten                                                          Set\n\
clandestine-port          8534                                                             Default\n\
neighborhood-mode         zero-hop                                                         Configured\n\
\n\
ERRORS:
ip                        Nosir, I don't like it.\n\
\n\
NOTE: no changes were made to the setup because the Node is currently running.\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }
}
