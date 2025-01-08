// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COLUMN_WIDTH, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::commands::configuration_command::value_list_interface::ValueList;
use crate::commands::parameter_columns_formatting::{
    add_char_after, dump_parameter_line, dump_single_line_parameters,
};
use crate::masq_short_writeln;
use crate::terminal::{TerminalWriter, WTermInterface};
use async_trait::async_trait;
use clap::{Arg, Command as ClapCommand};
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::implement_as_any;
use masq_lib::messages::{UiConfigurationRequest, UiConfigurationResponse};
#[cfg(test)]
use std::any::Any;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::sync::Arc;
use thousands::Separable;

const COLUMN_WIDTH: usize = 33;

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigurationCommand {
    pub db_password: Option<String>,
}

const CONFIGURATION_ABOUT: &str = "Displays a running Node's current configuration.";
const CONFIGURATION_ARG_HELP: &str =
    "Password of the database from which the configuration will be read.";

pub fn configuration_subcommand() -> ClapCommand {
    ClapCommand::new("configuration")
        .about(CONFIGURATION_ABOUT)
        .arg(
            Arg::new("db-password")
                .help(CONFIGURATION_ARG_HELP)
                .index(1)
                .required(false),
        )
}

#[async_trait(?Send)]
impl Command for ConfigurationCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let input = UiConfigurationRequest {
            db_password_opt: self.db_password.clone(),
        };
        let output: Result<UiConfigurationResponse, CommandError> =
            transaction(input, context, &stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await;
        match output {
            Ok(response) => {
                Self::dump_configuration(&stdout, response).await;
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                masq_short_writeln!(
                    stderr,
                    "MASQNode is not running; therefore its configuration cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                masq_short_writeln!(stderr, "Configuration retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }

    implement_as_any!();
}

impl ConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match configuration_subcommand().try_get_matches_from(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        Ok(ConfigurationCommand {
            db_password: matches
                .get_one::<String>("db-password")
                .map(|s| s.to_string()),
        })
    }

    async fn dump_configuration(stream: &TerminalWriter, configuration: UiConfigurationResponse) {
        dump_parameter_line(stream, "NAME", None, "VALUE").await;
        dump_single_line_parameters(
            stream,
            vec![
                (
                    "Blockchain service URL",
                    &configuration
                        .blockchain_service_url_opt
                        .unwrap_or_else(|| "[?]".to_string()),
                ),
                ("Chain", &configuration.chain_name),
                (
                    "Clandestine port",
                    &configuration.clandestine_port.to_string(),
                ),
                (
                    "Consuming wallet private key",
                    &Self::interpret_option(&configuration.consuming_wallet_private_key_opt),
                ),
                (
                    "Current schema version",
                    &configuration.current_schema_version,
                ),
                (
                    "Earning wallet address",
                    &Self::interpret_option(&configuration.earning_wallet_address_opt),
                ),
                ("Gas price", &configuration.gas_price.to_string()),
                ("Neighborhood mode", &configuration.neighborhood_mode),
                (
                    "Port mapping protocol",
                    &Self::interpret_option(&configuration.port_mapping_protocol_opt),
                ),
                ("Start block", &configuration.start_block.to_string()),
            ],
        )
        .await;
        ValueList::default()
            .umbrella_parameter_name("Past neighbors")
            .format_list(&configuration.past_neighbors, |val| val.clone())
            .dump_list(stream)
            .await;
        ValueList::default()
            .umbrella_parameter_name("Payment thresholds")
            .format_list(
                &[
                    (
                        "Debt threshold",
                        &configuration.payment_thresholds.debt_threshold_gwei
                            as &dyn DisplaySeparable,
                        "gwei",
                    ),
                    (
                        "Maturity threshold",
                        &configuration.payment_thresholds.maturity_threshold_sec,
                        "s",
                    ),
                    (
                        "Payment grace period",
                        &configuration.payment_thresholds.payment_grace_period_sec,
                        "s",
                    ),
                    (
                        "Permanent debt allowed",
                        &configuration.payment_thresholds.permanent_debt_allowed_gwei,
                        "gwei",
                    ),
                    (
                        "Threshold interval",
                        &configuration.payment_thresholds.threshold_interval_sec,
                        "s",
                    ),
                    (
                        "Unban below",
                        &configuration.payment_thresholds.unban_below_gwei,
                        "gwei",
                    ),
                ],
                combined_parameters_formatter,
            )
            .has_named_sub_parameters()
            .dump_list(stream)
            .await;
        ValueList::default()
            .umbrella_parameter_name("Rate pack")
            .format_list(
                &[
                    (
                        "Routing byte rate",
                        &configuration.rate_pack.routing_byte_rate as &dyn DisplaySeparable,
                        "wei",
                    ),
                    (
                        "Routing service rate",
                        &configuration.rate_pack.routing_service_rate,
                        "wei",
                    ),
                    (
                        "Exit byte rate",
                        &configuration.rate_pack.exit_byte_rate,
                        "wei",
                    ),
                    (
                        "Exit service rate",
                        &configuration.rate_pack.exit_service_rate,
                        "wei",
                    ),
                ],
                combined_parameters_formatter,
            )
            .has_named_sub_parameters()
            .dump_list(stream)
            .await;
        ValueList::default()
            .umbrella_parameter_name("Scan intervals")
            .format_list(
                &[
                    (
                        "Pending payable",
                        &configuration.scan_intervals.pending_payable_sec as &dyn DisplaySeparable,
                        "s",
                    ),
                    ("Payable", &configuration.scan_intervals.payable_sec, "s"),
                    (
                        "Receivable",
                        &configuration.scan_intervals.receivable_sec,
                        "s",
                    ),
                ],
                combined_parameters_formatter,
            )
            .has_named_sub_parameters()
            .dump_list(stream)
            .await
    }

    fn interpret_option(value_opt: &Option<String>) -> String {
        match value_opt {
            None => "[?]".to_string(),
            Some(s) => s.clone(),
        }
    }
}

pub mod value_list_interface {
    use crate::commands::commands_common::STANDARD_COLUMN_WIDTH;
    use crate::commands::parameter_columns_formatting::{
        dump_already_formatted_parameter_line, dump_parameter_line,
    };
    use crate::terminal::TerminalWriter;
    use futures::future::join_all;

    #[derive(Default)]
    pub struct ValueList {
        umbrella_parameter_name_opt: Option<String>,
        has_named_sub_parameters: bool,
        prepared_formatted_values: Vec<String>,
    }

    impl ValueList {
        pub fn umbrella_parameter_name(mut self, str: &str) -> Self {
            self.umbrella_parameter_name_opt.replace(str.to_string());
            self
        }

        pub fn format_list<Formatter, UnformattedValue>(
            mut self,
            unformatted_list: &[UnformattedValue],
            formatter: Formatter,
        ) -> Self
        where
            Formatter: FnMut(&UnformattedValue) -> String,
        {
            self.prepared_formatted_values = unformatted_list.into_iter().map(formatter).collect();
            self
        }

        pub fn has_named_sub_parameters(mut self) -> Self {
            self.has_named_sub_parameters = true;
            self
        }

        pub async fn dump_list(self, stream: &TerminalWriter) {
            if !self.has_named_sub_parameters && self.prepared_formatted_values.is_empty() {
                self.handle_empty_simple_list(stream).await;
                return;
            }
            self.dump_list_internal(stream).await
        }

        async fn handle_empty_simple_list(&self, stream: &TerminalWriter) {
            let header = self
                .umbrella_parameter_name_opt
                .as_ref()
                .expect("Trying to dump an unnamed parameter list while list empty");
            dump_parameter_line(stream, &header, Some(':'), "[?]").await;
        }

        async fn dump_list_internal(&self, stream: &TerminalWriter) {
            let mut iterator = self.prepared_formatted_values.iter();
            self.first_line_dilemma(&mut iterator, stream).await;
            self.dump_formatted_values(iterator, stream).await
        }

        async fn first_line_dilemma(
            &self,
            iter: &mut impl Iterator<Item = &String>,
            stream: &TerminalWriter,
        ) {
            let first_line_value = if !self.has_named_sub_parameters {
                iter.next()
                    .expect("No entries. Should've been caught previously")
                    .clone()
            } else {
                "".to_string()
            };

            let header = self
                .umbrella_parameter_name_opt
                .as_ref()
                .expect("Trying to dump an unnamed parameter list");
            dump_parameter_line(stream, header, Some(':'), &first_line_value).await;
        }

        async fn dump_formatted_values(
            &self,
            iter: impl Iterator<Item = &String>,
            stream: &TerminalWriter,
        ) {
            let _ = join_all(iter.map(|formatted_value| {
                dump_already_formatted_parameter_line(
                    stream,
                    STANDARD_COLUMN_WIDTH + 1,
                    &formatted_value,
                )
            }))
            .await;
        }
    }
}

fn combined_parameters_formatter(
    (sub_param_name, value, unit): &(&str, &dyn DisplaySeparable, &str),
) -> String {
    format!(
        "{:width$} {} {}",
        add_char_after(sub_param_name, Some(':')),
        value.separate_with_commas(),
        unit,
        width = STANDARD_COLUMN_WIDTH
    )
}

trait DisplaySeparable: Display + Separable {}
impl DisplaySeparable for u64 {}
impl DisplaySeparable for String {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::terminal::test_utils::allow_in_test_spawned_task_to_finish;
    use crate::test_utils::mocks::{CommandContextMock, MockTerminalMode, TermInterfaceMock};
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{
        ToMessageBody, UiConfigurationResponse, UiPaymentThresholds, UiRatePack, UiScanIntervals,
    };
    use masq_lib::utils::AutomapProtocol;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONFIGURATION_ABOUT,
            "Displays a running Node's current configuration."
        );
        assert_eq!(
            CONFIGURATION_ARG_HELP,
            "Password of the database from which the configuration will be read."
        );
    }

    #[test]
    fn command_factory_works_with_password() {
        let subject = CommandFactoryReal::new();

        let command = subject
            .make(&["configuration".to_string(), "password".to_string()])
            .unwrap();

        let configuration_command = command
            .as_any()
            .downcast_ref::<ConfigurationCommand>()
            .unwrap();

        assert_eq!(
            *configuration_command,
            ConfigurationCommand {
                db_password: Some("password".to_string())
            }
        );
    }

    #[test]
    fn command_factory_works_without_password() {
        let subject = CommandFactoryReal::new();

        let command = subject.make(&["configuration".to_string()]).unwrap();

        let configuration_command = command
            .as_any()
            .downcast_ref::<ConfigurationCommand>()
            .unwrap();
        assert_eq!(
            configuration_command,
            &ConfigurationCommand { db_password: None }
        );
    }

    #[tokio::test]
    async fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_in_test_spawned_task_to_finish().await;
        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "MASQNode is not running; therefore its configuration cannot be displayed.\n"
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn configuration_command_happy_path_with_secrets() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConfigurationResponse {
            blockchain_service_url_opt: Some("https://infura.io/ID".to_string()),
            current_schema_version: "schema version".to_string(),
            clandestine_port: 1234,
            chain_name: "ropsten".to_string(),
            gas_price: 2345,
            neighborhood_mode: "standard".to_string(),
            consuming_wallet_private_key_opt: Some("consuming wallet private key".to_string()),
            consuming_wallet_address_opt: Some("consuming wallet address".to_string()),
            earning_wallet_address_opt: Some("earning address".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec!["neighbor 1".to_string(), "neighbor 2".to_string()],
            payment_thresholds: UiPaymentThresholds {
                threshold_interval_sec: 11111,
                debt_threshold_gwei: 1201412000,
                payment_grace_period_sec: 4578,
                permanent_debt_allowed_gwei: 112000,
                maturity_threshold_sec: 3333,
                unban_below_gwei: 120000,
            },
            rate_pack: UiRatePack {
                routing_byte_rate: 99025000,
                routing_service_rate: 138000000,
                exit_byte_rate: 129000000,
                exit_service_rate: 160000000,
            },
            start_block: 3456,
            scan_intervals: UiScanIntervals {
                pending_payable_sec: 150500,
                payable_sec: 155000,
                receivable_sec: 250666,
            },
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);
        let subject =
            ConfigurationCommand::new(&["configuration".to_string(), "password".to_string()])
                .unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_in_test_spawned_task_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: Some("password".to_string())
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            format!(
                "\
|NAME                              VALUE\n\
|Blockchain service URL:           https://infura.io/ID\n\
|Chain:                            ropsten\n\
|Clandestine port:                 1234\n\
|Consuming wallet private key:     consuming wallet private key\n\
|Current schema version:           schema version\n\
|Earning wallet address:           earning address\n\
|Gas price:                        2345\n\
|Neighborhood mode:                standard\n\
|Port mapping protocol:            PCP\n\
|Start block:                      3456\n\
|Past neighbors:                   neighbor 1\n\
|                                  neighbor 2\n\
|Payment thresholds:               \n\
|                                  Debt threshold:                   1,201,412,000 gwei\n\
|                                  Maturity threshold:               3,333 s\n\
|                                  Payment grace period:             4,578 s\n\
|                                  Permanent debt allowed:           112,000 gwei\n\
|                                  Threshold interval:               11,111 s\n\
|                                  Unban below:                      120,000 gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                99,025,000 wei\n\
|                                  Routing service rate:             138,000,000 wei\n\
|                                  Exit byte rate:                   129,000,000 wei\n\
|                                  Exit service rate:                160,000,000 wei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  150,500 s\n\
|                                  Payable:                          155,000 s\n\
|                                  Receivable:                       250,666 s\n"
            )
            .replace('|', "")
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn configuration_command_happy_path_without_secrets() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConfigurationResponse {
            blockchain_service_url_opt: Some("https://infura.io/ID".to_string()),
            current_schema_version: "schema version".to_string(),
            clandestine_port: 1234,
            chain_name: "mumbai".to_string(),
            gas_price: 2345,
            neighborhood_mode: "zero-hop".to_string(),
            consuming_wallet_address_opt: None,
            consuming_wallet_private_key_opt: None,
            earning_wallet_address_opt: Some("earning wallet".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec![],
            payment_thresholds: UiPaymentThresholds {
                threshold_interval_sec: 1000,
                debt_threshold_gwei: 2500,
                payment_grace_period_sec: 666,
                permanent_debt_allowed_gwei: 1200,
                maturity_threshold_sec: 500,
                unban_below_gwei: 1400,
            },
            rate_pack: UiRatePack {
                routing_byte_rate: 15,
                routing_service_rate: 17,
                exit_byte_rate: 20,
                exit_service_rate: 30,
            },
            start_block: 3456,
            scan_intervals: UiScanIntervals {
                pending_payable_sec: 1000,
                payable_sec: 1000,
                receivable_sec: 1000,
            },
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_in_test_spawned_task_to_finish().await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stream_handles.stdout_all_in_one(),
            format!(
                "\
|NAME                              VALUE\n\
|Blockchain service URL:           https://infura.io/ID\n\
|Chain:                            mumbai\n\
|Clandestine port:                 1234\n\
|Consuming wallet private key:     [?]\n\
|Current schema version:           schema version\n\
|Earning wallet address:           earning wallet\n\
|Gas price:                        2345\n\
|Neighborhood mode:                zero-hop\n\
|Port mapping protocol:            PCP\n\
|Start block:                      3456\n\
|Past neighbors:                   [?]\n\
|Payment thresholds:               \n\
|                                  Debt threshold:                   2,500 gwei\n\
|                                  Maturity threshold:               500 s\n\
|                                  Payment grace period:             666 s\n\
|                                  Permanent debt allowed:           1,200 gwei\n\
|                                  Threshold interval:               1,000 s\n\
|                                  Unban below:                      1,400 gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                15 wei\n\
|                                  Routing service rate:             17 wei\n\
|                                  Exit byte rate:                   20 wei\n\
|                                  Exit service rate:                30 wei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  1,000 s\n\
|                                  Payable:                          1,000 s\n\
|                                  Receivable:                       1,000 s\n",
            )
            .replace('|', "")
        );
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn configuration_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let (mut term_interface, stream_handles, _) =
            TermInterfaceMock::new(MockTerminalMode::NonInteractiveMode);
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = Box::new(subject)
            .execute(&mut context, &mut term_interface)
            .await;

        allow_in_test_spawned_task_to_finish().await;
        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConfigurationRequest {
                    db_password_opt: None
                }
                .tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        stream_handles.assert_empty_stdout();
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "Configuration retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
