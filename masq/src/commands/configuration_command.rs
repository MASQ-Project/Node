// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::{App, Arg, SubCommand};
use masq_lib::as_any_impl;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiConfigurationRequest, UiConfigurationResponse};
use masq_lib::short_writeln;
#[cfg(test)]
use std::any::Any;
use std::fmt::{Debug, Display};
use std::io::Write;
use std::iter::once;

const COLUMN_WIDTH: usize = 33;

#[derive(Debug, PartialEq)]
pub struct ConfigurationCommand {
    pub db_password: Option<String>,
}

const CONFIGURATION_ABOUT: &str = "Displays a running Node's current configuration.";
const CONFIGURATION_ARG_HELP: &str =
    "Password of the database from which the configuration will be read";

pub fn configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("configuration")
        .about(CONFIGURATION_ABOUT)
        .arg(
            Arg::with_name("db-password")
                .help(CONFIGURATION_ARG_HELP)
                .index(1)
                .required(false),
        )
}

impl Command for ConfigurationCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiConfigurationRequest {
            db_password_opt: self.db_password.clone(),
        };
        let output: Result<UiConfigurationResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                Self::dump_configuration(context.stdout(), response);
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore its configuration cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Configuration retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }

    as_any_impl!();
}

impl ConfigurationCommand {
    pub fn new(pieces: &[String]) -> Result<Self, String> {
        let matches = match configuration_subcommand().get_matches_from_safe(pieces) {
            Ok(matches) => matches,
            Err(e) => return Err(format!("{}", e)),
        };

        Ok(ConfigurationCommand {
            db_password: matches.value_of("db-password").map(|s| s.to_string()),
        })
    }

    fn dump_configuration(stream: &mut dyn Write, configuration: UiConfigurationResponse) {
        Self::dump_configuration_line(stream, "NAME", "VALUE");
        Self::dump_configuration_line(
            stream,
            "Blockchain service URL:",
            &configuration
                .blockchain_service_url_opt
                .unwrap_or_else(|| "[?]".to_string()),
        );
        Self::dump_configuration_line(stream, "Chain:", &configuration.chain_name);
        Self::dump_configuration_line(
            stream,
            "Clandestine port:",
            &configuration.clandestine_port.to_string(),
        );
        Self::dump_configuration_line(
            stream,
            "Consuming wallet private key:",
            &Self::interpret_option(&configuration.consuming_wallet_private_key_opt),
        );
        Self::dump_configuration_line(
            stream,
            "Current schema version:",
            &configuration.current_schema_version,
        );
        Self::dump_configuration_line(
            stream,
            "Earning wallet address:",
            &Self::interpret_option(&configuration.earning_wallet_address_opt),
        );
        Self::dump_configuration_line(stream, "Gas price:", &configuration.gas_price.to_string());
        Self::dump_configuration_line(
            stream,
            "Neighborhood mode:",
            &configuration.neighborhood_mode,
        );
        Self::dump_configuration_line(
            stream,
            "Port mapping protocol:",
            &Self::interpret_option(&configuration.port_mapping_protocol_opt),
        );
        Self::dump_configuration_line(
            stream,
            "Start block:",
            &configuration.start_block.to_string(),
        );
        Self::dump_value_list(stream, "Past neighbors:", &configuration.past_neighbors);
        let payment_thresholds = Self::preprocess_combined_parameters({
            let p_c = &configuration.payment_thresholds;
            &[
                ("Debt threshold:", &p_c.debt_threshold_gwei, "Gwei"),
                ("Maturity threshold:", &p_c.maturity_threshold_sec, "s"),
                ("Payment grace period:", &p_c.payment_grace_period_sec, "s"),
                (
                    "Permanent debt allowed:",
                    &p_c.permanent_debt_allowed_gwei,
                    "Gwei",
                ),
                ("Threshold interval:", &p_c.threshold_interval_sec, "s"),
                ("Unban below:", &p_c.unban_below_gwei, "Gwei"),
            ]
        });
        Self::dump_value_list(stream, "Payment thresholds:", &payment_thresholds);
        let rate_pack = Self::preprocess_combined_parameters({
            let r_p = &configuration.rate_pack;
            &[
                ("Routing byte rate:", &r_p.routing_byte_rate, "Gwei"),
                ("Routing service rate:", &r_p.routing_service_rate, "Gwei"),
                ("Exit byte rate:", &r_p.exit_byte_rate, "Gwei"),
                ("Exit service rate:", &r_p.exit_service_rate, "Gwei"),
            ]
        });
        Self::dump_value_list(stream, "Rate pack:", &rate_pack);
        let scan_intervals = Self::preprocess_combined_parameters({
            let s_i = &configuration.scan_intervals;
            &[
                ("Pending payable:", &s_i.pending_payable_sec, "s"),
                ("Payable:", &s_i.payable_sec, "s"),
                ("Receivable:", &s_i.receivable_sec, "s"),
            ]
        });
        Self::dump_value_list(stream, "Scan intervals:", &scan_intervals);
    }

    fn dump_value_list(stream: &mut dyn Write, name: &str, values: &[String]) {
        if values.is_empty() {
            Self::dump_configuration_line(stream, name, "[?]");
            return;
        }
        let mut name_row = true;
        values.iter().for_each(|value| {
            if name_row {
                Self::dump_configuration_line(stream, name, value);
                name_row = false;
            } else {
                Self::dump_configuration_line(stream, "", value);
            }
        })
    }

    fn dump_configuration_line(stream: &mut dyn Write, name: &str, value: &str) {
        short_writeln!(stream, "{:width$} {}", name, value, width = COLUMN_WIDTH);
    }

    fn interpret_option(value_opt: &Option<String>) -> String {
        match value_opt {
            None => "[?]".to_string(),
            Some(s) => s.clone(),
        }
    }

    fn preprocess_combined_parameters(parameters: &[(&str, &dyn Display, &str)]) -> Vec<String> {
        let iter_of_strings = parameters.iter().map(|(description, value, unit)| {
            format!(
                "{:width$} {} {}",
                description,
                value,
                unit,
                width = COLUMN_WIDTH
            )
        });
        once(String::from("")).chain(iter_of_strings).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{
        ToMessageBody, UiConfigurationResponse, UiPaymentThresholds, UiRatePack, UiScanIntervals,
    };
    use masq_lib::utils::AutomapProtocol;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONFIGURATION_ABOUT,
            "Displays a running Node's current configuration."
        );
        assert_eq!(
            CONFIGURATION_ARG_HELP,
            "Password of the database from which the configuration will be read"
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

    #[test]
    fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode is not running; therefore its configuration cannot be displayed.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn configuration_command_happy_path_with_secrets() {
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
                debt_threshold_gwei: 1212,
                payment_grace_period_sec: 4578,
                permanent_debt_allowed_gwei: 11222,
                maturity_threshold_sec: 3333,
                unban_below_gwei: 12000,
            },
            rate_pack: UiRatePack {
                routing_byte_rate: 8,
                routing_service_rate: 9,
                exit_byte_rate: 12,
                exit_service_rate: 14,
            },
            start_block: 3456,
            scan_intervals: UiScanIntervals {
                pending_payable_sec: 150,
                payable_sec: 155,
                receivable_sec: 250,
            },
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject =
            ConfigurationCommand::new(&["configuration".to_string(), "password".to_string()])
                .unwrap();

        let result = subject.execute(&mut context);

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
            stdout_arc.lock().unwrap().get_string(),
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
|                                  Debt threshold:                   1212 Gwei\n\
|                                  Maturity threshold:               3333 s\n\
|                                  Payment grace period:             4578 s\n\
|                                  Permanent debt allowed:           11222 Gwei\n\
|                                  Threshold interval:               11111 s\n\
|                                  Unban below:                      12000 Gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                8 Gwei\n\
|                                  Routing service rate:             9 Gwei\n\
|                                  Exit byte rate:                   12 Gwei\n\
|                                  Exit service rate:                14 Gwei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  150 s\n\
|                                  Payable:                          155 s\n\
|                                  Receivable:                       250 s\n"
            )
            .replace('|', "")
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn configuration_command_happy_path_without_secrets() {
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
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

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
            stdout_arc.lock().unwrap().get_string(),
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
|                                  Debt threshold:                   2500 Gwei\n\
|                                  Maturity threshold:               500 s\n\
|                                  Payment grace period:             666 s\n\
|                                  Permanent debt allowed:           1200 Gwei\n\
|                                  Threshold interval:               1000 s\n\
|                                  Unban below:                      1400 Gwei\n\
|Rate pack:                        \n\
|                                  Routing byte rate:                15 Gwei\n\
|                                  Routing service rate:             17 Gwei\n\
|                                  Exit byte rate:                   20 Gwei\n\
|                                  Exit service rate:                30 Gwei\n\
|Scan intervals:                   \n\
|                                  Pending payable:                  1000 s\n\
|                                  Payable:                          1000 s\n\
|                                  Receivable:                       1000 s\n",
            )
            .replace('|', "")
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn configuration_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConfigurationCommand::new(&["configuration".to_string()]).unwrap();

        let result = subject.execute(&mut context);

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
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Configuration retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
