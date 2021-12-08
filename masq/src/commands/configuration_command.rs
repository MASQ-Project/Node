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
use std::fmt::Debug;
use std::io::Write;

#[derive(Debug, PartialEq)]
pub struct ConfigurationCommand {
    pub db_password: Option<String>,
}

pub fn configuration_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("configuration")
        .about("Displays a running Node's current configuration.")
        .arg(
            Arg::with_name("db-password")
                .help("Password of the database from which the configuration will be read")
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

    //put non-secret parameters first with both sorts alphabetical ordered
    fn dump_configuration(stream: &mut dyn Write, configuration: UiConfigurationResponse) {
        Self::dump_configuration_line(stream, "NAME", "VALUE");
        Self::dump_configuration_line(
            stream,
            "Blockchain service URL:",
            &configuration
                .blockchain_service_url_opt
                .unwrap_or_else(|| "[?]".to_string()),
        );
        Self::dump_configuration_line(stream, "Chain", &configuration.chain_name);
        Self::dump_configuration_line(
            stream,
            "Clandestine port:",
            &configuration.clandestine_port.to_string(),
        );
        Self::dump_configuration_line(
            stream,
            "Consuming wallet derivation path:",
            &Self::interpret_option(&configuration.consuming_wallet_derivation_path_opt),
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
        Self::dump_configuration_line(
            stream,
            "Mnemonic seed:",
            &configuration
                .mnemonic_seed_opt
                .unwrap_or_else(|| "[?]".to_string()),
        );
        Self::dump_value_list(stream, "Past neighbors:", &configuration.past_neighbors);
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
        short_writeln!(stream, "{:33} {}", name, value);
    }

    fn interpret_option(value_opt: &Option<String>) -> String {
        match value_opt {
            None => "[?]".to_string(),
            Some(s) => s.clone(),
        }
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
    use masq_lib::messages::{ToMessageBody, UiConfigurationResponse};
    use masq_lib::utils::AutomapProtocol;
    use std::sync::{Arc, Mutex};

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
            mnemonic_seed_opt: Some("mnemonic seed".to_string()),
            neighborhood_mode: "standard".to_string(),
            consuming_wallet_derivation_path_opt: Some("consuming path".to_string()),
            earning_wallet_address_opt: Some("earning address".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec!["neighbor 1".to_string(), "neighbor 2".to_string()],
            start_block: 3456,
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
            "\
|NAME                              VALUE\n\
|Blockchain service URL:           https://infura.io/ID\n\
|Chain                             ropsten\n\
|Clandestine port:                 1234\n\
|Consuming wallet derivation path: consuming path\n\
|Current schema version:           schema version\n\
|Earning wallet address:           earning address\n\
|Gas price:                        2345\n\
|Neighborhood mode:                standard\n\
|Port mapping protocol:            PCP\n\
|Start block:                      3456\n\
|Mnemonic seed:                    mnemonic seed\n\
|Past neighbors:                   neighbor 1\n\
|                                  neighbor 2\n\
"
            .replace('|', "")
            .to_string()
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
            mnemonic_seed_opt: None,
            neighborhood_mode: "zero-hop".to_string(),
            consuming_wallet_derivation_path_opt: Some("consuming path".to_string()),
            earning_wallet_address_opt: Some("earning wallet".to_string()),
            port_mapping_protocol_opt: Some(AutomapProtocol::Pcp.to_string()),
            past_neighbors: vec![],
            start_block: 3456,
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
            "\
NAME                              VALUE\n\
Blockchain service URL:           https://infura.io/ID\n\
Chain                             mumbai\n\
Clandestine port:                 1234\n\
Consuming wallet derivation path: consuming path\n\
Current schema version:           schema version\n\
Earning wallet address:           earning wallet\n\
Gas price:                        2345\n\
Neighborhood mode:                zero-hop\n\
Port mapping protocol:            PCP\n\
Start block:                      3456\n\
Mnemonic seed:                    [?]\n\
Past neighbors:                   [?]\n\
"
            .to_string()
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
