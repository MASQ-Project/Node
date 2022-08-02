// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    dump_parameter_line, transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
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
pub struct ConnectionStatusCommand {}

const CONNECTION_STATUS_ABOUT: &str = "Displays a running Node's current configuration.";

//
// pub fn configuration_subcommand() -> App<'static, 'static> {
//     SubCommand::with_name("configuration")
//         .about(CONFIGURATION_ABOUT)
//         .arg(
//             Arg::with_name("db-password")
//                 .help(CONFIGURATION_ARG_HELP)
//                 .index(1)
//                 .required(false),
//         )
// }

impl Command for ConnectionStatusCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        todo!()
        // let input = UiConfigurationRequest {
        //     db_password_opt: self.db_password.clone(),
        // };
        // let output: Result<UiConfigurationResponse, CommandError> =
        //     transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        // match output {
        //     Ok(response) => {
        //         Self::dump_configuration(context.stdout(), response);
        //         Ok(())
        //     }
        //     Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
        //         short_writeln!(
        //             context.stderr(),
        //             "MASQNode is not running; therefore its configuration cannot be displayed."
        //         );
        //         Err(Payload(code, message))
        //     }
        //     Err(e) => {
        //         short_writeln!(context.stderr(), "Configuration retrieval failed: {:?}", e);
        //         Err(e)
        //     }
        // }
    }

    as_any_impl!();
}

impl ConnectionStatusCommand {
    pub fn new() -> Self {
        todo!()
        // let matches = match configuration_subcommand().get_matches_from_safe(pieces) {
        //     Ok(matches) => matches,
        //     Err(e) => return Err(format!("{}", e)),
        // };
        //
        // Ok(ConfigurationCommand {
        //     db_password: matches.value_of("db-password").map(|s| s.to_string()),
        // })
    }

    // fn dump_configuration(stream: &mut dyn Write, configuration: UiConfigurationResponse) {
    //     dump_parameter_line(stream, "NAME", "VALUE");
    //     dump_parameter_line(
    //         stream,
    //         "Blockchain service URL:",
    //         &configuration
    //             .blockchain_service_url_opt
    //             .unwrap_or_else(|| "[?]".to_string()),
    //     );
    //     dump_parameter_line(stream, "Chain:", &configuration.chain_name);
    //     dump_parameter_line(
    //         stream,
    //         "Clandestine port:",
    //         &configuration.clandestine_port.to_string(),
    //     );
    //     dump_parameter_line(
    //         stream,
    //         "Consuming wallet private key:",
    //         &Self::interpret_option(&configuration.consuming_wallet_private_key_opt),
    //     );
    //     dump_parameter_line(
    //         stream,
    //         "Current schema version:",
    //         &configuration.current_schema_version,
    //     );
    //     dump_parameter_line(
    //         stream,
    //         "Earning wallet address:",
    //         &Self::interpret_option(&configuration.earning_wallet_address_opt),
    //     );
    //     dump_parameter_line(stream, "Gas price:", &configuration.gas_price.to_string());
    //     dump_parameter_line(
    //         stream,
    //         "Neighborhood mode:",
    //         &configuration.neighborhood_mode,
    //     );
    //     dump_parameter_line(
    //         stream,
    //         "Port mapping protocol:",
    //         &Self::interpret_option(&configuration.port_mapping_protocol_opt),
    //     );
    //     dump_parameter_line(
    //         stream,
    //         "Start block:",
    //         &configuration.start_block.to_string(),
    //     );
    //     Self::dump_value_list(stream, "Past neighbors:", &configuration.past_neighbors);
    //     let payment_thresholds = Self::preprocess_combined_parameters({
    //         let p_c = &configuration.payment_thresholds;
    //         &[
    //             ("Debt threshold:", &p_c.debt_threshold_gwei, "Gwei"),
    //             ("Maturity threshold:", &p_c.maturity_threshold_sec, "s"),
    //             ("Payment grace period:", &p_c.payment_grace_period_sec, "s"),
    //             (
    //                 "Permanent debt allowed:",
    //                 &p_c.permanent_debt_allowed_gwei,
    //                 "Gwei",
    //             ),
    //             ("Threshold interval:", &p_c.threshold_interval_sec, "s"),
    //             ("Unban below:", &p_c.unban_below_gwei, "Gwei"),
    //         ]
    //     });
    //     Self::dump_value_list(stream, "Payment thresholds:", &payment_thresholds);
    //     let rate_pack = Self::preprocess_combined_parameters({
    //         let r_p = &configuration.rate_pack;
    //         &[
    //             ("Routing byte rate:", &r_p.routing_byte_rate, "Gwei"),
    //             ("Routing service rate:", &r_p.routing_service_rate, "Gwei"),
    //             ("Exit byte rate:", &r_p.exit_byte_rate, "Gwei"),
    //             ("Exit service rate:", &r_p.exit_service_rate, "Gwei"),
    //         ]
    //     });
    //     Self::dump_value_list(stream, "Rate pack:", &rate_pack);
    //     let scan_intervals = Self::preprocess_combined_parameters({
    //         let s_i = &configuration.scan_intervals;
    //         &[
    //             ("Pending payable:", &s_i.pending_payable_sec, "s"),
    //             ("Payable:", &s_i.payable_sec, "s"),
    //             ("Receivable:", &s_i.receivable_sec, "s"),
    //         ]
    //     });
    //     Self::dump_value_list(stream, "Scan intervals:", &scan_intervals);
    // }

    // fn dump_value_list(stream: &mut dyn Write, name: &str, values: &[String]) {
    //     if values.is_empty() {
    //         dump_parameter_line(stream, name, "[?]");
    //         return;
    //     }
    //     let mut name_row = true;
    //     values.iter().for_each(|value| {
    //         if name_row {
    //             dump_parameter_line(stream, name, value);
    //             name_row = false;
    //         } else {
    //             dump_parameter_line(stream, "", value);
    //         }
    //     })
    // }
    //
    // fn interpret_option(value_opt: &Option<String>) -> String {
    //     match value_opt {
    //         None => "[?]".to_string(),
    //         Some(s) => s.clone(),
    //     }
    // }
    //
    // fn preprocess_combined_parameters(parameters: &[(&str, &dyn Display, &str)]) -> Vec<String> {
    //     let iter_of_strings = parameters.iter().map(|(description, value, unit)| {
    //         format!(
    //             "{:width$} {} {}",
    //             description,
    //             value,
    //             unit,
    //             width = COLUMN_WIDTH
    //         )
    //     });
    //     once(String::from("")).chain(iter_of_strings).collect()
    // }
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
        ToMessageBody, UiConfigurationResponse, UiConnectionStage, UiConnectionStatusRequest,
        UiConnectionStatusResponse, UiPaymentThresholds, UiRatePack, UiScanIntervals,
    };
    use masq_lib::utils::AutomapProtocol;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONNECTION_STATUS_ABOUT,
            "Returns the current stage of the connection status. (NotConnected, ConnectedToNeighbor \
            or ThreeHopsRouteFound)"
        );
    }

    #[test]
    fn connection_status_works() {
        let subject = CommandFactoryReal::new();

        let command = subject.make(&["connection-status".to_string()]).unwrap();

        let connnection_status_command = command
            .as_any()
            .downcast_ref::<ConnectionStatusCommand>()
            .unwrap();
        assert_eq!(connnection_status_command, &ConnectionStatusCommand {});
    }

    #[test]
    fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

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
            "MASQNode is not running; therefore connection status cannot be displayed.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn connection_status_command_happy_path_for_not_connected() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConnectionStatusResponse {
            stage: UiConnectionStage::NotConnected,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConnectionStatusRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\nNotConnected: No external neighbor is connected to us.\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn connection_status_command_happy_path_for_connected_to_neighbor() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConnectionStatusResponse {
            stage: UiConnectionStage::ConnectedToNeighbor,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConnectionStatusRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\nConnectedToNeighbor: Established neighborship with an external node.\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn connection_status_command_happy_path_for_three_hops_route_found() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConnectionStatusResponse {
            stage: UiConnectionStage::ThreeHopsRouteFound,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConnectionStatusRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "\nThreeHopsRouteFound: You can now relay data over the network.\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), "");
    }

    #[test]
    fn connection_status_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiConnectionStatusRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Connection status retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
