// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::Command as ClapCommand;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::implement_as_any;
use masq_lib::messages::{
    UiConnectionStage, UiConnectionStatusRequest, UiConnectionStatusResponse,
};
use masq_lib::short_writeln;
#[cfg(test)]
use std::any::Any;
use std::fmt::Debug;

#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionStatusCommand {}

const CONNECTION_STATUS_ABOUT: &str =
    "Returns the current stage of the connection status. (NotConnected, ConnectedToNeighbor \
            or RouteFound).";
const NOT_CONNECTED_MSG: &str = "NotConnected: No external neighbor is connected to us.";
const CONNECTED_TO_NEIGHBOR_MSG: &str =
    "ConnectedToNeighbor: External neighbor(s) are connected to us.";
const ROUTE_FOUND_MSG: &str = "RouteFound: You can relay data over the network.";

pub fn connection_status_subcommand() -> ClapCommand {
    ClapCommand::new("connection-status").about(CONNECTION_STATUS_ABOUT)
}

impl Command for ConnectionStatusCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiConnectionStatusRequest {};
        let output: Result<UiConnectionStatusResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                let stdout_msg = match response.stage {
                    UiConnectionStage::NotConnected => NOT_CONNECTED_MSG,
                    UiConnectionStage::ConnectedToNeighbor => CONNECTED_TO_NEIGHBOR_MSG,
                    UiConnectionStage::RouteFound => ROUTE_FOUND_MSG,
                };
                short_writeln!(context.stdout(), "\n{}\n", stdout_msg);
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore connection status cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                short_writeln!(
                    context.stderr(),
                    "Connection status retrieval failed: {:?}",
                    e
                );
                Err(e)
            }
        }
    }

    implement_as_any!();
}

impl ConnectionStatusCommand {
    pub fn new() -> Self {
        ConnectionStatusCommand {}
    }
}

impl Default for ConnectionStatusCommand {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_context::ContextError::ConnectionDropped;
    use crate::commands::commands_common::CommandError::ConnectionProblem;
    use crate::test_utils::mocks::CommandContextMock;
    use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
    use masq_lib::messages::{
        ToMessageBody, UiConnectionStage, UiConnectionStatusRequest, UiConnectionStatusResponse,
    };
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            CONNECTION_STATUS_ABOUT,
            "Returns the current stage of the connection status. (NotConnected, ConnectedToNeighbor \
            or RouteFound)."
        );
        assert_eq!(
            NOT_CONNECTED_MSG,
            "NotConnected: No external neighbor is connected to us."
        );
        assert_eq!(
            CONNECTED_TO_NEIGHBOR_MSG,
            "ConnectedToNeighbor: External neighbor(s) are connected to us."
        );
        assert_eq!(
            ROUTE_FOUND_MSG,
            "RouteFound: You can relay data over the network."
        )
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
        assert_on_connection_status_response(
            UiConnectionStage::NotConnected,
            (
                "\nNotConnected: No external neighbor is connected to us.\n\n",
                "",
            ),
        );
    }

    #[test]
    fn connection_status_command_happy_path_for_connected_to_neighbor() {
        assert_on_connection_status_response(
            UiConnectionStage::ConnectedToNeighbor,
            (
                "\nConnectedToNeighbor: External neighbor(s) are connected to us.\n\n",
                "",
            ),
        );
    }

    #[test]
    fn connection_status_command_happy_path_for_three_hops_route_found() {
        assert_on_connection_status_response(
            UiConnectionStage::RouteFound,
            ("\nRouteFound: You can relay data over the network.\n\n", ""),
        );
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

    fn assert_on_connection_status_response(stage: UiConnectionStage, response: (&str, &str)) {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiConnectionStatusResponse { stage };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ConnectionStatusCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap().clone();
        let stdout = stdout_arc.lock().unwrap().get_string();
        let stderr = stderr_arc.lock().unwrap().get_string();
        let (stdout_expected, stderr_expected) = response;
        assert_eq!(
            transact_params,
            vec![(
                UiConnectionStatusRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS,
            )]
        );
        assert_eq!(stdout, stdout_expected);
        assert_eq!(stderr, stderr_expected);
    }
}
