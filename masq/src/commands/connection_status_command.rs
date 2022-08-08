// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use masq_lib::as_any_impl;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{
    UiConnectionStage, UiConnectionStatusRequest, UiConnectionStatusResponse,
};
use masq_lib::short_writeln;
#[cfg(test)]
use std::any::Any;
use std::fmt::Debug;

#[derive(Debug, PartialEq)]
pub struct ConnectionStatusCommand {}

const CONNECTION_STATUS_ABOUT: &str =
    "Returns the current stage of the connection status. (NotConnected, ConnectedToNeighbor \
            or ThreeHopsRouteFound)";
const NOT_CONNECTED_MSG: &str = "NotConnected: No external neighbor is connected to us.";
const CONNECTED_TO_NEIGHBOR_MSG: &str =
    "ConnectedToNeighbor: External node(s) are connected to us.";
const THREE_HOPS_ROUTE_FOUND_MSG: &str =
    "ThreeHopsRouteFound: You can relay data over the network.";

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
                    UiConnectionStage::ThreeHopsRouteFound => THREE_HOPS_ROUTE_FOUND_MSG,
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

    as_any_impl!();
}

impl ConnectionStatusCommand {
    pub fn new() -> Self {
        ConnectionStatusCommand {}
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
            or ThreeHopsRouteFound)"
        );
        assert_eq!(
            NOT_CONNECTED_MSG,
            "NotConnected: No external neighbor is connected to us."
        );
        assert_eq!(
            CONNECTED_TO_NEIGHBOR_MSG,
            "ConnectedToNeighbor: External node(s) are connected to us."
        );
        assert_eq!(
            THREE_HOPS_ROUTE_FOUND_MSG,
            "ThreeHopsRouteFound: You can relay data over the network."
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
            "\nNotConnected: No external neighbor is connected to us.\n\n"
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
            "\nConnectedToNeighbor: External node(s) are connected to us.\n\n"
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
            "\nThreeHopsRouteFound: You can relay data over the network.\n\n"
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
