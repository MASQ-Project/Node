// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use clap::Command as ClapCommand;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiDescriptorRequest, UiDescriptorResponse};
use masq_lib::short_writeln;
use std::fmt::Debug;

#[derive(Debug)]
pub struct DescriptorCommand {}

const DESCRIPTOR_SUBCOMMAND_ABOUT: &str =
    "Displays the Node descriptor of the running MASQNode. Only valid if Node is already running.";

pub fn descriptor_subcommand() -> ClapCommand {
    ClapCommand::new("descriptor").about(DESCRIPTOR_SUBCOMMAND_ABOUT)
}

impl Command for DescriptorCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiDescriptorRequest {};
        let output: Result<UiDescriptorResponse, CommandError> =
            transaction(input, context, STANDARD_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(response) => {
                match response.node_descriptor_opt {
                    Some(node_descriptor) => {
                        short_writeln!(context.stdout(), "{}", node_descriptor)
                    }
                    None => short_writeln!(
                        context.stdout(),
                        "Node descriptor is not yet available; try again later"
                    ),
                }
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore its descriptor cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                short_writeln!(context.stderr(), "Descriptor retrieval failed: {:?}", e);
                Err(e)
            }
        }
    }
}

impl Default for DescriptorCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl DescriptorCommand {
    pub fn new() -> Self {
        Self {}
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
    use masq_lib::messages::{ToMessageBody, UiDescriptorRequest, UiDescriptorResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            DESCRIPTOR_SUBCOMMAND_ABOUT,
            "Displays the Node descriptor of the running MASQNode. Only valid if Node is already running."
        );
    }

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiDescriptorResponse {
            node_descriptor_opt: Some("Node descriptor".to_string()),
        }
        .tmb(0)));
        let subject = factory.make(&["descriptor".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = DescriptorCommand::new();

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
            "MASQNode is not running; therefore its descriptor cannot be displayed.\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn descriptor_command_when_descriptor_is_returned() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiDescriptorResponse {
            node_descriptor_opt: Some("Booga:1234".to_string()),
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = DescriptorCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiDescriptorRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), "Booga:1234\n");
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn descriptor_command_when_descriptor_is_not_returned() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiDescriptorResponse {
            node_descriptor_opt: None,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = DescriptorCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiDescriptorRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "Node descriptor is not yet available; try again later\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn descriptor_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = DescriptorCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiDescriptorRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "Descriptor retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
