// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::Payload;
use crate::commands::commands_common::{
    transaction, Command, CommandError, STANDARD_COMMAND_TIMEOUT_MILLIS,
};
use crate::masq_short_writeln;
use crate::terminal::{TerminalWriter, WTermInterface};
use async_trait::async_trait;
use clap::Command as ClapCommand;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiDescriptorRequest, UiDescriptorResponse};
use std::fmt::Debug;

#[derive(Debug)]
pub struct DescriptorCommand {}

const DESCRIPTOR_SUBCOMMAND_ABOUT: &str =
    "Displays the Node descriptor of the running MASQNode. Only valid if Node is already running.";

pub fn descriptor_subcommand() -> ClapCommand {
    ClapCommand::new("descriptor").about(DESCRIPTOR_SUBCOMMAND_ABOUT)
}

#[async_trait(?Send)]
impl Command for DescriptorCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        stdout: TerminalWriter,
        stderr: TerminalWriter,
    ) -> Result<(), CommandError> {
        let input = UiDescriptorRequest {};
        let output: Result<UiDescriptorResponse, CommandError> =
            transaction(input, context, &stderr, STANDARD_COMMAND_TIMEOUT_MILLIS).await;
        match output {
            Ok(response) => {
                match response.node_descriptor_opt {
                    Some(node_descriptor) => {
                        masq_short_writeln!(stdout, "{}", node_descriptor)
                    }
                    None => masq_short_writeln!(
                        stdout,
                        "Node descriptor is not yet available; try again later"
                    ),
                }
                Ok(())
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                masq_short_writeln!(
                    stderr,
                    "MASQNode is not running; therefore its descriptor cannot be displayed."
                );
                Err(Payload(code, message))
            }
            Err(e) => {
                masq_short_writeln!(stderr, "Descriptor retrieval failed: {:?}", e);
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
    use crate::terminal::test_utils::allow_flushed_writings_to_finish;
    use crate::test_utils::mocks::{CommandContextMock, TermInterfaceMock};
    use masq_lib::messages::{ToMessageBody, UiDescriptorRequest, UiDescriptorResponse};
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            DESCRIPTOR_SUBCOMMAND_ABOUT,
            "Displays the Node descriptor of the running MASQNode. Only valid if Node is already running."
        );
    }

    #[tokio::test]
    async fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new().transact_result(Ok(UiDescriptorResponse {
            node_descriptor_opt: Some("Node descriptor".to_string()),
        }
        .tmb(0)));
        let (term_interface, _stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        let subject = factory.make(&["descriptor".to_string()]).unwrap();

        let result = subject.execute(&mut context, stdout, stderr).await;

        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let subject = DescriptorCommand::new();

        let result = Box::new(subject)
            .execute(&mut context, stdout, stderr)
            .await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "MASQNode is not running; therefore its descriptor cannot be displayed.\n"
        );
        stream_handles.assert_empty_stdout();
    }

    #[tokio::test]
    async fn descriptor_command_when_descriptor_is_returned() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiDescriptorResponse {
            node_descriptor_opt: Some("Booga:1234".to_string()),
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let subject = DescriptorCommand::new();

        let result = Box::new(subject)
            .execute(&mut context, stdout, stderr)
            .await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiDescriptorRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        assert_eq!(stream_handles.stdout_all_in_one(), "Booga:1234\n");
        stream_handles.assert_empty_stderr();
    }

    #[tokio::test]
    async fn descriptor_command_when_descriptor_is_not_returned() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let expected_response = UiDescriptorResponse {
            node_descriptor_opt: None,
        };
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(expected_response.tmb(42)));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let subject = DescriptorCommand::new();

        let result = Box::new(subject)
            .execute(&mut context, stdout, stderr)
            .await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
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
            stream_handles.stdout_all_in_one(),
            "Node descriptor is not yet available; try again later\n"
        );
        stream_handles.assert_empty_stderr()
    }

    #[tokio::test]
    async fn descriptor_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ConnectionDropped("Booga".to_string())));
        let (term_interface, stream_handles) = TermInterfaceMock::new_non_interactive();
        let (stdout, stdout_flush_handle) = term_interface.stdout();
        let (stderr, stderr_flush_handle) = term_interface.stderr();
        let subject = DescriptorCommand::new();

        let result = Box::new(subject)
            .execute(&mut context, stdout, stderr)
            .await;

        allow_flushed_writings_to_finish(Some(stdout_flush_handle), Some(stderr_flush_handle))
            .await;
        assert_eq!(result, Err(ConnectionProblem("Booga".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(
                UiDescriptorRequest {}.tmb(0),
                STANDARD_COMMAND_TIMEOUT_MILLIS
            )]
        );
        stream_handles.assert_empty_stdout();
        assert_eq!(
            stream_handles.stderr_all_in_one(),
            "Descriptor retrieval failed: ConnectionProblem(\"Booga\")\n"
        );
    }
}
