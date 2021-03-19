// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handler::StreamFactory;
use crate::schema::app;
use clap::value_t;

pub trait CommandProcessorFactory {
    fn make(
        &self,
        broadcast_stream_factory: Box<dyn StreamFactory>,
        args: &[String],
    ) -> Result<Box<dyn CommandProcessor>, CommandError>;
}

#[derive(Default)]
pub struct CommandProcessorFactoryReal {}

impl CommandProcessorFactory for CommandProcessorFactoryReal {
    fn make(
        &self,
        broadcast_stream_factory: Box<dyn StreamFactory>,
        args: &[String],
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        let matches = app().get_matches_from(args);
        let ui_port = value_t!(matches, "ui-port", u16).expect("ui-port is not properly defaulted");
        match CommandContextReal::new(ui_port, broadcast_stream_factory) {
            Ok(context) => Ok(Box::new(CommandProcessorReal { context })),
            Err(ContextError::ConnectionRefused(s)) => Err(CommandError::ConnectionProblem(s)),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}

impl CommandProcessorFactoryReal {
    pub fn new() -> Self {
        Self::default()
    }
}

pub trait CommandProcessor {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError>;
    fn close(&mut self);
}

pub struct CommandProcessorReal {
    #[allow(dead_code)]
    context: CommandContextReal,
}

impl CommandProcessor for CommandProcessorReal {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        command.execute(&mut self.context)
    }

    fn close(&mut self) {
        self.context.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::communications::broadcast_handler::StreamFactoryReal;
    use crate::test_utils::mocks::TestStreamFactory;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::find_free_port;

    #[derive(Debug)]
    struct TestCommand {}

    impl Command for TestCommand {
        fn execute<'a>(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            match context.transact(UiShutdownRequest {}.tmb(1), 1000) {
                Ok(_) => Ok(()),
                Err(e) => Err(CommandError::Other(format!("{:?}", e))),
            }
        }
    }

    #[test]
    fn handles_nonexistent_server() {
        let port = find_free_port();
        let args = [
            "masq".to_string(),
            "--ui-port".to_string(),
            format!("{}", port),
        ];
        let subject = CommandProcessorFactoryReal::new();

        let result = subject.make(Box::new(StreamFactoryReal::new()), &args);

        match result.err() {
            Some(CommandError::ConnectionProblem(_)) => (),
            x => panic!(
                "Expected Some(CommandError::ConnectionProblem(_); got {:?} instead",
                x
            ),
        }
    }

    #[test]
    fn factory_parses_out_the_correct_port_when_specified() {
        let port = find_free_port();
        let args = [
            "masq".to_string(),
            "--ui-port".to_string(),
            format!("{}", port),
        ];
        let subject = CommandProcessorFactoryReal::new();
        let server = MockWebSocketsServer::new(port).queue_response(UiShutdownResponse {}.tmb(1));
        let stop_handle = server.start();

        let mut result = subject
            .make(Box::new(StreamFactoryReal::new()), &args)
            .unwrap();

        let command = TestCommand {};
        result.process(Box::new(command)).unwrap();
        let received = stop_handle.stop();
        assert_eq!(received, vec![Ok(UiShutdownRequest {}.tmb(1))]);
    }

    #[derive(Debug)]
    struct TameCommand {}

    impl Command for TameCommand {
        fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            writeln!(context.stdout(), "Tame output");
            Ok(())
        }
    }

    #[test]
    fn process_locks_output_synchronizer() {
        let port = find_free_port();
        let (broadcast_stream_factory, broadcast_stream_factory_handle) = TestStreamFactory::new();
        let mut command_context = CommandContextReal::new(port, Box::new(broadcast_stream_factory)).unwrap();
        let stdout = ByteArrayWriter::new();
        command_context.stdout = Box::new(stdout);
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let subject = CommandProcessorFactoryReal::new();

        unimplemented! ()
        // Lock a clone of the output_synchronizer
        // Start background thread
        // On the background thread, execute TameCommand
        // After starting the thread, wait for a few milliseconds
        // Verify that nothing has been written to stdout
        // Unlock the output_synchronizer clone
        // Verify that the proper string has been written to stdout
        // Done!
    }
}
