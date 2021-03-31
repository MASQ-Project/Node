// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handler::StreamFactory;
use crate::schema::app;
use crate::terminal_interface::{Terminal, TerminalWrapper};
use clap::value_t;

pub trait CommandProcessorFactory {
    fn make(
        &self,
        interface: Box<dyn Terminal + Send + Sync>,
        broadcast_stream_factory: Box<dyn StreamFactory>,
        args: &[String],
    ) -> Result<Box<dyn CommandProcessor>, CommandError>;
}

#[derive(Default)]
pub struct CommandProcessorFactoryReal {}

impl CommandProcessorFactory for CommandProcessorFactoryReal {
    fn make(
        &self,
        interface: Box<dyn Terminal + Send + Sync>,
        broadcast_stream_factory: Box<dyn StreamFactory>,
        args: &[String],
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        let matches = app().get_matches_from(args);
        let ui_port = value_t!(matches, "ui-port", u16).expect("ui-port is not properly defaulted");
        match CommandContextReal::new(interface, ui_port, broadcast_stream_factory) {
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
    fn clone_terminal_interface(&mut self) -> TerminalWrapper;
}

pub struct CommandProcessorReal {
    #[allow(dead_code)]
    context: CommandContextReal,
}

impl CommandProcessor for CommandProcessorReal {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        let synchronizer = self.context.terminal_interface.clone();
        let _lock = synchronizer.lock();
        command.execute(&mut self.context)
    }

    fn close(&mut self) {
        self.context.close();
    }

    fn clone_terminal_interface(&mut self) -> TerminalWrapper {
        self.context.terminal_interface.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::communications::broadcast_handler::StreamFactoryReal;
    use crate::test_utils::mocks::{TerminalActiveMock, TestStreamFactory};
    use crossbeam_channel::Sender;
    use masq_lib::messages::{ToMessageBody, UiBroadcastTrigger, UiUndeliveredFireAndForget};
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::{find_free_port, running_test};
    use std::thread;
    use std::time::Duration;

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
        let interface = Box::new(TerminalActiveMock::new());

        let result = subject.make(interface, Box::new(StreamFactoryReal::new()), &args);

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
        let interface = Box::new(TerminalActiveMock::new());

        let mut result = subject
            .make(interface, Box::new(StreamFactoryReal::new()), &args)
            .unwrap();

        let command = TestCommand {};
        result.process(Box::new(command)).unwrap();
        let received = stop_handle.stop();
        assert_eq!(received, vec![Ok(UiShutdownRequest {}.tmb(1))]);
    }

    #[derive(Debug)]
    struct TameCommand {
        sender: Sender<String>,
    }

    impl Command for TameCommand {
        fn execute(&self, _context: &mut dyn CommandContext) -> Result<(), CommandError> {
            self.sender.send("This is a message".to_string()).unwrap();
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" which must be delivered as one piece".to_string())
                .unwrap();
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send("; we'll do all being possible for that.".to_string())
                .unwrap();
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" If only we have enough strength and spirit".to_string())
                .unwrap();
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" and determination and support and... snacks.".to_string())
                .unwrap();
            thread::sleep(Duration::from_millis(10));
            self.sender.send(" Roger.".to_string()).unwrap();
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ToUiBroadcastTrigger {}

    impl Command for ToUiBroadcastTrigger {
        fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            let input = UiBroadcastTrigger {}.tmb(0);
            context.send(input).unwrap(); //send instead of transact; using FFM.
            Ok(())
        }
    }

    #[test]
    fn process_locks_writing_and_prevents_interferences_from_broadcast_messages() {
        running_test();
        let port = find_free_port();
        let broadcast = UiUndeliveredFireAndForget {
            opcode: "whateverTheOpcodeHereIs".to_string(),
        }
        .tmb(0);
        let server = MockWebSocketsServer::new(port)
            .queue_response(broadcast.clone())
            .queue_response(broadcast.clone())
            .queue_response(broadcast.clone())
            .queue_response(broadcast);

        let (broadcast_stream_factory, broadcast_stream_factory_handle) = TestStreamFactory::new();
        let (cloned_stdout_sender, _) = broadcast_stream_factory.clone_senders();

        let args = [
            "masq".to_string(),
            "--ui-port".to_string(),
            format!("{}", port),
        ];
        let processor_factory = CommandProcessorFactoryReal::new();
        let stop_handle = server.start();
        let interface = Box::new(TerminalActiveMock::new());
        let mut subject = processor_factory
            .make(interface, Box::new(broadcast_stream_factory), &args)
            .unwrap();

        subject.process(Box::new(ToUiBroadcastTrigger {})).unwrap();
        thread::sleep(Duration::from_millis(50));
        subject
            .process(Box::new(TameCommand {
                sender: cloned_stdout_sender,
            }))
            .unwrap();

        let tamed_message_as_a_whole = "This is a message which must be delivered as one piece; we'll do all being \
             possible for that. If only we have enough strength and spirit and determination and support and... snacks. Roger.";
        let received_output = broadcast_stream_factory_handle.stdout_so_far();
        assert!(
            received_output.contains(tamed_message_as_a_whole),
            "Message wasn't printed uninterrupted: {}",
            received_output
        );

        let tamed_output_filtered_out = received_output.replace(tamed_message_as_a_whole, "");
        let number_of_broadcast_received = tamed_output_filtered_out
            .clone()
            .lines()
            .filter(|line| {
                line.contains("Cannot handle whateverTheOpcodeHereIs request: Node is not running")
            })
            .count();
        assert_eq!(number_of_broadcast_received, 4);

        stop_handle.stop();
    }
}
