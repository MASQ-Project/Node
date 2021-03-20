// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{transaction, Command, CommandError};
use crate::communications::broadcast_handler::StreamFactory;
use crate::schema::app;
use clap::value_t;
use masq_lib::messages::UiBroadcastTrigger;

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
        self.context.output_synchronizer.lock().unwrap();
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
    use crate::commands::commands_common::{transaction, STANDARD_COMMAND_TIMEOUT_MILLIS};
    use crate::communications::broadcast_handler::StreamFactoryReal;
    use crate::test_utils::mocks::{CommandFactoryMock, TestStreamFactory};
    use crossbeam_channel::Sender;
    use masq_lib::messages::{ToMessageBody, UiUndeliveredFireAndForget};
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::{find_free_port, running_test};
    use std::io::Read;
    use std::sync::Arc;
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

    #[test]
    fn spike_process_locks_output_synchronizer() {
        running_test();
        let port = find_free_port();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();
        let mut command_context =
            CommandContextReal::new(port, Box::new(StreamFactoryReal::new())).unwrap();
        let stdout = ByteArrayWriter::new();

        let stdout_arc = stdout.inner_arc();
        let stdout_arc_clone = stdout_arc.clone();
        command_context.stdout = Box::new(stdout);

        let synchronizer_cloned = Arc::clone(&command_context.output_synchronizer);
        let guard = synchronizer_cloned.lock().unwrap();

        let thread_handle = thread::spawn(move || {
            command_context.output_synchronizer.lock().unwrap();
            TameCommand {
                sender: unimplemented!(),
            }
            .execute(&mut command_context);
            thread::sleep(Duration::from_millis(10)) //outer structure of stdout must not be dropped too early
        });
        thread::sleep(Duration::from_millis(50));
        {
            let read = stdout_arc_clone.lock().unwrap().get_string();
            assert_eq!(read, "".to_string());
        }
        drop(guard); //dropping the guard in the foreground, allowing writing in the background to start

        thread::sleep(Duration::from_millis(5));
        assert_eq!(
            stdout_arc_clone.lock().unwrap().get_string(),
            "Tame output\n".to_string()
        );

        thread_handle.join().unwrap();

        stop_handle.stop();
        // Lock a clone of the output_synchronizer
        // Start background thread
        // On the background thread, execute TameCommand
        // After starting the thread, wait for a few milliseconds
        // Verify that nothing has been written to stdout
        // Unlock the output_synchronizer clone
        // Verify that the proper string has been written to stdout
        // Done!
    }

    #[derive(Debug)]
    struct TameCommand {
        sender: Sender<String>,
    }

    impl Command for TameCommand {
        fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            self.sender.send("This is a message".to_string());
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" which must be delivered as one piece".to_string());
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send("; we'll do all being possible for that.".to_string());
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" If only we have enough strength and spirit".to_string());
            thread::sleep(Duration::from_millis(10));
            self.sender
                .send(" and determination and support and... snacks.".to_string());
            thread::sleep(Duration::from_millis(10));
            self.sender.send(" Roger.".to_string());

            let message ="This is a message which must be delivered as one piece; we'll do all being possible for that. If only we have enough strength and spirit and determination and support and... snacks. Roger.";
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ToUiBroadcastTrigger {}

    impl Command for ToUiBroadcastTrigger {
        fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            let input = UiBroadcastTrigger {}.tmb(0);
            let output = context.send(input); //send instead of transact; using FFM.
            Ok(())
        }
    }

    #[test]
    fn process_locks_output_synchronizer() {
        running_test();
        let port = find_free_port();
        let broadcast = UiUndeliveredFireAndForget {
            opcode: "whateverTheOpcodeHereIs".to_string(),
            original_payload: "++++++++++++++++".to_string(),
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
        let mut subject = processor_factory
            .make(Box::new(broadcast_stream_factory), &args)
            .unwrap();

        let result = subject.process(Box::new(ToUiBroadcastTrigger {}));
        thread::sleep(Duration::from_millis(50));
        let result = subject.process(Box::new(TameCommand {
            sender: cloned_stdout_sender,
        }));
        let received_output = broadcast_stream_factory_handle.stdout_so_far();
        assert!(received_output
            .contains("This is a message which must be delivered as one piece; we'll do all being \
             possible for that. If only we have enough strength and spirit and determination and support and... snacks. Roger."),
                "Message wasn't printed uninterrupted: {}",received_output);

        stop_handle.stop();
    }
}
