// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handler::StreamFactory;
use crate::schema::app;
use crate::terminal_interface::TerminalWrapper;
use clap::value_t;
use masq_lib::intentionally_blank;
use std::sync::atomic::Ordering;

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
    fn upgrade_terminal_interface(&mut self) -> Result<(), String>;
    fn clone_terminal_interface(&mut self) -> TerminalWrapper;
    #[cfg(test)]
    fn clone_terminal_from_processor_test_only(&self) -> TerminalWrapper {
        intentionally_blank!()
    }
}

pub struct CommandProcessorReal {
    #[allow(dead_code)]
    context: CommandContextReal,
}

impl CommandProcessor for CommandProcessorReal {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        let mut synchronizer = self.context.terminal_interface.clone();
        let _lock = synchronizer.lock();
        command.execute(&mut self.context)
    }

    fn close(&mut self) {
        self.context.close();
    }

    fn upgrade_terminal_interface(&mut self) -> Result<(), String> {
        self.context.terminal_interface.upgrade()
    }

    fn clone_terminal_interface(&mut self) -> TerminalWrapper {
        self.context.terminal_interface.check_update();
        self.context.terminal_interface.clone()
    }

    #[cfg(test)]
    fn clone_terminal_from_processor_test_only(&self) -> TerminalWrapper {
        self.context.terminal_interface.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::communications::broadcast_handler::StreamFactoryReal;
    use crate::test_utils::mocks::TestStreamFactory;
    use crossbeam_channel::Sender;
    use masq_lib::messages::{ToMessageBody, UiBroadcastTrigger, UiUndeliveredFireAndForget};
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::test_utils::mock_websockets_server::MockWebSocketsServer;
    use masq_lib::utils::{find_free_port, running_test};
    use std::sync::atomic::Ordering;
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
        let mut processor = processor_factory
            .make(Box::new(broadcast_stream_factory), &args)
            .unwrap();

        processor.upgrade_terminal_interface();

        processor
            .process(Box::new(ToUiBroadcastTrigger {}))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        processor
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
    #[test]
    fn upgrade_terminal_interface_works() {
        let port = find_free_port();
        let args = [
            "masq".to_string(),
            "--ui-port".to_string(),
            format!("{}", port),
        ];
        let processor_factory = CommandProcessorFactoryReal::new();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();

        let mut processor = processor_factory
            .make(Box::new(StreamFactoryReal::new()), &args)
            .unwrap();

        //in reality we don't use this function so early, now I just want to check the setting of TerminalWrapper
        let mut terminal_first_check = processor.clone_terminal_from_processor_test_only();
        assert!((*terminal_first_check.inspect_inner_active()).is_none());
        assert!(terminal_first_check
            .inspect_share_point()
            .lock()
            .unwrap()
            .is_none());
        assert_eq!(
            terminal_first_check
                .inspect_interactive_flag()
                .load(Ordering::Relaxed),
            false
        ); //means as if we haven't entered go_interactive() yet

        processor.upgrade_terminal_interface();

        let mut terminal_second_check = processor.clone_terminal_from_processor_test_only();
        //Now there should be MemoryTerminal inside TerminalWrapper instead of TerminalIdle
        //In production code it'd be DefaultTerminal at the place, thanks to conditional compilation done by attributes
        assert_eq!(
            terminal_second_check
                .inspect_interactive_flag()
                .load(Ordering::Relaxed),
            true
        );
        assert!((*terminal_second_check.inspect_inner_active()).is_none());
        //This means that it must be linefeed::Writer<'_,'_,MemoryTerminal> because DefaultTerminal would have made the test fail.
        assert_eq!(
            (*terminal_second_check
                .inspect_share_point()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap())
            .tell_me_who_you_are(),
            "TerminalReal<linefeed::Writer<_>>"
        );

        let received = stop_handle.stop();
    }

    #[test]
    fn clone_terminal_interface_works() {
        let port = find_free_port();
        let args = [
            "masq".to_string(),
            "--ui-port".to_string(),
            format!("{}", port),
        ];

        let processor_factory = CommandProcessorFactoryReal::new();
        let server = MockWebSocketsServer::new(port);
        let stop_handle = server.start();

        let mut processor = processor_factory
            .make(Box::new(StreamFactoryReal::new()), &args)
            .unwrap();

        processor.upgrade_terminal_interface();

        let mut terminal_first_check = processor.clone_terminal_from_processor_test_only();

        assert_eq!(
            terminal_first_check
                .inspect_interactive_flag()
                .load(Ordering::Relaxed),
            true
        );
        assert!((*terminal_first_check.inspect_inner_active()).is_none());
        assert_eq!(
            (*terminal_first_check
                .inspect_share_point()
                .lock()
                .unwrap()
                .as_ref()
                .unwrap())
            .tell_me_who_you_are(),
            "TerminalReal<linefeed::Writer<_>>"
        );

        processor.clone_terminal_interface();

        let mut terminal_second_check = processor.clone_terminal_from_processor_test_only();
        let inner_active = (*terminal_second_check.inspect_inner_active())
            .as_ref()
            .unwrap();
        assert_eq!(
            inner_active.tell_me_who_you_are(),
            "TerminalReal<linefeed::Writer<_>>"
        );
        assert!((*terminal_second_check.inspect_share_point().lock().unwrap()).is_none());
        assert_eq!(
            terminal_second_check
                .inspect_interactive_flag()
                .load(Ordering::Relaxed),
            true
        );

        let received = stop_handle.stop();
    }
}
