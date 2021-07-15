// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContextReal;
use crate::command_context::{CommandContext, ContextError};
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handler::BroadcastHandle;
use crate::terminal::terminal_interface::TerminalWrapper;
use masq_lib::utils::ExpectValue;

pub trait CommandProcessorFactory {
    fn make(
        &self,
        terminal_interface: Option<TerminalWrapper>,
        generic_broadcast_handle: Box<dyn BroadcastHandle>,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError>;
}

#[derive(Default)]
pub struct CommandProcessorFactoryReal;

impl CommandProcessorFactory for CommandProcessorFactoryReal {
    fn make(
        &self,
        terminal_interface: Option<TerminalWrapper>,
        generic_broadcast_handle: Box<dyn BroadcastHandle>,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        match CommandContextReal::new(ui_port, terminal_interface, generic_broadcast_handle) {
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
    fn terminal_wrapper_ref(&self) -> &TerminalWrapper;
}

pub struct CommandProcessorReal {
    context: CommandContextReal,
}

impl CommandProcessor for CommandProcessorReal {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        if let Some(synchronizer) = self.context.terminal_interface.clone() {
            let _lock = synchronizer.lock();
            command.execute(&mut self.context)
        } else {
            command.execute(&mut self.context)
        }
    }

    fn close(&mut self) {
        self.context.close();
    }

    fn terminal_wrapper_ref(&self) -> &TerminalWrapper {
        &self
            .context
            .terminal_interface
            .as_ref()
            .expect_v("TerminalWrapper")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::communications::broadcast_handler::{
        BroadcastHandleInactive, BroadcastHandler, BroadcastHandlerReal,
    };
    use crate::test_utils::mocks::TestStreamFactory;
    use crossbeam_channel::{bounded, Sender};
    use masq_lib::messages::UiShutdownRequest;
    use masq_lib::messages::{ToMessageBody, UiBroadcastTrigger, UiUndeliveredFireAndForget};
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
        let ui_port = find_free_port();
        let subject = CommandProcessorFactoryReal::new();
        let broadcast_handle = BroadcastHandleInactive;

        let result = subject.make(None, Box::new(broadcast_handle), ui_port);

        match result.err() {
            Some(CommandError::ConnectionProblem(_)) => (),
            x => panic!(
                "Expected Some(CommandError::ConnectionProblem(_); got {:?} instead",
                x
            ),
        }
    }

    #[derive(Debug)]
    struct TameCommand {
        sender: Sender<String>,
    }

    impl TameCommand {
        fn send_piece_of_whole_message(&self, time_lap_after: u64, piece: &str) {
            self.sender.send(piece.to_string()).unwrap();
            thread::sleep(Duration::from_millis(time_lap_after));
        }
    }

    impl Command for TameCommand {
        fn execute(&self, _context: &mut dyn CommandContext) -> Result<(), CommandError> {
            self.send_piece_of_whole_message(1, "This is a message");
            self.send_piece_of_whole_message(1, " which must be delivered as one piece");
            self.send_piece_of_whole_message(1, "; we'll do all possible for that.");
            self.send_piece_of_whole_message(1, " If only we have enough strength and spirit");
            self.send_piece_of_whole_message(1, " and determination and support and... snacks.");
            self.send_piece_of_whole_message(0, " Roger.");
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ToUiBroadcastTrigger {
        pub signal_position: Option<usize>,
    }

    impl Command for ToUiBroadcastTrigger {
        fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
            let input = UiBroadcastTrigger {
                number_of_broadcasts_in_one_batch: None,
                position_to_send_the_signal_opt: self.signal_position,
            }
            .tmb(0);
            context.send(input).unwrap(); //send instead of transact; using FFM.
            Ok(())
        }
    }

    #[test]
    fn process_locks_writing_and_prevents_interferences_from_broadcast_messages() {
        running_test();
        let ui_port = find_free_port();
        let broadcast = UiUndeliveredFireAndForget {
            opcode: "whateverTheOpcodeHereIs".to_string(),
        }
        .tmb(0);
        let (tx, rx) = bounded(1);
        let position_of_the_signal_message = 1; //means the one after the first
        let server = MockWebSocketsServer::new(ui_port)
            .queue_response(broadcast.clone())
            .queue_response(broadcast.clone())
            .queue_response(broadcast.clone())
            .queue_response(broadcast.clone())
            .queue_response(broadcast)
            .inject_signal_sender(tx);
        let (broadcast_stream_factory, broadcast_stream_factory_handle) = TestStreamFactory::new();
        let (cloned_stdout_sender, _) = broadcast_stream_factory.clone_senders();
        let terminal_interface = TerminalWrapper::configure_interface().unwrap();
        let background_terminal_interface = terminal_interface.clone();
        let generic_broadcast_handler =
            BroadcastHandlerReal::new(Some(background_terminal_interface));
        let generic_broadcast_handle =
            generic_broadcast_handler.start(Box::new(broadcast_stream_factory));
        let processor_factory = CommandProcessorFactoryReal::new();
        let stop_handle = server.start();

        let mut processor = processor_factory
            .make(Some(terminal_interface), generic_broadcast_handle, ui_port)
            .unwrap();
        processor
            .process(Box::new(ToUiBroadcastTrigger {
                signal_position: Some(position_of_the_signal_message),
            }))
            .unwrap();
        rx.recv_timeout(Duration::from_millis(200)).unwrap();
        processor
            .process(Box::new(TameCommand {
                sender: cloned_stdout_sender,
            }))
            .unwrap();

        let tamed_message_as_a_whole = "This is a message which must be delivered as one piece; we'll do all \
             possible for that. If only we have enough strength and spirit and determination and support and... snacks. Roger.";
        let received_output = broadcast_stream_factory_handle.stdout_so_far();
        assert!(
            received_output.contains(tamed_message_as_a_whole),
            "Message wasn't printed uninterrupted: {}",
            received_output
        );
        let output_with_broadcasts_only = received_output.replace(tamed_message_as_a_whole, "");
        let number_of_broadcast_received = output_with_broadcasts_only
            .clone()
            .lines()
            .filter(|line| {
                line.contains("Cannot handle whateverTheOpcodeHereIs request: Node is not running")
            })
            .count();
        assert_eq!(number_of_broadcast_received, 5);
        stop_handle.stop();
    }
}
