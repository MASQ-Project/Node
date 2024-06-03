// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::terminal::async_streams::AsyncStdStreamsFactory;
use crate::terminal::{
    FlushHandle, FlushHandleInner, TerminalWriter, WTermInterface, WTermInterfaceDup,
};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWrite;

pub struct NonInteractiveFlushHandle {}

pub struct InteractiveFlushHandle {}

pub struct NonInteractiveWTermInterface {
    stdout: Arc<Mutex<Box<dyn AsyncWrite + Send>>>,
    stderr: Arc<Mutex<Box<dyn AsyncWrite + Send>>>,
}

impl WTermInterface for NonInteractiveWTermInterface {
    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        todo!()
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        todo!()
    }
}

impl WTermInterfaceDup for NonInteractiveWTermInterface {
    fn dup(&self) -> Box<dyn WTermInterfaceDup> {
        todo!()
    }
}

impl NonInteractiveWTermInterface {
    pub fn new(stream_factory: Box<dyn AsyncStdStreamsFactory>) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::non_interactive_terminal_interface::NonInteractiveWTermInterface;
    use crate::terminal::test_utils::{
        test_writing_streams_of_particular_terminal, NonInteractiveStreamsAssertionHandles,
        WritingTestInput, WritingTestInputByTermInterfaces,
    };
    use crate::terminal::WTermInterface;
    use crate::terminal::WTermInterfaceDup;
    use crate::test_utils::mocks::{
        make_async_std_streams, make_async_std_write_stream, AsyncStdStreamsFactoryMock,
    };
    use itertools::Either;

    #[tokio::test]
    async fn writing_works_for_non_interactive_terminal_interface_as_well_as_its_duplicate() {
        let (first_instance_std_streams, first_instance_handles) = make_async_std_streams(vec![]);
        let (second_instance_std_streams, second_instance_handles) = make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(first_instance_std_streams)
            .make_result(second_instance_std_streams);

        let subject = NonInteractiveWTermInterface::new(Box::new(std_streams_factory));

        let duplicate = subject.dup();

        test_writing_streams_of_particular_terminal(
            WritingTestInputByTermInterfaces::NonInteractive(WritingTestInput {
                term_interface: &subject,
                streams_assertion_handles: NonInteractiveStreamsAssertionHandles {
                    stdout: first_instance_handles.stdout.left().unwrap(),
                    stderr: first_instance_handles.stderr.left().unwrap(),
                },
            }),
            "subject",
        )
        .await;
        test_writing_streams_of_particular_terminal(
            WritingTestInputByTermInterfaces::NonInteractive(WritingTestInput {
                term_interface: duplicate.as_ref(),
                streams_assertion_handles: NonInteractiveStreamsAssertionHandles {
                    stdout: second_instance_handles.stdout.left().unwrap(),
                    stderr: second_instance_handles.stderr.left().unwrap(),
                },
            }),
            "duplicate",
        )
        .await
    }
}
