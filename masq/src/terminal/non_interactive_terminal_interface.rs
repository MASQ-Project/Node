// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::async_streams::AsyncStdStreamsFactory;
use crate::terminal::liso_wrappers::LisoOutputWrapper;
use crate::terminal::writing_utils::{ArcMutexFlushHandleInner, WritingUtils};
use crate::terminal::{
    FlushHandle, FlushHandleInner, TerminalWriter, WTermInterface, WTermInterfaceDup, WriteResult,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct NonInteractiveFlushHandle {}

pub struct InteractiveFlushHandle {}

pub struct NonInteractiveWTermInterface {
    stream_factory: Arc<dyn AsyncStdStreamsFactory>,
    stdout_utils: WritingUtils,
    stderr_utils: WritingUtils,
}

impl WTermInterface for NonInteractiveWTermInterface {
    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        self.stdout_utils.get_utils("Stdout")
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.stderr_utils.get_utils("Stderr")
    }
}

impl WTermInterfaceDup for NonInteractiveWTermInterface {
    fn dup(&self) -> Box<dyn WTermInterfaceDup> {
        Box::new(NonInteractiveWTermInterface::new(
            self.stream_factory.clone(),
        ))
    }
}

impl NonInteractiveWTermInterface {
    pub fn new(stream_factory: Arc<dyn AsyncStdStreamsFactory>) -> Self {
        let streams = stream_factory.make();
        let stdout_utils = Self::prepare_utils(streams.stdout);
        let stderr_utils = Self::prepare_utils(streams.stderr);
        Self {
            stream_factory,
            stdout_utils,
            stderr_utils,
        }
    }

    fn prepare_utils(stream: Box<dyn AsyncWrite + Send + Sync + Unpin>) -> WritingUtils {
        let flush_handle_inner_constructor = |output_chunks_receiver| {
            let inner = NonInteractiveFlushHandleInner::new(
                Arc::from(tokio::sync::Mutex::from(stream)),
                output_chunks_receiver,
            );
            Arc::new(tokio::sync::Mutex::new(inner)) as ArcMutexFlushHandleInner
        };
        WritingUtils::new(flush_handle_inner_constructor)
    }
}

pub struct NonInteractiveFlushHandleInner {
    writer_instance: Arc<tokio::sync::Mutex<dyn AsyncWrite + Send + Unpin>>,
    output_chunks_receiver: UnboundedReceiver<String>,
}

impl NonInteractiveFlushHandleInner {
    pub fn new(
        writer_instance: Arc<tokio::sync::Mutex<dyn AsyncWrite + Send + Unpin>>,
        output_chunks_receiver: UnboundedReceiver<String>,
    ) -> Self {
        Self {
            writer_instance,
            output_chunks_receiver,
        }
    }
}

#[async_trait]
impl FlushHandleInner for NonInteractiveFlushHandleInner {
    async fn write_internal(&self, full_output: String) -> Result<(), WriteResult> {
        match self
            .writer_instance
            .lock()
            .await
            .write(full_output.as_bytes())
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => todo!(),
        }
    }

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String> {
        &mut self.output_chunks_receiver
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
    use crate::test_utils::mocks::{make_async_std_streams, AsyncStdStreamsFactoryMock};
    use std::sync::Arc;

    #[test]
    #[should_panic(expected = "Another Stdout FLushHandle not permitted, already referencing 1")]
    fn test_double_call_panic_for_stdout() {
        let (async_std_streams, _handles) = make_async_std_streams(vec![]);
        let stream_factory = AsyncStdStreamsFactoryMock::default().make_result(async_std_streams);
        let subject = NonInteractiveWTermInterface::new(Arc::new(stream_factory));

        let _first = subject.stdout();
        let _second = subject.stdout();
    }

    #[test]
    #[should_panic(expected = "Another Stderr FLushHandle not permitted, already referencing 1")]
    fn test_double_call_panic_for_stderr() {
        let (async_std_streams, _handles) = make_async_std_streams(vec![]);
        let stream_factory = AsyncStdStreamsFactoryMock::default().make_result(async_std_streams);
        let subject = NonInteractiveWTermInterface::new(Arc::new(stream_factory));

        let _first = subject.stderr();
        let _second = subject.stderr();
    }

    #[tokio::test]
    async fn writing_works_for_non_interactive_terminal_interface_as_well_as_its_duplicate() {
        let (first_instance_std_streams, first_instance_handles) = make_async_std_streams(vec![]);
        let (second_instance_std_streams, second_instance_handles) = make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(first_instance_std_streams)
            .make_result(second_instance_std_streams);

        let subject = NonInteractiveWTermInterface::new(Arc::new(std_streams_factory));

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
