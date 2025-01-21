// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::async_streams::AsyncStdStreamsFactory;
use crate::terminal::liso_wrappers::LisoOutputWrapper;
use crate::terminal::writing_utils::{ArcMutexFlushHandleInner, WritingUtils};
use crate::terminal::{
    FlushHandle, FlushHandleInner, TerminalWriter, WTermInterface, WriteResult,
    WriteStreamType,
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
        self.stdout_utils.get_utils()
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.stderr_utils.get_utils()
    }
}

impl NonInteractiveWTermInterface {
    pub fn new(stream_factory: Arc<dyn AsyncStdStreamsFactory>) -> Self {
        let streams = stream_factory.make();
        let stdout_utils = Self::prepare_utils(streams.stdout, WriteStreamType::Stdout);
        let stderr_utils = Self::prepare_utils(streams.stderr, WriteStreamType::Stderr);
        Self {
            stream_factory,
            stdout_utils,
            stderr_utils,
        }
    }

    fn prepare_utils(
        stream: Box<dyn AsyncWrite + Send + Sync + Unpin>,
        stream_type: WriteStreamType,
    ) -> WritingUtils {
        let flush_handle_inner_constructor = |output_chunks_receiver, stream_type| {
            let inner = NonInteractiveFlushHandleInner::new(
                stream_type,
                Arc::from(tokio::sync::Mutex::from(stream)),
                output_chunks_receiver,
            );
            Arc::new(tokio::sync::Mutex::new(inner)) as ArcMutexFlushHandleInner
        };
        WritingUtils::new(flush_handle_inner_constructor, stream_type)
    }
}

pub struct NonInteractiveFlushHandleInner {
    stream_type: WriteStreamType,
    writer_instance: Arc<tokio::sync::Mutex<dyn AsyncWrite + Send + Unpin>>,
    output_chunks_receiver: UnboundedReceiver<String>,
}

impl NonInteractiveFlushHandleInner {
    pub fn new(
        stream_type: WriteStreamType,
        writer_instance: Arc<tokio::sync::Mutex<dyn AsyncWrite + Send + Unpin>>,
        output_chunks_receiver: UnboundedReceiver<String>,
    ) -> Self {
        Self {
            stream_type,
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
            Err(e) => Err(WriteResult::OSError(e)),
        }
    }

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String> {
        &mut self.output_chunks_receiver
    }

    fn stream_type(&self) -> WriteStreamType {
        self.stream_type
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::non_interactive_terminal_interface::NonInteractiveWTermInterface;
    use crate::terminal::test_utils::{
        test_writing_streams_of_particular_terminal, NonInteractiveStreamsAssertionHandles,
        WritingTestInput, WritingTestInputByTermInterfaces,
    };
    use crate::terminal::{WTermInterface, WriteResult};
    use crate::test_utils::mocks::{
        make_async_std_streams, make_async_std_streams_with_further_setup,
        AsyncStdStreamsFactoryMock,
    };
    use itertools::Either;
    use masq_lib::test_utils::utils::make_rt;
    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

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
    async fn writing_works_for_non_interactive_terminal_interface() {
        let (first_instance_std_streams, first_instance_handles) = make_async_std_streams(vec![]);
        let (second_instance_std_streams, second_instance_handles) = make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default()
            .make_result(first_instance_std_streams)
            .make_result(second_instance_std_streams);

        let subject = NonInteractiveWTermInterface::new(Arc::new(std_streams_factory));

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
    }

    #[tokio::test]
    async fn error_flushing_through_non_interactive_flush_handle() {
        let (std_streams, stream_handles) = make_async_std_streams_with_further_setup(
            Either::Left(vec![]),
            Some(std::io::Error::from(ErrorKind::BrokenPipe)),
            None,
        );
        let std_streams_factory = AsyncStdStreamsFactoryMock::default().make_result(std_streams);
        let subject = NonInteractiveWTermInterface::new(Arc::new(std_streams_factory));
        let (writer, mut flush_handle) = subject.stdout();

        let result = flush_handle
            .inner_arc_opt
            .as_mut()
            .unwrap()
            .lock()
            .await
            .write_internal("blah".to_string())
            .await;

        let err_kind = match result {
            Err(WriteResult::OSError(os_err)) => os_err.kind(),
            x => panic!("We expected OS error but got: {:?}", x),
        };
        assert_eq!(err_kind, ErrorKind::BrokenPipe)
    }
}
