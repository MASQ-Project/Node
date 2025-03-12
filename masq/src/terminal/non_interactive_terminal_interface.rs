// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::writing_utils::{ArcMutexFlushHandleInner, WritingUtils};
use crate::terminal::{
    FlushHandle, FlushHandleInner, TerminalWriter, WTermInterface, WriteResult, WriteStreamType,
};
use async_trait::async_trait;
use masq_lib::async_streams::AsyncStdStreamsFactory;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct NonInteractiveWTermInterface {
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
            stdout_utils,
            stderr_utils,
        }
    }

    fn prepare_utils(
        stream: Box<dyn AsyncWrite + Send + Sync + Unpin>,
        stream_type: WriteStreamType,
    ) -> WritingUtils {
        let construct_flush_handle_inner = |output_chunks_receiver, stream_type| {
            let inner = NonInteractiveFlushHandleInner::new(
                stream_type,
                Arc::from(tokio::sync::Mutex::from(stream)),
                output_chunks_receiver,
            );
            Arc::new(tokio::sync::Mutex::new(inner)) as ArcMutexFlushHandleInner
        };
        WritingUtils::new(construct_flush_handle_inner, stream_type)
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
        allow_flushed_writings_to_finish, test_write_streams_of_particular_terminal,
        NonInteractiveStreamsAssertionHandles, WriteInput, WriteInputsByTermInterfaceKind,
    };
    use crate::terminal::{WTermInterface, WriteResult};
    use crate::test_utils::mocks::{
        make_async_std_streams, make_async_std_streams_with_error_setup, AsyncStdStreamsFactoryMock,
    };
    use std::io::ErrorKind;
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
    async fn writing_works_for_non_interactive_terminal_interface() {
        let (first_instance_std_streams, first_instance_handles) = make_async_std_streams(vec![]);
        let std_streams_factory =
            AsyncStdStreamsFactoryMock::default().make_result(first_instance_std_streams);

        let subject = NonInteractiveWTermInterface::new(Arc::new(std_streams_factory));

        test_write_streams_of_particular_terminal(
            WriteInputsByTermInterfaceKind::NonInteractive(WriteInput {
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
        let (std_streams, stream_handles) = make_async_std_streams_with_error_setup(
            vec![],
            Some(std::io::Error::from(ErrorKind::BrokenPipe)),
            None,
        );
        let std_streams_factory = AsyncStdStreamsFactoryMock::default().make_result(std_streams);
        let subject = NonInteractiveWTermInterface::new(Arc::new(std_streams_factory));
        let (_writer, mut flush_handle) = subject.stdout();

        let result = flush_handle
            .inner_arc_opt
            .as_mut()
            .unwrap()
            .lock()
            .await
            .write_internal("blah".to_string())
            .await;

        allow_flushed_writings_to_finish(None, None).await;
        let err_kind = match result {
            Err(WriteResult::OSError(os_err)) => os_err.kind(),
            x => panic!("We expected OS error but got: {:?}", x),
        };
        assert_eq!(err_kind, ErrorKind::BrokenPipe);
        stream_handles.assert_empty_stdout();
    }
}
