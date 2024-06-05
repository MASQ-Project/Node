// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::interactive_terminal_interface::InteractiveFlushHandleInner;
use async_trait::async_trait;
use clap::builder::Str;
use itertools::Itertools;
use std::fmt::{Display, Formatter};
use std::io::Error;
use std::sync::Arc;
use std::thread::panicking;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

pub mod async_streams;
pub mod interactive_terminal_interface;
mod liso_wrappers;
pub mod non_interactive_terminal_interface;
pub mod terminal_interface_factory;
mod test_utils;
mod writing_utils;

#[derive(Debug)]
pub enum WriteResult {
    OSError(Error),
}

#[derive(Debug, PartialEq)]
pub enum ReadError {
    ConnectionRefused,
    TerminalOutputInputDisconnected,
    UnexpectedNewValueFromLibrary,
}

#[derive(Debug, PartialEq)]
pub enum ReadInput {
    Line(String),
    Quit,
    Ignored { msg_opt: Option<String> },
}

#[derive(Debug)]
pub struct TerminalWriter {
    output_chunks_sender: UnboundedSender<String>,
}

impl TerminalWriter {
    pub fn new(output_chunks_sender: UnboundedSender<String>) -> Self {
        Self {
            output_chunks_sender,
        }
    }

    pub async fn writeln(&self, str: &str) {
        self.write_internal(format!("{}\n", str))
    }

    pub async fn write(&self, str: &str) {
        self.write_internal(str.to_string())
    }

    fn write_internal(&self, output: String) {
        self.output_chunks_sender
            .send(output)
            .unwrap_or_else(|e| panic!("SendError on trying to write '{}'", e.0))
    }
}

pub trait WTermInterfaceImplementingSend: WTermInterface + Send {}

pub trait WTermInterface {
    fn stdout(&self) -> (TerminalWriter, FlushHandle);
    fn stderr(&self) -> (TerminalWriter, FlushHandle);
}

pub trait WTermInterfaceDup: WTermInterface {
    fn dup(&self) -> Box<dyn WTermInterfaceDup>;
}

#[async_trait(?Send)]
pub trait RWTermInterface {
    async fn read_line(&mut self) -> Result<ReadInput, ReadError>;

    fn write_only_ref(&self) -> &dyn WTermInterfaceDup;

    fn write_only_clone_opt(&self) -> Option<Box<dyn WTermInterfaceDup>>;
}

#[async_trait]
pub trait FlushHandleInner: Send + Sync {
    async fn write_internal(&self, full_output: String) -> Result<(), WriteResult>;

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String>;

    fn stream_type(&self) -> WriteStreamType;

    async fn flush_during_drop(&mut self) -> Result<(), WriteResult> {
        let output = self
            .buffered_strings()
            .await
            .into_iter()
            .collect::<String>();
        self.write_internal(output).await
    }

    async fn buffered_strings(&mut self) -> Vec<String> {
        let mut vec = vec![];
        loop {
            match self.output_chunks_receiver_ref_mut().try_recv() {
                Ok(output_fragment) => vec.push(output_fragment),
                Err(e) => break,
            }
        }
        vec
    }
}

#[derive(Clone, Copy)]
pub enum WriteStreamType {
    Stdout,
    Stderr,
}

impl Display for WriteStreamType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteStreamType::Stdout => write!(f, "Stdout"),
            WriteStreamType::Stderr => write!(f, "Stderr"),
        }
    }
}

pub struct FlushHandle {
    // Strictly private!
    inner_arc_opt: Option<Arc<tokio::sync::Mutex<dyn FlushHandleInner>>>,
}

impl FlushHandle {
    pub fn new(flush_handle_inner: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>) -> Self {
        Self {
            inner_arc_opt: Some(flush_handle_inner),
        }
    }

    fn flush_whole_buffer(&mut self) -> Option<JoinHandle<()>> {
        if !panicking() {
            let mut inner_arc_opt = self.inner_arc_opt.take();
            let handle = tokio::task::spawn(async move {
                // Spawning seems neat as we're escaping the drop impl and can eventually handle
                // a panic outside
                let inner_arc = inner_arc_opt.expect("Flush handle with missing guts!");

                let mut flush_inner = inner_arc.lock().await;

                let stream_type = flush_inner.stream_type();

                let result = flush_inner.flush_during_drop().await;

                if let Err(e) = result {
                    panic!("Flushing {} stream failed due to: {:?}", stream_type, e)
                }
            });
            Some(handle)
        } else {
            None
        }
    }

    #[cfg(test)]
    fn life_checking_reference(&self) -> Arc<tokio::sync::Mutex<dyn FlushHandleInner>> {
        self.inner_arc_opt.as_ref().unwrap().clone()
    }
}

impl Drop for FlushHandle {
    fn drop(&mut self) {
        let _ = self.flush_whole_buffer();
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::test_utils::FlushHandleInnerMock;
    use crate::terminal::writing_utils::ArcMutexFlushHandleInner;
    use crate::terminal::{FlushHandle, TerminalWriter, WriteResult, WriteStreamType};
    use std::io::{Error, ErrorKind};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn flushes_if_thread_is_okay() {
        let flush_during_drop_params_arc = Arc::new(Mutex::new(vec![]));
        let inner =
            FlushHandleInnerMock::default().flush_during_drop_params(&flush_during_drop_params_arc);
        let flush_handle = FlushHandle::new(Arc::new(tokio::sync::Mutex::new(inner)));

        drop(flush_handle);

        let flush_during_drop_params = flush_during_drop_params_arc.lock().unwrap();
        assert_eq!(*flush_during_drop_params, vec![])
    }

    #[test]
    fn does_not_flush_if_thread_is_panicking() {
        // The standard drop procedure for this handle uses tokio::spawn so the runtime is important
        // to be present. Because we didn't get a nested panic (panic beginning in an already
        // unwinding panic (due to that missing runtime), which would've killed the test, we can
        // conclude that the spawn call wasn't reached as it shouldn't when the thread is already
        // panicking
        let flush_during_drop_params_arc = Arc::new(Mutex::new(vec![]));
        let inner =
            FlushHandleInnerMock::default().flush_during_drop_params(&flush_during_drop_params_arc);
        let mut flush_handle = FlushHandle::new(Arc::new(tokio::sync::Mutex::new(inner)));

        let experiment_thread = thread::spawn(move || {
            panic!("Intended panic");
            let _handle = flush_handle;
        });

        experiment_thread.join().unwrap_err();
        let flush_during_drop_params = flush_during_drop_params_arc.lock().unwrap();
        assert_eq!(*flush_during_drop_params, vec![])
    }

    #[test]
    #[should_panic(expected = "SendError on trying to write 'My testament'")]
    fn write_internal_panics_on_send() {
        let (tx, rx) = unbounded_channel();
        let subject = TerminalWriter::new(tx);
        drop(rx);

        let _ = subject.write_internal("My testament".to_string());
    }

    #[test]
    fn writing_stream_type_can_display() {
        assert_eq!(WriteStreamType::Stdout.to_string(), "Stdout");
        assert_eq!(WriteStreamType::Stderr.to_string(), "Stderr")
    }

    #[tokio::test]
    async fn flush_error_is_always_fatal() {
        let flush_handle_inner = FlushHandleInnerMock::default()
            .flush_during_drop_result(Err(WriteResult::OSError(Error::from(ErrorKind::Other))))
            .stream_type_result(WriteStreamType::Stderr);
        let flush_inner_arc = Arc::new(tokio::sync::Mutex::new(flush_handle_inner));
        let mut subject = FlushHandle::new(flush_inner_arc);

        let spawn_handle = subject.flush_whole_buffer().unwrap();

        let boxed_panic = spawn_handle.await.unwrap_err().into_panic();
        let panic_msg = boxed_panic.downcast_ref::<String>().unwrap();
        assert_eq!(
            panic_msg,
            "Flushing Stderr stream failed due to: OSError(Kind(Other))"
        )
    }
}
