// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::liso_wrappers::{LisoInputWrapper, LisoOutputWrapper};
use crate::terminal::test_utils::WritingTestInputByTermInterfaces::{Interactive, NonInteractive};
use crate::terminal::{
    FlushHandle, FlushHandleInner, RWTermInterface, TerminalWriter, WTermInterface,
    WTermInterfaceDup, WriteResult,
};
use async_trait::async_trait;
use itertools::{Either, Itertools};
use liso::Response;
use masq_lib::test_utils::fake_stream_holder::{
    AsyncByteArrayWriter, FlushedString, FlushedStrings, StringAssertionMethods,
};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct WritingTestInput<TerminalInterface, StreamsAssertionHandles> {
    pub term_interface: TerminalInterface,
    pub streams_assertion_handles: StreamsAssertionHandles,
}

pub struct NonInteractiveStreamsAssertionHandles {
    pub stdout: AsyncByteArrayWriter,
    pub stderr: AsyncByteArrayWriter,
}

pub enum WritingTestInputByTermInterfaces<'test> {
    NonInteractive(
        WritingTestInput<&'test dyn WTermInterfaceDup, NonInteractiveStreamsAssertionHandles>,
    ),
    Interactive(WritingTestInput<InteractiveInterfaceByModes<'test>, LisoFlushedAssertableStrings>),
}

pub enum InteractiveInterfaceByModes<'test> {
    ReadWrite(&'test dyn WTermInterface),
    Write(&'test dyn WTermInterfaceDup),
}

pub async fn test_writing_streams_of_particular_terminal<'test>(
    inputs: WritingTestInputByTermInterfaces<'test>,
    attempt_info: &'test str,
) {
    let form_test_case_name = |description: &str| format!("{attempt_info}: {description}");

    match inputs {
        NonInteractive(WritingTestInput {
            term_interface,
            streams_assertion_handles: NonInteractiveStreamsAssertionHandles { stdout, stderr },
        }) => {
            assert_proper_writing(
                term_interface.stdout(),
                &stdout,
                &form_test_case_name("non-interactive stdout"),
            )
            .await;
            assert_proper_writing(
                term_interface.stderr(),
                &stderr,
                &form_test_case_name("non-interactive stderr"),
            )
            .await
        }
        Interactive(WritingTestInput {
            term_interface,
            streams_assertion_handles,
        }) => {
            let (stdout_components, stderr_components) = match term_interface {
                InteractiveInterfaceByModes::ReadWrite(term_interface) => {
                    (term_interface.stdout(), term_interface.stderr())
                }
                InteractiveInterfaceByModes::Write(term_interface) => {
                    (term_interface.stdout(), term_interface.stderr())
                }
            };

            assert_proper_writing(
                stdout_components,
                &streams_assertion_handles,
                &form_test_case_name("interactive stdout"),
            )
            .await;
            assert_proper_writing(
                stderr_components,
                &streams_assertion_handles,
                &form_test_case_name("interactive pseudo stderr"),
            )
            .await;
        }
    }
}

async fn assert_proper_writing<'test>(
    (writer, flush_handle): (TerminalWriter, FlushHandle),
    test_output_handle: &'test dyn StringAssertionMethods,
    tested_case: &'test str,
) {
    writer.write("Word.").await;
    writer.writeln("This seems like a sentence.").await;
    let stream_output_first_check = test_output_handle.get_string();
    let life_checker = flush_handle.life_checking_reference();
    let references_at_start = Arc::strong_count(&flush_handle.life_checking_reference());

    drop(flush_handle);

    wait_for_write_to_finish(life_checker, references_at_start).await;
    let stream_output_first_check_expected = String::new();
    assert_eq!(
        stream_output_first_check, stream_output_first_check_expected,
        "In {}: initial check of output emptiness failed",
        tested_case
    );
    let mut stream_output_after_check = test_output_handle.drain_flushed_strings().unwrap();
    eprintln!("{:?}", stream_output_after_check);
    assert_eq!(
        stream_output_after_check.next_flush().unwrap().output(),
        "Word.This seems like a sentence.\n",
        "In {}: expected output doesn't match",
        tested_case
    );
    assert_eq!(
        stream_output_after_check.next_flush(),
        None,
        "Expected no other flush but got this"
    )
}

pub async fn wait_for_write_to_finish(
    life_checker: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
    references_at_start: usize,
) {
    let now = SystemTime::now();
    while Arc::strong_count(&life_checker) != (references_at_start - 2) {
        if now.elapsed().expect("OS time handling issue") > Duration::from_secs(5) {
            panic!("Test timed out waiting for a flush to be completed")
        }
        tokio::time::sleep(Duration::from_millis(2)).await
    }
}

#[derive(Default)]
pub struct LisoInputWrapperMock {
    read_async_results: RefCell<Vec<Response>>,
}

#[async_trait(?Send)]
impl LisoInputWrapper for LisoInputWrapperMock {
    async fn read_async(&mut self) -> Response {
        self.read_async_results.borrow_mut().remove(0)
    }
}

impl LisoInputWrapperMock {
    pub fn read_async_result(self, result: Response) -> Self {
        self.read_async_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct LisoOutputWrapperMock {
    println_params: LisoFlushedAssertableStrings,
    prompt_params: Arc<Mutex<Vec<(String, bool, bool)>>>,
    clone_output_params: Arc<Mutex<Vec<()>>>,
    // Arc<Mutex<>> as the object must be Send + Sync
    clone_output_results: Arc<Mutex<Vec<Box<dyn LisoOutputWrapper>>>>,
}

impl LisoOutputWrapper for LisoOutputWrapperMock {
    fn println(&self, formatted_text: &str) {
        self.println_params
            .flushes
            .lock()
            .unwrap()
            .push(FlushedString::new(formatted_text.to_string()))
    }

    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool) {
        self.prompt_params.lock().unwrap().push((
            appearance.to_string(),
            input_allowed,
            clear_input,
        ))
    }

    fn clone_output(&self) -> Box<dyn LisoOutputWrapper> {
        self.clone_output_params.lock().unwrap().push(());
        self.clone_output_results.lock().unwrap().remove(0)
    }
}

impl LisoOutputWrapperMock {
    pub fn println_params(mut self, params: &LisoFlushedAssertableStrings) -> Self {
        self.println_params = params.clone();
        self
    }

    pub fn prompt_params(mut self, params: &Arc<Mutex<Vec<(String, bool, bool)>>>) -> Self {
        self.prompt_params = params.clone();
        self
    }

    pub fn clone_output_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.clone_output_params = params.clone();
        self
    }

    pub fn clone_output_result(self, result: Box<dyn LisoOutputWrapper>) -> Self {
        self.clone_output_results.lock().unwrap().push(result);
        self
    }
}

#[derive(Default, Clone)]
pub struct LisoFlushedAssertableStrings {
    flushes: Arc<Mutex<Vec<FlushedString>>>,
}

impl StringAssertionMethods for LisoFlushedAssertableStrings {
    fn get_string(&self) -> String {
        self.flushes
            .lock()
            .unwrap()
            .iter()
            .map(|flushed_str| flushed_str.output())
            .join("")
    }
    fn drain_flushed_strings(&self) -> Option<FlushedStrings> {
        Some(
            self.flushes
                .lock()
                .unwrap()
                .drain(..)
                .collect::<Vec<FlushedString>>()
                .into(),
        )
    }
}

impl LisoFlushedAssertableStrings {
    pub fn is_empty(&self) -> bool {
        self.flushes.lock().unwrap().is_empty()
    }
}

#[derive(Default)]
pub struct FlushHandleInnerMock {
    flush_during_drop_params: Arc<Mutex<Vec<()>>>,
    // The trait object representing this is Send + Sync, thus Arc<Mutex<T>> is required
    flush_during_drop_results: Arc<Mutex<Vec<Result<(), WriteResult>>>>,
}

#[async_trait]
impl FlushHandleInner for FlushHandleInnerMock {
    async fn flush_during_drop(&mut self) -> Result<(), WriteResult> {
        self.flush_during_drop_params.lock().unwrap().push(());
        self.flush_during_drop_results.lock().unwrap().remove(0)
    }

    async fn write_internal(&self, _full_output: String) -> Result<(), WriteResult> {
        unimplemented!("Required method, but never be called in a mock")
    }

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String> {
        unimplemented!("Required method, but never be called in a mock")
    }
}

impl FlushHandleInnerMock {
    pub fn flush_during_drop_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.flush_during_drop_params = params.clone();
        self
    }
}
