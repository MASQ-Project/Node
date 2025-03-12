// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::terminal::liso_wrappers::{LisoInputWrapper, LisoOutputWrapper};
use crate::terminal::test_utils::WriteInputsByTermInterfaceKind::{Interactive, NonInteractive};
use crate::terminal::{
    FlushHandle, FlushHandleInner, TerminalWriter, WTermInterface, WTermInterfaceDupAndSend,
    WriteResult, WriteStreamType,
};
use crate::test_utils::mocks::TerminalWriterTestReceiver;
use async_trait::async_trait;
use itertools::Itertools;
use liso::Response;
use masq_lib::test_utils::fake_stream_holder::{
    AsyncByteArrayWriter, FlushedString, FlushedStrings, StringAssertableStdHandle,
};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::UnboundedReceiver;

pub struct WriteInput<TerminalInterface, StreamsAssertionHandles> {
    pub term_interface: TerminalInterface,
    pub streams_assertion_handles: StreamsAssertionHandles,
}

pub struct NonInteractiveStreamsAssertionHandles {
    pub stdout: AsyncByteArrayWriter,
    pub stderr: AsyncByteArrayWriter,
}

pub enum WriteInputsByTermInterfaceKind<'test> {
    NonInteractive(WriteInput<&'test dyn WTermInterface, NonInteractiveStreamsAssertionHandles>),
    Interactive(WriteInput<InteractiveInterfaceByUse<'test>, LisoFlushedAssertableStrings>),
}

pub enum InteractiveInterfaceByUse<'test> {
    RWPrimeInterface(&'test dyn WTermInterface),
    WOnlyPrimeInterface(&'test dyn WTermInterface),
    WOnlyBroadcastsInterface(&'test dyn WTermInterfaceDupAndSend),
}

pub async fn test_write_streams_of_particular_terminal<'test: 'a, 'a>(
    inputs: WriteInputsByTermInterfaceKind<'test>,
    attempt_info: &'test str,
) {
    match inputs {
        NonInteractive(WriteInput {
            term_interface,
            streams_assertion_handles: NonInteractiveStreamsAssertionHandles { stdout, stderr },
        }) => {
            assert_writes(
                term_interface.stdout(),
                &stdout,
                term_interface.stderr(),
                &stderr,
                attempt_info,
                "non-interactive",
            )
            .await
        }
        Interactive(WriteInput {
            term_interface,
            streams_assertion_handles,
        }) => {
            let (stdout_components, stderr_components) = match term_interface {
                InteractiveInterfaceByUse::RWPrimeInterface(term_interface) => {
                    (term_interface.stdout(), term_interface.stderr())
                }
                InteractiveInterfaceByUse::WOnlyPrimeInterface(term_interface) => {
                    (term_interface.stdout(), term_interface.stderr())
                }
                InteractiveInterfaceByUse::WOnlyBroadcastsInterface(term_interface) => {
                    (term_interface.stdout(), term_interface.stderr())
                }
            };
            assert_writes(
                stdout_components,
                &streams_assertion_handles,
                stderr_components,
                &streams_assertion_handles,
                attempt_info,
                "interactive",
            )
            .await
        }
    }
}

async fn assert_writes(
    stdout_write_utils: (TerminalWriter, FlushHandle),
    stdout: &dyn StringAssertableStdHandle,
    stderr_writing_utils: (TerminalWriter, FlushHandle),
    stderr: &dyn StringAssertableStdHandle,
    attempt_info: &str,
    term_interface_spec: &str,
) {
    assert_write_abilities(
        stdout_write_utils,
        stdout,
        &form_test_case_name(attempt_info, term_interface_spec, "stdout"),
    )
    .await;
    assert_write_abilities(
        stderr_writing_utils,
        stderr,
        &form_test_case_name(attempt_info, term_interface_spec, "stderr"),
    )
    .await
}

fn form_test_case_name(attempt_info: &str, terminal_spec: &str, stream_spec: &str) -> String {
    format!("{attempt_info}: {terminal_spec} {stream_spec}")
}

const WRITE_OUTPUT_EXAMPLE: &str = "Bobbles.";
const WRITELN_OUTPUT_EXAMPLE: &str = "Another bunch of bobbles.";

async fn assert_write_abilities<'test>(
    (writer, flush_handle): (TerminalWriter, FlushHandle),
    test_output_handle: &'test dyn StringAssertableStdHandle,
    tested_case: &'test str,
) {
    writer.write(WRITE_OUTPUT_EXAMPLE).await;
    writer.write(" ").await;
    writer.writeln(WRITELN_OUTPUT_EXAMPLE).await;
    let actual_stream_output_beforehand = test_output_handle.get_string();
    let life_checker = flush_handle.life_checking_reference();
    let references_at_start = Arc::strong_count(&life_checker);

    drop(flush_handle);

    wait_for_write_to_finish(life_checker, references_at_start).await;
    let expected_stream_output_check_beforehand = String::new();
    assert_eq!(
        actual_stream_output_beforehand, expected_stream_output_check_beforehand,
        "In {}: initial check of output emptiness failed, it was: {}",
        tested_case, actual_stream_output_beforehand
    );
    let mut stream_output_after_check = test_output_handle.drain_flushed_strings();
    let actual_first_flush_raw = stream_output_after_check.next_flush().unwrap();
    let actual_first_flush = actual_first_flush_raw.output();
    let expected_first_flush = format!(
        "{}{}{}{}",
        WRITE_OUTPUT_EXAMPLE, " ", WRITELN_OUTPUT_EXAMPLE, "\n"
    );
    assert_eq!(
        actual_first_flush, expected_first_flush,
        "In {}: expected output: '{}', doesn't match: '{}'",
        tested_case, expected_first_flush, actual_first_flush
    );
    let second_flush = stream_output_after_check.next_flush();
    assert_eq!(
        second_flush, None,
        "Expected no other flush but got this: {:?}",
        second_flush
    )
}

pub async fn wait_for_write_to_finish(
    life_checker_arc: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
    reference_count_at_start: usize,
) {
    let now = SystemTime::now();
    while Arc::strong_count(&life_checker_arc) != (reference_count_at_start - 1) {
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

impl StringAssertableStdHandle for LisoFlushedAssertableStrings {
    fn get_string(&self) -> String {
        self.flushes
            .lock()
            .unwrap()
            .iter()
            .map(|flushed_str| flushed_str.output())
            .join("")
    }
    fn drain_flushed_strings(&self) -> FlushedStrings {
        self.flushes
            .lock()
            .unwrap()
            .drain(..)
            .collect::<Vec<FlushedString>>()
            .into()
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
    flush_during_drop_results: Arc<Mutex<Vec<Result<(), WriteResult>>>>,
    // Once specified, it should always return the same value
    stream_type_result: Option<WriteStreamType>,
    // For tests with requirement on real connection with the TerminalWriter
    terminal_writer_connection_opt: Option<TerminalWriterLinkToFlushHandleInnerMock>,
}

pub struct TerminalWriterLinkToFlushHandleInnerMock {
    output_receiver: TerminalWriterTestReceiver,
    flushed_strings: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl FlushHandleInner for FlushHandleInnerMock {
    async fn write_internal(&self, _full_output: String) -> Result<(), WriteResult> {
        unimplemented!("Required method, but never to be called in a mock")
    }

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String> {
        unimplemented!("Required method, but never to be called in a mock")
    }

    fn stream_type(&self) -> WriteStreamType {
        *self
            .stream_type_result
            .as_ref()
            .expect("WriteStreamType in FlushHandleInnerMock was not specified in the test setup")
    }

    async fn flush_during_drop(&mut self) -> Result<(), WriteResult> {
        self.flush_during_drop_params.lock().unwrap().push(());
        if let Some(linked) = self.terminal_writer_connection_opt.as_mut() {
            let output_to_be_flushed = linked.output_receiver.drain_test_output();
            if !output_to_be_flushed.is_empty() {
                linked
                    .flushed_strings
                    .lock()
                    .unwrap()
                    .push(output_to_be_flushed)
            }
        }
        // I think this is a better solution than the standard layout because this utility can also
        // be found in some nested test utils, and it'd be quite hard to supply the expected result
        // for each successful write. It also isn't clearly discoverable and so this makes it easy.
        // In the rare cases when you need the result be different you don't have to miss out, also
        // possible.
        if let Some(prepared_result) = self.flush_during_drop_results.lock().unwrap().pop() {
            prepared_result
        } else {
            Ok(())
        }
    }
}

impl FlushHandleInnerMock {
    pub fn flush_during_drop_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.flush_during_drop_params = params.clone();
        self
    }

    pub fn flush_during_drop_result(self, result: Result<(), WriteResult>) -> Self {
        self.flush_during_drop_results.lock().unwrap().push(result);
        self
    }

    pub fn stream_type_result(mut self, result: WriteStreamType) -> Self {
        self.stream_type_result.replace(result);
        self
    }

    pub fn connect_terminal_writer(
        mut self,
        receiver_from_terminal_writer: UnboundedReceiver<String>,
        reference_for_assertions_on_flushes: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        let output_receiver = TerminalWriterTestReceiver {
            receiver_from_terminal_writer,
        };
        let utils = TerminalWriterLinkToFlushHandleInnerMock {
            output_receiver,
            flushed_strings: reference_for_assertions_on_flushes,
        };
        self.terminal_writer_connection_opt = Some(utils);
        self
    }
}

pub async fn allow_flushed_writings_to_finish(
    stdout_flush_handle_opt: Option<FlushHandle>,
    stderr_flush_handle_opt: Option<FlushHandle>,
) {
    // If none, it means that handles are already gone and hence flushing has begun
    drop(stderr_flush_handle_opt);
    drop(stdout_flush_handle_opt);
    // Giving up execution on behalf of the spawned flushing tasks in the background
    tokio::time::sleep(Duration::from_millis(1)).await
}
