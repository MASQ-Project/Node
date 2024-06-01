// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use itertools::Either;
use liso::Response;
use masq_lib::test_utils::fake_stream_holder::{AsyncByteArrayWriter, MockedStreamHandleWithStringAssertionMethods};
use crate::terminal::liso_wrappers::{LisoInputWrapper, LisoOutputWrapper};
use crate::terminal::{FlushHandle, RWTermInterface, TerminalWriter, WTermInterface};

pub async fn test_writing_streams_of_particular_terminal(
    non_interactive_vs_interactive: Either<(&dyn WTermInterface, AsyncByteArrayWriter, AsyncByteArrayWriter), (&dyn WTermInterface, LisoFlushedAssertableStrings)>,
    attempt_info: &str
) {
    let test_case = |description: &str|format!("{attempt_info}:{description}");

    match non_interactive_vs_interactive {
        Either::Left((non_interactive_terminal, stdout_assertion_handle, stderr_assertion_handle)) => {
            assert_proper_writing(||non_interactive_terminal.stdout(), &stdout_assertion_handle, &test_case("non-interactive stdout")).await;
            assert_proper_writing(||non_interactive_terminal.stderr(), &stderr_assertion_handle, &test_case("non-interactive stderr")).await
        }
        Either::Right((interactive_terminal, united_stream)) => {
            assert_proper_writing(||interactive_terminal.stdout(), &united_stream, &test_case("interactive stdout")).await;
            assert_proper_writing(||interactive_terminal.stderr(), &united_stream, &test_case("interactive pseudo stderr")).await;
        }
    }
}

async fn assert_proper_writing<'a, WriteComponentsGetter>(
    components_getter: WriteComponentsGetter,
    test_output_handle: &'a dyn MockedStreamHandleWithStringAssertionMethods,
    tested_case: &'a str
) where WriteComponentsGetter: FnOnce()->(&'a TerminalWriter, Box<dyn FlushHandle>)
{
    let (writer, flush_handle) = components_getter();
    writer.write("Word.").await;
    writer.writeln("This makes up a one-liner.").await;
    let stdout_first_check = test_output_handle.get_string();

    flush_handle.flush().await.unwrap();

    let stdout_after_check = test_output_handle.drain_flushed_strings().unwrap();
    assert_eq!(stdout_first_check, String::new(), "In {}: initial check of output emptiness failed", tested_case);
    assert_eq!(stdout_after_check, vec!["Word.This resembles a sentence.\n"], "In {}: expected strings don't match", tested_case)
}

#[derive(Default)]
pub struct LisoInputWrapperMock {
  //  read_async_params: Arc<Mutex<Vec<()>>>,
    read_async_results: RefCell<Vec<Response>>,
}

#[async_trait(?Send)]
impl LisoInputWrapper for LisoInputWrapperMock {
    async fn read_async(&mut self) -> Response {
        self.read_async_results.borrow_mut().remove(0)
    }
}

impl LisoInputWrapperMock {
    pub fn read_async_result(self, result: Response)-> Self{
        self.read_async_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct LisoOutputWrapperMock{
    println_params: LisoFlushedAssertableStrings,
    prompt_params: Arc<Mutex<Vec<(String, bool, bool)>>>,
    clone_output_params: Arc<Mutex<Vec<()>>>,
    clone_output_results: RefCell<Vec<Box<dyn LisoOutputWrapper>>>
}

impl LisoOutputWrapper for LisoOutputWrapperMock{
    fn println(&self, formatted_text: &str) {
        todo!()
    }

    fn prompt(&self, appearance: &str, input_allowed: bool, clear_input: bool) {
        self.prompt_params.lock().unwrap().push((appearance.to_string(), input_allowed, clear_input))
    }

    fn clone_output(&self) -> Box<dyn LisoOutputWrapper> {
        self.clone_output_params.lock().unwrap().push(());
        self.clone_output_results.borrow_mut().remove(0)
    }
}

impl LisoOutputWrapperMock{
    pub fn println_params(mut self, params: &LisoFlushedAssertableStrings) -> Self{
        self.println_params = params.clone();
        self
    }

    pub fn prompt_params(mut self, params: &Arc<Mutex<Vec<(String, bool, bool)>>>)->Self {
        self.prompt_params = params.clone();
        self
    }

    pub fn clone_output_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.clone_output_params = params.clone();
        self
    }

    pub fn clone_output_result(self, result: Box<dyn LisoOutputWrapper>) -> Self {
        self.clone_output_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default, Clone)]
pub struct LisoFlushedAssertableStrings {
    flushes: Arc<Mutex<Vec<String>>>
}

impl MockedStreamHandleWithStringAssertionMethods for LisoFlushedAssertableStrings {
    fn get_string(&self) -> String {
        todo!()
    }
    fn drain_flushed_strings(&self) -> Option<Vec<String>> {
        todo!()
    }
}

impl LisoFlushedAssertableStrings{
    pub fn is_empty(&self)-> bool{
        self.flushes.lock().unwrap().is_empty()
    }
}