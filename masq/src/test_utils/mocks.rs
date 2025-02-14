// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::clap_before_entrance::InitialArgsParser;
use crate::command_context::{CommandContext, ContextError};
use crate::command_context_factory::CommandContextFactory;
use crate::command_factory::{CommandFactory, CommandFactoryError};
use crate::command_processor::{
    CommandExecutionHelper, CommandExecutionHelperFactory
};
use crate::commands::commands_common::CommandError::Transmission;
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::client_listener_thread::WSClientHandle;
use crate::run_modes::CLIProgramEntering;
use crate::terminal::terminal_interface_factory::TerminalInterfaceFactory;
use crate::terminal::test_utils::FlushHandleInnerMock;
use crate::terminal::{
    FlushHandle, RWTermInterface, ReadError, ReadInput, TerminalWriter, WTermInterface,
    WTermInterfaceDupAndSend, WriteStreamType,
};
use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use itertools::Either;
use masq_lib::async_streams::{AsyncStdStreams, AsyncStdStreamsFactory};
use masq_lib::test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
use masq_lib::test_utils::fake_stream_holder::{
    AsyncByteArrayReader, AsyncByteArrayWriter, HandleToCountReads, StdinReadCounter,
    StringAssertableStdHandle,
};
use masq_lib::ui_gateway::MessageBody;
use masq_lib::websockets_handshake::HandshakeResultTx;
use masq_lib::{
    arbitrary_id_stamp_in_trait_impl, implement_as_any,
    set_arbitrary_id_stamp_in_mock_impl,
};
use std::any::Any;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncWrite};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use workflow_websocket::client::{Error, Handshake, Message, Result as ClientResult};

#[derive(Default)]
pub struct CommandFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: RefCell<Vec<Result<Box<dyn Command>, CommandFactoryError>>>,
}

impl CommandFactory for CommandFactoryMock {
    fn make(&self, pieces: &[String]) -> Result<Box<dyn Command>, CommandFactoryError> {
        self.make_params.lock().unwrap().push(pieces.to_vec());
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandFactoryMock {
    pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn Command>, CommandFactoryError>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

pub struct CommandContextMock {
    active_port_results: RefCell<Vec<Option<u16>>>,
    send_one_way_params: Arc<Mutex<Vec<MessageBody>>>,
    send_one_way_results: RefCell<Vec<Result<(), ContextError>>>,
    transact_params: Arc<Mutex<Vec<(MessageBody, u64)>>>,
    transact_results: RefCell<Vec<Result<MessageBody, ContextError>>>,
    close_params: Arc<Mutex<Vec<()>>>,
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

#[async_trait(?Send)]
impl CommandContext for CommandContextMock {
    async fn active_port(&self) -> Option<u16> {
        self.active_port_results.borrow_mut().remove(0)
    }

    async fn send_one_way(&self, message: MessageBody) -> Result<(), ContextError> {
        self.send_one_way_params.lock().unwrap().push(message);
        self.send_one_way_results.borrow_mut().remove(0)
    }

    async fn transact(
        &self,
        message: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ContextError> {
        self.transact_params
            .lock()
            .unwrap()
            .push((message, timeout_millis));
        self.transact_results.borrow_mut().remove(0)
    }

    fn close(&self) {
        self.close_params.lock().unwrap().push(())
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl Default for CommandContextMock {
    fn default() -> Self {
        Self {
            active_port_results: RefCell::new(vec![]),
            send_one_way_params: Arc::new(Mutex::new(vec![])),
            send_one_way_results: RefCell::new(vec![]),
            transact_params: Arc::new(Mutex::new(vec![])),
            transact_results: RefCell::new(vec![]),
            close_params: Arc::new(Mutex::new(vec![])),
            arbitrary_id_stamp_opt: None,
        }
    }
}

impl CommandContextMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_port_result(self, result: Option<u16>) -> Self {
        self.active_port_results.borrow_mut().push(result);
        self
    }

    pub fn send_one_way_params(mut self, params: &Arc<Mutex<Vec<MessageBody>>>) -> Self {
        self.send_one_way_params = params.clone();
        self
    }

    pub fn send_one_way_result(self, result: Result<(), ContextError>) -> Self {
        self.send_one_way_results.borrow_mut().push(result);
        self
    }

    pub fn transact_params(mut self, params: &Arc<Mutex<Vec<(MessageBody, u64)>>>) -> Self {
        self.transact_params = params.clone();
        self
    }

    pub fn transact_result(self, result: Result<MessageBody, ContextError>) -> Self {
        self.transact_results.borrow_mut().push(result);
        self
    }

    pub fn close_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.close_params = params.clone();
        self
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

#[derive(Default)]
pub struct CommandContextFactoryMock {
    make_params: Arc<Mutex<Vec<(u16, Option<Box<dyn WTermInterfaceDupAndSend>>)>>>,
    make_results: Arc<Mutex<Vec<Result<Box<dyn CommandContext>, CommandError>>>>,
}

#[async_trait(?Send)]
impl CommandContextFactory for CommandContextFactoryMock {
    async fn make(
        &self,
        ui_port: u16,
        term_interface_opt: Option<Box<dyn WTermInterfaceDupAndSend>>,
    ) -> Result<Box<dyn CommandContext>, CommandError> {
        self.make_params
            .lock()
            .unwrap()
            .push((ui_port, term_interface_opt));
        self.make_results.lock().unwrap().remove(0)
    }
}

impl CommandContextFactoryMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn make_params(
        mut self,
        params: &Arc<Mutex<Vec<(u16, Option<Box<dyn WTermInterfaceDupAndSend>>)>>>,
    ) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn CommandContext>, CommandError>) -> Self {
        self.make_results.lock().unwrap().push(result);
        self
    }
}

#[derive(Default)]
pub struct CommandExecutionHelperFactoryMock {
    make_results: RefCell<Vec<Box<dyn CommandExecutionHelper>>>,
}

impl CommandExecutionHelperFactory for CommandExecutionHelperFactoryMock {
    fn make(&self) -> Box<dyn CommandExecutionHelper> {
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandExecutionHelperFactoryMock {
    pub fn make_result(self, result: Box<dyn CommandExecutionHelper>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct CommandExecutionHelperMock {
    execute_command_params: Arc<Mutex<Vec<(Box<dyn Command>, ArbitraryIdStamp, ArbitraryIdStamp)>>>,
    execute_command_results: RefCell<Vec<Result<(), CommandError>>>,
}

#[async_trait(?Send)]
impl CommandExecutionHelper for CommandExecutionHelperMock {
    async fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        self.execute_command_params.lock().unwrap().push((
            command,
            context.arbitrary_id_stamp(),
            term_interface.arbitrary_id_stamp(),
        ));
        self.execute_command_results.borrow_mut().remove(0)
    }
}

impl CommandExecutionHelperMock {
    pub fn execute_command_params(
        mut self,
        params: &Arc<Mutex<Vec<(Box<dyn Command>, ArbitraryIdStamp, ArbitraryIdStamp)>>>,
    ) -> Self {
        self.execute_command_params = params.clone();
        self
    }

    pub fn execute_command_result(self, result: Result<(), CommandError>) -> Self {
        self.execute_command_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct InitialArgsParserMock {
    parse_initialization_args_results: RefCell<Vec<CLIProgramEntering>>,
}

#[async_trait(?Send)]
impl InitialArgsParser for InitialArgsParserMock {
    async fn parse_initialization_args(
        &self,
        _args: &[String],
        _std_streams: &mut AsyncStdStreams,
    ) -> CLIProgramEntering {
        self.parse_initialization_args_results
            .borrow_mut()
            .remove(0)
    }
}

impl InitialArgsParserMock {
    pub fn parse_initialization_args_result(self, result: CLIProgramEntering) -> Self {
        self.parse_initialization_args_results
            .borrow_mut()
            .push(result);
        self
    }
}

#[derive(Clone)]
pub struct MockCommand {
    pub message: MessageBody,
    pub execute_results: Arc<Mutex<Vec<Result<(), CommandError>>>>,
}

impl std::fmt::Debug for MockCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "MockCommand")
    }
}

#[async_trait(?Send)]
impl Command for MockCommand {
    async fn execute(
        self: Box<Self>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        let (stdout, _stdout_flush_handle) = term_interface.stdout();
        let (stderr, _stderr_flush_handle) = term_interface.stderr();
        stdout.write("MockCommand output").await;
        stderr.write("MockCommand error").await;
        match context.transact(self.message.clone(), 1000).await {
            Ok(_) => self.execute_results.lock().unwrap().remove(0),
            Err(e) => Err(Transmission(format!("{:?}", e))),
        }
    }

    implement_as_any!();
}

impl MockCommand {
    pub fn new(message: MessageBody) -> Self {
        Self {
            message,
            execute_results: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn execute_result(self, result: Result<(), CommandError>) -> Self {
        self.execute_results.lock().unwrap().push(result);
        self
    }
}

pub struct WSClientHandshakeAlwaysAcceptingHandler {
    handshake_confirmation_tx: HandshakeResultTx,
}

#[async_trait]
impl Handshake for WSClientHandshakeAlwaysAcceptingHandler {
    async fn handshake(
        &self,
        _sender: &Sender<Message>,
        _receiver: &Receiver<Message>,
    ) -> ClientResult<()> {
        self.handshake_confirmation_tx.send(Ok(())).unwrap();
        Ok(())
    }
}

impl WSClientHandshakeAlwaysAcceptingHandler {
    pub fn new(handshake_confirmation_tx: HandshakeResultTx) -> Self {
        Self {
            handshake_confirmation_tx,
        }
    }
}

#[derive(Default)]
pub struct WSClientHandleMock {
    send_params: Arc<Mutex<Vec<Message>>>,
    send_results: Mutex<Vec<std::result::Result<(), Arc<Error>>>>,
}

#[async_trait]
impl WSClientHandle for WSClientHandleMock {
    async fn send(&self, msg: Message) -> std::result::Result<(), Arc<Error>> {
        self.send_params.lock().unwrap().push(msg);
        self.send_results.lock().unwrap().remove(0)
    }

    async fn disconnect(&self) -> ClientResult<()> {
        unimplemented!("Not needed yet")
    }

    fn close_talker_half(&self) -> bool {
        unimplemented!("Not needed yet")
    }

    fn dismiss_event_loop(&self) {
        unimplemented!("Not needed yet")
    }

    fn is_connection_open(&self) -> bool {
        unimplemented!("Test-only method that has an effect only at the real one")
    }

    fn is_event_loop_spinning(&self) -> bool {
        unimplemented!("Test-only method that has an effect only at the real one")
    }
}

impl WSClientHandleMock {
    pub fn send_params(mut self, params: &Arc<Mutex<Vec<Message>>>) -> Self {
        self.send_params = params.clone();
        self
    }

    pub fn send_result(self, result: std::result::Result<(), Arc<Error>>) -> Self {
        self.send_results.lock().unwrap().push(result);
        self
    }
}

pub fn make_terminal_writer() -> (TerminalWriter, TerminalWriterTestReceiver) {
    let (tx, rx) = unbounded_channel();
    (
        TerminalWriter::new(tx),
        TerminalWriterTestReceiver {
            receiver_from_terminal_writer: rx,
        },
    )
}

pub struct TerminalWriterTestReceiver {
    pub receiver_from_terminal_writer: UnboundedReceiver<String>,
}

impl TerminalWriterTestReceiver {
    pub fn drain_test_output(&mut self) -> String {
        let mut captured_output = String::new();
        loop {
            match self.receiver_from_terminal_writer.try_recv() {
                Ok(output_fragment) => captured_output.push_str(&output_fragment),
                Err(e) => match e {
                    tokio::sync::mpsc::error::TryRecvError::Empty
                    | tokio::sync::mpsc::error::TryRecvError::Disconnected => break,
                },
            }
        }
        captured_output
    }

    pub fn assert_is_empty(&mut self) {
        if let Some(some_stuff_received) = self.drain_all() {
            panic!(
                "We expected this TerminalWriter to do no writing but it did: {}",
                some_stuff_received
            )
        }
    }

    fn drain_all(&mut self) -> Option<String> {
        let mut captured_output_opt: Option<String> = None;
        loop {
            match self.receiver_from_terminal_writer.try_recv() {
                Ok(output_fragment) => match captured_output_opt.as_mut() {
                    Some(container) => container.push_str(&output_fragment),
                    None => captured_output_opt = Some(output_fragment),
                },
                Err(e) => match e {
                    tokio::sync::mpsc::error::TryRecvError::Empty
                    | tokio::sync::mpsc::error::TryRecvError::Disconnected => break,
                },
            }
        }
        captured_output_opt
    }
}

pub struct TermInterfaceMock {
    inner: TerminalInterfaceMockInner,
    // TODO: I don't know if we want to keep this
    arbitrary_id_stamp_opt: Option<ArbitraryIdStamp>,
}

enum TerminalInterfaceMockInner {
    NonInteractive {
        writing_streams: WritingStreamsContainers,
    },
    Interactive {
        stdin_read_results: Arc<Mutex<ReadLineResults>>,
        // Simplification by helping ourselves with a whole new terminal.
        // It should be configured as non-interactive though
        writing_part: Box<TermInterfaceMock>,
        // Optional so that it can be pulled out
        background_terminal_interface_arc_opt: Arc<Mutex<Option<TermInterfaceMock>>>,
    },
}

impl TerminalInterfaceMockInner {
    fn write_only_terminal_for_interactive_mode(&self) -> &dyn WTermInterface {
        match self {
            TerminalInterfaceMockInner::NonInteractive { ..} => panic!("Trying to access an auxiliary write only terminal on a mock not having been set up as interactive"),
            TerminalInterfaceMockInner::Interactive {writing_part,..} => writing_part.as_ref()
        }
    }

    fn background_terminal(&self) -> TermInterfaceMock {
        match self {
            TerminalInterfaceMockInner::NonInteractive { .. } => panic!("Trying to fetch the background terminal from a mock not having been set up as interactive"),
            TerminalInterfaceMockInner::Interactive { background_terminal_interface_arc_opt, .. } => background_terminal_interface_arc_opt.lock().unwrap().take().expect("Trying to fetch the background terminal more than once")
        }
    }

    fn stdin_read_results(&self) -> &Arc<Mutex<ReadLineResults>> {
        match self {
            TerminalInterfaceMockInner::NonInteractive { .. } => panic!("Trying to access stdin results from a mock terminal not having been set up as interactive"),
            TerminalInterfaceMockInner::Interactive { stdin_read_results,..} => stdin_read_results
        }
    }

    fn stdout_arc(&self) -> &Arc<Mutex<Vec<String>>> {
        match self {
            TerminalInterfaceMockInner::NonInteractive { writing_streams } => {
                &writing_streams.stdout
            }
            TerminalInterfaceMockInner::Interactive { writing_part, .. } => {
                writing_part.inner.stdout_arc()
            }
        }
    }

    fn stderr_arc(&self) -> &Arc<Mutex<Vec<String>>> {
        match self {
            TerminalInterfaceMockInner::NonInteractive { writing_streams } => {
                &writing_streams.stderr
            }
            TerminalInterfaceMockInner::Interactive { writing_part, .. } => {
                writing_part.inner.stderr_arc()
            }
        }
    }
}

struct WritingStreamsContainers {
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl WritingStreamsContainers {
    fn new() -> (Self, Arc<Mutex<Vec<String>>>, Arc<Mutex<Vec<String>>>) {
        let stdout = Arc::new(Mutex::new(vec![]));
        let stderr = Arc::new(Mutex::new(vec![]));
        (
            Self {
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            },
            stdout,
            stderr,
        )
    }
}

#[async_trait(?Send)]
impl RWTermInterface for TermInterfaceMock {
    async fn read_line(&mut self) -> Result<ReadInput, ReadError> {
        self.inner
            .stdin_read_results()
            .lock()
            .unwrap()
            .stdin_read_results
            .remove(0)
    }

    fn write_only_ref(&self) -> &dyn WTermInterface {
        self.inner.write_only_terminal_for_interactive_mode()
    }

    fn write_only_clone(&self) -> Box<dyn WTermInterfaceDupAndSend> {
        Box::new(self.inner.background_terminal())
    }
}

impl WTermInterface for TermInterfaceMock {
    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        Self::set_up_assertable_writer(self.inner.stdout_arc(), WriteStreamType::Stdout)
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        Self::set_up_assertable_writer(self.inner.stderr_arc(), WriteStreamType::Stderr)
    }

    arbitrary_id_stamp_in_trait_impl!();
}

impl WTermInterfaceDupAndSend for TermInterfaceMock {
    fn write_ref(&self) -> &dyn WTermInterface {
        unimplemented!("not needed")
    }

    fn dup(&self) -> Box<dyn WTermInterfaceDupAndSend> {
        unimplemented!("not needed")
    }
}

impl TermInterfaceMock {
    pub fn new_non_interactive() -> (Self, AsyncTestStreamHandles) {
        let (writing_streams, stdout_handle, stderr_handle) = WritingStreamsContainers::new();
        let inner = TerminalInterfaceMockInner::NonInteractive { writing_streams };

        let mock = Self {
            inner,
            arbitrary_id_stamp_opt: None,
        };

        let terminal_interface_stream_handles = AsyncTestStreamHandles {
            stdin_counter: StdinReadCounter::reading_not_available(),
            stdout: Either::Right(stdout_handle),
            stderr: Either::Right(stderr_handle),
        };

        (mock, terminal_interface_stream_handles)
    }

    pub fn new_interactive(
        read_results: Vec<Result<ReadInput, ReadError>>,
    ) -> (Self, AsyncTestStreamHandles, AsyncTestStreamHandles) {
        let (background_terminal_interface_mock, background_terminal_interface_stream_handles) =
            Self::new_non_interactive();

        let (writing_streams, stdout_handle, stderr_handle) = WritingStreamsContainers::new();

        let stdin_read_results = Arc::new(Mutex::new(ReadLineResults::new(read_results)));

        let writing_part = Box::new(TermInterfaceMock {
            inner: TerminalInterfaceMockInner::NonInteractive { writing_streams },
            arbitrary_id_stamp_opt: None,
        });

        let inner = TerminalInterfaceMockInner::Interactive {
            stdin_read_results: stdin_read_results.clone(),
            writing_part,
            background_terminal_interface_arc_opt: Arc::new(Mutex::new(Some(
                background_terminal_interface_mock,
            ))),
        };

        let mock = Self {
            inner,
            arbitrary_id_stamp_opt: None,
        };

        let prime_terminal_interface_stream_handles = AsyncTestStreamHandles {
            stdin_counter: StdinReadCounter::new(stdin_read_results),
            stdout: Either::Right(stdout_handle),
            stderr: Either::Right(stderr_handle),
        };

        (
            mock,
            prime_terminal_interface_stream_handles,
            background_terminal_interface_stream_handles,
        )
    }

    fn set_up_assertable_writer(
        stream_writes_arc: &Arc<Mutex<Vec<String>>>,
        write_stream_type: WriteStreamType,
    ) -> (TerminalWriter, FlushHandle) {
        let (tx, rx) = unbounded_channel();
        let terminal_writer = TerminalWriter::new(tx);
        let flush_handle_inner = FlushHandleInnerMock::default()
            .stream_type_result(write_stream_type)
            .connect_terminal_writer(rx, stream_writes_arc.clone());
        (
            terminal_writer,
            FlushHandle::new(Arc::new(tokio::sync::Mutex::new(flush_handle_inner))),
        )
    }

    set_arbitrary_id_stamp_in_mock_impl!();
}

impl HandleToCountReads for ReadLineResults {
    fn count_reads(&self) -> usize {
        self.results_initially - self.stdin_read_results.len()
    }
}

struct ReadLineResults {
    stdin_read_results: Vec<Result<ReadInput, ReadError>>,
    results_initially: usize,
}

impl Default for ReadLineResults {
    fn default() -> Self {
        Self {
            stdin_read_results: vec![],
            results_initially: 0,
        }
    }
}

impl ReadLineResults {
    fn new(stdin_read_results: Vec<Result<ReadInput, ReadError>>) -> Self {
        let results_initially = stdin_read_results.len();
        Self {
            stdin_read_results,
            results_initially,
        }
    }
}

pub enum MockTerminalMode {
    // None in the Option means the terminal is a write-only clone from the prime one
    InteractiveMode(Option<Vec<Result<ReadInput, ReadError>>>),
    NonInteractiveMode,
}

pub struct AsyncTestStreamHandles {
    pub stdin_counter: StdinReadCounter,
    pub stdout: Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>,
    pub stderr: Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>,
}

impl AsyncTestStreamHandles {
    pub fn reads_opt(&self) -> Option<usize> {
        self.stdin_counter.reads_opt()
    }
    // Recommended to call only once (and keep the result) as repeated calls may be unnecessarily
    // expensive
    pub fn stdout_flushed_strings(&self) -> Vec<String> {
        Self::drain_flushed_strings(&self.stdout)
    }

    // Recommended to call only once (and keep the result) as repeated calls may be unnecessarily
    // expensive
    pub fn stderr_flushed_strings(&self) -> Vec<String> {
        Self::drain_flushed_strings(&self.stderr)
    }

    pub fn stdout_all_in_one(&self) -> String {
        Self::join_flushed(self.stdout_flushed_strings())
    }

    pub fn stderr_all_in_one(&self) -> String {
        Self::join_flushed(self.stderr_flushed_strings())
    }

    pub fn assert_empty_stdout(&self) {
        Self::assert_empty_stream(&self.stdout, "stdout")
    }

    pub fn assert_empty_stderr(&self) {
        Self::assert_empty_stream(&self.stderr, "stderr")
    }

    pub async fn await_stdout_is_not_empty(&self) {
        Self::wait_until_is_not_empty(&self.stdout, 3000, "stdout", None).await
    }

    pub async fn await_stderr_is_not_empty(&self) {
        Self::wait_until_is_not_empty(&self.stderr, 3000, "stderr", None).await
    }

    pub async fn await_stdout_is_not_empty_or_panic_with_expected(&self, expected_value: &str) {
        Self::wait_until_is_not_empty(&self.stdout, 3000, "stdout", Some(expected_value)).await
    }

    pub async fn await_stderr_is_not_empty_or_panic_with_expected(&self, expected_value: &str) {
        Self::wait_until_is_not_empty(&self.stderr, 3000, "stderr", Some(expected_value)).await
    }

    fn join_flushed(strings: Vec<String>) -> String {
        strings.into_iter().collect::<String>()
    }

    fn assert_empty_stream(
        handle: &Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>,
        stream_name: &str,
    ) {
        let received = AsyncTestStreamHandles::drain_flushed_strings(handle);
        assert!(
            received.is_empty(),
            "We thought this {} stream was empty, but it contained {:?}",
            stream_name,
            received
        )
    }

    async fn wait_until_is_not_empty(
        handle: &Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>,
        hard_limit_ms: u64,
        stream_name: &str,
        expected_value_opt: Option<&str>,
    ) {
        let start = SystemTime::now();
        let hard_limit = Duration::from_millis(hard_limit_ms);
        while Self::check_is_empty(handle) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if start.elapsed().unwrap() >= hard_limit {
                panic!(
                    "Waited for {} while we didn't receive any output written in {} despite expected some. {}",
                    hard_limit_ms,
                    stream_name,
                    expected_value_opt
                        .map(|val| format!("The expected values were '{}'", val))
                        .unwrap_or_else(|| String::new())
                )
            }
        }
    }

    fn check_is_empty(handle: &Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>) -> bool {
        match handle {
            Either::Left(async_byte_array) => async_byte_array.is_empty(),
            Either::Right(naked_string_containers) => {
                naked_string_containers.lock().unwrap().is_empty()
            }
        }
    }

    fn drain_flushed_strings(
        handle: &Either<AsyncByteArrayWriter, Arc<Mutex<Vec<String>>>>,
    ) -> Vec<String> {
        match handle {
            Either::Left(async_byte_array) => {
                async_byte_array.drain_flushed_strings().as_simple_strings()
            }
            Either::Right(naked_string_containers) => {
                naked_string_containers.lock().unwrap().drain(..).collect()
            }
        }
    }
}

pub fn make_async_std_write_stream(
    error_opt: Option<std::io::Error>,
) -> (
    Box<dyn AsyncWrite + Send + Sync + Unpin>,
    AsyncByteArrayWriter,
) {
    let writer = AsyncByteArrayWriter::new(true, error_opt);
    (Box::new(writer.clone()), writer)
}

pub fn make_async_std_streams(
    read_inputs: Vec<Vec<u8>>,
) -> (AsyncStdStreams, AsyncTestStreamHandles) {
    make_async_std_streams_with_error_setup(read_inputs, None, None)
}

pub fn make_async_std_streams_with_error_setup(
    stdin: Vec<Vec<u8>>,
    stdout_write_err_opt: Option<std::io::Error>,
    stderr_write_err_opt: Option<std::io::Error>,
) -> (AsyncStdStreams, AsyncTestStreamHandles) {
    let reader = AsyncByteArrayReader::new(Either::Left(stdin));
    let stdin_counter = StdinReadCounter::from(&reader);
    let (stdout, stdout_clone) = make_async_std_write_stream(stdout_write_err_opt);
    let (stderr, stderr_clone) = make_async_std_write_stream(stderr_write_err_opt);
    let std_streams = AsyncStdStreams {
        stdin: Box::new(reader),
        stdout,
        stderr,
    };
    let test_stream_handles = AsyncTestStreamHandles {
        stdin_counter,
        stdout: Either::Left(stdout_clone),
        stderr: Either::Left(stderr_clone),
    };
    (std_streams, test_stream_handles)
}

#[derive(Default)]
pub struct AsyncStdStreamsFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<AsyncStdStreams>>,
}

impl AsyncStdStreamsFactory for AsyncStdStreamsFactoryMock {
    fn make(&self) -> AsyncStdStreams {
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl AsyncStdStreamsFactoryMock {
    pub fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.make_params = params.clone();
        self
    }
    pub fn make_result(self, result: AsyncStdStreams) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct TerminalInterfaceFactoryMock {
    make_params: Arc<Mutex<Vec<bool>>>,
    make_results: RefCell<Vec<Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>>>,
}

impl TerminalInterfaceFactory for TerminalInterfaceFactoryMock {
    fn make(
        &self,
        is_interactive: bool,
        _streams_factory: &dyn AsyncStdStreamsFactory,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>> {
        self.make_params.lock().unwrap().push(is_interactive);
        self.make_results.borrow_mut().remove(0)
    }
}

impl TerminalInterfaceFactoryMock {
    pub fn make_params(mut self, params: &Arc<Mutex<Vec<bool>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(
        self,
        result: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
    ) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}
