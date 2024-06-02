// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, ContextError};
use crate::command_factory::{CommandFactory, CommandFactoryError};
use crate::command_processor::{CommandProcessor, CommandProcessorFactory};
use crate::commands::commands_common::CommandError::Transmission;
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handlers::{
    BroadcastHandle, BroadcastHandler, RedirectBroadcastHandleFactory,
    StandardBroadcastHandlerFactory, StreamFactory,
};
use crate::communications::connection_manager::{ConnectionManagerBootstrapper, RedirectOrder};
use crate::non_interactive_clap::{
    InitializationArgs, NonInteractiveClap, NonInteractiveClapFactory,
};
use crate::terminal::line_reader::TerminalEvent;
use crate::terminal::secondary_infrastructure::{InterfaceWrapper, MasqTerminal, WriterLock};
use crate::terminal::terminal_interface::TerminalWrapper;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TryRecvError};
use linefeed::memory::MemoryTerminal;
use linefeed::{Interface, ReadResult, Signal};
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_UI_PORT;
use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, ByteArrayWriterInner};
use masq_lib::ui_gateway::MessageBody;
use std::cell::RefCell;
use std::fmt::Arguments;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{io, thread};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedSender;

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
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

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
    send_params: Arc<Mutex<Vec<MessageBody>>>,
    send_results: RefCell<Vec<Result<(), ContextError>>>,
    transact_params: Arc<Mutex<Vec<(MessageBody, u64)>>>,
    transact_results: RefCell<Vec<Result<MessageBody, ContextError>>>,
    stdout: Box<dyn Write>,
    stdout_arc: Arc<Mutex<ByteArrayWriterInner>>,
    stderr: Box<dyn Write>,
    stderr_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl CommandContext for CommandContextMock {
    fn active_port(&self) -> Option<u16> {
        self.active_port_results.borrow_mut().remove(0)
    }

    fn send(&mut self, message: MessageBody) -> Result<(), ContextError> {
        self.send_params.lock().unwrap().push(message);
        self.send_results.borrow_mut().remove(0)
    }

    fn transact(
        &mut self,
        message: MessageBody,
        timeout_millis: u64,
    ) -> Result<MessageBody, ContextError> {
        self.transact_params
            .lock()
            .unwrap()
            .push((message, timeout_millis));
        self.transact_results.borrow_mut().remove(0)
    }

    fn stdin(&mut self) -> &mut dyn Read {
        unimplemented!()
    }

    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn close(&mut self) {
        unimplemented!()
    }
}

impl Default for CommandContextMock {
    fn default() -> Self {
        let stdout = ByteArrayWriter::new();
        let stdout_arc = stdout.inner_arc();
        let stderr = ByteArrayWriter::new();
        let stderr_arc = stderr.inner_arc();
        Self {
            active_port_results: RefCell::new(vec![]),
            send_params: Arc::new(Mutex::new(vec![])),
            send_results: RefCell::new(vec![]),
            transact_params: Arc::new(Mutex::new(vec![])),
            transact_results: RefCell::new(vec![]),
            stdout: Box::new(stdout),
            stdout_arc,
            stderr: Box::new(stderr),
            stderr_arc,
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

    pub fn send_params(mut self, params: &Arc<Mutex<Vec<MessageBody>>>) -> Self {
        self.send_params = params.clone();
        self
    }

    pub fn send_result(self, result: Result<(), ContextError>) -> Self {
        self.send_results.borrow_mut().push(result);
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

    pub fn stdout_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.stdout_arc.clone()
    }

    pub fn stderr_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
        self.stderr_arc.clone()
    }
}

#[derive(Default)]
pub struct CommandProcessorMock {
    process_params: Arc<Mutex<Vec<Box<dyn Command>>>>,
    process_results: RefCell<Vec<Result<(), CommandError>>>,
    close_params: Arc<Mutex<Vec<()>>>,
    terminal_interface: Option<TerminalWrapper>,
}

impl CommandProcessor for CommandProcessorMock {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        self.process_params.lock().unwrap().push(command);
        self.process_results.borrow_mut().remove(0)
    }

    fn close(&mut self) {
        self.close_params.lock().unwrap().push(());
    }

    fn terminal_wrapper_ref(&self) -> &TerminalWrapper {
        self.terminal_interface.as_ref().unwrap()
    }
}

impl CommandProcessorMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inject_terminal_interface(
        mut self,
        terminal_interface_arc_clone: TerminalWrapper,
    ) -> Self {
        self.terminal_interface = Some(terminal_interface_arc_clone);
        self
    }

    pub fn process_params(mut self, params: &Arc<Mutex<Vec<Box<dyn Command>>>>) -> Self {
        self.process_params = params.clone();
        self
    }

    pub fn process_result(self, result: Result<(), CommandError>) -> Self {
        self.process_results.borrow_mut().push(result);
        self
    }

    pub fn close_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.close_params = params.clone();
        self
    }
}

#[derive(Default)]
pub struct CommandProcessorFactoryMock {
    make_params: Arc<Mutex<Vec<(Option<TerminalWrapper>, u16)>>>,
    make_results: RefCell<Vec<Result<Box<dyn CommandProcessor>, CommandError>>>,
}

impl CommandProcessorFactory for CommandProcessorFactoryMock {
    fn make(
        &self,
        _runtime_ref: &Runtime,
        terminal_interface_opt: Option<TerminalWrapper>,
        ui_port: u16,
    ) -> Result<Box<dyn CommandProcessor>, CommandError> {
        self.make_params
            .lock()
            .unwrap()
            .push((terminal_interface_opt, ui_port));
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandProcessorFactoryMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<(Option<TerminalWrapper>, u16)>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn CommandProcessor>, CommandError>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

pub struct NIClapFactoryMock;

impl NonInteractiveClapFactory for NIClapFactoryMock {
    fn make(&self) -> Box<dyn NonInteractiveClap> {
        Box::new(NonInteractiveClapMock {})
    }
}

pub struct NonInteractiveClapMock;

impl NonInteractiveClap for NonInteractiveClapMock {
    fn parse_initialization_args(&self, _args: &[String]) -> InitializationArgs {
        InitializationArgs::new(DEFAULT_UI_PORT)
    }
}

pub struct MockCommand {
    message: MessageBody,
    execute_results: RefCell<Vec<Result<(), CommandError>>>,
}

impl std::fmt::Debug for MockCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "MockCommand")
    }
}

impl Command for MockCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        write!(context.stdout(), "MockCommand output").unwrap();
        write!(context.stderr(), "MockCommand error").unwrap();
        match context.transact(self.message.clone(), 1000) {
            Ok(_) => self.execute_results.borrow_mut().remove(0),
            Err(e) => Err(Transmission(format!("{:?}", e))),
        }
    }
}

impl MockCommand {
    pub fn new(message: MessageBody) -> Self {
        Self {
            message,
            execute_results: RefCell::new(vec![]),
        }
    }

    pub fn execute_result(self, result: Result<(), CommandError>) -> Self {
        self.execute_results.borrow_mut().push(result);
        self
    }
}

#[derive(Clone, Debug)]
pub struct TestWrite {
    write_tx: Sender<String>,
}

impl Write for TestWrite {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let len = buf.len();
        let string = String::from_utf8(buf.to_vec()).unwrap();
        self.write_tx.send(string).unwrap();
        Ok(len)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl TestWrite {
    pub fn new(write_tx: Sender<String>) -> Self {
        Self { write_tx }
    }
}

#[derive(Clone, Debug)]
pub struct TestStreamFactory {
    stdout_opt: RefCell<Option<TestWrite>>,
    stderr_opt: RefCell<Option<TestWrite>>,
}

impl StreamFactory for TestStreamFactory {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        let stdout = self.stdout_opt.borrow_mut().take().unwrap();
        let stderr = self.stderr_opt.borrow_mut().take().unwrap();
        (Box::new(stdout), Box::new(stderr))
    }
}

impl TestStreamFactory {
    pub fn new() -> (TestStreamFactory, TestStreamFactoryHandle) {
        let (stdout_tx, stdout_rx) = unbounded();
        let (stderr_tx, stderr_rx) = unbounded();
        let stdout = TestWrite::new(stdout_tx);
        let stderr = TestWrite::new(stderr_tx);
        let factory = TestStreamFactory {
            stdout_opt: RefCell::new(Some(stdout)),
            stderr_opt: RefCell::new(Some(stderr)),
        };
        let handle = TestStreamFactoryHandle {
            stdout_rx,
            stderr_rx,
        };
        (factory, handle)
    }

    pub fn clone_stdout_writer(&self) -> Sender<String> {
        self.stdout_opt.borrow().as_ref().unwrap().write_tx.clone()
    }
}

#[derive(Clone, Debug)]
pub struct TestStreamFactoryHandle {
    stdout_rx: Receiver<String>,
    stderr_rx: Receiver<String>,
}

impl TestStreamFactoryHandle {
    pub fn stdout_so_far(&self) -> String {
        Self::text_so_far(&self.stdout_rx)
    }

    pub fn stderr_so_far(&self) -> String {
        Self::text_so_far(&self.stderr_rx)
    }

    fn text_so_far(rx: &Receiver<String>) -> String {
        let mut accum = String::new();
        let mut retries_left = 5;
        loop {
            match rx.try_recv() {
                Ok(s) => {
                    accum.push_str(&s);
                    retries_left = 5;
                }
                Err(TryRecvError::Empty) => {
                    retries_left -= 1;
                    if retries_left <= 0 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
        accum
    }
}

impl StreamFactory for TestStreamsWithThreadLifeCheckerFactory {
    fn make(&self) -> (Box<dyn Write>, Box<dyn Write>) {
        //TODO could I refactor this out, using just one test factory??

        // let (stdout, stderr) = self.stream_factory.make();
        // let stream_with_checker = TestStreamWithThreadLifeChecker {
        //     stream: stdout,
        //     threads_connector: self.threads_connector.borrow_mut().take().unwrap(),
        // };
        // (Box::new(stream_with_checker), stderr)
        todo!()
    }
}

// TODO review this and other uts with comments
// This set is invented just for a single special test; checking that the background thread doesn't outlive the foreground thread
#[derive(Debug)]
pub struct TestStreamsWithThreadLifeCheckerFactory {
    stream_factory: TestStreamFactory,
    threads_connector: RefCell<Option<Sender<()>>>,
}

struct TestStreamWithThreadLifeChecker {
    stream: Box<dyn Write>,
    threads_connector: Sender<()>,
}

impl Write for TestStreamWithThreadLifeChecker {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Drop for TestStreamWithThreadLifeChecker {
    fn drop(&mut self) {
        self.threads_connector.send(()).unwrap();
    }
}

pub fn make_tools_for_test_streams_with_thread_life_checker() -> (
    Receiver<()>,
    TestStreamsWithThreadLifeCheckerFactory,
    TestStreamFactoryHandle,
) {
    let (stream_factory, stream_handle) = TestStreamFactory::new();
    let (tx, life_checker_receiver) = bounded(1);
    (
        life_checker_receiver,
        TestStreamsWithThreadLifeCheckerFactory {
            stream_factory,
            threads_connector: RefCell::new(Some(tx)),
        },
        stream_handle,
    )
}

// This is used in tests aimed at synchronization
#[derive(Clone)]
pub struct StdoutBlender {
    channel_half: Sender<String>,
}

impl StdoutBlender {
    pub fn new(sender: Sender<String>) -> Self {
        StdoutBlender {
            channel_half: sender,
        }
    }
}

impl Write for StdoutBlender {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let chunk = std::str::from_utf8(buf).unwrap().to_string();
        let length = chunk.len();
        self.channel_half.send(chunk).unwrap();
        Ok(length)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn write_fmt(&mut self, fmt: Arguments<'_>) -> std::io::Result<()> {
        self.channel_half.send(fmt.to_string()).unwrap();
        Ok(())
    }
}

//light-weight mock ("passive" = without functions of the linefeed interface and without functional locking
//thus unusable for sync tests

#[derive(Clone)]
pub struct TerminalPassiveMock {
    read_line_results: Arc<Mutex<Vec<TerminalEvent>>>,
}

impl MasqTerminal for TerminalPassiveMock {
    fn read_line(&self) -> TerminalEvent {
        self.read_line_results.lock().unwrap().remove(0)
    }
    fn lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(WriterInactive {})
    }
    fn lock_without_prompt(&self, _streams: &mut StdStreams, _stderr: bool) -> Box<dyn WriterLock> {
        Box::new(WriterInactive {})
    }
}

impl TerminalPassiveMock {
    pub fn new() -> Self {
        Self {
            read_line_results: Arc::new(Mutex::new(vec![])),
        }
    }
    pub fn read_line_result(self, result: TerminalEvent) -> Self {
        self.read_line_results.lock().unwrap().push(result);
        self
    }
}

//mock incorporating with in-memory using functional locking corresponding to how it works in the production code;

pub struct TerminalActiveMock {
    in_memory_terminal: Interface<MemoryTerminal>,
    read_line_results: Arc<Mutex<Vec<TerminalEvent>>>,
}

impl MasqTerminal for TerminalActiveMock {
    fn read_line(&self) -> TerminalEvent {
        self.read_line_results.lock().unwrap().remove(0)
    }
    fn lock(&self) -> Box<dyn WriterLock + '_> {
        Box::new(self.in_memory_terminal.lock_writer_append().unwrap())
    }

    fn lock_without_prompt(
        &self,
        _streams: &mut StdStreams,
        _stderr: bool,
    ) -> Box<dyn WriterLock + '_> {
        Box::new(self.in_memory_terminal.lock_writer_append().unwrap())
    }
}

impl TerminalActiveMock {
    pub fn new() -> Self {
        Self {
            in_memory_terminal: Interface::with_term(
                "test only terminal",
                MemoryTerminal::new().clone(),
            )
            .unwrap(),
            read_line_results: Arc::new(Mutex::new(vec![])),
        }
    }

    //seems like dead code according to the search tool but the responsibility for properly tested code is taken by TerminalPassiveMock
    pub fn read_line_result(self, event: TerminalEvent) -> Self {
        self.read_line_results.lock().unwrap().push(event);
        self
    }
}

#[derive(Clone)]
pub struct WriterInactive {}

impl WriterLock for WriterInactive {
    #[cfg(test)]
    fn improvised_struct_id(&self) -> String {
        "WriterInactive".to_string()
    }
}

#[derive(Default)]
pub struct InterfaceRawMock {
    //this mock seems crippled, but the seeming overuse of Arc<Mutex<>> stems from InterfaceRawMock requires Sync
    read_line_results: Arc<Mutex<Vec<std::io::Result<ReadResult>>>>,
    add_history_unique_params: Arc<Mutex<Vec<String>>>,
    set_prompt_params: Arc<Mutex<Vec<String>>>,
    set_prompt_results: Arc<Mutex<Vec<std::io::Result<()>>>>,
    set_report_signal_params: Arc<Mutex<Vec<(Signal, bool)>>>,
    get_buffer_results: Arc<Mutex<Vec<String>>>,
    set_buffer_params: Arc<Mutex<Vec<String>>>,
    set_buffer_results: Arc<Mutex<Vec<std::io::Result<()>>>>,
    lock_writer_append_results: Arc<Mutex<Vec<std::io::Result<Box<WriterInactive>>>>>, //for testing the outer result not the structure when ok
}

impl InterfaceWrapper for InterfaceRawMock {
    fn read_line(&self) -> std::io::Result<ReadResult> {
        self.read_line_results.lock().unwrap().remove(0)
    }
    fn add_history(&self, line: String) {
        self.add_history_unique_params.lock().unwrap().push(line)
    }
    fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + 'static>> {
        //I tried to avoid this inconvenient mock but WriterLock cannot implement Send;
        //even though I discovered a path to throw away my own MutexGuard used in
        //my IntegrationTestWriter then I was warned that the crucial implementer linefeed::Writer
        //has one within as well.
        let taken_result = self.lock_writer_append_results.lock().unwrap().remove(0);
        if let Err(err) = taken_result {
            Err(err)
        } else {
            Ok(taken_result.unwrap() as Box<dyn WriterLock + 'static>)
        }
    }

    fn get_buffer(&self) -> String {
        self.get_buffer_results.lock().unwrap().remove(0)
    }

    fn set_buffer(&self, text: &str) -> io::Result<()> {
        self.set_buffer_params
            .lock()
            .unwrap()
            .push(text.to_string());
        self.set_buffer_results.lock().unwrap().remove(0)
    }

    fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
        self.set_prompt_params
            .lock()
            .unwrap()
            .push(prompt.to_string());
        self.set_prompt_results.lock().unwrap().remove(0)
    }

    fn set_report_signal(&self, signal: Signal, set: bool) {
        self.set_report_signal_params
            .lock()
            .unwrap()
            .push((signal, set))
    }
}

impl InterfaceRawMock {
    pub fn new() -> Self {
        Self {
            read_line_results: Arc::new(Mutex::new(vec![])),
            add_history_unique_params: Arc::new(Mutex::new(vec![])),
            set_prompt_params: Arc::new(Mutex::new(vec![])),
            set_prompt_results: Arc::new(Mutex::new(vec![])),
            set_report_signal_params: Arc::new(Mutex::new(vec![])),
            get_buffer_results: Arc::new(Mutex::new(vec![])),
            set_buffer_params: Arc::new(Mutex::new(vec![])),
            set_buffer_results: Arc::new(Mutex::new(vec![])),
            lock_writer_append_results: Arc::new(Mutex::new(vec![])),
        }
    }
    pub fn read_line_result(self, result: std::io::Result<ReadResult>) -> Self {
        self.read_line_results.lock().unwrap().push(result);
        self
    }
    pub fn add_history_unique_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.add_history_unique_params = params.clone();
        self
    }
    pub fn set_prompt_result(self, result: std::io::Result<()>) -> Self {
        self.set_prompt_results.lock().unwrap().push(result);
        self
    }
    pub fn set_prompt_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_prompt_params = params.clone();
        self
    }
    pub fn set_report_signal_params(mut self, params: &Arc<Mutex<Vec<(Signal, bool)>>>) -> Self {
        self.set_report_signal_params = params.clone();
        self
    }
    pub fn get_buffer_result(self, result: String) -> Self {
        self.get_buffer_results.lock().unwrap().push(result);
        self
    }
    pub fn set_buffer_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
        self.set_buffer_params = params.clone();
        self
    }

    pub fn set_buffer_result(self, result: std::io::Result<()>) -> Self {
        self.set_buffer_results.lock().unwrap().push(result);
        self
    }

    pub fn lock_writer_append_result(self, result: std::io::Result<Box<WriterInactive>>) -> Self {
        self.lock_writer_append_results.lock().unwrap().push(result);
        self
    }
}

#[derive(Default)]
pub struct StandardBroadcastHandlerMock {
    spawn_results: RefCell<Vec<Box<dyn BroadcastHandle<MessageBody>>>>,
}

impl BroadcastHandler<MessageBody> for StandardBroadcastHandlerMock {
    fn spawn(&mut self) -> Box<dyn BroadcastHandle<MessageBody>> {
        todo!("finish me");
        self.spawn_results.borrow_mut().remove(0)
    }
}

impl StandardBroadcastHandlerMock {
    pub fn spawn_result(self, result: Box<dyn BroadcastHandle<MessageBody>>) -> Self {
        self.spawn_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct StandardBroadcastHandlerFactoryMock {
    make_params: Arc<Mutex<Vec<Option<TerminalWrapper>>>>,
    make_results: RefCell<Vec<Box<dyn BroadcastHandler<MessageBody>>>>,
}

impl StandardBroadcastHandlerFactory for StandardBroadcastHandlerFactoryMock {
    fn make(
        &self,
        terminal_interface_opt: Option<TerminalWrapper>,
    ) -> Box<dyn BroadcastHandler<MessageBody>> {
        self.make_params
            .lock()
            .unwrap()
            .push(terminal_interface_opt);
        self.make_results.borrow_mut().remove(0)
    }
}

impl StandardBroadcastHandlerFactoryMock {
    pub fn make_result(self, result: Box<dyn BroadcastHandler<MessageBody>>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct RedirectBroadcastHandleFactoryMock {
    make_params: Arc<Mutex<Vec<UnboundedSender<RedirectOrder>>>>,
    make_results: RefCell<Vec<Box<dyn BroadcastHandle<RedirectOrder>>>>,
}

impl RedirectBroadcastHandleFactory for RedirectBroadcastHandleFactoryMock {
    fn make(
        &self,
        redirect_order_tx: UnboundedSender<RedirectOrder>,
    ) -> Box<dyn BroadcastHandle<RedirectOrder>> {
        self.make_results.borrow_mut().remove(0)
    }
}

impl RedirectBroadcastHandleFactoryMock {
    pub fn make_result(self, result: Box<dyn BroadcastHandle<RedirectOrder>>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}
