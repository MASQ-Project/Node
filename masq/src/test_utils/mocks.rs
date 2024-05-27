// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, ContextError};
use crate::command_context_factory::CommandContextFactory;
use crate::command_factory::{CommandFactory, CommandFactoryError};
use crate::command_processor::{
    CommandExecutionHelper, CommandExecutionHelperFactory, CommandProcessor,
    CommandProcessorFactory,
};
use crate::commands::commands_common::CommandError::Transmission;
use crate::commands::commands_common::{Command, CommandError};
use crate::communications::broadcast_handlers::{
    BroadcastHandle, BroadcastHandler, RedirectBroadcastHandleFactory,
    StandardBroadcastHandlerFactory,
};
use crate::communications::connection_manager::{ConnectionManagerBootstrapper, RedirectOrder};
use crate::non_interactive_clap::{InitialArgsParser, InitializationArgs};
use crate::terminal::async_streams::{AsyncStdStreams, AsyncStdStreamsFactory};
use crate::terminal::line_reader::TerminalEvent;
use crate::terminal::secondary_infrastructure::{InterfaceWrapper, MasqTerminal, WriterLock};
use crate::terminal::terminal_interface::{
    FlushHandle, RWTermInterface, ReadInput, ReadResult, TerminalWriter, WTermInterface,
};
use crate::terminal::terminal_interface_factory::TerminalInterfaceFactory;
use async_trait::async_trait;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender, TryRecvError};
use itertools::Either;
use masq_lib::command::StdStreams;
use masq_lib::constants::DEFAULT_UI_PORT;
use masq_lib::shared_schema::VecU64;
use masq_lib::test_utils::fake_stream_holder::{
    AsyncByteArrayReader, AsyncByteArrayWriter, ByteArrayWriter, ByteArrayWriterInner,
};
use masq_lib::ui_gateway::MessageBody;
use std::cell::RefCell;
use std::fmt::Arguments;
use std::future::Future;
use std::io::{stdout, Read, Write};
use std::ops::Not;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{io, thread};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Default)]
pub struct CommandFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: Arc<Mutex<Vec<Result<Box<dyn Command>, CommandFactoryError>>>>,
}

impl CommandFactory for CommandFactoryMock {
    fn make(&self, pieces: &[String]) -> Result<Box<dyn Command>, CommandFactoryError> {
        self.make_params.lock().unwrap().push(pieces.to_vec());
        self.make_results.lock().unwrap().remove(0)
    }
}

impl CommandFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn Command>, CommandFactoryError>) -> Self {
        self.make_results.lock().unwrap().push(result);
        self
    }
}

pub struct CommandContextMock {
    active_port_results: RefCell<Vec<Option<u16>>>,
    send_one_way_params: Arc<Mutex<Vec<MessageBody>>>,
    send_one_way_results: RefCell<Vec<Result<(), ContextError>>>,
    transact_params: Arc<Mutex<Vec<(MessageBody, u64)>>>,
    transact_results: RefCell<Vec<Result<MessageBody, ContextError>>>,
    // stdout: Box<dyn Write>,
    // stdout_arc: Arc<Mutex<ByteArrayWriterInner>>,
    // stderr: Box<dyn Write>,
    // stderr_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl CommandContext for CommandContextMock {
    fn active_port(&self) -> Option<u16> {
        self.active_port_results.borrow_mut().remove(0)
    }

    fn send_one_way(&self, message: MessageBody) -> Result<(), ContextError> {
        self.send_one_way_params.lock().unwrap().push(message);
        self.send_one_way_results.borrow_mut().remove(0)
    }

    fn transact(
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
        unimplemented!()
    }
}

impl Default for CommandContextMock {
    fn default() -> Self {
        let stdout = ByteArrayWriter::new(false);
        let stdout_arc = stdout.inner_arc();
        let stderr = ByteArrayWriter::new(false);
        let stderr_arc = stderr.inner_arc();
        Self {
            active_port_results: RefCell::new(vec![]),
            send_one_way_params: Arc::new(Mutex::new(vec![])),
            send_one_way_results: RefCell::new(vec![]),
            transact_params: Arc::new(Mutex::new(vec![])),
            transact_results: RefCell::new(vec![]),
            // stdout: Box::new(stdout),
            // stdout_arc,
            // stderr: Box::new(stderr),
            // stderr_arc,
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
        todo!()
    }

    // pub fn stdout_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
    //     self.stdout_arc.clone()
    // }
    //
    // pub fn stderr_arc(&self) -> Arc<Mutex<ByteArrayWriterInner>> {
    //     self.stderr_arc.clone()
    // }
}

#[derive(Default)]
pub struct CommandProcessorMock {
    process_params: Arc<Mutex<Vec<Box<dyn Command>>>>,
    process_results: RefCell<Vec<Result<(), CommandError>>>,
    close_params: Arc<Mutex<Vec<()>>>,
}

#[async_trait]
impl CommandProcessor for CommandProcessorMock {
    async fn process(
        &mut self,
        initial_subcommand_opt: Option<&[String]>,
    ) -> Result<(), CommandError> {
        todo!()
        // self.process_params.lock().unwrap().push(command);
        // self.process_results.borrow_mut().remove(0)
    }

    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn close(&mut self) {
        self.close_params.lock().unwrap().push(());
    }
}

impl CommandProcessorMock {
    pub fn new() -> Self {
        Self::default()
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
pub struct CommandContextFactoryMock {
    make_params: Arc<Mutex<Vec<(u16, Option<Box<dyn WTermInterface>>)>>>,
    make_results: Arc<Mutex<Vec<Result<Box<dyn CommandContext>, CommandError>>>>,
}

#[async_trait]
impl CommandContextFactory for CommandContextFactoryMock {
    async fn make(
        &self,
        ui_port: u16,
        term_interface_opt: Option<Box<dyn WTermInterface>>,
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
        params: &Arc<Mutex<Vec<(u16, Option<Box<dyn WTermInterface>>)>>>,
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
        todo!()
    }
}

impl CommandExecutionHelperFactoryMock {
    pub fn make_result(self, result: Box<dyn CommandExecutionHelper>) -> Self {
        todo!()
    }
}

#[derive(Default)]
pub struct CommandExecutionHelperMock {
    execute_command_results: RefCell<Vec<Result<(), CommandError>>>,
}

impl CommandExecutionHelper for CommandExecutionHelperMock {
    fn execute_command(
        &self,
        command: Box<dyn Command>,
        context: &dyn CommandContext,
        term_interface: &dyn WTermInterface,
    ) -> Result<(), CommandError> {
        todo!()
    }
}

impl CommandExecutionHelperMock {
    pub fn execute_command_params(mut self, params: &Arc<Mutex<Vec<Box<dyn Command>>>>) -> Self {
        todo!()
    }

    pub fn execute_command_result(self, result: Result<(), CommandError>) -> Self {
        todo!()
    }
}

#[derive(Default)]
pub struct InitialArgsParserMock;

impl InitialArgsParser for InitialArgsParserMock {
    fn parse_initialization_args(
        &self,
        _args: &[String],
        std_streams: &AsyncStdStreams,
    ) -> InitializationArgs {
        InitializationArgs::new(DEFAULT_UI_PORT)
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
        match context.transact(self.message.clone(), 1000) {
            Ok(_) => self.execute_results.lock().unwrap().remove(0),
            Err(e) => Err(Transmission(format!("{:?}", e))),
        }
    }
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
    // I have an opinion that the standard Mutex is okay as long as we don't use it to keep multiple
    // references to the product. We don't, we just create it once. It is important tokio::sync::Mutex
    // would require the trait of the factory use an async method which makes everything much more
    // complicated
    // Eh, shouldn't it be implemented with a vector and not an option?
    stdout_arc_opt: Arc<Mutex<Option<TestWrite>>>,
    stderr_arc_opt: Arc<Mutex<Option<TestWrite>>>,
}

impl AsyncStdStreamsFactory for TestStreamFactory {
    fn make(&self) -> AsyncStdStreams {
        todo!()
        // let stdout = self.stdout_arc_opt.lock().unwrap().take().unwrap();
        // let stderr = self.stderr_arc_opt.lock().unwrap().take().unwrap();
        // (Box::new(stdout), Box::new(stderr))
    }
}

impl TestStreamFactory {
    pub fn new() -> (TestStreamFactory, TestStreamFactoryHandle) {
        let (stdout_tx, stdout_rx) = unbounded();
        let (stderr_tx, stderr_rx) = unbounded();
        let stdout = TestWrite::new(stdout_tx);
        let stderr = TestWrite::new(stderr_tx);
        let factory = TestStreamFactory {
            stdout_arc_opt: Arc::new(Mutex::new(Some(stdout))),
            stderr_arc_opt: Arc::new(Mutex::new(Some(stderr))),
        };
        let handle = TestStreamFactoryHandle {
            stdout_rx,
            stderr_rx,
        };
        (factory, handle)
    }

    pub fn clone_stdout_writer(&self) -> Sender<String> {
        self.stdout_arc_opt
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .write_tx
            .clone()
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
//
// //light-weight mock ("passive" = without functions of the linefeed interface and without functional locking
// //thus unusable for sync tests
//
// #[derive(Clone)]
// pub struct TerminalPassiveMock {
//     read_line_results: Arc<Mutex<Vec<TerminalEvent>>>,
// }
//
// impl MasqTerminal for TerminalPassiveMock {
//     fn read_line(&self) -> TerminalEvent {
//         self.read_line_results.lock().unwrap().remove(0)
//     }
//     fn lock(&self) -> Box<dyn WriterLock + '_> {
//         Box::new(WriterInactive {})
//     }
//     fn lock_without_prompt(&self, _streams: &mut StdStreams, _stderr: bool) -> Box<dyn WriterLock> {
//         Box::new(WriterInactive {})
//     }
// }
//
// impl TerminalPassiveMock {
//     pub fn new() -> Self {
//         Self {
//             read_line_results: Arc::new(Mutex::new(vec![])),
//         }
//     }
//     pub fn read_line_result(self, result: TerminalEvent) -> Self {
//         self.read_line_results.lock().unwrap().push(result);
//         self
//     }
// }
//
// //mock incorporating with in-memory using functional locking corresponding to how it works in the production code;
//
// pub struct TerminalActiveMock {
//     in_memory_terminal: Interface<MemoryTerminal>,
//     read_line_results: Arc<Mutex<Vec<TerminalEvent>>>,
// }
//
// impl MasqTerminal for TerminalActiveMock {
//     fn read_line(&self) -> TerminalEvent {
//         self.read_line_results.lock().unwrap().remove(0)
//     }
//     fn lock(&self) -> Box<dyn WriterLock + '_> {
//         Box::new(self.in_memory_terminal.lock_writer_append().unwrap())
//     }
//
//     fn lock_without_prompt(
//         &self,
//         _streams: &mut StdStreams,
//         _stderr: bool,
//     ) -> Box<dyn WriterLock + '_> {
//         Box::new(self.in_memory_terminal.lock_writer_append().unwrap())
//     }
// }
//
// impl TerminalActiveMock {
//     pub fn new() -> Self {
//         Self {
//             in_memory_terminal: Interface::with_term(
//                 "test only terminal",
//                 MemoryTerminal::new().clone(),
//             )
//             .unwrap(),
//             read_line_results: Arc::new(Mutex::new(vec![])),
//         }
//     }
//
//     //seems like dead code according to the search tool but the responsibility for properly tested code is taken by TerminalPassiveMock
//     pub fn read_line_result(self, event: TerminalEvent) -> Self {
//         self.read_line_results.lock().unwrap().push(event);
//         self
//     }
// }
//
// #[derive(Clone)]
// pub struct WriterInactive {}
//
// impl WriterLock for WriterInactive {
//     #[cfg(test)]
//     fn improvised_struct_id(&self) -> String {
//         "WriterInactive".to_string()
//     }
// }
//
// #[derive(Default)]
// pub struct InterfaceRawMock {
//     //this mock seems crippled, but the seeming overuse of Arc<Mutex<>> stems from InterfaceRawMock requires Sync
//     read_line_results: Arc<Mutex<Vec<std::io::Result<ReadResult>>>>,
//     add_history_unique_params: Arc<Mutex<Vec<String>>>,
//     set_prompt_params: Arc<Mutex<Vec<String>>>,
//     set_prompt_results: Arc<Mutex<Vec<std::io::Result<()>>>>,
//     set_report_signal_params: Arc<Mutex<Vec<(Signal, bool)>>>,
//     get_buffer_results: Arc<Mutex<Vec<String>>>,
//     set_buffer_params: Arc<Mutex<Vec<String>>>,
//     set_buffer_results: Arc<Mutex<Vec<std::io::Result<()>>>>,
//     lock_writer_append_results: Arc<Mutex<Vec<std::io::Result<Box<WriterInactive>>>>>, //for testing the outer result not the structure when ok
// }
//
// impl InterfaceWrapper for InterfaceRawMock {
//     fn read_line(&self) -> std::io::Result<ReadResult> {
//         self.read_line_results.lock().unwrap().remove(0)
//     }
//     fn add_history(&self, line: String) {
//         self.add_history_unique_params.lock().unwrap().push(line)
//     }
//     fn lock_writer_append(&self) -> std::io::Result<Box<dyn WriterLock + 'static>> {
//         //I tried to avoid this inconvenient mock but WriterLock cannot implement Send;
//         //even though I discovered a path to throw away my own MutexGuard used in
//         //my IntegrationTestWriter then I was warned that the crucial implementer linefeed::Writer
//         //has one within as well.
//         let taken_result = self.lock_writer_append_results.lock().unwrap().remove(0);
//         if let Err(err) = taken_result {
//             Err(err)
//         } else {
//             Ok(taken_result.unwrap() as Box<dyn WriterLock + 'static>)
//         }
//     }
//
//     fn get_buffer(&self) -> String {
//         self.get_buffer_results.lock().unwrap().remove(0)
//     }
//
//     fn set_buffer(&self, text: &str) -> io::Result<()> {
//         self.set_buffer_params
//             .lock()
//             .unwrap()
//             .push(text.to_string());
//         self.set_buffer_results.lock().unwrap().remove(0)
//     }
//
//     fn set_prompt(&self, prompt: &str) -> std::io::Result<()> {
//         self.set_prompt_params
//             .lock()
//             .unwrap()
//             .push(prompt.to_string());
//         self.set_prompt_results.lock().unwrap().remove(0)
//     }
//
//     fn set_report_signal(&self, signal: Signal, set: bool) {
//         self.set_report_signal_params
//             .lock()
//             .unwrap()
//             .push((signal, set))
//     }
// }
//
// impl InterfaceRawMock {
//     pub fn new() -> Self {
//         Self {
//             read_line_results: Arc::new(Mutex::new(vec![])),
//             add_history_unique_params: Arc::new(Mutex::new(vec![])),
//             set_prompt_params: Arc::new(Mutex::new(vec![])),
//             set_prompt_results: Arc::new(Mutex::new(vec![])),
//             set_report_signal_params: Arc::new(Mutex::new(vec![])),
//             get_buffer_results: Arc::new(Mutex::new(vec![])),
//             set_buffer_params: Arc::new(Mutex::new(vec![])),
//             set_buffer_results: Arc::new(Mutex::new(vec![])),
//             lock_writer_append_results: Arc::new(Mutex::new(vec![])),
//         }
//     }
//     pub fn read_line_result(self, result: std::io::Result<ReadResult>) -> Self {
//         self.read_line_results.lock().unwrap().push(result);
//         self
//     }
//     pub fn add_history_unique_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
//         self.add_history_unique_params = params.clone();
//         self
//     }
//     pub fn set_prompt_result(self, result: std::io::Result<()>) -> Self {
//         self.set_prompt_results.lock().unwrap().push(result);
//         self
//     }
//     pub fn set_prompt_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
//         self.set_prompt_params = params.clone();
//         self
//     }
//     pub fn set_report_signal_params(mut self, params: &Arc<Mutex<Vec<(Signal, bool)>>>) -> Self {
//         self.set_report_signal_params = params.clone();
//         self
//     }
//     pub fn get_buffer_result(self, result: String) -> Self {
//         self.get_buffer_results.lock().unwrap().push(result);
//         self
//     }
//     pub fn set_buffer_params(mut self, params: &Arc<Mutex<Vec<String>>>) -> Self {
//         self.set_buffer_params = params.clone();
//         self
//     }
//
//     pub fn set_buffer_result(self, result: std::io::Result<()>) -> Self {
//         self.set_buffer_results.lock().unwrap().push(result);
//         self
//     }
//
//     pub fn lock_writer_append_result(self, result: std::io::Result<Box<WriterInactive>>) -> Self {
//         self.lock_writer_append_results.lock().unwrap().push(result);
//         self
//     }
// }

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
    make_params: Arc<Mutex<Vec<Option<Box<dyn WTermInterface>>>>>,
    make_results: Arc<Mutex<Vec<Box<dyn BroadcastHandler<MessageBody>>>>>,
}

impl StandardBroadcastHandlerFactory for StandardBroadcastHandlerFactoryMock {
    fn make(
        &self,
        terminal_interface_opt: Option<Box<dyn WTermInterface>>,
    ) -> Box<dyn BroadcastHandler<MessageBody>> {
        self.make_params
            .lock()
            .unwrap()
            .push(terminal_interface_opt);
        self.make_results.lock().unwrap().remove(0)
    }
}

impl StandardBroadcastHandlerFactoryMock {
    pub fn make_result(self, result: Box<dyn BroadcastHandler<MessageBody>>) -> Self {
        self.make_results.lock().unwrap().push(result);
        self
    }
}

#[derive(Default)]
pub struct RedirectBroadcastHandleFactoryMock {
    make_params: Arc<Mutex<Vec<UnboundedSender<RedirectOrder>>>>,
    make_results: Arc<Mutex<Vec<Box<dyn BroadcastHandle<RedirectOrder>>>>>,
}

impl RedirectBroadcastHandleFactory for RedirectBroadcastHandleFactoryMock {
    fn make(
        &self,
        redirect_order_tx: UnboundedSender<RedirectOrder>,
    ) -> Box<dyn BroadcastHandle<RedirectOrder>> {
        self.make_results.lock().unwrap().remove(0)
    }
}

impl RedirectBroadcastHandleFactoryMock {
    pub fn make_result(self, result: Box<dyn BroadcastHandle<RedirectOrder>>) -> Self {
        self.make_results.lock().unwrap().push(result);
        self
    }
}

// #[derive(Default)]
// pub struct WTermInterfaceMock {}
//
// impl WTermInterface for WTermInterfaceMock {
//     fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
//         todo!()
//     }
//
//     fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
//         todo!()
//     }
//
//     fn dup(&self) -> Box<dyn WTermInterface> {
//         todo!()
//     }
// }
//
// impl WTermInterfaceMock {
//     pub fn stdout_arc(&self) -> &Arc<Mutex<ByteArrayWriter>> {
//         todo!()
//     }
//
//     pub fn stderr_arc(&self) -> &Arc<Mutex<ByteArrayWriter>> {
//         todo!()
//     }
// }
//

pub fn make_terminal_writer() -> (TerminalWriter, Arc<Mutex<ByteArrayWriter>>) {
    todo!()
}

pub struct TermInterfaceMock {
    stdin_opt: Option<StdinMock>,
    stdout: Arc<tokio::sync::Mutex<Vec<String>>>, // Box<dyn AsyncWrite + Send + Sync + Unpin>,
    stderr: Arc<tokio::sync::Mutex<Vec<String>>>, //Box<dyn AsyncWrite + Send + Sync + Unpin>,
}

#[derive(Default)]
pub struct StdinMockBuilder {
    results: Vec<Result<ReadInput, ReadResult>>,
}

impl StdinMockBuilder {
    pub fn read_line_result(mut self, result: Result<ReadInput, ReadResult>) -> Self {
        todo!()
    }

    pub fn build(self) -> StdinMock {
        todo!()
    }
}

pub struct StdinMock {
    reader: Arc<tokio::sync::Mutex<AsyncByteArrayReader>>,
    // None means a normal result will come out, Some means this prepared error will be taken
    situated_errors_opt:
        Arc<tokio::sync::Mutex<Vec<Option<crate::terminal::terminal_interface::ReadResult>>>>,
}

impl AsyncRead for StdinMock {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        todo!()
    }
}

impl StdinMock {
    pub fn new(reader: AsyncByteArrayReader, situated_errors_opt: Option<Vec<ReadResult>>) -> Self {
        todo!()
    }
}

#[async_trait]
impl RWTermInterface for TermInterfaceMock {
    async fn read_line(
        &self,
    ) -> Result<ReadInput, crate::terminal::terminal_interface::ReadResult> {
        todo!()
    }

    fn write_only_ref(&mut self) -> &dyn WTermInterface {
        todo!()
    }

    fn write_only_clone_opt(&mut self) -> Option<Box<dyn WTermInterface>> {
        todo!()
    }
}

impl WTermInterface for TermInterfaceMock {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    // TODO will I really need this?
    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}

pub fn make_async_std_write_stream() -> (Box<dyn AsyncWrite + Send + Unpin>, AsyncByteArrayWriter) {
    let writer = AsyncByteArrayWriter::default();
    (Box::new(writer.clone()), writer)
}

pub async fn make_async_std_streams(
    read_inputs: Vec<Vec<u8>>,
) -> (AsyncStdStreams, AsyncTestStreamHandles) {
    make_async_std_streams_with_diff_setup_for_stdin(Either::Left(read_inputs)).await
}

async fn make_async_std_streams_with_diff_setup_for_stdin(
    stdin_either: Either<Vec<Vec<u8>>, StdinMock>,
) -> (AsyncStdStreams, AsyncTestStreamHandles) {
    let mut stdin = match stdin_either {
        Either::Left(read_inputs) => StdinMock::new(AsyncByteArrayReader::new(read_inputs), None),
        Either::Right(ready_stdin) => ready_stdin,
    };
    let stdin_clone = stdin.reader.lock().await.clone();
    let (stdout, stdout_clone) = make_async_std_write_stream();
    let (stderr, stderr_clone) = make_async_std_write_stream();
    let std_streams = AsyncStdStreams {
        stdin: Box::new(stdin),
        stdout,
        stderr,
    };
    let test_stream_handles = AsyncTestStreamHandles {
        stdin_opt: Some(stdin_clone),
        stdout: Either::Left(stdout_clone),
        stderr: Either::Left(stderr_clone),
    };
    (std_streams, test_stream_handles)
}

impl TermInterfaceMock {
    pub async fn new(stdin_opt: Option<StdinMock>) -> (Self, AsyncTestStreamHandles) {
        // let read_inputs = read_inputs_opt.is_some();
        // let stdin_setup = match read_inputs_opt{
        //     Some() => todo!(),
        //     None => todo!()
        // };
        // let (mut streams, mut stream_handles) =
        //     make_async_std_streams_with_diff_setup_for_stdin();
        // let (stdin_opt, stream_handles) = if read_inputs {
        //     (Some(streams.stdin), stream_handles)
        // } else {
        //     stream_handles.stdin_opt = None;
        //     (None, stream_handles)
        // };
        let stdin_handle_opt = match stdin_opt.as_ref() {
            Some(stdin) => Some(stdin.reader.lock().await.clone()),
            None => None,
        };
        // let (stdout, stdout_clone) = make_async_std_write_stream();
        // let (stderr, stderr_clone) = make_async_std_write_stream();
        let stdout = Arc::new(tokio::sync::Mutex::new(vec![]));
        let stderr = Arc::new(tokio::sync::Mutex::new(vec![]));
        let mock = TermInterfaceMock {
            stdin_opt,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        };
        let stream_handles = AsyncTestStreamHandles {
            stdin_opt: stdin_handle_opt,
            stdout: Either::Right(stdout),
            stderr: Either::Right(stderr),
        };
        (mock, stream_handles)
    }
}

pub struct AsyncTestStreamHandles {
    pub stdin_opt: Option<AsyncByteArrayReader>,
    pub stdout: Either<AsyncByteArrayWriter, Arc<tokio::sync::Mutex<Vec<String>>>>,

    pub stderr: Either<AsyncByteArrayWriter, Arc<tokio::sync::Mutex<Vec<String>>>>,
}

impl AsyncTestStreamHandles {
    // Recommended to call only once (and keep the result) as repeated calls may be unnecessarily
    // expensive
    pub async fn stdout_flushed_strings(&self) -> Vec<String> {
        Self::drain_flushed_strings(&self.stdout).await
    }

    // Recommended to call only once (and keep the result) as repeated calls may be unnecessarily
    // expensive
    pub async fn stderr_flushed_strings(&self) -> Vec<String> {
        Self::drain_flushed_strings(&self.stderr).await
    }

    pub async fn stdout_all_in_one(&self) -> String {
        Self::join_flushed(self.stdout_flushed_strings()).await
    }

    pub async fn stderr_all_in_one(&self) -> String {
        Self::join_flushed(self.stderr_flushed_strings()).await
    }

    pub async fn assert_empty_stdout(&self) {
        Self::assert_empty_stream(&self.stdout, "stdout").await
    }

    pub async fn assert_empty_stderr(&self) {
        Self::assert_empty_stream(&self.stderr, "stderr").await
    }

    async fn join_flushed(strings_future: impl Future<Output = Vec<String>>) -> String {
        strings_future.await.into_iter().collect::<String>()
    }

    async fn assert_empty_stream(
        handle: &Either<AsyncByteArrayWriter, Arc<tokio::sync::Mutex<Vec<String>>>>,
        stream_name: &str,
    ) {
        let received = AsyncTestStreamHandles::drain_flushed_strings(handle).await;
        assert!(
            received.is_empty(),
            "We thought this {} stream was empty, but it contained {:?}",
            stream_name,
            received
        )
    }

    async fn drain_flushed_strings(
        handle: &Either<AsyncByteArrayWriter, Arc<tokio::sync::Mutex<Vec<String>>>>,
    ) -> Vec<String> {
        match handle {
            Either::Left(async_byte_array) => {
                async_byte_array.drain_flushed_strings().await.unwrap()
            }
            Either::Right(naked_string_containers) => {
                naked_string_containers.lock().await.drain(..).collect()
            }
        }
    }
}

#[derive(Default)]
pub struct AsyncStdStreamFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<AsyncStdStreams>>,
}

impl AsyncStdStreamsFactory for AsyncStdStreamFactoryMock {
    fn make(&self) -> AsyncStdStreams {
        todo!()
    }
}

impl AsyncStdStreamFactoryMock {
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
    make_params: Arc<Mutex<Vec<(bool, AsyncStdStreams)>>>,
    make_result: Arc<Mutex<Vec<Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>>>>,
}

impl TerminalInterfaceFactory for TerminalInterfaceFactoryMock {
    fn make(
        &self,
        is_interactive: bool,
        streams: AsyncStdStreams,
    ) -> Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>> {
        todo!()
    }
}

impl TerminalInterfaceFactoryMock {
    pub fn make_params(mut self, params: &Arc<Mutex<Vec<(bool, AsyncStdStreams)>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(
        self,
        result: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
    ) -> Self {
        self.make_result.lock().unwrap().push(result);
        self
    }
}
