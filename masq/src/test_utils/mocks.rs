// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::{CommandContext, ContextError};
use crate::command_factory::{CommandFactory, CommandFactoryError};
use crate::command_processor::{CommandProcessor, CommandProcessorFactory};
use crate::commands::commands_common::CommandError::Transmission;
use crate::commands::commands_common::{Command, CommandError};
use masq_lib::test_utils::fake_stream_holder::{ByteArrayWriter, ByteArrayWriterInner};
use masq_lib::ui_gateway::MessageBody;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct CommandFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: RefCell<Vec<Result<Box<dyn Command>, CommandFactoryError>>>,
}

impl CommandFactory for CommandFactoryMock {
    fn make(&self, pieces: Vec<String>) -> Result<Box<dyn Command>, CommandFactoryError> {
        self.make_params.lock().unwrap().push(pieces);
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
    active_port_results: RefCell<Vec<u16>>,
    transact_params: Arc<Mutex<Vec<MessageBody>>>,
    transact_results: RefCell<Vec<Result<MessageBody, ContextError>>>,
    stdout: Box<dyn Write>,
    stdout_arc: Arc<Mutex<ByteArrayWriterInner>>,
    stderr: Box<dyn Write>,
    stderr_arc: Arc<Mutex<ByteArrayWriterInner>>,
}

impl CommandContext for CommandContextMock {
    fn active_port(&self) -> u16 {
        self.active_port_results.borrow_mut().remove(0)
    }

    fn transact(&mut self, message: MessageBody) -> Result<MessageBody, ContextError> {
        self.transact_params.lock().unwrap().push(message);
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

    pub fn active_port_result(self, result: u16) -> Self {
        self.active_port_results.borrow_mut().push(result);
        self
    }

    pub fn transact_params(mut self, params: &Arc<Mutex<Vec<MessageBody>>>) -> Self {
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
}

impl CommandProcessor for CommandProcessorMock {
    fn process(&mut self, command: Box<dyn Command>) -> Result<(), CommandError> {
        self.process_params.lock().unwrap().push(command);
        self.process_results.borrow_mut().remove(0)
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
pub struct CommandProcessorFactoryMock {
    make_params: Arc<Mutex<Vec<Vec<String>>>>,
    make_results: RefCell<Vec<Result<Box<dyn CommandProcessor>, CommandError>>>,
}

impl CommandProcessorFactory for CommandProcessorFactoryMock {
    fn make(&self, args: &[String]) -> Result<Box<dyn CommandProcessor>, CommandError> {
        self.make_params.lock().unwrap().push(args.to_vec());
        self.make_results.borrow_mut().remove(0)
    }
}

impl CommandProcessorFactoryMock {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<String>>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: Result<Box<dyn CommandProcessor>, CommandError>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
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
        match context.transact(self.message.clone()) {
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
