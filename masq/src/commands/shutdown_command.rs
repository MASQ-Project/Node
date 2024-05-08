// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_context::CommandContext;
use crate::commands::commands_common::CommandError::{
    ConnectionProblem, Other, Payload, Transmission,
};
use crate::commands::commands_common::{transaction, Command, CommandError};
use clap::Command as ClapCommand;
use masq_lib::constants::NODE_NOT_RUNNING_ERROR;
use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
use masq_lib::short_writeln;
use masq_lib::utils::localhost;
use std::fmt::Debug;
use std::net::{SocketAddr, TcpStream};
use std::ops::Add;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL: u64 = 250; // milliseconds
const DEFAULT_SHUTDOWN_ATTEMPT_LIMIT: u64 = 4;
const SHUTDOWN_COMMAND_TIMEOUT_MILLIS: u64 = 60000;

#[derive(Debug)]
pub struct ShutdownCommand {
    shutdown_awaiter: Box<dyn ShutdownAwaiter>,
    attempt_interval: u64,
    attempt_limit: u64,
}

const SHUTDOWN_SUBCOMMAND_ABOUT: &str =
    "Shuts down the running MASQNode. Only valid if Node is already running.";

pub fn shutdown_subcommand() -> ClapCommand {
    ClapCommand::new("shutdown").about(SHUTDOWN_SUBCOMMAND_ABOUT)
}

impl Command for ShutdownCommand {
    fn execute(&self, context: &mut dyn CommandContext) -> Result<(), CommandError> {
        let input = UiShutdownRequest {};
        let output: Result<UiShutdownResponse, CommandError> =
            transaction(input, context, SHUTDOWN_COMMAND_TIMEOUT_MILLIS);
        match output {
            Ok(_) => (),
            Err(ConnectionProblem(_)) => {
                short_writeln!(
                    context.stdout(),
                    "MASQNode was instructed to shut down and has broken its connection"
                );
                return Ok(());
            }
            Err(Transmission(_)) => {
                short_writeln!(
                    context.stdout(),
                    "MASQNode was instructed to shut down and has broken its connection"
                );
                return Ok(());
            }
            Err(Payload(code, message)) if code == NODE_NOT_RUNNING_ERROR => {
                short_writeln!(
                    context.stderr(),
                    "MASQNode is not running; therefore it cannot be shut down"
                );
                return Err(Payload(code, message));
            }

            Err(unknown_error) => {
                panic!("Unexpected error: please report to us: {}", unknown_error)
            }
        }
        match context.active_port() {
            None => {
                short_writeln!(
                    context.stdout(),
                    "MASQNode was instructed to shut down and has stopped answering; but the Daemon seems to be down as well"
                );
                Ok(())
            }
            Some(active_port) => {
                if self.shutdown_awaiter.wait(
                    active_port,
                    self.attempt_interval,
                    self.attempt_limit,
                ) {
                    short_writeln!(
                        context.stdout(),
                        "MASQNode was instructed to shut down and has stopped answering"
                    );
                    Ok(())
                } else {
                    short_writeln!(
                        context.stderr(),
                        "MASQNode ignored the instruction to shut down and is still running"
                    );
                    Err(Other("Shutdown failed".to_string()))
                }
            }
        }
    }
}

impl Default for ShutdownCommand {
    fn default() -> Self {
        Self {
            shutdown_awaiter: Box::new(ShutdownAwaiterReal {}),
            attempt_interval: DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL,
            attempt_limit: DEFAULT_SHUTDOWN_ATTEMPT_LIMIT,
        }
    }
}

impl ShutdownCommand {
    pub fn new() -> Self {
        Self::default()
    }
}

trait ShutdownAwaiter: Debug {
    fn wait(&self, active_port: u16, interval_ms: u64, timeout_ms: u64) -> bool;
}

#[derive(Debug)]
struct ShutdownAwaiterReal {}

impl ShutdownAwaiter for ShutdownAwaiterReal {
    fn wait(&self, active_port: u16, interval_ms: u64, timeout_ms: u64) -> bool {
        let interval = Duration::from_millis(interval_ms);
        let timeout_at = Instant::now().add(Duration::from_millis(timeout_ms));
        let address = SocketAddr::new(localhost(), active_port);
        while Instant::now() < timeout_at {
            match TcpStream::connect_timeout(&address, interval) {
                Ok(_) => (),
                Err(_) => return true,
            }
            thread::sleep(interval);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::ContextError;
    use crate::command_factory::{CommandFactory, CommandFactoryReal};
    use crate::test_utils::mocks::CommandContextMock;
    use crossbeam_channel::unbounded;
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::{UiShutdownRequest, UiShutdownResponse};
    use masq_lib::utils::find_free_port;
    use std::cell::RefCell;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL, 250);
        assert_eq!(DEFAULT_SHUTDOWN_ATTEMPT_LIMIT, 4);
        assert_eq!(SHUTDOWN_COMMAND_TIMEOUT_MILLIS, 60000);
        assert_eq!(
            SHUTDOWN_SUBCOMMAND_ABOUT,
            "Shuts down the running MASQNode. Only valid if Node is already running."
        );
    }

    #[derive(Debug)]
    struct ShutdownAwaiterMock {
        wait_params: Arc<Mutex<Vec<(u16, u64, u64)>>>,
        wait_results: RefCell<Vec<bool>>,
    }

    impl ShutdownAwaiter for ShutdownAwaiterMock {
        fn wait(&self, active_port: u16, interval_ms: u64, timeout_ms: u64) -> bool {
            self.wait_params
                .lock()
                .unwrap()
                .push((active_port, interval_ms, timeout_ms));
            self.wait_results.borrow_mut().remove(0)
        }
    }

    impl ShutdownAwaiterMock {
        pub fn new() -> Self {
            Self {
                wait_params: Arc::new(Mutex::new(vec![])),
                wait_results: RefCell::new(vec![]),
            }
        }

        pub fn wait_params(mut self, params: &Arc<Mutex<Vec<(u16, u64, u64)>>>) -> Self {
            self.wait_params = params.clone();
            self
        }

        pub fn wait_result(self, result: bool) -> Self {
            self.wait_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn shutdown_command_defaults_parameters() {
        let subject = ShutdownCommand::new();

        assert_eq!(subject.attempt_interval, DEFAULT_SHUTDOWN_ATTEMPT_INTERVAL);
        assert_eq!(subject.attempt_limit, DEFAULT_SHUTDOWN_ATTEMPT_LIMIT);
    }

    #[test]
    fn testing_command_factory_here() {
        let factory = CommandFactoryReal::new();
        let mut context = CommandContextMock::new()
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));
        let subject = factory.make(&["shutdown".to_string()]).unwrap();

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn shutdown_command_doesnt_work_if_node_is_not_running() {
        let mut context = CommandContextMock::new().transact_result(Err(
            ContextError::PayloadError(NODE_NOT_RUNNING_ERROR, "irrelevant".to_string()),
        ));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let subject = ShutdownCommand::new();

        let result = subject.execute(&mut context);

        assert_eq!(
            result,
            Err(CommandError::Payload(
                NODE_NOT_RUNNING_ERROR,
                "irrelevant".to_string()
            ))
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode is not running; therefore it cannot be shut down\n"
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
    }

    #[test]
    fn shutdown_command_happy_path_immediate_receive() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ContextError::ConnectionDropped("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let wait_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_awaiter = ShutdownAwaiterMock::new().wait_params(&wait_params_arc);
        let mut subject = ShutdownCommand::new();
        subject.shutdown_awaiter = Box::new(shutdown_awaiter);
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiShutdownRequest {}.tmb(0), SHUTDOWN_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode was instructed to shut down and has broken its connection\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(wait_params_arc.lock().unwrap().is_empty(), true);
    }

    #[test]
    fn shutdown_command_happy_path_immediate_transmit() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(ContextError::Other("booga".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let wait_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_awaiter = ShutdownAwaiterMock::new().wait_params(&wait_params_arc);
        let mut subject = ShutdownCommand::new();
        subject.shutdown_awaiter = Box::new(shutdown_awaiter);
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiShutdownRequest {}.tmb(0), SHUTDOWN_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode was instructed to shut down and has broken its connection\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(wait_params_arc.lock().unwrap().is_empty(), true);
    }

    #[test]
    fn shutdown_command_happy_path_delayed() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let msg = UiShutdownResponse {}.tmb(0);
        let port = find_free_port();
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(msg.clone()))
            .active_port_result(Some(port));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let wait_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_awaiter = ShutdownAwaiterMock::new()
            .wait_params(&wait_params_arc)
            .wait_result(true);
        let mut subject = ShutdownCommand::new();
        subject.shutdown_awaiter = Box::new(shutdown_awaiter);
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiShutdownRequest {}.tmb(0), SHUTDOWN_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode was instructed to shut down and has stopped answering\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let wait_params = wait_params_arc.lock().unwrap();
        assert_eq!(*wait_params, vec![(port, 10, 3)])
    }

    #[test]
    fn shutdown_command_happy_path_daemon_crash() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let msg = UiShutdownResponse {}.tmb(0);
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(msg.clone()))
            .active_port_result(None);
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let wait_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_awaiter = ShutdownAwaiterMock::new()
            .wait_params(&wait_params_arc)
            .wait_result(true);
        let mut subject = ShutdownCommand::new();
        subject.shutdown_awaiter = Box::new(shutdown_awaiter);
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Ok(()));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiShutdownRequest {}.tmb(0), SHUTDOWN_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MASQNode was instructed to shut down and has stopped answering; but the Daemon seems to be down as well\n"
        );
        assert_eq!(stderr_arc.lock().unwrap().get_string(), String::new());
        let wait_params = wait_params_arc.lock().unwrap();
        assert_eq!(*wait_params, vec![]);
    }

    #[test]
    fn shutdown_command_sad_path() {
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let msg = UiShutdownResponse {}.tmb(0);
        let port = find_free_port();
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Ok(msg.clone()))
            .active_port_result(Some(port));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();
        let wait_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_awaiter = ShutdownAwaiterMock::new()
            .wait_params(&wait_params_arc)
            .wait_result(false);
        let mut subject = ShutdownCommand::new();
        subject.shutdown_awaiter = Box::new(shutdown_awaiter);
        subject.attempt_interval = 10;
        subject.attempt_limit = 3;

        let result = subject.execute(&mut context);

        assert_eq!(result, Err(Other("Shutdown failed".to_string())));
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![(UiShutdownRequest {}.tmb(0), SHUTDOWN_COMMAND_TIMEOUT_MILLIS)]
        );
        assert_eq!(stdout_arc.lock().unwrap().get_string(), String::new());
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MASQNode ignored the instruction to shut down and is still running\n"
        );
        let wait_params = wait_params_arc.lock().unwrap();
        assert_eq!(*wait_params, vec![(port, 10, 3)])
    }

    #[test]
    fn shutdown_awaiter_sad_path() {
        let port = find_free_port();
        let server = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();
        server.set_nonblocking(true).unwrap();
        let (term_tx, term_rx) = unbounded();
        let handle = thread::spawn(move || {
            while term_rx.try_recv().is_err() {
                let _ = server.accept();
                thread::sleep(Duration::from_millis(10));
            }
        });
        let subject = ShutdownAwaiterReal {};

        let result = subject.wait(port, 50, 150);

        term_tx.send(()).unwrap();
        handle.join().unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn shutdown_awaiter_happy_path() {
        let port = find_free_port();
        let server = TcpListener::bind(SocketAddr::new(localhost(), port)).unwrap();
        let handle = thread::spawn(move || {
            let now = Instant::now();
            let limit = Duration::from_millis(100);
            while Instant::now().duration_since(now) < limit {
                let _ = server.accept();
            }
        });
        let subject = ShutdownAwaiterReal {};

        let result = subject.wait(port, 25, 1000);

        handle.join().unwrap();
        assert_eq!(result, true);
    }
}
