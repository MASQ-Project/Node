// Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_cli_lib::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use masq_cli_lib::command_factory::{CommandFactory, CommandFactoryReal};
use masq_cli_lib::command_processor::{
    CommandProcessor, CommandProcessorFactory, CommandProcessorFactoryReal,
};
use masq_lib::command;
use masq_lib::command::{Command, StdStreams};
use std::io;
use std::io::{BufRead, BufReader};

fn main() {
    let mut streams: StdStreams<'_> = StdStreams {
        stdin: &mut io::stdin(),
        stdout: &mut io::stdout(),
        stderr: &mut io::stderr(),
    };

    let args: Vec<String> = std::env::args().collect();
    let streams_ref: &mut StdStreams<'_> = &mut streams;
    let exit_code = Main::new().go(streams_ref, &args);
    ::std::process::exit(i32::from(exit_code));
}

struct Main {
    command_factory: Box<dyn CommandFactory>,
    processor_factory: Box<dyn CommandProcessorFactory>,
}

impl command::Command for Main {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> u8 {
        let mut processor = match self.processor_factory.make(args) {
            Ok(processor) => processor,
            Err(e) => {
                writeln!(streams.stderr, "Can't connect to Daemon or Node ({:?}). Probably this means the Daemon isn't running.", e).expect ("writeln! failed");
                return 1;
            }
        };
        let result = match Self::extract_subcommand(args) {
            Some(command_parts) => {
                match self.handle_command(&mut *processor, command_parts, streams.stderr) {
                    Ok(_) => 0,
                    Err(_) => 1,
                }
            }
            None => self.go_interactive(&mut *processor, streams),
        };
        processor.close();
        result
    }
}

impl Main {
    pub fn new() -> Self {
        Self {
            command_factory: Box::new(CommandFactoryReal::new()),
            processor_factory: Box::new(CommandProcessorFactoryReal {}),
        }
    }

    fn extract_subcommand(args: &[String]) -> Option<Vec<String>> {
        let args_vec: Vec<String> = args.to_vec();
        for idx in 1..args_vec.len() {
            let one = &args_vec[idx - 1];
            let two = &args_vec[idx];
            if !one.starts_with("--") && !two.starts_with("--") {
                return Some(args_vec.into_iter().skip(idx).collect());
            }
        }
        None
    }

    fn accept_subcommand(stdin: &mut dyn BufRead) -> Result<Option<Vec<String>>, std::io::Error> {
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(
                line.split(char::is_whitespace)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect(),
            )),
            Err(e) => Err(e),
        }
    }

    fn go_interactive(
        &self,
        processor: &mut dyn CommandProcessor,
        streams: &mut StdStreams<'_>,
    ) -> u8 {
        let mut reader = BufReader::new(&mut streams.stdin);
        loop {
            write!(streams.stdout, "masq> ").expect("write! failed");
            streams.stdout.flush().expect("flush failed");
            let args = match Self::accept_subcommand(&mut reader) {
                Ok(Some(args)) => args,
                Ok(None) => break,
                Err(e) => {
                    writeln!(streams.stderr, "{:?}", e.kind()).expect("writeln! failed");
                    return 1;
                }
            };
            if args.is_empty() {
                continue;
            }
            if args[0] == "exit" {
                break;
            }
            match self.handle_command(processor, args, streams.stderr) {
                Ok(_) => (),
                Err(_) => continue,
            }
        }
        0
    }

    fn handle_command(
        &self,
        processor: &mut dyn CommandProcessor,
        command_parts: Vec<String>,
        stderr: &mut dyn io::Write,
    ) -> Result<(), ()> {
        let command = match self.command_factory.make(command_parts) {
            Ok(c) => c,
            Err(UnrecognizedSubcommand(msg)) => {
                writeln!(stderr, "Unrecognized command: '{}'", msg).expect("writeln! failed");
                return Err(());
            }
            Err(CommandSyntax(msg)) => {
                writeln!(stderr, "{}", msg).expect("writeln! failed");
                return Err(());
            }
        };
        if let Err(e) = processor.process(command) {
            writeln!(stderr, "{:?}", e).expect("writeln! failed");
            Err(())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_cli_lib::command_context::CommandContext;
    use masq_cli_lib::command_context::ContextError::Other;
    use masq_cli_lib::command_factory::CommandFactoryError;
    use masq_cli_lib::commands::commands_common;
    use masq_cli_lib::commands::commands_common::CommandError;
    use masq_cli_lib::commands::commands_common::CommandError::Transmission;
    use masq_cli_lib::test_utils::mocks::{
        CommandContextMock, CommandFactoryMock, CommandProcessorFactoryMock, CommandProcessorMock,
        MockCommand,
    };
    use masq_lib::messages::ToMessageBody;
    use masq_lib::messages::UiShutdownRequest;
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, FakeStreamHolder};
    use masq_lib::ui_gateway::NodeFromUiMessage;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};

    #[test]
    fn noninteractive_mode_works_when_everything_is_copacetic() {
        let command = MockCommand::new(UiShutdownRequest {});
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&c_make_params_arc)
            .make_result(Ok(Box::new(command)));
        let process_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .process_params(&process_params_arc)
            .process_result(Ok(()));
        let p_make_params_arc = Arc::new(Mutex::new(vec![]));
        let processor_factory = CommandProcessorFactoryMock::new()
            .make_params(&p_make_params_arc)
            .make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };

        let result = subject.go(
            &mut FakeStreamHolder::new().streams(),
            &[
                "command".to_string(),
                "--param1".to_string(),
                "value1".to_string(),
                "--param2".to_string(),
                "value2".to_string(),
                "subcommand".to_string(),
                "--param3".to_string(),
                "value3".to_string(),
                "param4".to_string(),
                "param5".to_string(),
            ],
        );

        assert_eq!(result, 0);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(
            *c_make_params,
            vec![vec![
                "subcommand".to_string(),
                "--param3".to_string(),
                "value3".to_string(),
                "param4".to_string(),
                "param5".to_string()
            ],]
        );
        let p_make_params = p_make_params_arc.lock().unwrap();
        assert_eq!(
            *p_make_params,
            vec![vec![
                "command".to_string(),
                "--param1".to_string(),
                "value1".to_string(),
                "--param2".to_string(),
                "value2".to_string(),
                "subcommand".to_string(),
                "--param3".to_string(),
                "value3".to_string(),
                "param4".to_string(),
                "param5".to_string(),
            ]]
        );
        let mut process_params = process_params_arc.lock().unwrap();
        let command = process_params.remove(0);
        let transact_params_arc = Arc::new(Mutex::new(vec![]));
        let mut context = CommandContextMock::new()
            .transact_params(&transact_params_arc)
            .transact_result(Err(Other("not really an error".to_string())));
        let stdout_arc = context.stdout_arc();
        let stderr_arc = context.stderr_arc();

        let result = command.execute(&mut context);

        assert_eq!(
            result,
            Err(Transmission("Other(\"not really an error\")".to_string()))
        );
        let transact_params = transact_params_arc.lock().unwrap();
        assert_eq!(
            *transact_params,
            vec![NodeFromUiMessage {
                client_id: 0,
                body: UiShutdownRequest {}.tmb(0),
            }]
        );
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MockCommand output".to_string()
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MockCommand error".to_string()
        );
    }

    #[derive(Debug)]
    struct FakeCommand {
        output: String,
    }

    impl commands_common::Command for FakeCommand {
        fn execute(&self, _context: &mut dyn CommandContext) -> Result<(), CommandError> {
            unimplemented!()
        }
    }

    impl FakeCommand {
        pub fn new(output: &str) -> Self {
            Self {
                output: output.to_string(),
            }
        }
    }

    #[test]
    fn interactive_mode_works_when_everything_is_copacetic() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
            .make_result(Ok(Box::new(FakeCommand::new("start command"))));
        let processor = CommandProcessorMock::new()
            .process_result(Ok(()))
            .process_result(Ok(()));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder.stdin = ByteArrayReader::new(b"setup\nstart\nexit\n");

        let result = subject.go(
            &mut stream_holder.streams(),
            &[
                "command".to_string(),
                "--param1".to_string(),
                "value1".to_string(),
            ],
        );

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["setup".to_string()], vec!["start".to_string()]]
        );
    }

    #[test]
    fn interactive_mode_works_for_stdin_read_error() {
        let command_factory = CommandFactoryMock::new();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new().close_params(&close_params_arc);
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder
            .stdin
            .reject_next_read(std::io::Error::from(ErrorKind::ConnectionRefused));

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 1);
        assert_eq!(
            stream_holder.stderr.get_string(),
            "ConnectionRefused\n".to_string()
        );
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(close_params.len(), 1);
    }

    #[test]
    fn interactive_mode_works_for_eof_on_stdin() {
        let command_factory = CommandFactoryMock::new();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new().close_params(&close_params_arc);
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder.stdin = ByteArrayReader::new(b"");

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(close_params.len(), 1);
    }

    #[test]
    fn interactive_mode_works_for_blank_command() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))));
        let processor = CommandProcessorMock::new().process_result(Ok(()));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder.stdin = ByteArrayReader::new(b"\nsetup\nexit\n");

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(*make_params, vec![vec!["setup".to_string()]]);
    }

    #[test]
    fn interactive_mode_works_for_unrecognized_command() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::UnrecognizedSubcommand(
                "Booga!".to_string(),
            )));
        let processor = CommandProcessorMock::new();
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder.stdin = ByteArrayReader::new(b"error command\nexit\n");

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Unrecognized command: 'Booga!'\n".to_string()
        );
    }

    #[test]
    fn interactive_mode_works_for_command_with_bad_syntax() {
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Err(CommandFactoryError::CommandSyntax(
                "Booga!".to_string(),
            )));
        let processor = CommandProcessorMock::new();
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();
        stream_holder.stdin = ByteArrayReader::new(b"error command\nexit\n");

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["error".to_string(), "command".to_string()]]
        );
        assert_eq!(stream_holder.stderr.get_string(), "Booga!\n".to_string());
    }

    #[test]
    fn go_works_when_command_is_unrecognized() {
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&c_make_params_arc)
            .make_result(Err(UnrecognizedSubcommand("booga".to_string())));
        let processor = CommandProcessorMock::new();
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &["command".to_string(), "subcommand".to_string()],
        );

        assert_eq!(result, 1);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
        assert_eq!(stream_holder.stdout.get_string(), "".to_string());
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Unrecognized command: 'booga'\n".to_string()
        );
    }

    #[test]
    fn go_works_when_command_has_bad_syntax() {
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&c_make_params_arc)
            .make_result(Err(CommandSyntax("booga".to_string())));
        let processor = CommandProcessorMock::new();
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &["command".to_string(), "subcommand".to_string()],
        );

        assert_eq!(result, 1);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
        assert_eq!(stream_holder.stdout.get_string(), "".to_string());
        assert_eq!(stream_holder.stderr.get_string(), "booga\n".to_string());
    }

    #[test]
    fn go_works_when_command_execution_fails() {
        let command = MockCommand::new(UiShutdownRequest {}).execute_result(Ok(())); // irrelevant
        let command_factory = CommandFactoryMock::new().make_result(Ok(Box::new(command)));
        let process_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .process_params(&process_params_arc)
            .process_result(Err(Transmission("Booga!".to_string())));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &["command".to_string(), "subcommand".to_string()],
        );

        assert_eq!(result, 1);
        assert_eq!(stream_holder.stdout.get_string(), "".to_string());
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Transmission(\"Booga!\")\n".to_string()
        );
    }

    #[test]
    fn go_works_when_daemon_is_not_running() {
        let processor_factory = CommandProcessorFactoryMock::new()
            .make_result(Err(CommandError::ConnectionRefused("booga".to_string())));
        let mut subject = Main {
            command_factory: Box::new(CommandFactoryMock::new()),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &["command".to_string(), "subcommand".to_string()],
        );

        assert_eq!(result, 1);
        assert_eq!(stream_holder.stdout.get_string(), "".to_string());
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Can't connect to Daemon or Node (ConnectionRefused(\"booga\")). Probably this means the Daemon isn't running.\n".to_string()
        );
    }
}
