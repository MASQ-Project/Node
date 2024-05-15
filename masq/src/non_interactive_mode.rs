// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
use crate::command_factory::{CommandFactory, CommandFactoryReal};
use crate::command_processor::{
    CommandProcessor, CommandProcessorFactory, CommandProcessorFactoryReal,
};
use crate::communications::broadcast_handlers::{
    BroadcastHandle, BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
    StreamFactory, StreamFactoryReal,
};
use crate::communications::connection_manager::ConnectionManagerBootstrapper;
use crate::interactive_mode::go_interactive;
use crate::non_interactive_clap::{
    InitializationArgs, NonInteractiveClapFactory, NonInteractiveClapFactoryReal,
};
use crate::terminal::terminal_interface::TerminalWrapper;
use itertools::Either;
use masq_lib::command::{Command, StdStreams};
use masq_lib::short_writeln;
use masq_lib::ui_gateway::MessageBody;
use std::io::Write;
use std::ops::Not;
use tokio::runtime::Runtime;

pub struct Main {
    non_interactive_clap_factory: Box<dyn NonInteractiveClapFactory>,
    command_factory: Box<dyn CommandFactory>,
    processor_factory: Box<dyn CommandProcessorFactory>,
}

impl Default for Main {
    fn default() -> Self {
        Main::new()
    }
}

impl Command<u8> for Main {
    fn go(&mut self, streams: &mut StdStreams<'_>, args: &[String]) -> u8 {
        let initialization_args = self.parse_initialization_args(args);
        let subcommand_opt = Self::extract_subcommand(args);

        let terminal_interface = match Self::initialize_terminal_interface(subcommand_opt.is_none())
        {
            Ok(d) => d,
            Err(e) => {
                short_writeln!(streams.stderr, "Pre-configuration error: {}", e);
                return Self::bool_into_numeric_code(false);
            }
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build a Runtime");

        let mut command_processor =
            match self
                .processor_factory
                .make(&rt, terminal_interface, initialization_args.ui_port)
            {
                Ok(processor) => processor,
                Err(error) => {
                    short_writeln!(
                        streams.stderr,
                        "Can't connect to Daemon or Node ({:?}). Probably this means the Daemon \
                    isn't running.",
                        error
                    );
                    return Self::bool_into_numeric_code(false);
                }
            };

        let result = match subcommand_opt {
            Some(command_parts) => handle_command_common(
                &*self.command_factory,
                &mut *command_processor,
                &command_parts,
                streams.stderr,
            ),
            None => go_interactive(&*self.command_factory, &mut *command_processor, streams),
        };
        command_processor.close();
        Self::bool_into_numeric_code(result)
    }
}

impl Main {
    pub fn new() -> Self {
        Self {
            non_interactive_clap_factory: Box::new(NonInteractiveClapFactoryReal),
            command_factory: Box::new(CommandFactoryReal),
            processor_factory: Box::new(CommandProcessorFactoryReal::new(
                ConnectionManagerBootstrapper::default(),
            )),
        }
    }

    fn parse_initialization_args(&self, args: &[String]) -> InitializationArgs {
        self.non_interactive_clap_factory
            .make()
            .parse_initialization_args(args)
    }

    fn initialize_terminal_interface(
        is_interactive: bool,
    ) -> Result<Option<TerminalWrapper>, String> {
        if is_interactive {
            TerminalWrapper::configure_interface().map(|interface| Some(interface))
        } else {
            Ok(None)
        }
    }

    fn extract_subcommand(args: &[String]) -> Option<Vec<String>> {
        fn both_do_not_start_with_two_dashes(
            one_program_arg: &&String,
            program_arg_next_to_the_previous: &&String,
        ) -> bool {
            [one_program_arg, program_arg_next_to_the_previous]
                .iter()
                .any(|arg| arg.starts_with("--"))
                .not()
        }

        let original_args = args.iter();
        let one_item_shifted_forth = args.iter().skip(1);
        original_args
            .zip(one_item_shifted_forth)
            .enumerate()
            .find(|(_index, (left, right))| both_do_not_start_with_two_dashes(left, right))
            .map(|(index, _)| args.iter().skip(index + 1).cloned().collect())
    }

    fn bool_into_numeric_code(bool_flag: bool) -> u8 {
        if bool_flag {
            0
        } else {
            1
        }
    }
}
//
// pub struct CommandContextDependencies {
//     pub standard_broadcast_handle: Box<dyn BroadcastHandle<MessageBody>>,
//     pub terminal_wrapper_opt: Option<TerminalWrapper>,
// }
//
// impl CommandContextDependencies {
//     fn new(is_interactive: bool, rt_ref: &Runtime) -> Result<Self, String> {
//         let (standard_broadcast_handle, terminal_wrapper_opt) = if is_interactive {
//             Self::populate_interactive_dependencies(StreamFactoryReal, rt_ref)?
//         } else {
//             Self::populate_non_interactive_dependencies()
//         };
//
//         Ok(Self {
//             standard_broadcast_handle,
//             terminal_wrapper_opt,
//         })
//     }
//
//     fn populate_non_interactive_dependencies() -> (Box<dyn BroadcastHandle>, Option<TerminalWrapper>)
//     {
//         (Box::new(BroadcastHandleInactive), None)
//     }
//
//     fn populate_interactive_dependencies(
//         stream_factory: impl StreamFactory + 'static,
//         rt_ref: &Runtime,
//     ) -> Result<(Box<dyn BroadcastHandle>, Option<TerminalWrapper>), String> {
//         let foreground_terminal_interface = ;
//         let background_terminal_interface = foreground_terminal_interface.clone();
//
//         let standard_broadcast_handler =
//             BroadcastHandlerReal::new(Some(background_terminal_interface));
//         let standard_broadcast_handle = standard_broadcast_handler.spawn(Box::new(stream_factory));
//
//         Ok((
//             standard_broadcast_handle,
//             Some(foreground_terminal_interface),
//         ))
//     }
//
//     #[cfg(test)]
//     pub fn new_in_test(
//         standard_broadcast_handle: Box<dyn BroadcastHandle>,
//         terminal_wrapper_opt: Option<TerminalWrapper>,
//     ) -> Self {
//         Self {
//             standard_broadcast_handle,
//             terminal_wrapper_opt,
//         }
//     }
// }

pub fn handle_command_common(
    command_factory: &dyn CommandFactory,
    processor: &mut dyn CommandProcessor,
    command_parts: &[String],
    stderr: &mut dyn Write,
) -> bool {
    let command = match command_factory.make(command_parts) {
        Ok(c) => c,
        Err(UnrecognizedSubcommand(msg)) => {
            short_writeln!(stderr, "Unrecognized command: '{}'", msg);
            return false;
        }
        Err(CommandSyntax(msg)) => {
            short_writeln!(stderr, "{}", msg);
            return false;
        }
    };
    if let Err(e) = processor.process(command) {
        short_writeln!(stderr, "{}", e);
        false
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_context::CommandContext;
    use crate::command_context::ContextError::Other;
    use crate::commands::commands_common;
    use crate::commands::commands_common::CommandError;
    use crate::commands::commands_common::CommandError::Transmission;
    use crate::commands::setup_command::SetupCommand;
    use crate::terminal::line_reader::TerminalEvent;
    use crate::test_utils::mocks::{
        CommandContextMock, CommandFactoryMock, CommandProcessorFactoryMock, CommandProcessorMock,
        MockCommand, NIClapFactoryMock, TerminalPassiveMock, TestStreamFactory,
    };
    use masq_lib::intentionally_blank;
    use masq_lib::messages::{ToMessageBody, UiNewPasswordBroadcast, UiShutdownRequest};
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::any::Any;
    use std::sync::{Arc, Mutex};

    #[cfg(target_os = "windows")]
    mod win_test_import {
        pub use std::thread;
        pub use std::time::Duration;
    }

    #[test]
    fn noninteractive_mode_works_when_everything_is_copacetic() {
        let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
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
            non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };

        let result = subject.go(
            &mut FakeStreamHolder::new().streams(),
            &[
                "command",
                "subcommand",
                "--param1",
                "value1",
                "--param2",
                "--param3",
            ]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>(),
        );

        assert_eq!(result, 0);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(
            *c_make_params,
            vec![
                vec!["subcommand", "--param1", "value1", "--param2", "--param3"]
                    .iter()
                    .map(|str| str.to_string())
                    .collect::<Vec<String>>(),
            ]
        );
        let mut p_make_params = p_make_params_arc.lock().unwrap();
        let (terminal_wrapper_opt, ui_port) = p_make_params.pop().unwrap();
        assert_eq!(ui_port, 5333);
        assert!(terminal_wrapper_opt.is_none());
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
        assert_eq!(*transact_params, vec![(UiShutdownRequest {}.tmb(1), 1000)]);
        assert_eq!(
            stdout_arc.lock().unwrap().get_string(),
            "MockCommand output".to_string()
        );
        assert_eq!(
            stderr_arc.lock().unwrap().get_string(),
            "MockCommand error".to_string()
        );
    }

    #[test]
    fn go_works_when_command_is_unrecognized() {
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&c_make_params_arc)
            .make_result(Err(UnrecognizedSubcommand("booga".to_string())));
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new().close_params(&close_params_arc);
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
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
        assert_eq!(
            stream_holder.stderr.get_string(),
            "Unrecognized command: 'booga'\n".to_string()
        );
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(close_params.len(), 1);
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
            non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
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
        let command = MockCommand::new(UiShutdownRequest {}.tmb(1)).execute_result(Ok(())); // irrelevant
        let command_factory = CommandFactoryMock::new().make_result(Ok(Box::new(command)));
        let process_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .process_params(&process_params_arc)
            .process_result(Err(Transmission("Booga!".to_string())));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
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
            "Transmission problem: Booga!\n".to_string()
        );
    }

    #[test]
    fn go_works_when_daemon_is_not_running() {
        let processor_factory = CommandProcessorFactoryMock::new()
            .make_result(Err(CommandError::ConnectionProblem("booga".to_string())));
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
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
            "Can't connect to Daemon or Node (ConnectionProblem(\"booga\")). \
             Probably this means the Daemon isn't running.\n"
                .to_string()
        );
    }

    #[test]
    fn populate_interactive_dependencies_produces_all_needed_to_block_printing_from_another_thread_when_the_lock_is_acquired(
    ) {
        //TODO rewrite me
        // let (test_stream_factory, test_stream_handle) = TestStreamFactory::new();
        // let (broadcast_handle, terminal_interface) =
        //     CommandContextDependencies::populate_interactive_dependencies(test_stream_factory)
        //         .unwrap();
        // {
        //     let _lock = terminal_interface.as_ref().unwrap().lock();
        //     broadcast_handle.send(UiNewPasswordBroadcast {}.tmb(0));
        //
        //     let output = test_stream_handle.stdout_so_far();
        //
        //     assert_eq!(output, "")
        // }
        // // Because of Win from Actions
        // #[cfg(target_os = "windows")]
        // win_test_import::thread::sleep(win_test_import::Duration::from_millis(200));
        //
        // let output_when_unlocked = test_stream_handle.stdout_so_far();
        //
        // assert_eq!(
        //     output_when_unlocked,
        //     "\nThe Node\'s database password has changed.\n\n"
        // )
    }

    #[test]
    fn noninteractive_mode_works_when_special_ui_port_is_required() {
        let c_make_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&c_make_params_arc)
            .make_result(Ok(Box::new(SetupCommand::new(&[]).unwrap())));
        let process_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .process_params(&process_params_arc)
            .process_result(Ok(()));
        let p_make_params_arc = Arc::new(Mutex::new(vec![]));
        let processor_factory = CommandProcessorFactoryMock::new()
            .make_params(&p_make_params_arc)
            .make_result(Ok(Box::new(processor)));
        let clap_factory = NonInteractiveClapFactoryReal;
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(clap_factory),
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };

        let result = subject.go(
            &mut FakeStreamHolder::new().streams(),
            &[
                "masq".to_string(),
                "--ui-port".to_string(),
                "10000".to_string(),
                "setup".to_string(),
            ],
        );

        assert_eq!(result, 0);
        let c_make_params = c_make_params_arc.lock().unwrap();
        assert_eq!(*c_make_params, vec![vec!["setup".to_string(),],]);
        let mut p_make_params = p_make_params_arc.lock().unwrap();
        let (terminal_wrapper_opt, ui_port) = p_make_params.pop().unwrap();
        assert_eq!(ui_port, 10000);
        assert!(terminal_wrapper_opt.is_none());
        let mut process_params = process_params_arc.lock().unwrap();
        assert_eq!(
            *(*process_params)
                .pop()
                .unwrap()
                .as_any()
                .downcast_ref::<SetupCommand>()
                .unwrap(),
            SetupCommand { values: vec![] }
        )
    }

    #[test]
    fn extract_subcommands_can_process_interactive_mode_request() {
        let args = vec!["masq".to_string()];

        let result = Main::extract_subcommand(&args);

        assert_eq!(result, None)
    }

    #[test]
    fn extract_subcommands_can_process_normal_non_interactive_request() {
        let args = vec!["masq", "setup", "--log-level", "off"]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>();

        let result = Main::extract_subcommand(&args);

        assert_eq!(
            result,
            Some(vec![
                "setup".to_string(),
                "--log-level".to_string(),
                "off".to_string()
            ])
        )
    }

    #[test]
    fn extract_subcommands_can_process_non_interactive_request_including_special_port() {
        let args = vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
            .iter()
            .map(|str| str.to_string())
            .collect::<Vec<String>>();

        let result = Main::extract_subcommand(&args);

        assert_eq!(
            result,
            Some(vec![
                "setup".to_string(),
                "--log-level".to_string(),
                "off".to_string()
            ])
        )
    }

    #[derive(Debug)]
    struct FakeCommand {
        output: String,
    }

    impl commands_common::Command for FakeCommand {
        fn execute(&self, _context: &mut dyn CommandContext) -> Result<(), CommandError> {
            intentionally_blank!()
        }
        fn as_any(&self) -> &dyn Any {
            self
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
        let process_params_arc = Arc::new(Mutex::new(vec![]));
        let command_factory = CommandFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
            .make_result(Ok(Box::new(FakeCommand::new("start command"))));
        let terminal_mock = TerminalPassiveMock::new()
            .read_line_result(TerminalEvent::CommandLine(vec!["setup".to_string()]))
            .read_line_result(TerminalEvent::CommandLine(vec!["start".to_string()]))
            .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()]));
        let processor = CommandProcessorMock::new()
            .process_result(Ok(()))
            .process_result(Ok(()))
            .process_params(&process_params_arc)
            .inject_terminal_interface(TerminalWrapper::new(Arc::new(terminal_mock)));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(NIClapFactoryMock),
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(
            &mut stream_holder.streams(),
            &[
                "command".to_string(),
                "--param".to_string(),
                "value".to_string(),
            ],
        );
        assert_eq!(result, 0);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(
            *make_params,
            vec![vec!["setup".to_string()], vec!["start".to_string()]]
        );
        let mut process_params = process_params_arc.lock().unwrap();
        let (first_command, second_command) = (process_params.remove(0), process_params.remove(0));
        let first_command = first_command
            .as_any()
            .downcast_ref::<FakeCommand>()
            .unwrap();
        assert_eq!(first_command.output, "setup command".to_string());
        let second_command = second_command
            .as_any()
            .downcast_ref::<FakeCommand>()
            .unwrap();
        assert_eq!(second_command.output, "start command".to_string())
    }

    #[test]
    fn interactive_mode_works_for_stdin_read_error() {
        let command_factory = CommandFactoryMock::new();
        let close_params_arc = Arc::new(Mutex::new(vec![]));
        let processor = CommandProcessorMock::new()
            .close_params(&close_params_arc)
            .inject_terminal_interface(TerminalWrapper::new(Arc::new(
                TerminalPassiveMock::new()
                    .read_line_result(TerminalEvent::Error(Some("ConnectionRefused".to_string()))),
            )));
        let processor_factory =
            CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
        let mut subject = Main {
            non_interactive_clap_factory: Box::new(NIClapFactoryMock),
            command_factory: Box::new(command_factory),
            processor_factory: Box::new(processor_factory),
        };
        let mut stream_holder = FakeStreamHolder::new();

        let result = subject.go(&mut stream_holder.streams(), &["command".to_string()]);

        assert_eq!(result, 1);
        assert_eq!(
            stream_holder.stderr.get_string(),
            "ConnectionRefused\n".to_string()
        );
        let close_params = close_params_arc.lock().unwrap();
        assert_eq!(close_params.len(), 1);
    }
}
