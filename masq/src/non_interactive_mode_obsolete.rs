// // Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
//
// use crate::command_factory::CommandFactoryError::{CommandSyntax, UnrecognizedSubcommand};
// use crate::command_factory::{CommandFactory, CommandFactoryReal};
// use crate::command_processor::{
//     CommandProcessor, CommandProcessorFactory, CommandProcessorFactoryReal,
// };
// use crate::communications::broadcast_handlers::{
//     BroadcastHandle, BroadcastHandleInactive, BroadcastHandler, StandardBroadcastHandlerReal,
// };
// use crate::communications::connection_manager::ConnectionManagerBootstrapper;
// use crate::interactive_mode::go_interactive;
// use crate::non_interactive_clap::{
//     InitializationArgs, NonInteractiveClapFactory, NonInteractiveClapFactoryReal,
// };
// use crate::terminal::async_streams::{
//     AsyncStdStreamFactoryReal, AsyncStdStreams, AsyncStdStreamsFactory,
// };
// use crate::terminal::terminal_interface::{RWTermInterface, TerminalWriter, WTermInterface};
// use crate::terminal::terminal_interface_factory::{
//     TerminalInterfaceFactory, TerminalInterfaceFactoryReal,
// };
// use async_trait::async_trait;
// use itertools::Either;
// use crate::masq_short_writeln;
// use masq_lib::test_utils::fake_stream_holder::AsyncByteArrayWriter;
// use masq_lib::ui_gateway::MessageBody;
// use masq_lib::ui_traffic_converter::TrafficConversionError;
// use std::io::Write;
// use std::ops::Not;
// use std::pin::pin;
// use std::sync::Arc;
// use tokio::io::{AsyncWrite, AsyncWriteExt};
// use tokio::runtime::Runtime;
//
// pub struct Main {
//     std_streams_factory: Box<dyn AsyncStdStreamsFactory>,
//     non_interactive_clap_factory: Box<dyn NonInteractiveClapFactory>,
//     term_interface_factory: Box<dyn TerminalInterfaceFactory>,
//     command_factory: Box<dyn CommandFactory>,
//     processor_factory: Arc<dyn CommandProcessorFactory>,
// }
//
// // #[async_trait]
// // pub trait Command: Send {
// //     async fn go(self: Box<Self>, args: &[String], stderr:  &mut (dyn AsyncWrite + Send + Unpin)) -> u8;
// // }
//
// impl Default for Main {
//     fn default() -> Self {
//         Main::new()
//     }
// }
//
// impl Main {
//     async fn go(&mut self, args: &[String]) -> u8 {
//         let initialization_args = self.parse_initialization_args(args);
//         let subcommand_opt = Self::extract_subcommand(args);
//         // let terminal_interface = match Self::initialize_terminal_interface(subcommand_opt.is_none())
//         // {
//         //     Ok(d) => d,
//         //     Err(e) => {
//         //         masq_short_writeln!(streams.stderr, "Pre-configuration error: {}", e);
//         //         return Self::bool_into_numeric_code(false);
//         //     }
//         // };
//         let streams = self.std_streams_factory.make();
//         let term_interface = self
//             .term_interface_factory
//             .make(subcommand_opt.is_none(), streams);
//
//         // let mut command_processor = match self
//         //     .processor_factory_arc()
//         //     .make(rw_term_interface, initialization_args.ui_port)
//         //     .await
//         // {
//         //     Ok(processor) => processor,
//         //     Err(error) => {
//         //         //TODO maybe hide into a fn
//         //         streams.stderr.write(format!(
//         //             "Can't connect to Daemon or Node ({:?}). Probably this means the Daemon \
//         //             isn't running.\n",
//         //             error
//         //         ).as_bytes()).await.expect("Error writing failed");
//         //         return Self::bool_into_numeric_code(false);
//         //     }
//         // };
//         //
//
//         match self
//             .say_hello_to_your_next_shift(
//                 initialization_args.ui_port,
//                 term_interface,
//                 subcommand_opt.as_deref(),
//             )
//             .await
//         {
//             Ok(_) => todo!(),
//             Err(e) => {
//                 // let mut streams = self.std_streams_factory.make();
//                 //         streams.stderr.write(format!(
//                 //             "Can't connect to Daemon or Node ({:?}). Probably this means the Daemon \
//                 //             isn't running.\n",
//                 //             error
//                 //         ).as_bytes()).await.expect("Error writing failed");
//                 //         return Self::bool_into_numeric_code(false);
//
//                 //self.write_err()
//                 todo!()
//             }
//         }
//     }
//
//     pub fn new() -> Self {
//         Self {
//             std_streams_factory: Box::new(AsyncStdStreamFactoryReal::default()),
//             non_interactive_clap_factory: Box::new(NonInteractiveClapFactoryReal::default()),
//             term_interface_factory: Box::new(TerminalInterfaceFactoryReal::default()),
//             command_factory: Box::new(CommandFactoryReal::default()),
//             processor_factory: Arc::new(CommandProcessorFactoryReal::new(
//                 ConnectionManagerBootstrapper::default(),
//             )),
//         }
//     }
//
//     fn parse_initialization_args(&self, args: &[String]) -> InitializationArgs {
//         self.non_interactive_clap_factory
//             .make()
//             .parse_initialization_args(args)
//     }
//
//     async fn say_hello_to_your_next_shift(
//         &mut self,
//         ui_port: u16,
//         term_interface: Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
//         subcommand_opt: Option<&[String]>,
//     ) -> Result<(), String> {
//         let mut command_processor = match self
//             .processor_factory_arc()
//             .make(term_interface, ui_port)
//             .await
//         {
//             Ok(processor) => processor,
//             Err(error) => {
//                 todo!()
//             }
//         };
//
//         let result = match command_processor.process(subcommand_opt.as_deref()).await {
//             Ok(_) => todo!(),
//             Err(e) => todo!(),
//         };
//
//         command_processor.close();
//
//         result
//     }
//
//     fn processor_factory_arc(&self) -> Arc<dyn CommandProcessorFactory> {
//         todo!()
//     }
//
//     fn write_err(&self, stderr: &mut (dyn AsyncWrite + Send + Unpin), msg: &str) {
//         todo!()
//     }
//
//     fn extract_subcommand(args: &[String]) -> Option<Vec<String>> {
//         fn both_do_not_start_with_two_dashes(
//             one_program_arg: &&String,
//             program_arg_next_to_the_previous: &&String,
//         ) -> bool {
//             [one_program_arg, program_arg_next_to_the_previous]
//                 .iter()
//                 .any(|arg| arg.starts_with("--"))
//                 .not()
//         }
//
//         let original_args = args.iter();
//         let one_item_shifted_forth = args.iter().skip(1);
//         original_args
//             .zip(one_item_shifted_forth)
//             .enumerate()
//             .find(|(_index, (left, right))| both_do_not_start_with_two_dashes(left, right))
//             .map(|(index, _)| args.iter().skip(index + 1).cloned().collect())
//     }
//
//     fn bool_into_numeric_code(bool_flag: bool) -> u8 {
//         if bool_flag {
//             0
//         } else {
//             1
//         }
//     }
// }
//
// pub async fn handle_command_common(
//     command_factory: &dyn CommandFactory,
//     processor: &mut dyn CommandProcessor,
//     command_parts: &[String],
//     stderr: &TerminalWriter,
// ) -> bool {
//     todo!()
//     // let command = match command_factory.make(command_parts) {
//     //     Ok(c) => c,
//     //     Err(UnrecognizedSubcommand(msg)) => {
//     //         masq_short_writeln!(stderr, "Unrecognized command: '{}'", msg);
//     //         return false;
//     //     }
//     //     Err(CommandSyntax(msg)) => {
//     //         masq_short_writeln!(stderr, "{}", msg);
//     //         return false;
//     //     }
//     // };
//     // if let Err(e) = processor.process(command) {
//     //     masq_short_writeln!(stderr, "{}", e);
//     //     false
//     // } else {
//     //     true
//     // }
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::command_context::CommandContext;
//     use crate::command_context::ContextError::Other;
//     use crate::commands::commands_common;
//     use crate::commands::commands_common::CommandError;
//     use crate::commands::commands_common::CommandError::Transmission;
//     use crate::commands::setup_command::SetupCommand;
//     use crate::terminal::line_reader::TerminalEvent;
//     use crate::terminal::terminal_interface::WTermInterface;
//     use crate::test_utils::mocks::{
//         make_async_std_streams, make_terminal_writer, AsyncStdStreamFactoryMock,
//         AsyncTestStreamHandles, CommandContextMock, CommandFactoryMock,
//         CommandProcessorFactoryMock, CommandProcessorMock, MockCommand, NIClapFactoryMock,
//         RWTerminalInterfaceFactoryMock, TermInterfaceMock, TerminalPassiveMock, TestStreamFactory,
//         WTermInterfaceMock,
//     };
//     use masq_lib::intentionally_blank;
//     use masq_lib::messages::{ToMessageBody, UiNewPasswordBroadcast, UiShutdownRequest};
//     use masq_lib::test_utils::fake_stream_holder::ByteArrayHelperMethods;
//     use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
//     use std::any::Any;
//     use std::sync::{Arc, Mutex};
//
//     #[cfg(target_os = "windows")]
//     mod win_test_import {
//         pub use std::thread;
//         pub use std::time::Duration;
//     }
//
//     #[tokio::test]
//     async fn noninteractive_mode_works_when_everything_is_copacetic() {
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_params(&make_std_streams_params_arc)
//             .make_result(processor_std_streams);
//         let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_params(&make_term_interface_params_arc)
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
//         let c_make_params_arc = Arc::new(Mutex::new(vec![]));
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&c_make_params_arc)
//             .make_result(Ok(Box::new(command)));
//         let process_params_arc = Arc::new(Mutex::new(vec![]));
//         let close_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor = CommandProcessorMock::new()
//             .close_params(&close_params_arc)
//             .process_params(&process_params_arc)
//             .process_result(Ok(()));
//         let make_processor_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory = CommandProcessorFactoryMock::new()
//             .make_params(&make_processor_params_arc)
//             .make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             std_streams_factory: Box::new(std_streams_factory),
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
//             term_interface_factory: Box::new(terminal_interface_factory),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//
//         let result = subject
//             .go(&[
//                 "command",
//                 "subcommand",
//                 "--param1",
//                 "value1",
//                 "--param2",
//                 "--param3",
//             ]
//             .iter()
//             .map(|str| str.to_string())
//             .collect::<Vec<String>>())
//             .await;
//
//         assert_eq!(result, 0);
//         let make_std_streams_params = make_std_streams_params_arc.lock().unwrap();
//         // Only once because there isn't an error to display from other than inside the processor and
//         // so the single set of streams is enough
//         assert_eq!(*make_std_streams_params, vec![()]);
//         let mut make_processor_params = make_processor_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = make_processor_params.pop().unwrap();
//         assert_eq!(ui_port, 5333);
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false,
//             }),
//             first_tier_streams_opt: None,
//         };
//         assert_all_possible_stream_outputs(matrix).await;
//         let c_make_params = c_make_params_arc.lock().unwrap();
//         assert_eq!(
//             *c_make_params,
//             vec![
//                 vec!["subcommand", "--param1", "value1", "--param2", "--param3"]
//                     .iter()
//                     .map(|str| str.to_string())
//                     .collect::<Vec<String>>(),
//             ]
//         );
//         let mut process_params = process_params_arc.lock().unwrap();
//         let command = process_params.remove(0);
//         let transact_params_arc = Arc::new(Mutex::new(vec![]));
//         let mut context = CommandContextMock::new()
//             .transact_params(&transact_params_arc)
//             .transact_result(Err(Other("not really an error".to_string())));
//         let (mut term_interface, stream_handles) = TermInterfaceMock::new(None).await;
//         let stdout_arc = term_interface.stdout_arc().clone();
//         let stderr_arc = term_interface.stderr_arc().clone();
//
//         let result = command.execute(&mut context, &mut term_interface).await;
//
//         assert_eq!(
//             result,
//             Err(Transmission("Other(\"not really an error\")".to_string()))
//         );
//         let transact_params = transact_params_arc.lock().unwrap();
//         assert_eq!(*transact_params, vec![(UiShutdownRequest {}.tmb(1), 1000)]);
//         assert_eq!(
//             stdout_arc.lock().unwrap().get_string(),
//             "MockCommand output".to_string()
//         );
//         assert_eq!(
//             stderr_arc.lock().unwrap().get_string(),
//             "MockCommand error".to_string()
//         );
//         let close_params = close_params_arc.lock().unwrap();
//         assert_eq!(*close_params, vec![()]);
//     }
//
//     #[tokio::test]
//     async fn go_works_when_command_is_unrecognized() {
//         let c_make_params_arc = Arc::new(Mutex::new(vec![]));
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&c_make_params_arc)
//             .make_result(Err(UnrecognizedSubcommand("booga".to_string())));
//         let close_params_arc = Arc::new(Mutex::new(vec![]));
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let (first_tier_std_streams, f_t_stream_handles) = make_async_std_streams(vec![]);
//         let make_std_streams_params_arc = Arc::new(Mutex::new(vec![]));
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_params(&make_std_streams_params_arc)
//             .make_result(processor_std_streams)
//             .make_result(first_tier_std_streams);
//         let make_term_interface_params_arc = Arc::new(Mutex::new(vec![]));
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_params(&make_term_interface_params_arc)
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let processor = CommandProcessorMock::new().close_params(&close_params_arc);
//         let make_processor_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory = CommandProcessorFactoryMock::new()
//             .make_params(&make_processor_params_arc)
//             .make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             std_streams_factory: Box::new(std_streams_factory),
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
//             term_interface_factory: Box::new(terminal_interface_factory),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//
//         let result = subject
//             .go(&["command".to_string(), "subcommand".to_string()])
//             .await;
//
//         let make_std_streams_params = make_std_streams_params_arc.lock().unwrap();
//         assert_eq!(*make_std_streams_params, vec![(), ()]);
//         let mut make_processor_params = make_processor_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = make_processor_params.pop().unwrap();
//         assert_eq!(ui_port, 5333);
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "Unrecognized command: 'booga'\n",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false
//             }),
//             first_tier_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &f_t_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "grrrrrrrrrrr",
//                 reading_attempted: false
//             }),
//         };
//         assert_all_possible_stream_outputs(matrix).await;
//         let c_make_params = c_make_params_arc.lock().unwrap();
//         assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
//         let close_params = close_params_arc.lock().unwrap();
//         assert_eq!(*close_params, vec![()]);
//         assert_eq!(result, 1);
//     }
//
//     #[tokio::test]
//     async fn go_works_when_command_has_bad_syntax() {
//         let c_make_params_arc = Arc::new(Mutex::new(vec![]));
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&c_make_params_arc)
//             .make_result(Err(CommandSyntax("Unknown syntax booga".to_string())));
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let (first_tier_std_streams, f_t_stream_handles) = make_async_std_streams(vec![]);
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_result(processor_std_streams)
//             .make_result(first_tier_std_streams);
//
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let processor = CommandProcessorMock::new();
//         let make_processor_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory =
//             CommandProcessorFactoryMock::new()
//                 .make_params(&make_processor_params_arc)
//                 .make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             std_streams_factory: Box::new(std_streams_factory),
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
//             term_interface_factory: Box::new(terminal_interface_factory),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//
//         let result = subject
//             .go(&["command".to_string(), "subcommand".to_string()])
//             .await;
//
//         assert_eq!(result, 1);
//         let c_make_params = c_make_params_arc.lock().unwrap();
//         assert_eq!(*c_make_params, vec![vec!["subcommand".to_string()],]);
//         let mut make_processor_params = make_processor_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = make_processor_params.pop().unwrap();
//         assert_eq!(ui_port, 5333);
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "Unknown syntax booga\n",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false
//             }),
//             first_tier_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "grrrrrrrrrrrrr",
//                 reading_attempted: false
//             }),
//         };
//         assert_all_possible_stream_outputs(matrix).await
//     }
//
//     #[tokio::test]
//     async fn go_works_when_command_execution_fails() {
//         let command = MockCommand::new(UiShutdownRequest {}.tmb(1));
//         let command_factory = CommandFactoryMock::new().make_result(Ok(Box::new(command.clone())));
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let (first_tier_std_streams, f_t_stream_handles) = make_async_std_streams(vec![]);
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_result(processor_std_streams)
//             .make_result(first_tier_std_streams);
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let process_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor = CommandProcessorMock::new()
//             .process_params(&process_params_arc)
//             .process_result(Err(Transmission("Booga!".to_string())));
//         let make_processor_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory =
//             CommandProcessorFactoryMock::new().make_params(&make_processor_params_arc).make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             std_streams_factory: Box::new(std_streams_factory),
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
//             term_interface_factory: Box::new(terminal_interface_factory),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//
//         let result = subject
//             .go(
//                 &["command".to_string(), "subcommand".to_string()],
//             )
//             .await;
//
//         let mut make_processor_params = make_processor_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = make_processor_params.pop().unwrap();
//         assert_eq!(ui_port, 5333);
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "Transmission problem: Booga!\n",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false
//             }),
//             first_tier_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "grrrrrrrrrrrrrr",
//                 reading_attempted: false
//             }),
//         };
//         assert_all_possible_stream_outputs(matrix).await;
//         let mut process_params = process_params_arc.lock().unwrap();
//         let dyn_command = process_params.remove(0);
//         let actual_command = dyn_command.as_any().downcast_ref::<MockCommand>().unwrap();
//         assert_eq!(actual_command.message, command.message);
//         assert_eq!(result, 1);
//     }
//
//     #[tokio::test]
//     async fn go_works_when_daemon_is_not_running() {
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let (first_tier_std_streams, f_t_stream_handles) = make_async_std_streams(vec![]);
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_result(processor_std_streams)
//             .make_result(first_tier_std_streams);
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let make_processor_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory = CommandProcessorFactoryMock::new()
//             .make_params(&make_processor_params_arc)
//             .make_result(Err(CommandError::ConnectionProblem("booga".to_string())));
//         let mut subject = Main {
//             std_streams_factory: Box::new(std_streams_factory),
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock {}),
//             term_interface_factory: Box::new(terminal_interface_factory),
//             command_factory: Box::new(CommandFactoryMock::new()),
//             processor_factory: Arc::new(processor_factory),
//         };
//         let mut stream_holder = FakeStreamHolder::new();
//
//         let result = subject
//             .go(
//                 &["command".to_string(), "subcommand".to_string()],
//             )
//             .await;
//
//         let mut make_processor_params = make_processor_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = make_processor_params.pop().unwrap();
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "Can't connect to Daemon or Node \
//             (ConnectionProblem(\"booga\")). Probably this means the Daemon isn't running.\n",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false
//             }),
//             first_tier_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "grrrrrrrrrrrrrr",
//                 reading_attempted: false
//             }),
//         };
//         assert_all_possible_stream_outputs(matrix).await;
//         assert_eq!(result, 1);
//     }
//
//     #[test]
//     fn populate_interactive_dependencies_produces_all_needed_to_block_printing_from_another_thread_when_the_lock_is_acquired(
//     ) {
//         //TODO rewrite me
//         // let (test_stream_factory, test_stream_handle) = TestStreamFactory::new();
//         // let (broadcast_handle, terminal_interface) =
//         //     CommandContextDependencies::populate_interactive_dependencies(test_stream_factory)
//         //         .unwrap();
//         // {
//         //     let _lock = terminal_interface.as_ref().unwrap().lock();
//         //     broadcast_handle.send(UiNewPasswordBroadcast {}.tmb(0));
//         //
//         //     let output = test_stream_handle.stdout_so_far();
//         //
//         //     assert_eq!(output, "")
//         // }
//         // // Because of Win from Actions
//         // #[cfg(target_os = "windows")]
//         // win_test_import::thread::sleep(win_test_import::Duration::from_millis(200));
//         //
//         // let output_when_unlocked = test_stream_handle.stdout_so_far();
//         //
//         // assert_eq!(
//         //     output_when_unlocked,
//         //     "\nThe Node\'s database password has changed.\n\n"
//         // )
//     }
//
//     #[tokio::test]
//     async fn noninteractive_mode_works_when_special_ui_port_is_required() {
//         let (processor_std_streams, p_stream_handles) = make_async_std_streams(vec![]);
//         let std_streams_factory = AsyncStdStreamFactoryMock::default()
//             .make_result(processor_std_streams);
//         let (w_term_interface, term_interface_stream_handles) = TermInterfaceMock::new(None);
//         let terminal_interface_factory = RWTerminalInterfaceFactoryMock::default()
//             .make_result(Either::Left(Box::new(w_term_interface)));
//         let c_make_params_arc = Arc::new(Mutex::new(vec![]));
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&c_make_params_arc)
//             .make_result(Ok(Box::new(SetupCommand::new(&[]).unwrap())));
//         let process_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor = CommandProcessorMock::new()
//             .process_params(&process_params_arc)
//             .process_result(Ok(()));
//         let p_make_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor_factory = CommandProcessorFactoryMock::new()
//             .make_params(&p_make_params_arc)
//             .make_result(Ok(Box::new(processor)));
//         let clap_factory = NonInteractiveClapFactoryReal::default();
//         let mut subject = Main {
//             std_streams_factory: Box::new(()),
//             non_interactive_clap_factory: Box::new(clap_factory),
//             term_interface_factory: Box::new(()),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//
//         let result = subject
//             .go(
//                 &[
//                     "masq".to_string(),
//                     "--ui-port".to_string(),
//                     "10000".to_string(),
//                     "setup".to_string(),
//                 ],
//             )
//             .await;
//
//         assert_eq!(result, 0);
//         let c_make_params = c_make_params_arc.lock().unwrap();
//         assert_eq!(*c_make_params, vec![vec!["setup".to_string(),],]);
//         let mut p_make_params = p_make_params_arc.lock().unwrap();
//         let (supplied_term_interface, ui_port) = p_make_params.pop().unwrap();
//         assert_eq!(ui_port, 10000);
//         let matrix = AssertionMatrixForStreams{
//             supplied_term_interface: &supplied_term_interface,
//             original_stream_handles_for_this_terminal: &term_interface_stream_handles,
//             term_interface_stdout_expected: "",
//             term_interface_stderr_expected: "",
//             should_be_w_only_terminal: true,
//             processor_supplied_streams_opt: Some(StreamFactoryStreamMatrix{
//                 stream_handles: &p_stream_handles,
//                 expected_stdout: "",
//                 expected_stderr: "",
//                 reading_attempted: false
//             }),
//             first_tier_streams_opt:None,
//         };
//         let mut process_params = process_params_arc.lock().unwrap();
//         assert_eq!(
//             *(*process_params)
//                 .pop()
//                 .unwrap()
//                 .as_any()
//                 .downcast_ref::<SetupCommand>()
//                 .unwrap(),
//             SetupCommand { values: vec![] }
//         )
//     }
//
//     #[test]
//     fn extract_subcommands_can_process_interactive_mode_request() {
//         let args = vec!["masq".to_string()];
//
//         let result = Main::extract_subcommand(&args);
//
//         assert_eq!(result, None)
//     }
//
//     #[test]
//     fn extract_subcommands_can_process_normal_non_interactive_request() {
//         let args = vec!["masq", "setup", "--log-level", "off"]
//             .iter()
//             .map(|str| str.to_string())
//             .collect::<Vec<String>>();
//
//         let result = Main::extract_subcommand(&args);
//
//         assert_eq!(
//             result,
//             Some(vec![
//                 "setup".to_string(),
//                 "--log-level".to_string(),
//                 "off".to_string()
//             ])
//         )
//     }
//
//     #[test]
//     fn extract_subcommands_can_process_non_interactive_request_including_special_port() {
//         let args = vec!["masq", "--ui-port", "10000", "setup", "--log-level", "off"]
//             .iter()
//             .map(|str| str.to_string())
//             .collect::<Vec<String>>();
//
//         let result = Main::extract_subcommand(&args);
//
//         assert_eq!(
//             result,
//             Some(vec![
//                 "setup".to_string(),
//                 "--log-level".to_string(),
//                 "off".to_string()
//             ])
//         )
//     }
//
//     #[derive(Debug)]
//     struct FakeCommand {
//         output: String,
//     }
//
//     #[async_trait(?Send)]
//     impl commands_common::Command for FakeCommand {
//         async fn execute(
//             self: Box<Self>,
//             _context: &mut dyn CommandContext,
//             term_interface: &mut dyn WTermInterface,
//         ) -> Result<(), CommandError> {
//             intentionally_blank!()
//         }
//         fn as_any(&self) -> &dyn Any {
//             self
//         }
//     }
//
//     impl FakeCommand {
//         pub fn new(output: &str) -> Self {
//             Self {
//                 output: output.to_string(),
//             }
//         }
//     }
//
//     #[tokio::test]
//     async fn interactive_mode_works_when_everything_is_copacetic() {
//         let make_params_arc = Arc::new(Mutex::new(vec![]));
//         let process_params_arc = Arc::new(Mutex::new(vec![]));
//         let command_factory = CommandFactoryMock::new()
//             .make_params(&make_params_arc)
//             .make_result(Ok(Box::new(FakeCommand::new("setup command"))))
//             .make_result(Ok(Box::new(FakeCommand::new("start command"))));
//         let terminal_mock = TerminalPassiveMock::new()
//             .read_line_result(TerminalEvent::CommandLine(vec!["setup".to_string()]))
//             .read_line_result(TerminalEvent::CommandLine(vec!["start".to_string()]))
//             .read_line_result(TerminalEvent::CommandLine(vec!["exit".to_string()]));
//         let processor = CommandProcessorMock::new()
//             .process_result(Ok(()))
//             .process_result(Ok(()))
//             .process_params(&process_params_arc)
//             .inject_terminal_interface(TerminalWrapper::new(Arc::new(terminal_mock)));
//         let processor_factory =
//             CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//         let mut stream_holder = FakeStreamHolder::new();
//
//         let result = Box::new(subject)
//             .go(
//                 &mut stream_holder.streams(),
//                 &[
//                     "command".to_string(),
//                     "--param".to_string(),
//                     "value".to_string(),
//                 ],
//             )
//             .await;
//
//         assert_eq!(result, 0);
//         let make_params = make_params_arc.lock().unwrap();
//         assert_eq!(
//             *make_params,
//             vec![vec!["setup".to_string()], vec!["start".to_string()]]
//         );
//         let mut process_params = process_params_arc.lock().unwrap();
//         let (first_command, second_command) = (process_params.remove(0), process_params.remove(0));
//         let first_command = first_command
//             .as_any()
//             .downcast_ref::<FakeCommand>()
//             .unwrap();
//         assert_eq!(first_command.output, "setup command".to_string());
//         let second_command = second_command
//             .as_any()
//             .downcast_ref::<FakeCommand>()
//             .unwrap();
//         assert_eq!(second_command.output, "start command".to_string())
//     }
//
//     #[tokio::test]
//     async fn interactive_mode_works_for_stdin_read_error() {
//         let command_factory = CommandFactoryMock::new();
//         let close_params_arc = Arc::new(Mutex::new(vec![]));
//         let processor = CommandProcessorMock::new()
//             .close_params(&close_params_arc)
//             .inject_terminal_interface(TerminalWrapper::new(Arc::new(
//                 TerminalPassiveMock::new()
//                     .read_line_result(TerminalEvent::Error(Some("ConnectionRefused".to_string()))),
//             )));
//         let processor_factory =
//             CommandProcessorFactoryMock::new().make_result(Ok(Box::new(processor)));
//         let mut subject = Main {
//             non_interactive_clap_factory: Box::new(NIClapFactoryMock),
//             command_factory: Box::new(command_factory),
//             processor_factory: Arc::new(processor_factory),
//         };
//         let mut stream_holder = FakeStreamHolder::new();
//
//         let result = Box::new(subject)
//             .go(&mut stream_holder.streams(), &["command".to_string()])
//             .await;
//
//         assert_eq!(result, 1);
//         assert_eq!(
//             stream_holder.stderr.get_string(),
//             "ConnectionRefused\n".to_string()
//         );
//         let close_params = close_params_arc.lock().unwrap();
//         assert_eq!(close_params.len(), 1);
//     }
//
//     struct AssertionMatrixForStreams<'test>{
//         supplied_term_interface: &'test Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
//         original_stream_handles_for_this_terminal: &'test AsyncTestStreamHandles,
//         term_interface_stdout_expected: &'test str,
//         term_interface_stderr_expected: &'test str,
//         should_be_w_only_terminal: bool,
//         processor_supplied_streams_opt: Option<StreamFactoryStreamMatrix<'test>>,
//         first_tier_streams_opt: Option<StreamFactoryStreamMatrix<'test>>
//     }
//
//     struct StreamFactoryStreamMatrix<'test>{
//         stream_handles: &'test AsyncTestStreamHandles,
//         expected_stdout: &'test str,
//         expected_stderr: &'test str,
//         reading_attempted: bool
//     }
//
//     async fn assert_all_possible_stream_outputs(assertion_matrix: AssertionMatrixForStreams<'_>){
//         assert_term_interface_stream_outputs(assertion_matrix.supplied_term_interface, assertion_matrix.original_stream_handles_for_this_terminal, assertion_matrix.term_interface_stdout_expected, assertion_matrix.term_interface_stderr_expected, assertion_matrix.should_be_w_only_terminal).await;
//         if let Some(sub_matrix) = assertion_matrix.processor_supplied_streams_opt {
//             assert_stream_outputs(sub_matrix.stream_handles, sub_matrix.expected_stdout, sub_matrix.expected_stderr)
//         }
//         if let Some(sub_matrix) = assertion_matrix.first_tier_streams_opt {
//             assert_stream_outputs(sub_matrix.stream_handles, sub_matrix.expected_stdout, sub_matrix.expected_stderr)
//         }
//     }
//
//     async fn assert_term_interface_stream_outputs(
//         supplied_term_interface: &Either<Box<dyn WTermInterface>, Box<dyn RWTermInterface>>,
//         original_stream_handles_for_this_terminal: &AsyncTestStreamHandles,
//         initial_stdout_expected: &str,
//         initial_stderr_expected: &str,
//         should_be_w_only_terminal: bool,
//     ) {
//         let is_w_only = supplied_term_interface.is_left();
//         let ((stdout, stdout_flusher), (stderr, stderr_flusher)) = match supplied_term_interface {
//             Either::Left(w_terminal) => (w_terminal.stdout(), w_terminal.stderr()),
//             Either::Right(rw_terminal) => (rw_terminal.stdout(), rw_terminal.stderr()),
//         };
//         assert_stream_outputs(
//             original_stream_handles_for_this_terminal,
//             initial_stdout_expected,
//             initial_stderr_expected,
//         );
//         stdout.write("AbCdEfG").await;
//         stdout_flusher.flush().await.unwrap();
//         assert_eq!(
//             original_stream_handles_for_this_terminal
//                 .stdout
//                 .get_string(),
//             format!("{}AbCdEfG", initial_stdout_expected)
//         );
//         stderr.write("1a2b3c4").await;
//         stderr_flusher.flush().await.unwrap();
//         assert_eq!(
//             original_stream_handles_for_this_terminal
//                 .stderr
//                 .get_string(),
//             format!("{}1a2b3c4", initial_stderr_expected)
//         );
//         assert_eq!(is_w_only, should_be_w_only_terminal)
//     }
//
//     fn assert_stream_outputs(
//         original_stream_handles: &AsyncTestStreamHandles,
//         stdout_expected: &str,
//         stderr_expected: &str,
//     ) {
//         assert_eq!(
//             original_stream_handles.stdout.get_string(),
//             stdout_expected,
//             "We expected this printed by Stdout {} but was {}",
//             stdout_expected,
//             original_stream_handles.stdout.get_string()
//         );
//         assert_eq!(
//             original_stream_handles.stderr.get_string(),
//             stderr_expected,
//             "We expected this printed by Stderr {} but was {}",
//             stderr_expected,
//             original_stream_handles.stderr.get_string()
//         );
//     }
// }
//
//
