// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::liso_wrappers::{LisoInputWrapper, LisoOutputWrapper};
use crate::terminal::writing_utils::{ArcMutexFlushHandleInner, WritingUtils};
use crate::terminal::{
    FlushHandle, FlushHandleInner, RWTermInterface, ReadError, ReadInput, TerminalWriter,
    WTermInterface, WTermInterfaceDup, WriteResult,
};
use async_trait::async_trait;
use liso::Response;
use masq_lib::constants::MASQ_PROMPT;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

// //most of the events depend on the default linefeed signal handlers which ignore them unless you explicitly set the opposite
// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum TerminalEvent {
//     CommandLine(Vec<String>),
//     Error(Option<String>), //'None' when already processed by printing out
//     Continue,              //as ignore
//     Break,
//     EoF,
// }

pub struct InteractiveRWTermInterface {
    read_liso: Box<dyn LisoInputWrapper>,
    write_terminal: Box<dyn WTermInterfaceDup>,
}

impl InteractiveRWTermInterface {
    pub fn new(
        read_liso: Box<dyn LisoInputWrapper>,
        write_liso: Box<dyn LisoOutputWrapper>,
    ) -> Self {
        Self {
            read_liso,
            write_terminal: Box::new(InteractiveWTermInterface::new(write_liso)),
        }
    }
}

pub const UNINTERPRETABLE_COMMAND: &str = "Uninterpretable command: Ignored";

#[async_trait(?Send)]
impl RWTermInterface for InteractiveRWTermInterface {
    async fn read_line(&mut self) -> Result<ReadInput, ReadError> {
        match self.read_liso.read_async().await {
            Response::Input(line) => Ok(ReadInput::Line(line)),
            Response::Dead => Err(ReadError::TerminalOutputInputDisconnected),
            Response::Quit => Ok(ReadInput::Quit),
            Response::Discarded(_unfinished) => Ok(ReadInput::Quit),
            Response::Finish => Ok(ReadInput::Ignored { msg_opt: None }),
            Response::Info => Ok(ReadInput::Ignored { msg_opt: None }),
            Response::Break => Ok(ReadInput::Quit),
            Response::Escape => Ok(ReadInput::Ignored { msg_opt: None }),
            Response::Swap => Ok(ReadInput::Ignored { msg_opt: None }),
            Response::Custom(_) => Ok(ReadInput::Ignored {
                msg_opt: Some(UNINTERPRETABLE_COMMAND.to_string()),
            }),
            Response::Unknown(_) => Ok(ReadInput::Ignored {
                msg_opt: Some(UNINTERPRETABLE_COMMAND.to_string()),
            }),
            // As to my knowledge, this is untestable
            _ => Err(ReadError::UnexpectedNewValueFromLibrary),
        }
    }

    fn write_only_ref(&self) -> &dyn WTermInterfaceDup {
        self.write_terminal.as_ref()
    }

    fn write_only_clone_opt(&self) -> Option<Box<dyn WTermInterfaceDup>> {
        Some(self.write_terminal.dup())
    }
}

impl WTermInterface for InteractiveRWTermInterface {
    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        self.write_terminal.stdout()
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.write_terminal.stderr()
    }
}

pub struct InteractiveWTermInterface {
    write_liso_arc: Arc<dyn LisoOutputWrapper>,
    stdout_utils: WritingUtils,
    // In fact, this next utils also contain a handle to Stdout (Liso doesn't operate with Stderr).
    // Keeping them separate, though, prevents mixing message fragments from both
    stderr_utils: WritingUtils,
}

impl WTermInterface for InteractiveWTermInterface {
    fn stdout(&self) -> (TerminalWriter, FlushHandle) {
        self.stdout_utils.get_utils("Stdout")
    }

    fn stderr(&self) -> (TerminalWriter, FlushHandle) {
        self.stderr_utils.get_utils("Stderr")
    }
}

impl WTermInterfaceDup for InteractiveWTermInterface {
    fn dup(&self) -> Box<dyn WTermInterfaceDup> {
        Box::new(InteractiveWTermInterface::new(
            self.write_liso_arc.clone_output(),
        ))
    }
}

impl InteractiveWTermInterface {
    pub fn new(write_liso_box: Box<dyn LisoOutputWrapper>) -> Self {
        write_liso_box.prompt(MASQ_PROMPT, true, false);
        let write_liso_arc: Arc<dyn LisoOutputWrapper> = Arc::from(write_liso_box);
        let flush_handle_inner_constructor = |output_chunks_receiver| {
            Arc::new(tokio::sync::Mutex::new(InteractiveFlushHandleInner::new(
                write_liso_arc.clone(),
                output_chunks_receiver,
            ))) as ArcMutexFlushHandleInner
        };
        let stdout_utils = WritingUtils::new(flush_handle_inner_constructor.clone());
        let stderr_utils = WritingUtils::new(flush_handle_inner_constructor);
        Self {
            write_liso_arc,
            stdout_utils,
            stderr_utils,
        }
    }
}

pub struct InteractiveFlushHandleInner {
    writer_instance: Arc<dyn LisoOutputWrapper>,
    output_chunks_receiver: UnboundedReceiver<String>,
}

impl InteractiveFlushHandleInner {
    pub fn new(
        writer_instance: Arc<dyn LisoOutputWrapper>,
        output_chunks_receiver: UnboundedReceiver<String>,
    ) -> Self {
        Self {
            writer_instance,
            output_chunks_receiver,
        }
    }
}

#[async_trait]
impl FlushHandleInner for InteractiveFlushHandleInner {
    async fn write_internal(&self, full_output: String) -> Result<(), WriteResult> {
        self.writer_instance.println(&full_output);
        Ok(())
    }

    fn output_chunks_receiver_ref_mut(&mut self) -> &mut UnboundedReceiver<String> {
        &mut self.output_chunks_receiver
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::interactive_terminal_interface::{
        InteractiveRWTermInterface, InteractiveWTermInterface, UNINTERPRETABLE_COMMAND,
    };
    use crate::terminal::test_utils::{
        test_writing_streams_of_particular_terminal, InteractiveInterfaceByModes,
        LisoFlushedAssertableStrings, LisoInputWrapperMock, LisoOutputWrapperMock,
        WritingTestInput, WritingTestInputByTermInterfaces,
    };
    use crate::terminal::{RWTermInterface, ReadError, ReadInput, WTermInterface};
    use liso::Response;
    use masq_lib::constants::MASQ_PROMPT;
    use std::sync::{Arc, Mutex};

    #[test]
    fn constants_are_correct() {
        assert_eq!(UNINTERPRETABLE_COMMAND, "Uninterpretable command: Ignored")
    }

    #[test]
    #[should_panic(expected = "Another Stdout FLushHandle not permitted, already referencing 1")]
    fn test_double_call_panic_for_stdout() {
        let subject = InteractiveWTermInterface::new(Box::new(LisoOutputWrapperMock::default()));

        let _first = subject.stdout();
        let _second = subject.stdout();
    }

    #[test]
    #[should_panic(expected = "Another Stderr FLushHandle not permitted, already referencing 1")]
    fn test_double_call_panic_for_stderr() {
        let subject = InteractiveWTermInterface::new(Box::new(LisoOutputWrapperMock::default()));

        let _first = subject.stderr();
        let _second = subject.stderr();
    }

    #[test]
    fn masq_prompt_is_set_upon_both_initialization_and_for_each_clone_too() {
        let initial_terminal_prompt_params_arc = Arc::new(Mutex::new(vec![]));
        let cloned_terminal_prompt_params_arc = Arc::new(Mutex::new(vec![]));
        let r_liso_wrapper = LisoInputWrapperMock::default();
        let cloned_w_liso_wrapper =
            LisoOutputWrapperMock::default().prompt_params(&cloned_terminal_prompt_params_arc);
        let initial_w_liso_wrapper = LisoOutputWrapperMock::default()
            .prompt_params(&initial_terminal_prompt_params_arc)
            .clone_output_result(Box::new(cloned_w_liso_wrapper));

        let rw_subject = InteractiveRWTermInterface::new(
            Box::new(r_liso_wrapper),
            Box::new(initial_w_liso_wrapper),
        );

        let input_allowed = true;
        let clear_interrupted_input = false;
        let expected_terminal_prompt_params = vec![(MASQ_PROMPT.to_string(), true, false)];
        let mut initial_terminal_prompt_params = initial_terminal_prompt_params_arc.lock().unwrap();
        assert_eq!(
            *initial_terminal_prompt_params,
            expected_terminal_prompt_params
        );
        let cloned_terminal_prompt_params = cloned_terminal_prompt_params_arc.lock().unwrap();
        assert_eq!(*cloned_terminal_prompt_params, vec![]);
        // Emptying the container to make the next assertions brighter
        initial_terminal_prompt_params.drain(..);
        drop(initial_terminal_prompt_params);
        drop(cloned_terminal_prompt_params);

        rw_subject.write_only_clone_opt().unwrap();

        let cloned_terminal_prompt_params = cloned_terminal_prompt_params_arc.lock().unwrap();
        assert_eq!(
            *cloned_terminal_prompt_params,
            expected_terminal_prompt_params
        );
        let initial_terminal_prompt_params = initial_terminal_prompt_params_arc.lock().unwrap();
        assert_eq!(*initial_terminal_prompt_params, vec![]);
    }

    #[tokio::test]
    async fn writing_works_for_interactive_terminal_interface_and_each_write_only_clone_or_reference(
    ) {
        let rw_liso_println_params = LisoFlushedAssertableStrings::default();
        let w_liso_println_params = LisoFlushedAssertableStrings::default();
        let cloned_w_liso_wrapper =
            LisoOutputWrapperMock::default().println_params(&w_liso_println_params);
        let r_liso_wrapper = LisoInputWrapperMock::default();
        let w_liso_wrapper = LisoOutputWrapperMock::default()
            .println_params(&rw_liso_println_params)
            .clone_output_result(Box::new(cloned_w_liso_wrapper));

        let rw_subject =
            InteractiveRWTermInterface::new(Box::new(r_liso_wrapper), Box::new(w_liso_wrapper));

        let w_only_clone = rw_subject.write_only_clone_opt().unwrap();

        let w_only_ref = rw_subject.write_only_ref();

        test_writing_streams_of_particular_terminal(
            WritingTestInputByTermInterfaces::Interactive(WritingTestInput {
                term_interface: InteractiveInterfaceByModes::ReadWrite(&rw_subject),
                streams_assertion_handles: rw_liso_println_params.clone(),
            }),
            "read-write subject",
        )
        .await;
        test_writing_streams_of_particular_terminal(
            WritingTestInputByTermInterfaces::Interactive(WritingTestInput {
                term_interface: InteractiveInterfaceByModes::Write(w_only_clone.as_ref()),
                streams_assertion_handles: w_liso_println_params,
            }),
            "write only clone",
        )
        .await;
        // Making sure the already asserted output is gone
        assert!(rw_liso_println_params.is_empty());
        test_writing_streams_of_particular_terminal(
            WritingTestInputByTermInterfaces::Interactive(WritingTestInput {
                term_interface: InteractiveInterfaceByModes::Write(w_only_ref),
                streams_assertion_handles: rw_liso_println_params,
            }),
            "write only ref",
        )
        .await;
    }

    #[tokio::test]
    async fn reading_lines_works() {
        let possible_internal_responses_from_liso = vec![
            (
                Response::Input("Command".to_string()),
                Ok(ReadInput::Line("Command".to_string())),
            ),
            (
                Response::Dead,
                Err(ReadError::TerminalOutputInputDisconnected),
            ),
            (Response::Quit, Ok(ReadInput::Quit)),
            (
                Response::Discarded("Unfinished command".to_string()),
                Ok(ReadInput::Quit),
            ),
            (Response::Finish, Ok(ReadInput::Ignored { msg_opt: None })),
            (Response::Info, Ok(ReadInput::Ignored { msg_opt: None })),
            (Response::Break, Ok(ReadInput::Quit)),
            (Response::Escape, Ok(ReadInput::Ignored { msg_opt: None })),
            (Response::Swap, Ok(ReadInput::Ignored { msg_opt: None })),
            (
                Response::Custom(Box::new(Some(vec![std::io::Empty::default()]))),
                Ok(ReadInput::Ignored {
                    msg_opt: Some(UNINTERPRETABLE_COMMAND.to_string()),
                }),
            ),
            (
                Response::Unknown(123),
                Ok(ReadInput::Ignored {
                    msg_opt: Some(UNINTERPRETABLE_COMMAND.to_string()),
                }),
            ),
        ];
        let (inputs_to_exercise, expected_translations): (Vec<_>, Vec<_>) =
            possible_internal_responses_from_liso.into_iter().unzip();
        let rw_liso_println_params = LisoFlushedAssertableStrings::default();
        let r_liso_wrapper = inputs_to_exercise
            .into_iter()
            .fold(LisoInputWrapperMock::default(), |mock, read_result| {
                mock.read_async_result(read_result)
            });
        let w_liso_wrapper = LisoOutputWrapperMock::default();
        let mut subject =
            InteractiveRWTermInterface::new(Box::new(r_liso_wrapper), Box::new(w_liso_wrapper));
        let mut subject_ref = &mut subject;

        for expected in expected_translations {
            let result = subject_ref.read_line().await;
            assert_eq!(result, expected)
        }
    }
}
