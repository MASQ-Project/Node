// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::sync::Arc;
use async_trait::async_trait;
use liso::InputOutput;
use crate::terminal::{FlushHandle, ReadInput, ReadResult, RWTermInterface, TerminalWriter, WTermInterface};
use crate::terminal::liso_wrapper::LisoInputOutputWrapper;

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
    liso_handler: Box<dyn LisoInputOutputWrapper>
}

pub struct InteractiveWTermInterface {}

impl WTermInterface for InteractiveWTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}

impl InteractiveRWTermInterface{
    pub fn new(liso_handler: Box<dyn LisoInputOutputWrapper>)-> Self{
        Self{
            liso_handler
        }
    }
}

#[async_trait]
impl RWTermInterface for InteractiveRWTermInterface {
    async fn read_line(&self) -> Result<ReadInput, ReadResult> {
        todo!()
    }

    fn write_only_ref(&self) -> &dyn WTermInterface {
        todo!()
    }

    fn write_only_clone_opt(&self) -> Option<Box<dyn WTermInterface>> {
        todo!()
    }
}

impl WTermInterface for InteractiveRWTermInterface {
    fn stdout(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn stderr(&self) -> (&TerminalWriter, Arc<dyn FlushHandle>) {
        todo!()
    }

    fn dup(&self) -> Box<dyn WTermInterface> {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use itertools::Either;
    use liso::Response;
    use crate::terminal::interactive_terminal_interface::InteractiveRWTermInterface;
    use crate::terminal::liso_wrapper::LisoInputOutputWrapperReal;
    use crate::terminal::{ReadInput, RWTermInterface};
    use crate::terminal::test_utils::{LisoFlushedAssertableStrings, LisoInputOutputWrapperMock, LisoOutputWrapperMock, test_writing_streams_of_particular_terminal};

    #[tokio::test]
    async fn writing_works_for_interactive_terminal_interface_and_its_write_only_clone_or_reference(){
        let rw_liso_println_params = LisoFlushedAssertableStrings::default();
        let w_liso_println_params = LisoFlushedAssertableStrings::default();
        let w_terminal = LisoOutputWrapperMock::default()
            .println_params(&w_liso_println_params);
        let rw_liso_wrapper = LisoInputOutputWrapperMock::default()
            .println_params(&rw_liso_println_params)
            .clone_output_result(Box::new(w_terminal));

        let rw_subject = InteractiveRWTermInterface::new(Box::new(rw_liso_wrapper));

        let w_only_clone = rw_subject.write_only_clone_opt().unwrap();

        let w_only_ref = rw_subject.write_only_ref();

        test_writing_streams_of_particular_terminal(Either::Right((&rw_subject, rw_liso_println_params.clone())), "read-write subject").await;
        test_writing_streams_of_particular_terminal(Either::Right((w_only_clone.as_ref(), w_liso_println_params)), "write only clone").await;
        // Making sure the already asserted output is gone
        assert!(rw_liso_println_params.is_empty());
        test_writing_streams_of_particular_terminal(Either::Right((w_only_ref, rw_liso_println_params)), "write only clone").await;
    }

    #[tokio::test]
    async fn reading_lines_works(){
        let rw_liso_println_params = LisoFlushedAssertableStrings::default();
        let rw_liso_wrapper = LisoInputOutputWrapperMock::default()
            .read_async_result(Response::Input("Command".to_string()))
            .read_async_result(Response::Quit)
            .println_params(&rw_liso_println_params);
        let subject = InteractiveRWTermInterface::new(Box::new(rw_liso_wrapper));

        let first_read = subject.read_line().await.unwrap();

        let second_read = subject.read_line().await.unwrap();

        assert_eq!(first_read, ReadInput::Line("Command".to_string()));
        assert_eq!(second_read, ReadInput::Quit);
        assert!(rw_liso_println_params.is_empty())
    }
}