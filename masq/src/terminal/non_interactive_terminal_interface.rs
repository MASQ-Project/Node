// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWrite;
use crate::terminal::{FlushHandle, TerminalWriter, WTermInterface};
use crate::terminal::async_streams::AsyncStdStreamsFactory;

pub struct NonInteractiveFlushHandle {}

pub struct InteractiveFlushHandle {}


pub struct NonInteractiveWTermInterface {
    stdout: Arc<Mutex<Box<dyn AsyncWrite + Send>>>,
    stderr: Arc<Mutex<Box<dyn AsyncWrite + Send>>>
}

impl WTermInterface for NonInteractiveWTermInterface {
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

impl NonInteractiveWTermInterface {
    pub fn new(stream_factory: Box<dyn AsyncStdStreamsFactory>) -> Self {
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use itertools::Either;
    use crate::terminal::non_interactive_terminal_interface::NonInteractiveWTermInterface;
    use crate::terminal::test_utils::test_writing_streams_of_particular_terminal;
    use crate::terminal::WTermInterface;
    use crate::test_utils::mocks::{AsyncStdStreamsFactoryMock, make_async_std_streams, make_async_std_write_stream};

    #[tokio::test]
    async fn writing_works_for_non_interactive_terminal_interface_as_well_as_its_duplicate(){
        let (first_instance_std_streams, first_instance_handles) = make_async_std_streams(vec![]);
        let (second_instance_std_streams, second_instance_handles) = make_async_std_streams(vec![]);
        let std_streams_factory = AsyncStdStreamsFactoryMock::default().make_result(first_instance_std_streams).make_result(second_instance_std_streams);

        let subject = NonInteractiveWTermInterface::new(Box::new(std_streams_factory));

        let duplicate = subject.dup();

        test_writing_streams_of_particular_terminal(Either::Left((&subject, first_instance_handles.stdout.left().unwrap(), first_instance_handles.stderr.left().unwrap())), "subject").await;
        test_writing_streams_of_particular_terminal(Either::Left((duplicate.as_ref(), second_instance_handles.stdout.left().unwrap(), second_instance_handles.stderr.left().unwrap())), "duplicate").await
    }
}

