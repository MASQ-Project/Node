// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::liso_wrappers::LisoOutputWrapper;
use crate::terminal::{FlushHandle, FlushHandleInner, TerminalWriter, WriteStreamType};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub struct WritingUtils {
    stream_type: WriteStreamType,
    terminal_writer_strict_provider: TerminalWriterStrictProvider,
    flush_handle_inner: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
}

pub type ArcMutexFlushHandleInner = Arc<tokio::sync::Mutex<dyn FlushHandleInner>>;

impl WritingUtils {
    pub fn new<ConstructFlushHandleInner>(
        construct_flush_handle_inner: ConstructFlushHandleInner,
        stream_type: WriteStreamType,
    ) -> Self
    where
        ConstructFlushHandleInner: FnOnce(
            UnboundedReceiver<String>,
            WriteStreamType,
        ) -> Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
    {
        let (output_chunks_sender, output_chunks_receiver) = unbounded_channel();
        let terminal_writer_strict_provider =
            TerminalWriterStrictProvider::new(output_chunks_sender);
        let flush_handle_inner = construct_flush_handle_inner(output_chunks_receiver, stream_type);
        Self {
            stream_type,
            terminal_writer_strict_provider,
            flush_handle_inner,
        }
    }

    pub fn get_utils(&self) -> (TerminalWriter, FlushHandle) {
        match self
            .terminal_writer_strict_provider
            .provide_if_not_already_in_use()
        {
            Ok(terminal_writer) => {
                let flush_handle = FlushHandle::new(self.flush_handle_inner.clone());
                (terminal_writer, flush_handle)
            }
            Err(count) => {
                let stream_type = self.stream_type;
                panic!(
                    "Another {stream_type} FLushHandle not permitted, already referencing {count}"
                )
            }
        }
    }
}

pub struct TerminalWriterStrictProvider {
    output_chunks_sender: UnboundedSender<String>,
}

impl TerminalWriterStrictProvider {
    pub fn new(output_chunks_sender: UnboundedSender<String>) -> Self {
        let current_tx_count = output_chunks_sender.strong_count();
        if current_tx_count > 1 {
            panic!(
                "Sender has already {} clones but should've had only one",
                current_tx_count
            )
        }
        Self {
            output_chunks_sender,
        }
    }

    fn provide_if_not_already_in_use(&self) -> Result<TerminalWriter, usize> {
        let sender_reference_count = self.output_chunks_sender.strong_count();
        if sender_reference_count == 1 {
            Ok(TerminalWriter::new(self.output_chunks_sender.clone()))
        } else {
            let in_use_outside_here = sender_reference_count - 1;
            Err(in_use_outside_here)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::writing_utils::TerminalWriterStrictProvider;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    #[should_panic(expected = "Sender has already 3 clones but should've had only one")]
    fn terminal_strict_provider_bad_initialization() {
        let (tx, _rx) = unbounded_channel();
        let _tx_clone_1 = tx.clone();
        let _tx_clone_2 = tx.clone();

        let _ = TerminalWriterStrictProvider::new(tx);
    }

    #[tokio::test]
    async fn terminal_strict_provider_happy_path() {
        let (tx, mut rx) = unbounded_channel();
        let subject = TerminalWriterStrictProvider::new(tx);

        let writer = subject.provide_if_not_already_in_use().unwrap();

        let longest_english_word = "pneumonoultramicroscopicsilicovolcanoconiosis";
        writer.write(longest_english_word).await;
        let received_output = rx.recv().await.unwrap();
        assert_eq!(received_output, longest_english_word)
    }

    #[tokio::test]
    async fn terminal_strict_provider_is_being_strict() {
        let (tx, _rx) = unbounded_channel();
        let subject = TerminalWriterStrictProvider::new(tx);
        let writer = subject.provide_if_not_already_in_use().unwrap();

        let second_attempt_res = subject.provide_if_not_already_in_use();
        drop(writer);
        let third_attempt_res = subject.provide_if_not_already_in_use();
        let _clone_1 = subject.output_chunks_sender.clone();
        let _clone_2 = subject.output_chunks_sender.clone();
        let fourth_attempt_res = subject.provide_if_not_already_in_use();

        let assert_err = |res, expected_reference_count| match res {
            Err(actual_reference_count) => {
                assert_eq!(actual_reference_count, expected_reference_count)
            }
            x => panic!("We expected an error but got: {:?}", x),
        };
        assert_err(second_attempt_res, 1);
        assert!(third_attempt_res.is_ok());
        assert_err(fourth_attempt_res, 3);
    }
}
