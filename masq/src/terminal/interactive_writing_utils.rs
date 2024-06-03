// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::interactive_terminal_interface::FlushHandleInnerForInteractiveMode;
use crate::terminal::liso_wrappers::LisoOutputWrapper;
use crate::terminal::{FlushHandle, FlushHandleInner, TerminalWriter};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub struct WritingUtils {
    terminal_writer_strict_provider: TerminalWriterStrictProvider,
    flush_handle: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
}

impl WritingUtils {
    pub fn new(write_liso_arc: Arc<dyn LisoOutputWrapper>) -> Self {
        let (output_chunks_sender, output_chunks_receiver) = unbounded_channel();
        let terminal_writer_strict_provider =
            TerminalWriterStrictProvider::new(output_chunks_sender);
        let flush_handle = Arc::new(tokio::sync::Mutex::new(
            FlushHandleInnerForInteractiveMode::new(write_liso_arc, output_chunks_receiver),
        ));
        Self {
            terminal_writer_strict_provider,
            flush_handle,
        }
    }

    pub fn utils(&self) -> Result<(TerminalWriter, FlushHandle), usize> {
        self.terminal_writer_strict_provider
            .provide_if_not_already_in_use()
            .map(|terminal_writer| (terminal_writer, FlushHandle::new(self.flush_handle.clone())))
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

    pub fn provide_if_not_already_in_use(&self) -> Result<TerminalWriter, usize> {
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
    use crate::terminal::interactive_writing_utils::TerminalWriterStrictProvider;
    use crate::terminal::test_utils::LisoOutputWrapperMock;
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
        let (tx, mut rx) = unbounded_channel();
        let subject = TerminalWriterStrictProvider::new(tx);

        let writer = subject.provide_if_not_already_in_use().unwrap();
        let second_writer_opt = subject.provide_if_not_already_in_use();
        let third_writer_opt = subject.provide_if_not_already_in_use();
        drop(writer);
        let fourth_writer_opt = subject.provide_if_not_already_in_use();
        let fifth_writer_opt = subject.provide_if_not_already_in_use();
        todo!()
    }
}
