// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::terminal::interactive_terminal_interface::InteractiveFlushHandleInner;
use crate::terminal::liso_wrappers::LisoOutputWrapper;
use crate::terminal::{FlushHandle, FlushHandleInner, TerminalWriter};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub struct WritingUtils {
    terminal_writer_strict_provider: TerminalWriterStrictProvider,
    flush_handle_inner: Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
}

pub type ArcMutexFlushHandleInner = Arc<tokio::sync::Mutex<dyn FlushHandleInner>>;

impl WritingUtils {
    pub fn new<FHIConstructor>(flush_handle_inner_constructor: FHIConstructor) -> Self
    where
        FHIConstructor:
            FnOnce(UnboundedReceiver<String>) -> Arc<tokio::sync::Mutex<dyn FlushHandleInner>>,
    {
        let (output_chunks_sender, output_chunks_receiver) = unbounded_channel();
        let terminal_writer_strict_provider =
            TerminalWriterStrictProvider::new(output_chunks_sender);
        Self {
            terminal_writer_strict_provider,
            flush_handle_inner: flush_handle_inner_constructor(output_chunks_receiver),
        }
    }

    fn utils(&self) -> Result<(TerminalWriter, FlushHandle), usize> {
        self.terminal_writer_strict_provider
            .provide_if_not_already_in_use()
            .map(|terminal_writer| {
                (
                    terminal_writer,
                    FlushHandle::new(self.flush_handle_inner.clone()),
                )
            })
    }

    pub fn get_utils(&self, stream_ranking: &str) -> (TerminalWriter, FlushHandle) {
        self.terminal_writer_strict_provider
            .provide_if_not_already_in_use()
            .map(|terminal_writer| {
                (
                    terminal_writer,
                    FlushHandle::new(self.flush_handle_inner.clone()),
                )
            })
            .unwrap_or_else(|count| {
                panic!(
                "Another {stream_ranking} FLushHandle not permitted, already referencing {count}"
            )
            })
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
    use crate::terminal::test_utils::LisoOutputWrapperMock;
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
