// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use crate::terminal::{FlushHandle, TerminalWriter};
use crate::terminal::interactive_terminal_interface::InteractiveModeFlushHandle;
use crate::terminal::liso_wrappers::LisoOutputWrapper;

pub struct WritingUtils{
    terminal_writer_strict_provider: TerminalWriterStrictProvider,
    flush_handle: Arc<dyn FlushHandle>
}

impl WritingUtils{
    pub fn new(write_liso_arc: Arc<dyn LisoOutputWrapper>) -> Self{
        let (output_chunks_sender, output_chuckns_receiver) = unbounded_channel();
        let terminal_writer_strict_provider = TerminalWriterStrictProvider::new(output_chunks_sender);
        Self{
            terminal_writer_strict_provider,
            flush_handle: Arc::new(InteractiveModeFlushHandle::new(write_liso_arc, output_chuckns_receiver))
        }
    }

    pub fn utils(&self)->Option<((TerminalWriter, Box<dyn FlushHandle>))>{
        todo!()
    }
}


pub struct TerminalWriterStrictProvider {
    output_chunks_sender: UnboundedSender<String>
}

impl TerminalWriterStrictProvider {
    pub fn new(output_chunks_sender: UnboundedSender<String>)->Self{
        let current_tx_count = output_chunks_sender.strong_count();
        if current_tx_count > 1 {
            todo!()
        }
        Self{
            output_chunks_sender
        }
    }

    pub fn provide_opt(&self) -> Option<TerminalWriter>{
        todo!()
    }
}


#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::unbounded_channel;
    use crate::terminal::interactive_writing_utils::TerminalWriterStrictProvider;
    use crate::terminal::test_utils::LisoOutputWrapperMock;

    #[test]
    #[should_panic(expected = "Sender has already two clones but should've had only one")]
    fn terminal_strict_provider_bad_initialization(){
        let (tx,_rx) = unbounded_channel();
        let _tx_clone = tx.clone();

        let _ = TerminalWriterStrictProvider::new(tx);
    }

    #[tokio::test]
    async fn terminal_strict_provider_happy_path(){
        let (tx, mut rx) = unbounded_channel();
        let subject = TerminalWriterStrictProvider::new(tx);

        let writer = subject.provide_opt().unwrap();

        let longest_english_word = "pneumonoultramicroscopicsilicovolcanoconiosis";
        writer.write(longest_english_word).await;
        let received_output = rx.recv().await.unwrap();
        assert_eq!(received_output, longest_english_word)
    }

    #[tokio::test]
    async fn terminal_strict_provider_is_being_strict(){
        let (tx, mut rx) = unbounded_channel();
        let subject = TerminalWriterStrictProvider::new(tx);

        let writer = subject.provide_opt().unwrap();
        let second_writer_opt = subject.provide_opt();
        let third_writer_opt = subject.provide_opt();
        drop(writer);
        let fourth_writer_opt = subject.provide_opt();
        let fifth_writer_opt = subject.provide_opt();


    }
}
