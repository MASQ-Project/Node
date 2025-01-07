// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::sub_lib::sequence_buffer::SequenceBuffer;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::tokio_wrappers::WriteHalfWrapper;
use crate::sub_lib::utils::indicates_dead_stream;
use masq_lib::logger::Logger;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use crate::sub_lib::channel_wrappers::ReceiverWrapper;

pub struct StreamWriter {
    stream: Box<dyn WriteHalfWrapper>,
    peer_addr: SocketAddr,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
    rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
    shutting_down: bool,
}

impl StreamWriter {
    pub fn new(
        stream: Box<dyn WriteHalfWrapper>,
        peer_addr: SocketAddr,
        rx_to_write: Box<dyn ReceiverWrapper<SequencedPacket>>,
        stream_key: StreamKey,
    ) -> StreamWriter {
        let name = format!("StreamWriter for {:?}/{}", stream_key, peer_addr);
        let logger = Logger::new(&name[..]);
        StreamWriter {
            stream,
            peer_addr,
            logger,
            sequence_buffer: SequenceBuffer::new(),
            rx_to_write,
            shutting_down: false,
        }
    }

    pub async fn future(mut self) -> io::Result<()> {
        loop {
            if self.shutting_down {
                return self.shutdown().await;
            }

            let read_result = self.read_data_from_channel().await;
            let write_result = self.write_from_buffer_to_stream().await;

            match (read_result, write_result) {
                (_, Err(e)) => {
                    // TODO: Drive this in:
                    // if indicates_dead_stream(e.kind()) {
                    //     error!(
                    //         self.logger,
                    //         "Error writing {} bytes: {}",
                    //         self.sequence_buffer.len(),
                    //         e
                    //     );
                    //     return Err(e);
                    // } else {
                    //     warning!(self.logger, "Continuing after write error: {}", e);
                    // }
                    return Err(e)
                },
                (_, wr) => (),
            }
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await
    }

    // TODO: This isn't the right way to do this. We're saving up all incoming data until we
    // have all of it, and then passing it on down the TCP stream in one big rush. We should be
    // holding data only until the first part of our buffer has no holes in it, and then passing
    // that first part on. In other words, whenever the first slot in the buffer is not blank,
    // we should send it.
    async fn read_data_from_channel(&mut self) -> Result<(), ()> {
        loop {
            match self.rx_to_write.recv().await {
                Some(sequenced_packet) => {
                    self.sequence_buffer.push(sequenced_packet);
                }
                None => return Ok(()),
            };
        }
    }

    async fn write_from_buffer_to_stream(&mut self) -> io::Result<()> {
        loop {
            let packet_opt = self.sequence_buffer.poll();

            match packet_opt {
                Some(packet) => {
                    debug!(
                        self.logger,
                        "Writing {} bytes over existing stream",
                        packet.data.len()
                    );
                    match self.stream.write(&packet.data).await {
                        Err(e) => {
                            if indicates_dead_stream(e.kind()) {
                                error!(
                                    self.logger,
                                    "Error writing {} bytes: {}",
                                    packet.data.len(),
                                    e
                                );
                                return Err(e);
                            } else {
                                // TODO this could be exploitable and inefficient: if we keep getting non-dead-stream errors, we go into a tight loop and do not return
                                warning!(self.logger, "Continuing after write error: {}", e);
                                self.sequence_buffer.repush(packet);
                            }
                        }
                        Ok(bytes_written_count) => {
                            debug!(
                                self.logger,
                                "Wrote {}/{} bytes of clear data (#{})",
                                bytes_written_count,
                                &packet.data.len(),
                                &packet.sequence_number
                            );
                            if bytes_written_count != packet.data.len() {
                                debug!(
                                    self.logger,
                                    "rescheduling {} bytes",
                                    packet.data.len() - bytes_written_count
                                );
                                self.sequence_buffer.repush(SequencedPacket::new(
                                    packet
                                        .data
                                        .iter()
                                        .skip(bytes_written_count)
                                        .cloned()
                                        .collect(),
                                    packet.sequence_number,
                                    packet.last_data,
                                ));
                            } else if packet.last_data {
                                debug!(self.logger, "Shutting down stream to server at {} in response to client-drop report", self.peer_addr);
                                self.shutting_down = true;
                                return self.shutdown().await;
                            }
                        }
                    }
                }
                None => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::channel_wrapper_mocks::ReceiverWrapperMock;
    use crate::test_utils::make_meaningless_stream_key;
    use crate::test_utils::tokio_wrapper_mocks::WriteHalfWrapperMock;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn stream_writer_writes_packets_in_sequenced_order() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
        let packet_b: Vec<u8> = vec![2, 4, 10, 8, 6, 3];
        let packet_c: Vec<u8> = vec![1, 0, 1, 2];
        let stream_key = make_meaningless_stream_key();
        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(packet_c.clone(), 2, false)))
            .recv_result(Some(SequencedPacket::new(packet_b.clone(), 1, false)))
            .recv_result(Some(SequencedPacket::new(vec![], 3, false)))
            .recv_result(Some(SequencedPacket::new(packet_a.clone(), 0, false)))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(packet_a.len()))
            .write_result(Ok(packet_b.len()))
            .write_result(Ok(packet_c.len()))
            .write_result(Ok(0));
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        let _res = subject.future().await;

        let write_params = write_params_arc.lock().unwrap();

        assert_eq!(write_params[0], packet_a);
        assert_eq!(write_params[1], packet_b);
        assert_eq!(write_params[2], packet_c);
        let empty_packet: Vec<u8> = vec![];
        assert_eq!(write_params[3], empty_packet);

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 6 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 6/6 bytes of clear data",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 4 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 4/4 bytes of clear data",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 0 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 0/0 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);
    }

    #[tokio::test]
    async fn stream_writer_logs_error_and_continues_when_it_gets_a_non_dead_stream_error() {
        init_test_logging();
        let text_data = b"These are the times";
        let stream_key = make_meaningless_stream_key();
        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(text_data.to_vec(), 0, false)))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Err(Error::from(ErrorKind::Other)))
            .write_result(Ok(text_data.len()));
        let peer_addr = SocketAddr::from_str("1.3.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        subject.future().await.unwrap();

        assert_eq!(write_params_arc.lock().unwrap().len(), 2);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec!(
            format!("DEBUG: StreamWriter for {:?}/1.3.3.4:5678: Writing 19 bytes over existing stream", stream_key).as_str (),
            format!("WARN: StreamWriter for {:?}/1.3.3.4:5678: Continuing after write error: other error", stream_key).as_str (),
            format!("DEBUG: StreamWriter for {:?}/1.3.3.4:5678: Wrote 19/19 bytes of clear data", stream_key).as_str ()));
    }

    #[tokio::test]
    async fn stream_writer_attempts_to_write_until_successful_before_reading_new_messages_from_channel() {
        let stream_key = make_meaningless_stream_key();
        let first_data = &b"These are the times"[..];
        let second_data = &b"These are the other times"[..];

        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(first_data.to_vec(), 0, false)))
            .recv_result(Some(SequencedPacket::new(second_data.to_vec(), 1, false)))
            .recv_result(None);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Err(Error::from(ErrorKind::Other)))
            .write_result(Ok(first_data.len()))
            .write_result(Ok(second_data.len()));
        let peer_addr = SocketAddr::from_str("1.2.3.9:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        let result = subject.future().await;

        assert_eq!(result.is_ok(), true);

        let mut params = write_params_arc.lock().unwrap();
        assert_eq!(params.len(), 3);
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), first_data.to_vec());
        assert_eq!(params.remove(0), second_data.to_vec());
    }

    #[tokio::test]
    async fn stream_writer_exits_if_channel_is_closed() {
        let stream_key = make_meaningless_stream_key();
        let rx_to_write = set_up_standard_results(
            ReceiverWrapperMock::new(),
            &b"These are the times".to_vec()
        );
        let writer = WriteHalfWrapperMock::new()
            .write_result(Ok(19));
        let peer_addr = SocketAddr::from_str("1.2.3.4:999").unwrap();
        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        let result = subject.future().await;

        assert_eq!(result.is_ok(), true);
    }

    #[tokio::test]
    async fn dead_stream_error_generates_log_and_returns_err() {
        init_test_logging();
        let stream_key = make_meaningless_stream_key();
        let rx_to_write = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(b"These are the times".to_vec(), 0, false)))
            .recv_result(None);
        let writer = WriteHalfWrapperMock::new()
            .write_result(Err(Error::from(ErrorKind::BrokenPipe)));
        let mut subject = StreamWriter::new(
            Box::new(writer),
            SocketAddr::from_str("2.3.4.5:80").unwrap(),
            Box::new(rx_to_write),
            stream_key,
        );

        let result = subject.future().await;

        assert_eq!(result.err().unwrap().kind(), ErrorKind::BrokenPipe);
        TestLogHandler::new().exists_log_containing(
            format!(
                "ERROR: StreamWriter for {:?}/2.3.4.5:80: Error writing 19 bytes: broken pipe",
                stream_key
            )
            .as_str(),
        );
    }

    // TODO: I don't think this test is necessary anymore, because I think async takes care of
    // things at this level.
    // #[test]
    // fn stream_writer_reattempts_writing_packets_that_were_prevented_by_not_ready() {
    //     let stream_key = make_meaningless_stream_key();
    //     let mut rx = Box::new(ReceiverWrapperMock::new());
    //     rx.poll_results = vec![
    //         Poll::Ready(Ok(Some(SequencedPacket {
    //             data: b"These are the times".to_vec(),
    //             sequence_number: 0,
    //             last_data: false,
    //         }))),
    //         Poll::Pending,
    //         Poll::Pending,
    //     ];
    //
    //     let writer = WriteHalfWrapperMock::new()
    //         .poll_write_result(Poll::Pending)
    //         .poll_write_result(Poll::Ready(Ok(19)))
    //         .poll_write_result(Poll::Pending);
    //
    //     let write_params = writer.poll_write_params.clone();
    //     let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();
    //
    //     let mut subject = StreamWriter::new(Box::new(writer), peer_addr, rx, stream_key);
    //
    //     let result = subject.poll();
    //     assert_eq!(result, Poll::Pending);
    //
    //     let result = subject.poll();
    //     assert_eq!(result, Poll::Pending);
    //
    //     assert_eq!(write_params.lock().unwrap().len(), 2);
    // }

    #[tokio::test]
    async fn stream_writer_resubmits_partial_packet_when_written_len_is_less_than_packet_len() {
        let stream_key = make_meaningless_stream_key();
        let rx = ReceiverWrapperMock::new()
            .recv_result(Some(SequencedPacket::new(b"worlds".to_vec(), 0, false)));

        let write_params_arc = Arc::new(Mutex::new(vec![vec![]]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(3))
            .write_result(Ok(2))
            .write_result(Ok(1));
        let peer_addr = SocketAddr::from_str("1.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx), stream_key);

        let result = subject.future().await;
        assert_eq!(result.is_ok(), true);

        let write_params = write_params_arc.lock().unwrap();
        assert_eq!(*write_params, vec![b"worlds".to_vec(), b"lds".to_vec(), b"s".to_vec()]);
    }

    #[tokio::test]
    async fn stream_writer_shuts_down_stream_after_writing_last_data() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
        let stream_key = make_meaningless_stream_key();
        let rx_to_write = set_up_standard_results(ReceiverWrapperMock::new(), &packet_a);
        let write_params_arc = Arc::new(Mutex::new(vec![]));
        let shutdown_params_arc = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_arc)
            .write_result(Ok(packet_a.len()))
            .shutdown_params(&shutdown_params_arc)
            .shutdown_result(Ok(()));
        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();
        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        let res = subject.future().await;

        let write_params = write_params_arc.lock().unwrap();
        assert_eq!(write_params[0], packet_a);
        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);
        assert_eq!(res.is_ok(), true);
        let shutdown_params = shutdown_params_arc.lock().unwrap();
        assert_eq!(shutdown_params.len(), 1);
    }

    // TODO: I think we don't need this test anymore, since we don't get Poll::Pending anymore
    // #[tokio::test]
    // async fn stream_writer_returns_not_ready_when_shutdown_is_not_ready_and_retries_on_next_poll() {
    //     init_test_logging();
    //     let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];
    //
    //     let stream_key = make_meaningless_stream_key();
    //
    //     let rx_to_write = set_up_standard_results(ReceiverWrapperMock::new(), &packet_a);
    //
    //     let writer = WriteHalfWrapperMock {
    //         poll_write_params: Arc::new(Mutex::new(vec![])),
    //         poll_write_results: vec![Poll::Ready(Ok(packet_a.len()))],
    //         poll_close_results: Arc::new(Mutex::new(vec![Poll::Pending, Poll::Ready(Ok(()))])),
    //     };
    //
    //     let shutdown_remainder = writer.poll_close_results.clone();
    //     let write_params_mutex = writer.poll_write_params.clone();
    //     let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();
    //
    //     let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);
    //
    //     let res = subject.future().await;
    //
    //     let write_params = write_params_mutex.lock().unwrap();
    //
    //     assert_eq!(write_params[0], packet_a);
    //
    //     let tlh = TestLogHandler::new();
    //     tlh.assert_logs_contain_in_order(vec![
    //         format!(
    //             "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes over existing stream",
    //             stream_key
    //         )
    //         .as_str(),
    //         format!(
    //             "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
    //             stream_key
    //         )
    //         .as_str(),
    //     ]);
    //
    //     assert_eq!(res, Poll::Pending);
    //     assert_eq!(shutdown_remainder.lock().unwrap().len(), 1);
    //
    //     let res = subject.future().await;
    //     assert_eq!(res, Ok(()));
    //     assert_eq!(shutdown_remainder.lock().unwrap().len(), 0);
    // }

    #[tokio::test]
    async fn stream_writer_returns_error_when_shutdown_returns_error() {
        init_test_logging();
        let packet_a: Vec<u8> = vec![1, 3, 5, 9, 7];

        let stream_key = make_meaningless_stream_key();

        let rx_to_write = set_up_standard_results(ReceiverWrapperMock::new(), &packet_a);

        let write_params_mutex = Arc::new(Mutex::new(vec![]));
        let writer = WriteHalfWrapperMock::new()
            .write_params(&write_params_mutex)
            .write_result(Ok(packet_a.len()))
            .shutdown_result(Err(Error::from(ErrorKind::Other)));

        let peer_addr = SocketAddr::from_str("2.2.3.4:5678").unwrap();

        let mut subject = StreamWriter::new(Box::new(writer), peer_addr, Box::new(rx_to_write), stream_key);

        let result = subject.future().await;

        let write_params = write_params_mutex.lock().unwrap();

        assert_eq!(write_params[0], packet_a);

        let tlh = TestLogHandler::new();
        tlh.assert_logs_contain_in_order(vec![
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Writing 5 bytes over existing stream",
                stream_key
            )
            .as_str(),
            format!(
                "DEBUG: StreamWriter for {:?}/2.2.3.4:5678: Wrote 5/5 bytes of clear data",
                stream_key
            )
            .as_str(),
        ]);

        assert_eq!(result.err().unwrap().kind(), ErrorKind::Other);
    }

    fn set_up_standard_results(
        rx_to_write: ReceiverWrapperMock<SequencedPacket>,
        packet_a: &Vec<u8>
    ) -> ReceiverWrapperMock<SequencedPacket> {
        rx_to_write
            .recv_result(
                Some(SequencedPacket {
                    data: packet_a.to_vec(),
                    sequence_number: 0,
                    last_data: true,
                })
            )
            .recv_result(None)
    }
}
