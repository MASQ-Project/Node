// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::tcp_wrappers::TcpStreamWrapper;
use sub_lib::sequence_buffer::SequencedPacket;
use sub_lib::sequence_buffer::SequenceBuffer;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt;
use std::io;
use std::net::Shutdown;
use sub_lib::logger::Logger;

pub struct StreamWriter {
    stream: Box<TcpStreamWrapper>,
    peer_addr: String,
    logger: Logger,
    sequence_buffer: SequenceBuffer,
}

impl StreamWriter {
    pub fn new (stream: Box<TcpStreamWrapper>) -> StreamWriter {
        let peer_addr = match stream.peer_addr () {
            Ok (a) => format! ("{}", a),
            Err (_) => String::from ("<unknown>")
        };
        StreamWriter {
            peer_addr,
            stream,
            logger: Logger::new("Proxy Client"),
            sequence_buffer: SequenceBuffer::new(),
        }
    }

    pub fn write(&mut self, packet: SequencedPacket) -> io::Result<()> {
        self.sequence_buffer.push(packet);

        while let Some(packet) = self.sequence_buffer.poll() {
            let data = &packet.data;
            match self.stream.write(data) {
                Err(e) => {
                    self.logger.error (format! ("Error writing {} bytes to {}: {}", data.len (), self.peer_addr (), e));
                    return Err(e);
                },
                Ok(_) => {
                    self.logger.debug (format! ("Wrote {} bytes to {}", data.len (), self.peer_addr ()));
                }
            }

            if packet.last_data {
                return self.stream.shutdown(Shutdown::Both);
            }
        }

        Ok(())
    }
}

impl Debug for StreamWriter {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write! (f, "StreamWriter for {}", self.peer_addr)
    }
}

impl Clone for StreamWriter {
    fn clone(&self) -> Self {
        StreamWriter {
            stream: self.stream.try_clone ().expect ("Error cloning stream"),
            peer_addr: self.peer_addr.clone (),
            logger: self.logger.clone(),
            sequence_buffer: self.sequence_buffer.clone(),
        }
    }
}

impl StreamWriter {
    pub fn peer_addr (&self) -> String {
        self.peer_addr.clone ()
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use local_test_utils::TcpStreamWrapperMock;
    use std::io::Error;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use test_utils::test_utils::init_test_logging;
    use test_utils::test_utils::TestLogHandler;

    #[test]
    fn stream_writer_writes_packets_in_sequenced_order() {
        init_test_logging();
        let packet_a : Vec<u8> = vec!(1, 3, 5, 9, 7);
        let packet_b : Vec<u8> = vec!(2, 4, 10, 8, 6, 3);
        let packet_c : Vec<u8> = vec!(1, 0, 1, 2);

        let stream = TcpStreamWrapperMock::new ()
            .peer_addr_result(Ok(SocketAddr::from_str("1.2.3.4:80").unwrap()))
            .write_result(Ok(packet_a.len()))
            .write_result(Ok(packet_b.len()))
            .write_result(Ok(packet_c.len()))
            .write_result(Ok(0))
            .shutdown_result(Ok(()));

        let write_params_mutex = stream.get_write_parameters();

        let mut subject = StreamWriter::new(Box::new(stream));

        subject.write(SequencedPacket::new(packet_c.clone(), 2, false)).unwrap();
        subject.write(SequencedPacket::new(packet_b.clone(), 1, false)).unwrap();
        subject.write(SequencedPacket::new(vec!(), 3, true)).unwrap();
        subject.write(SequencedPacket::new(packet_a.clone(), 0, false)).unwrap();

        let write_params = write_params_mutex.lock().unwrap();
        assert_eq!(write_params[0], packet_a);
        assert_eq!(write_params[1], packet_b);
        assert_eq!(write_params[2], packet_c);
        assert_eq!(write_params[3], vec!());

        let tlh = TestLogHandler::new();
        tlh.assert_logs_match_in_order(vec!(
            "DEBUG: Proxy Client: Wrote 5 bytes to 1.2.3.4:80",
            "DEBUG: Proxy Client: Wrote 6 bytes to 1.2.3.4:80",
            "DEBUG: Proxy Client: Wrote 4 bytes to 1.2.3.4:80",
            "DEBUG: Proxy Client: Wrote 0 bytes to 1.2.3.4:80"
        ));
    }

    #[test]
    fn stream_writer_saves_peer_addr_when_available() {
        let write_stream = TcpStreamWrapperMock::new()
            .peer_addr_result(Ok(SocketAddr::from_str("1.2.3.4:5678").unwrap()));

        let subject = StreamWriter::new(Box::new(write_stream));

        assert_eq!(subject.peer_addr, String::from("1.2.3.4:5678"));
    }

    #[test]
    fn stream_writer_notes_unknown_peer_addr_when_not_available() {
        let write_stream = TcpStreamWrapperMock::new()
            .peer_addr_result(Err(Error::from(ErrorKind::AddrInUse)));

        let subject = StreamWriter::new(Box::new(write_stream));

        assert_eq!(subject.peer_addr, String::from("<unknown>"));
    }
}