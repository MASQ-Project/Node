use sub_lib::tcp_wrappers::TcpStreamWrapper;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt;
use std::io::Write;
use std::io;

pub struct StreamWriter {
    stream: Box<TcpStreamWrapper>,
    peer_addr: String,
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
        }
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
        }
    }
}

impl Write for StreamWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write (buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
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