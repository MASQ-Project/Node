// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::limiter::Limiter;
use packet_server::PacketServerTrait;

pub struct Server {}

impl Server {
    pub fn start (&mut self, limiter: &mut Limiter, packet_server: &mut PacketServerTrait) -> u8 {
        let mut buf: [u8; 65536] = [0; 65536];
        while limiter.should_continue () {
            packet_server.serve (&mut buf);
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PacketServerFake {
        buf_sizes: Vec<usize>,
        call_count: u32
    }

    impl PacketServerTrait for PacketServerFake {
        fn serve(&mut self, buf: &mut [u8]) {
            self.buf_sizes.push (buf.len ());
            self.call_count += 1
        }
    }

    impl PacketServerFake {
        fn new () -> PacketServerFake {
            PacketServerFake {buf_sizes: vec![], call_count: 0}
        }
    }

    #[test]
    pub fn runs_two_iterations () {
        let mut limiter = Limiter::with_only (2);
        let mut packet_server = PacketServerFake::new ();
        let mut subject = Server {};

        let result = subject.start (&mut limiter, &mut packet_server);

        assert_eq! (packet_server.buf_sizes, vec![65536, 65536]);
        assert_eq! (packet_server.call_count, 2);
        assert_eq! (result, 0);
    }
}
