// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use proxy_server::ClientRequestPayload;
use std::cmp::Ordering;
use stream_handler_pool::TransmitDataMsg;
use std::collections::BinaryHeap;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SequencedPacket {
    pub data: Vec<u8>,
    pub sequence_number: u64,
    pub last_data: bool
}

impl Ord for SequencedPacket {
    fn cmp(&self, other: &SequencedPacket) -> Ordering {
        // This can not be self.sequence_number.cmp(&other.sequence_number) since BinaryHeap is a
        // max-heap. We want to retrieve the SequencedPackets with the lowest sequence number first.
        // Therefore, we reverse this to make BinaryHeap behave as a min-heap.
        other.sequence_number.cmp(&self.sequence_number)
    }
}

impl PartialOrd for SequencedPacket {
    fn partial_cmp(&self, other: &SequencedPacket) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> From<&'a ClientRequestPayload> for SequencedPacket {
    fn from(crp: &'a ClientRequestPayload) -> Self {
        SequencedPacket::new(
            crp.data.data.clone(),
            crp.sequence_number,
            crp.last_data
        )
    }
}

impl<'a> From<&'a TransmitDataMsg> for SequencedPacket {
    fn from(tdm: &'a TransmitDataMsg) -> Self {
        SequencedPacket::new(
            tdm.data.clone(),
            tdm.sequence_number.expect("internal error: got TDM with no sequence number"),
            tdm.last_data
        )
    }
}

impl SequencedPacket {
    pub fn new(data: Vec<u8>, sequence_number: u64, last_data: bool) -> SequencedPacket {
        SequencedPacket {
            data,
            sequence_number,
            last_data
        }
    }
}

#[derive(Clone)]
pub struct SequenceBuffer {
    // BinaryHeap is a Priority Queue implemented with a heap. The priority queue allows
    // SequencedPackets to come in in any order and be retrieved in a sorted order.
    buffer: BinaryHeap<SequencedPacket>,
    next_expected_sequence_number: u64
}

impl SequenceBuffer {
    pub fn new() -> SequenceBuffer {
        SequenceBuffer {
            buffer: BinaryHeap::new(),
            next_expected_sequence_number: 0
        }
    }

    pub fn push(&mut self, packet: SequencedPacket) {
        self.buffer.push(packet);
    }

    pub fn poll(&mut self) -> Option<SequencedPacket> {
        if self.buffer.is_empty() {
            None
        } else {
            if self.buffer.peek().expect("internal error").sequence_number == self.next_expected_sequence_number {
                self.next_expected_sequence_number += 1;
                self.buffer.pop()
            } else {
                None
            }
        }
    }

    pub fn repush(&mut self, packet: SequencedPacket) {
        if packet.sequence_number != self.next_expected_sequence_number - 1 {
            panic!("improper use of repush")
        } else {
            self.next_expected_sequence_number = packet.sequence_number;
            self.buffer.push(packet);
        }
    }

    pub fn next_expected(&self) -> u64 {
        self.next_expected_sequence_number
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptde::PlainData;
    use proxy_server::ProxyProtocol;
    use cryptde::Key;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use stream_handler_pool::TransmitDataMsg;
    use dispatcher::Endpoint;

    #[test]
    fn can_create_sequenced_packet_from_client_request_payload() {
        let crp = ClientRequestPayload {
            stream_key: SocketAddr::from_str("1.2.3.4:80").unwrap(),
            last_data: true,
            sequence_number: 2,
            data: PlainData::new(&[1, 2, 3, 5]),
            target_hostname: None,
            target_port: 0,
            protocol: ProxyProtocol::HTTP,
            originator_public_key: Key::new(&[5, 6, 9, 1]),
        };

        let result = SequencedPacket::from(&crp);

        assert_eq!(result.data, vec![1, 2, 3, 5]);
        assert_eq!(result.sequence_number, 2);
        assert!(result.last_data, true);
    }

    #[test]
    #[should_panic(expected="internal error: got TDM with no sequence number")]
    fn panics_when_creating_sequenced_packet_from_transmit_data_msg_with_no_sequence_number() {
        let tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:80").unwrap()),
            last_data: true,
            data: vec![1, 4, 5, 9],
            sequence_number: None,
        };

        let _result = SequencedPacket::from(&tdm);
    }

    #[test]
    fn can_create_sequenced_packet_from_transmit_data_msg() {
        let tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:80").unwrap()),
            last_data: true,
            data: vec![1, 4, 5, 9],
            sequence_number: Some(1),
        };

        let result = SequencedPacket::from(&tdm);

        assert_eq!(result.data, vec![1, 4, 5, 9]);
        assert_eq!(result.sequence_number, 1);
        assert!(result.last_data);
    }

    #[test]
    fn sequence_buffer_reorders_out_of_order_sequenced_packets() {
        let a = SequencedPacket::new(vec!(1, 23, 6, 5), 0, false);
        let b = SequencedPacket::new(vec!(5, 9, 1, 2, 5), 1, false);
        let c = SequencedPacket::new(vec!(1, 1, 1, 1, 0), 2, false);
        let d = SequencedPacket::new(vec!(32, 41, 0, 5, 1, 2, 6), 3, false);
        let e = SequencedPacket::new(vec!(), 4, true);

        let mut subject = SequenceBuffer::new();

        subject.push(b.clone());
        subject.push(d.clone());
        subject.push(a.clone());
        subject.push(e.clone());
        subject.push(c.clone());

        assert_eq!(subject.poll(), Some(a));
        assert_eq!(subject.poll(), Some(b));
        assert_eq!(subject.poll(), Some(c));
        assert_eq!(subject.poll(), Some(d));
        assert_eq!(subject.poll(), Some(e));
        assert_eq!(subject.poll(), None);
    }

    #[test]
    fn sequence_buffer_can_re_add_a_popped_packet() {
        let mut subject = SequenceBuffer::new();
        let a = SequencedPacket::new(vec!(1, 23, 6, 5), 1, false);
        let b = SequencedPacket::new(vec!(5, 9, 1, 2, 5), 2, false);
        let c = SequencedPacket::new(vec!(5, 9, 1, 2, 5), 0, false);

        subject.push(a);
        subject.push(b);
        subject.push(c.clone());

        let thing_we_pushed_back = subject.poll().unwrap();
        assert_eq!(thing_we_pushed_back, c);
        subject.repush(thing_we_pushed_back.clone());
        assert_eq!(subject.poll().unwrap(), thing_we_pushed_back);
    }

    #[test]
    #[should_panic(expected = "improper use of repush")]
    fn repush_panics_if_repushee_sequence_number_is_too_low() {
        let mut subject = SequenceBuffer::new();
        let a = SequencedPacket::new(vec!(1, 23, 6, 5), 1, false);
        let b = SequencedPacket::new(vec!(5, 9, 1, 2, 5), 2, false);
        let c = SequencedPacket::new(vec!(5, 9, 1, 2, 5), 0, false);

        subject.push(a);
        subject.push(b);
        subject.push(c);

        let first_thing_we_pulled_out = subject.poll().unwrap();
        let _second_thing_we_pulled_out = subject.poll().unwrap();
        subject.repush(first_thing_we_pulled_out);
    }
}