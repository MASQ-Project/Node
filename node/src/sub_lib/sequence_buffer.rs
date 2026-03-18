// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
use masq_lib::logger::Logger;
use masq_lib::utils::index_of;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::fmt;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct SequencedPacket {
    pub data: Vec<u8>,
    pub sequence_number: u64,
    pub last_data: bool,
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

impl<'a> From<&'a TransmitDataMsg> for SequencedPacket {
    fn from(tdm: &'a TransmitDataMsg) -> Self {
        SequencedPacket::new(
            tdm.data.clone(),
            tdm.sequence_number_opt.unwrap_or(0),
            tdm.last_data,
        )
    }
}

impl Serialize for SequencedPacket {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![0; self.data.len() + 9];
        bytes[0] = if self.last_data { 1 } else { 0 };
        SequencedPacketVisitor::u64_to(self.sequence_number, &mut bytes[1..9])?;
        bytes[9..(self.data.len() + 9)].copy_from_slice(&self.data);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for SequencedPacket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SequencedPacketVisitor)
    }
}

impl SequencedPacket {
    pub fn new(data: Vec<u8>, sequence_number: u64, last_data: bool) -> SequencedPacket {
        SequencedPacket {
            data,
            sequence_number,
            last_data,
        }
    }
}

struct SequencedPacketVisitor;

impl<'a> Visitor<'a> for SequencedPacketVisitor {
    type Value = SequencedPacket;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a SequencedPacket struct")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let last_data = match &v[0] {
            0 => false,
            1 => true,
            _ => {
                return Err(serde::de::Error::custom(format!(
                    "can't deserialize a bool from {}",
                    v[0]
                )));
            }
        };
        let sequence_number = Self::u64_from(&v[1..9])?;
        Ok(SequencedPacket::new(
            Vec::from(&v[9..]),
            sequence_number,
            last_data,
        ))
    }
}

impl SequencedPacketVisitor {
    fn u64_from<E>(bytes: &[u8]) -> Result<u64, E>
    where
        E: serde::de::Error,
    {
        if bytes.len() != 8 {
            return Err(E::custom(format!(
                "can't make a u64 from {} bytes",
                bytes.len()
            )));
        }
        let mut result = 0u64;
        for byte in bytes {
            result = (result << 8) + u64::from(*byte)
        }
        Ok(result)
    }

    fn u64_to<E>(value: u64, buf: &mut [u8]) -> Result<(), E>
    where
        E: serde::ser::Error,
    {
        if buf.len() != 8 {
            return Err(E::custom(format!(
                "can't serialize a u64 into {} bytes",
                buf.len()
            )));
        }
        let mut remaining = value;
        for idx in 0usize..8usize {
            buf[7 - idx] = (remaining & 0xFF) as u8;
            remaining >>= 8
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SequenceBuffer {
    // BinaryHeap is a Priority Queue implemented with a heap. The priority queue allows
    // SequencedPackets to come in in any order and be retrieved in a sorted order.
    buffer: BinaryHeap<SequencedPacket>,
    next_expected_sequence_number: u64,
    seen_sequence_numbers: Vec<u64>,
    logger: Logger,
}

impl Default for SequenceBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceBuffer {
    pub fn new() -> SequenceBuffer {
        SequenceBuffer {
            buffer: BinaryHeap::new(),
            next_expected_sequence_number: 0,
            seen_sequence_numbers: vec![],
            logger: Logger::new("SequenceBuffer"),
        }
    }

    pub fn push(&mut self, packet: SequencedPacket) {
        if packet.sequence_number >= self.next_expected_sequence_number
            && !self.seen_sequence_numbers.contains(&packet.sequence_number)
        {
            self.seen_sequence_numbers.push(packet.sequence_number);
            self.buffer.push(packet);
        } else {
            warning!(
                self.logger,
                "Dropping packet with duplicate sequence number {}",
                packet.sequence_number
            );
        }
    }

    pub fn poll(&mut self) -> Option<SequencedPacket> {
        if self.buffer.is_empty() {
            None
        } else {
            let sequence_number_to_pop =
                self.buffer.peek().expect("internal error").sequence_number;
            if sequence_number_to_pop == self.next_expected_sequence_number {
                self.next_expected_sequence_number += 1;
                let packet = self.buffer.pop();

                if let Some(index) = index_of(
                    self.seen_sequence_numbers.as_slice(),
                    &[sequence_number_to_pop],
                ) {
                    self.seen_sequence_numbers.remove(index);
                }

                packet
            } else {
                debug!(
                    self.logger,
                    "Buffer waiting for packet #{}", self.next_expected_sequence_number
                );
                None
            }
        }
    }

    pub fn repush(&mut self, packet: SequencedPacket) {
        if packet.sequence_number != self.next_expected_sequence_number - 1 {
            panic!("improper use of repush")
        } else {
            self.next_expected_sequence_number = packet.sequence_number;
            self.seen_sequence_numbers.push(packet.sequence_number);
            self.buffer.push(packet);
        }
    }

    pub fn next_expected(&self) -> u64 {
        self.next_expected_sequence_number
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::dispatcher::Endpoint;
    use crate::sub_lib::stream_handler_pool::TransmitDataMsg;
    use masq_lib::test_utils::logging::init_test_logging;
    use masq_lib::test_utils::logging::TestLogHandler;
    use std::net::SocketAddr;
    use std::str::FromStr;

    #[test]
    fn uses_zero_when_creating_sequenced_packet_from_transmit_data_msg_with_no_sequence_number() {
        let tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:80").unwrap()),
            last_data: true,
            data: vec![1, 4, 5, 9],
            sequence_number_opt: None,
        };

        let result = SequencedPacket::from(&tdm);

        assert_eq!(result.sequence_number, 0)
    }

    #[test]
    fn can_create_sequenced_packet_from_transmit_data_msg() {
        let tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:80").unwrap()),
            last_data: true,
            data: vec![1, 4, 5, 9],
            sequence_number_opt: Some(1),
        };

        let result = SequencedPacket::from(&tdm);

        assert_eq!(result.data, vec![1, 4, 5, 9]);
        assert_eq!(result.sequence_number, 1);
        assert_eq!(result.last_data, true);

        let tdm = TransmitDataMsg {
            endpoint: Endpoint::Socket(SocketAddr::from_str("1.2.3.4:80").unwrap()),
            last_data: false,
            data: vec![4, 2, 5, 67],
            sequence_number_opt: Some(4),
        };

        let result = SequencedPacket::from(&tdm);

        assert_eq!(result.data, vec![4, 2, 5, 67]);
        assert_eq!(result.sequence_number, 4);
        assert_eq!(result.last_data, false);
    }

    #[test]
    fn sequence_buffer_reorders_out_of_order_sequenced_packets() {
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 0, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 1, false);
        let c = SequencedPacket::new(vec![1, 1, 1, 1, 0], 2, false);
        let d = SequencedPacket::new(vec![32, 41, 0, 5, 1, 2, 6], 3, false);
        let e = SequencedPacket::new(vec![], 4, false);

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
    fn sequence_buffer_returns_none_while_waiting_for_next_ordered_sequenced_packet() {
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 0, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 1, false);
        let c = SequencedPacket::new(vec![1, 1, 1, 1, 0], 2, false);
        let d = SequencedPacket::new(vec![32, 41, 0, 5, 1, 2, 6], 3, false);
        let e = SequencedPacket::new(vec![], 4, false);

        let mut subject = SequenceBuffer::new();

        subject.push(b.clone());
        assert_eq!(subject.poll(), None);
        subject.push(d.clone());
        assert_eq!(subject.poll(), None);
        subject.push(a.clone());
        assert_eq!(subject.poll(), Some(a));
        assert_eq!(subject.poll(), Some(b));
        assert_eq!(subject.poll(), None);
        subject.push(e.clone());
        assert_eq!(subject.poll(), None);
        subject.push(c.clone());
        assert_eq!(subject.poll(), Some(c));
        assert_eq!(subject.poll(), Some(d));
        assert_eq!(subject.poll(), Some(e));
        assert_eq!(subject.poll(), None);
    }

    #[test]
    fn sequence_buffer_ignores_packets_with_duplicate_sequence_numbers() {
        init_test_logging();
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 0, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 1, false);
        let b_dup = SequencedPacket::new(vec![6, 8, 2, 3, 6], 1, false);
        let c = SequencedPacket::new(vec![1, 1, 1, 1, 0], 2, false);
        let d = SequencedPacket::new(vec![32, 41, 0, 5, 1, 2, 6], 3, false);
        let e = SequencedPacket::new(vec![], 4, false);

        let mut subject = SequenceBuffer::new();

        subject.push(b.clone());
        assert_eq!(subject.poll(), None);
        subject.push(d.clone());
        assert_eq!(subject.poll(), None);
        subject.push(b_dup.clone());
        assert_eq!(subject.poll(), None);
        subject.push(a.clone());
        assert_eq!(subject.poll(), Some(a));
        assert_eq!(subject.poll(), Some(b));
        assert_eq!(subject.poll(), None);
        subject.push(e.clone());
        assert_eq!(subject.poll(), None);
        subject.push(c.clone());
        assert_eq!(subject.poll(), Some(c));
        assert_eq!(subject.poll(), Some(d));
        assert_eq!(subject.poll(), Some(e));
        assert_eq!(subject.poll(), None);
        TestLogHandler::new().exists_log_containing(
            "WARN: SequenceBuffer: Dropping packet with duplicate sequence number 1",
        );
    }

    #[test]
    fn sequence_buffer_ignores_delayed_duplicate_sequence_number() {
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 0, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 1, false);
        let b_dup = SequencedPacket::new(vec![6, 8, 2, 3, 6], 1, false);
        let c = SequencedPacket::new(vec![1, 1, 1, 1, 0], 2, false);
        let d = SequencedPacket::new(vec![32, 41, 0, 5, 1, 2, 6], 3, false);
        let e = SequencedPacket::new(vec![], 4, false);

        let mut subject = SequenceBuffer::new();

        subject.push(b.clone());
        assert_eq!(subject.poll(), None);
        subject.push(d.clone());
        assert_eq!(subject.poll(), None);
        subject.push(a.clone());
        assert_eq!(subject.poll(), Some(a));
        assert_eq!(subject.poll(), Some(b));
        assert_eq!(subject.poll(), None);
        subject.push(e.clone());
        assert_eq!(subject.poll(), None);
        subject.push(c.clone());
        assert_eq!(subject.poll(), Some(c));
        assert_eq!(subject.poll(), Some(d));
        subject.push(b_dup.clone());
        assert_eq!(subject.poll(), Some(e));
        assert_eq!(subject.poll(), None);
    }

    #[test]
    fn sequence_buffer_does_not_explode_when_popping_a_packet_that_seems_unseen() {
        let a = SequencedPacket::new(vec![1, 2, 3], 0, false);
        let mut subject = SequenceBuffer::new();
        subject.push(a.clone());
        subject.seen_sequence_numbers.clear();

        let result = subject.poll();

        assert_eq!(result, Some(a));
    }

    #[test]
    fn sequence_buffer_can_re_add_a_popped_packet() {
        let mut subject = SequenceBuffer::new();
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 1, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 2, false);
        let c = SequencedPacket::new(vec![5, 9, 1, 2, 5], 0, false);

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
        let a = SequencedPacket::new(vec![1, 23, 6, 5], 1, false);
        let b = SequencedPacket::new(vec![5, 9, 1, 2, 5], 2, false);
        let c = SequencedPacket::new(vec![5, 9, 1, 2, 5], 0, false);

        subject.push(a);
        subject.push(b);
        subject.push(c);

        let first_thing_we_pulled_out = subject.poll().unwrap();
        let _second_thing_we_pulled_out = subject.poll().unwrap();
        subject.repush(first_thing_we_pulled_out);
    }

    #[test]
    fn repush_does_not_interfere_with_ignoring_duplicate_sequence_numbers() {
        let mut subject = SequenceBuffer::new();

        let a = SequencedPacket::new(vec![4, 5, 6], 0, false);
        let b = SequencedPacket::new(vec![89], 1, false);
        let b_imposter = SequencedPacket::new(vec![254, 5, 7], 1, false);
        let c = SequencedPacket::new(vec![89], 2, false);

        subject.push(a.clone());
        subject.push(b.clone());

        assert_eq!(subject.poll(), Some(a));
        assert_eq!(subject.poll(), Some(b.clone()));

        subject.repush(b.clone());

        subject.push(b_imposter);

        assert_eq!(subject.poll(), Some(b));
        assert_eq!(subject.poll(), None);

        subject.push(c.clone());
        assert_eq!(subject.poll(), Some(c));
    }

    #[test]
    fn serialization_and_deserialization_can_talk() {
        let subject_f = SequencedPacket::new(vec![1, 2, 3, 4], 0xFEDBCA9876543210, false);
        let subject_t = SequencedPacket::new(vec![4, 3, 2, 1], 0x0123456789ABCDEF, true);

        let serial_f = serde_cbor::ser::to_vec(&subject_f).unwrap();
        let serial_t = serde_cbor::ser::to_vec(&subject_t).unwrap();

        let result_f = serde_cbor::de::from_slice::<SequencedPacket>(serial_f.as_slice()).unwrap();
        let result_t = serde_cbor::de::from_slice::<SequencedPacket>(serial_t.as_slice()).unwrap();

        assert_eq!(result_f, subject_f);
        assert_eq!(result_t, subject_t);
    }
}
