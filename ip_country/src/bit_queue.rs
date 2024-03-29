use std::cmp::min;
use std::collections::VecDeque;

#[derive(Default)]
struct EndBuffer {
    buffer: u8,
    bit_count: usize
}

impl EndBuffer {
    fn bits_available(&self) -> usize {
        8 - self.bit_count
    }

    fn set(&mut self, buffer: u8, bit_count: usize) {
        self.buffer = buffer;
        self.bit_count = bit_count;
    }

    fn clear(&mut self) {
        self.buffer = 0;
        self.bit_count = 0;
    }
}

pub struct BitQueue {
    back_buffer: EndBuffer,
    byte_queue: VecDeque<u8>,
    front_buffer: EndBuffer,
}

impl BitQueue {

    pub fn new () -> Self {
        Self {
            back_buffer: EndBuffer::default(),
            byte_queue: VecDeque::new(),
            front_buffer: EndBuffer::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.back_buffer.bit_count + (self.byte_queue.len() * 8) + self.front_buffer.bit_count
    }

    pub fn add_bits(&mut self, bits: u64, count: usize) {
        if (count > 64) {
            panic! ("You can only add bits up to 64 at a time, not {}", count)
        }
        let mut cur_bits = bits;
        let mut cur_count = count;
        loop {
            let available_bits_in_back_buffer = self.back_buffer.bits_available();
            if cur_count < available_bits_in_back_buffer {
                break;
            }
            let transfer_chunk_mask = !(u64::MAX << available_bits_in_back_buffer);
            let transfer_chunk = bits & transfer_chunk_mask;
            let positioned_transfer_chunk = (transfer_chunk << self.back_buffer.bit_count) as u8;
            let new_byte = self.back_buffer.buffer | positioned_transfer_chunk;
            self.byte_queue.push_back(new_byte);
            self.back_buffer.clear();
            cur_bits >>= available_bits_in_back_buffer;
            cur_count -= available_bits_in_back_buffer;
        }
        let available_bits_in_back_buffer = self.back_buffer.bits_available();
        let transfer_chunk_mask = !(u64::MAX << available_bits_in_back_buffer);
        let transfer_chunk = bits & transfer_chunk_mask;
        let positioned_transfer_chunk = (transfer_chunk << self.back_buffer.bit_count) as u8;
        let new_buffer = self.back_buffer.buffer | positioned_transfer_chunk;
        self.back_buffer.set(new_buffer, self.back_buffer.bit_count + cur_count);
    }

    pub fn take_bits(&mut self, count: usize) -> Option<u64> {
        if count > 64 {
            panic!("You can only take bits up to 64 at a time, not {}", count)
        }
        let self_len = self.len();
        if count > self_len {
            return None
        }
        let mut cur_bits = 0u64;
        let mut cur_count = 0usize;
        // Satisfy request from front_buffer if possible
        let bits_needed_from_front_buffer = count.min(self.front_buffer.bit_count);
        cur_bits = (self.front_buffer.buffer as u64) & !(u64::MAX << bits_needed_from_front_buffer);
        cur_count = bits_needed_from_front_buffer;
        self.front_buffer.buffer >>= bits_needed_from_front_buffer;
        self.front_buffer.bit_count -= bits_needed_from_front_buffer;
        if cur_count == count {
            return Some(cur_bits)
        }
        // If not, use byte_queue
        self.front_buffer.clear();
        while (count - cur_count) >= 8 {
            let next_byte = self.byte_queue.pop_front().expect("You said there were enough!");
            cur_bits = (cur_bits << 8) | (next_byte as u64);
            cur_count += 8;
        }
        if self.byte_queue.is_empty() {
            // get remaining bits from back_buffer
            let bits_needed_from_back_buffer = (count - cur_count).min(self.back_buffer.bit_count);
            cur_bits = (self.back_buffer.buffer as u64) & !(u64::MAX << bits_needed_from_back_buffer);
            cur_count += bits_needed_from_back_buffer;
            self.back_buffer.buffer >>= bits_needed_from_back_buffer;
            self.back_buffer.bit_count -= bits_needed_from_back_buffer;
            return Some(cur_bits)
        }
        else {
            // repopulate front_buffer and get remaining bits from it
            self.front_buffer.buffer = self.byte_queue.pop_front().expect("You said there were enough!");
            self.front_buffer.bit_count = 8;
            let bits_still_needed = count - cur_count;
            let bits = self.front_buffer.buffer & !(u8::MAX << bits_still_needed);
            cur_bits = (cur_bits << bits_still_needed) | (bits as u64);
            self.front_buffer.buffer >>= bits_still_needed;
            self.front_buffer.bit_count -= bits_still_needed;
            Some (cur_bits)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_without_writing_produces_none() {
        let mut subject = BitQueue::new();

        let result = subject.take_bits(1);

        assert_eq! (result, None);
    }

    #[test]
    #[should_panic(expected = "You can only add bits up to 64 at a time, not 65")]
    fn adding_more_than_64_bits_causes_panic() {
        let mut subject = BitQueue::new();

        subject.add_bits(0, 65);
    }

    #[test]
    #[should_panic(expected = "You can only take bits up to 64 at a time, not 65")]
    fn taking_more_than_64_bits_causes_panic() {
        let mut subject = BitQueue::new();

        let _ = subject.take_bits(65);
    }

    #[test]
    fn queues_and_unqueues_one_bit() {
        let mut subject = BitQueue::new();

        subject.add_bits(1, 1);
        let one_bit = subject.take_bits(1);
        subject.add_bits(0, 1);
        let zero_bit = subject.take_bits(1);

        assert_eq!(one_bit, Some(1));
        assert_eq!(zero_bit, Some(0));
    }

    #[test]
    fn queues_and_unqueues_32_bits() {
        let mut subject = BitQueue::new();

        subject.add_bits(0xB77BEFDF, 32);
        let result = subject.take_bits(32);

        assert_eq!(result, Some(0xB77BEFDF));
    }

    #[test]
    fn can_queue_bits_properly() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b11011, 5);
        subject.add_bits(0b00111001110011100, 17);
        subject.add_bits(0b1, 1);

        let first_chunk = subject.take_bits(10).unwrap();
        let second_chunk = subject.take_bits(5).unwrap();
        let third_chunk = subject.take_bits(5).unwrap();
        let fourth_chunk = subject.take_bits(3).unwrap();
        let should_be_none = subject.take_bits(1);

        assert_eq!(first_chunk, 0b1101100111);
        assert_eq!(second_chunk, 0b00111);
        assert_eq!(third_chunk, 0b00111);
        assert_eq!(fourth_chunk, 0b001);
        assert_eq!(should_be_none, None);
    }
}

/*
        let mut cur_bits = 0u64;
        let mut cur_count = count;
        if self.front_buffer.bit_count >= cur_count {
            let mask = !(u64::MAX << cur_count);
            cur_bits = self.front_buffer.buffer as u64;
            cur_bits &= mask;
            self.front_buffer.buffer = self.front_buffer.buffer >> cur_bits;
            self.front_buffer.bit_count -= cur_bits;
            return Some(cur_bits)
        }
        // May have bits in the front_buffer still, but not enough to satisfy the request
        cur_bits = self.front_buffer.buffer as u64;
        cur_count -= self.front_buffer.bit_count;
        self.front_buffer.clear();
        while cur_count >= 8 {
            if self.byte_queue.is_empty() {
                return None
            }
            let next_byte = self.byte_queue.pop_front().expect("You said it wasn't empty!");
            cur_bits <<= 8;
            cur_bits &= next_byte as u64;
            cur_count -= 8;
        }


        // Get bits from front_buffer
        // If that's enough, return them
        // If not, pull bytes from queue until there are enough
        // Leave extra bits in front_buffer
 */