use std::collections::VecDeque;

#[derive(Debug)]
pub struct BitQueue {
    back_blank_bit_count: usize, // number of high-order bits in the back byte of the queue that are unused
    byte_queue: VecDeque<u8>,
    front_blank_bit_count: usize, // number of low-order bits in the front byte of the queue that are unused
}

impl BitQueue {
    pub fn new() -> Self {
        let byte_queue = VecDeque::from(vec![0, 0]);
        Self {
            back_blank_bit_count: 8,
            byte_queue,
            front_blank_bit_count: 8,
        }
    }

    pub fn len(&self) -> usize {
        (self.byte_queue.len() * 8) - self.back_blank_bit_count - self.front_blank_bit_count
    }

    #[allow(unused_assignments)]
    pub fn add_bits(&mut self, mut bit_data: u64, mut bit_count: usize) {
        if bit_count > 64 {
            panic!(
                "You can only add bits up to 64 at a time, not {}",
                bit_count
            )
        }
        let initial_bits_added = self.add_some_back_bits(bit_data, bit_count);
        bit_data >>= initial_bits_added;
        bit_count -= initial_bits_added;
        let byte_bits_added = self.add_back_bytes(bit_data, bit_count);
        bit_data >>= byte_bits_added;
        bit_count -= byte_bits_added;
        let final_bits_added = self.add_some_back_bits(bit_data, bit_count);
        bit_data >>= final_bits_added;
        bit_count -= final_bits_added;
        if bit_count != 0 {
            panic!("Didn't add all the bits: {} left", bit_count);
        }
    }

    #[allow(unused_assignments)]
    pub fn take_bits(&mut self, mut bit_count: usize) -> Option<u64> {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic!(
                "You can only take bits up to 64 at a time, not {}",
                bit_count
            )
        }
        if bit_count > self.len() {
            return None;
        }
        let mut bit_data = 0u64;
        let mut bit_position = 0usize;
        let (initial_bit_data, initial_bit_count) = self.take_some_front_bits(bit_count);
        bit_data |= initial_bit_data << bit_position;
        bit_position += initial_bit_count;
        bit_count -= initial_bit_count;
        let (byte_bit_data, byte_bit_count) = self.take_front_bytes(bit_count);
        bit_data |= byte_bit_data << bit_position;
        bit_position += byte_bit_count;
        bit_count -= byte_bit_count;
        let (final_front_bit_data, final_front_bit_count) = self.take_some_front_bits(bit_count);
        if final_front_bit_count > 0 {
            bit_data |= final_front_bit_data << bit_position;
            bit_position += final_front_bit_count;
        }
        bit_count -= final_front_bit_count;
        let (final_back_bit_data, final_back_bit_count) = self.take_some_back_bits(bit_count);
        if final_back_bit_count > 0 {
            bit_data |= final_back_bit_data << bit_position;
            bit_position += final_back_bit_count;
        }
        bit_count -= final_back_bit_count;
        if bit_position != original_bit_count {
            panic!(
                "Wanted {} bits, but got {} instead",
                original_bit_count, bit_position
            );
        }
        return Some(bit_data);
    }

    fn back_full_bit_count(&self) -> usize {
        8 - self.back_blank_bit_count
    }

    fn front_full_bit_count(&self) -> usize {
        8 - self.front_blank_bit_count
    }

    fn low_order_ones(count: usize) -> u64 {
        !(u64::MAX << count)
    }

    #[allow(dead_code)]
    fn dump_queue(&self) -> String {
        let queue_str = self
            .byte_queue
            .iter()
            .map(|b| format!("{:08b}", *b))
            .rev()
            .collect::<Vec<String>>()
            .join(" ");
        format!(
            "{}->{}->{}",
            self.back_blank_bit_count, queue_str, self.front_blank_bit_count
        )
    }

    fn add_some_back_bits(&mut self, bit_data: u64, bit_count: usize) -> usize {
        if self.back_blank_bit_count == 0 {
            self.byte_queue.push_back(0);
            self.back_blank_bit_count = 8;
        }
        let bits_to_add = bit_count.min(self.back_blank_bit_count);
        let back_full_bit_count = self.back_full_bit_count();
        let back_ref = self
            .byte_queue
            .back_mut()
            .expect("There should be a back byte");
        *back_ref |= (bit_data << back_full_bit_count) as u8;
        self.back_blank_bit_count -= bits_to_add;
        if self.back_blank_bit_count == 0 {
            self.byte_queue.push_back(0);
            self.back_blank_bit_count = 8;
        }
        return bits_to_add;
    }

    fn add_back_bytes(&mut self, mut bit_data: u64, mut bit_count: usize) -> usize {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic!(
                "add_back_bytes() can add a maximum of 64 bits per call, not {}",
                bit_count
            )
        }
        if bit_count < 8 {
            return 0;
        }
        if self.back_blank_bit_count == 8 {
            let _ = self.byte_queue.pop_back();
            self.back_blank_bit_count = 0;
        }
        if self.back_blank_bit_count > 0 {
            panic!(
                "add_back_bytes() only works when there are no back blank bits, not {}",
                self.back_blank_bit_count
            )
        }
        while bit_count >= 8 {
            let next_byte = (bit_data & Self::low_order_ones(8)) as u8;
            self.byte_queue.push_back(next_byte);
            bit_data >>= 8;
            bit_count -= 8;
        }
        return original_bit_count - bit_count;
    }

    fn take_some_front_bits(&mut self, bit_count: usize) -> (u64, usize) {
        if (self.front_full_bit_count() == 0) && (self.byte_queue.len() > 2) {
            let _ = self.byte_queue.pop_front();
            self.front_blank_bit_count = 0;
        }
        let bits_to_take = bit_count.min(self.front_full_bit_count());
        if bits_to_take == 0 {
            return (0, 0);
        }
        let front_ref = self
            .byte_queue
            .front_mut()
            .expect("There should be a front byte");
        let bit_data = *front_ref & (Self::low_order_ones(bits_to_take) as u8);
        *front_ref = if bits_to_take < 8 {
            *front_ref >> bits_to_take
        } else {
            0
        };
        self.front_blank_bit_count += bits_to_take;
        if (self.front_blank_bit_count == 8) && (self.byte_queue.len() > 2) {
            let _ = self.byte_queue.pop_front();
            self.front_blank_bit_count = 0;
        }
        return (bit_data as u64, bits_to_take);
    }

    fn take_front_bytes(&mut self, mut bit_count: usize) -> (u64, usize) {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic!(
                "take_front_bytes() can take a maximum of 64 bits per call, not {}",
                bit_count
            )
        }
        if bit_count < 8 {
            return (0, 0);
        }
        if self.front_blank_bit_count == 8 {
            let _ = self.byte_queue.pop_front();
            self.front_blank_bit_count = 0;
        }
        if self.front_blank_bit_count > 0 {
            panic!(
                "take_front_bytes() only works when there are no front blank bits, not {}",
                self.front_blank_bit_count
            )
        }
        let mut bit_data = 0u64;
        while bit_count >= 8 {
            let byte = self
                .byte_queue
                .pop_front()
                .expect("Demanded too many bytes") as u64;
            bit_data |= byte << (original_bit_count - bit_count);
            bit_count -= 8;
        }
        if self.byte_queue.len() < 2 {
            self.byte_queue.push_front(0);
            self.front_blank_bit_count = 8;
        }
        return (bit_data, original_bit_count - bit_count);
    }

    fn take_some_back_bits(&mut self, bit_count: usize) -> (u64, usize) {
        let bits_to_take = bit_count.min(self.back_full_bit_count());
        let remaining_bits = self.back_full_bit_count() - bits_to_take;
        let mask = Self::low_order_ones(bits_to_take);
        let back_ref = self
            .byte_queue
            .back_mut()
            .expect("There should be a back byte");
        let bit_data = if remaining_bits < 8 {
            *back_ref & (mask as u8)
        } else {
            0
        };
        *back_ref >>= bits_to_take;
        self.back_blank_bit_count += bits_to_take;
        if (self.back_blank_bit_count == 8) && (self.byte_queue.len() > 2) {
            let _ = self.byte_queue.pop_back();
            self.back_blank_bit_count = 0;
        }
        return (bit_data as u64, bits_to_take);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_without_writing_produces_none() {
        let mut subject = BitQueue::new();

        let result = subject.take_bits(1);

        assert_eq!(result, None);
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
    fn queues_and_unqueues_seven_bits() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b1101101, 7);
        let seven_bits = subject.take_bits(7).unwrap();

        assert_bit_field(seven_bits, 0b1101101);
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn queues_and_unqueues_nine_bits() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b110110111, 9);
        let nine_bits = subject.take_bits(9).unwrap();

        assert_bit_field(nine_bits, 0b110110111);
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn nine_and_seven_then_nine_and_seven() {
        let mut subject = BitQueue::new();
        let sixteen_bits = 0b1000001100000001u64;
        // let sixteen_bits = 0b1100111010101100u64;

        subject.add_bits(sixteen_bits & 0x1FF, 9);
        assert_eq!(subject.len(), 9);
        subject.add_bits(sixteen_bits >> 9, 7);
        assert_eq!(subject.len(), 16);
        let nine_bits = subject.take_bits(9).unwrap();
        assert_eq!(subject.len(), 7);
        let seven_bits = subject.take_bits(7).unwrap();
        assert_eq!(subject.len(), 0);

        assert_bit_field(nine_bits, sixteen_bits & 0x1FF);
        assert_bit_field(seven_bits, sixteen_bits >> 9);
    }

    #[test]
    fn nine_and_seven_then_seven_and_nine() {
        let mut subject = BitQueue::new();
        let sixteen_bits = 0b1000000110000001u64;
        // let sixteen_bits = 0b1100111010101100u64;

        subject.add_bits(sixteen_bits & 0x1FF, 9);
        assert_eq!(subject.len(), 9);
        subject.add_bits(sixteen_bits >> 9, 7);
        assert_eq!(subject.len(), 16);
        let seven_bits = subject.take_bits(7).unwrap();
        assert_eq!(subject.len(), 9);
        let nine_bits = subject.take_bits(9).unwrap();
        assert_eq!(subject.len(), 0);

        assert_bit_field(seven_bits, sixteen_bits & 0x7F);
        assert_bit_field(nine_bits, sixteen_bits >> 7);
    }

    #[test]
    fn seven_and_nine_then_nine_and_seven() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b0101100, 7);
        assert_eq!(subject.len(), 7);
        subject.add_bits(0b110011101, 9);
        assert_eq!(subject.len(), 16);
        let nine_bits = subject.take_bits(9).unwrap();
        assert_eq!(subject.len(), 7);
        let seven_bits = subject.take_bits(7).unwrap();
        assert_eq!(subject.len(), 0);

        assert_bit_field(nine_bits, 0b010101100);
        assert_bit_field(seven_bits, 0b1100111);
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn queues_and_unqueues_32_bits() {
        let value: u64 = 0xDEADBEEF;
        let mut subject = BitQueue::new();

        subject.add_bits(value, 32);
        let result = subject.take_bits(32).unwrap();

        assert_eq!(
            result, value,
            "Should have been {:08X}, but was {:08X}",
            value, result
        );
    }

    #[test]
    fn can_queue_bits_properly() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b11011, 5);
        subject.add_bits(0b00111001110011100, 17);
        subject.add_bits(0b1, 1);
        // 0b100_1110_0111_0011_1001_1011

        let first_chunk = subject.take_bits(10).unwrap();
        let second_chunk = subject.take_bits(5).unwrap();
        let third_chunk = subject.take_bits(5).unwrap();
        let fourth_chunk = subject.take_bits(3).unwrap();
        let should_be_none = subject.take_bits(1);

        assert_bit_field(first_chunk, 0b1110011011);
        assert_bit_field(second_chunk, 0b11100);
        assert_bit_field(third_chunk, 0b11100);
        assert_bit_field(fourth_chunk, 0b100);
        assert_eq!(should_be_none, None);
    }

    fn assert_bit_field(actual: u64, expected: u64) {
        assert_eq!(actual, expected, "Got {:b}, wanted {:b}", actual, expected)
    }
}
