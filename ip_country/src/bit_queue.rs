use std::collections::VecDeque;

pub struct BitQueue {
    back_blank_bit_count: usize, // number of high-order bits in the back byte of the queue that are unused
    byte_queue: VecDeque<u8>,
    front_blank_bit_count: usize, // number of low-order bits in the front byte of the queue that are unused
}

impl BitQueue {

    pub fn new () -> Self {
        let mut byte_queue = VecDeque::from(vec![0, 0]);
        Self {
            back_blank_bit_count: 8,
            byte_queue,
            front_blank_bit_count: 8,
        }
    }

    pub fn len(&self) -> usize {
        (self.byte_queue.len() * 8) - self.back_blank_bit_count - self.front_blank_bit_count
    }

    pub fn add_bits(&mut self, mut bit_data: u64, mut bit_count: usize) {
        if bit_count > 64 {
            panic! ("You can only add bits up to 64 at a time, not {}", bit_count)
        }
eprintln!("Before adding {} bits ({:b}): {}", bit_count, bit_data, self.dump_queue());
        let initial_bits_added = self.add_some_back_bits(bit_data, bit_count);
        bit_data >>= initial_bits_added;
        bit_count -= initial_bits_added;
eprintln!("After adding {} back bits: {}", initial_bits_added, self.dump_queue());
        let byte_bits_added = self.add_back_bytes(bit_data, bit_count);
        bit_data >>= byte_bits_added;
        bit_count -= byte_bits_added;
eprintln!("After adding {} byte bits: {}", byte_bits_added, self.dump_queue());
        let final_bits_added = self.add_some_back_bits(bit_data, bit_count);
        bit_data >>= final_bits_added;
        bit_count -= final_bits_added;
eprintln!("After adding {} final bits: {}", final_bits_added, self.dump_queue());
        if bit_count != 0 {
            panic! ("Didn't add all the bits: {} left", bit_count);
        }
    }

    pub fn take_bits(&mut self, mut bit_count: usize) -> Option<u64> {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic!("You can only take bits up to 64 at a time, not {}", bit_count)
        }
        if bit_count > self.len() {
            return None
        }
eprintln!("Before taking {} bits: {}", bit_count, self.dump_queue());
        let mut bit_data = 0u64;
        let mut bit_position = 0usize;
        let (initial_bit_data, initial_bit_count) = self.take_some_front_bits(bit_count);
        bit_data |= initial_bit_data << bit_position;
        bit_position += initial_bit_count;
        bit_count -= initial_bit_count;
eprintln!("After taking {} initial front bits ({:b}): {}", initial_bit_count, bit_data, self.dump_queue());
        let (byte_bit_data, byte_bit_count) = self.take_front_bytes(bit_count);
        bit_data |= byte_bit_data << bit_position;
        bit_position += byte_bit_count;
        bit_count -= byte_bit_count;
eprintln!("After taking {} byte front bits ({:b}): {}", byte_bit_count, bit_data, self.dump_queue());
        let (final_front_bit_data, final_front_bit_count) = self.take_some_front_bits(bit_count);
        bit_data |= final_front_bit_data << bit_position;
        bit_position += final_front_bit_count;
        bit_count -= final_front_bit_count;
eprintln!("After taking {} final front bits ({:b}): {}", final_front_bit_count, bit_data, self.dump_queue());
        let (final_back_bit_data, final_back_bit_count) = self.take_some_back_bits(bit_count);
        bit_data |= final_back_bit_data << bit_position;
        bit_position += final_back_bit_count;
        bit_count -= final_back_bit_count;
eprintln!("After taking {} final back bits ({:b}): {}", final_back_bit_count, bit_data, self.dump_queue());
        if bit_position != original_bit_count {
            panic! ("Wanted {} bits, but got {} instead", original_bit_count, bit_position);
        }
        return Some(bit_data);
    }

    fn back_full_bit_count(&self) -> usize {8 - self.back_blank_bit_count}

    fn front_full_bit_count(&self) -> usize {8 - self.front_blank_bit_count}

    fn low_order_ones(count: usize) -> u64 {
        !(u64::MAX << count)
    }

    fn dump_queue(&self) -> String {
        let queue_str = self.byte_queue.iter()
            .map(|b| format!("{:08b}", *b))
            .rev()
            .collect::<Vec<String>>()
            .join(" ");
        format!("{}->{}->{}", self.back_blank_bit_count, queue_str, self.front_blank_bit_count)
    }

    fn add_some_back_bits(&mut self, bit_data: u64, bit_count: usize) -> usize {
        let bits_to_add = bit_count.min(self.back_blank_bit_count);
        let back_ref = self.byte_queue.back_mut().expect("There should be a back byte");
        *back_ref = if bits_to_add < 8 {*back_ref << bits_to_add} else {0};
        *back_ref |= (Self::low_order_ones(bits_to_add) & bit_data) as u8;
        self.back_blank_bit_count -= bits_to_add;
        if self.back_blank_bit_count == 0 {
            self.byte_queue.push_back(0);
            self.back_blank_bit_count = 8;
        }
        return bits_to_add
    }

    fn add_back_bytes(&mut self, mut bit_data: u64, mut bit_count: usize) -> usize {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic! ("add_back_bytes() can add a maximum of 64 bits per call, not {}", bit_count)
        }
        if bit_count < 8 {
            return 0;
        }
        if self.back_blank_bit_count == 8 {
            let _ = self.byte_queue.pop_back();
            self.back_blank_bit_count = 0;
        }
        if self.back_blank_bit_count > 0 {
            panic! ("add_back_bytes() only works when there are no back blank bits, not {}", self.back_blank_bit_count)
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
        let bits_to_take = bit_count.min(self.front_full_bit_count());
        if bits_to_take == 0 {return (0, 0)}
        let remaining_bits = self.front_full_bit_count() - bits_to_take;
        let mask = Self::low_order_ones(bits_to_take) << remaining_bits;
        let front_ref = self.byte_queue.front_mut().expect ("There should be a front byte");
        let bit_data = if remaining_bits < 8 {(*front_ref & (mask as u8)) >> remaining_bits} else {0};
        *front_ref |= !mask as u8;
        self.front_blank_bit_count += bits_to_take;
        if (self.front_blank_bit_count == 8) && (self.byte_queue.len() > 2) {
            let _ = self.byte_queue.pop_front();
            self.front_blank_bit_count = 0;
        }
        return (bit_data as u64, bits_to_take)
    }

    fn take_front_bytes(&mut self, mut bit_count: usize) -> (u64, usize) {
        let original_bit_count = bit_count;
        if bit_count > 64 {
            panic! ("take_front_bytes() can take a maximum of 64 bits per call, not {}", bit_count)
        }
        if bit_count < 8 {
            return (0, 0)
        }
        if self.front_blank_bit_count == 8 {
            let _ = self.byte_queue.pop_front();
            self.front_blank_bit_count = 0;
        }
        if self.front_blank_bit_count > 0 {
            panic! ("take_front_bytes() only works when there are no front blank bits, not {}", self.front_blank_bit_count)
        }
        let mut bit_data = 0u64;
        while bit_count >= 8 {
            let byte = self.byte_queue.pop_front().expect("Demanded too many bytes") as u64;
            bit_data |= byte << (original_bit_count - bit_count);
            bit_count -= 8;
        }
        if self.byte_queue.len() < 2 {
            self.byte_queue.push_front(0);
            self.front_blank_bit_count = 8;
        }
        return (bit_data, original_bit_count - bit_count)
    }

    fn take_some_back_bits(&mut self, bit_count: usize) -> (u64, usize) {
        let bits_to_take = bit_count.min(self.back_full_bit_count());
        let remaining_bits = self.back_full_bit_count() - bits_to_take;
        let mask = Self::low_order_ones(bits_to_take);
        let back_ref = self.byte_queue.back_mut().expect ("There should be a back byte");
        let bit_data = if remaining_bits < 8 {(*back_ref & (mask as u8))} else {0};
        *back_ref >>= bits_to_take;
        self.back_blank_bit_count += bits_to_take;
        if (self.back_blank_bit_count == 8) && (self.byte_queue.len() > 2) {
            let _ = self.byte_queue.pop_back();
            self.back_blank_bit_count = 0;
        }
        return (bit_data as u64, bits_to_take)
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
    fn queues_and_unqueues_seven_bits() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b1101101, 7);
        let seven_bits = subject.take_bits(7);

        assert_eq!(seven_bits, Some(0b1101101));
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn queues_and_unqueues_nine_bits() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b110110111, 9);
        let nine_bits = subject.take_bits(9);

        assert_eq!(nine_bits, Some(0b110110111));
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn nine_and_seven_then_seven_and_nine() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b110011101, 9);
        assert_eq!(subject.len(), 9);
        subject.add_bits(0b0101100, 7);
        assert_eq!(subject.len(), 16);
        let seven_bits = subject.take_bits(7).unwrap();
        assert_eq!(subject.len(), 11);
        let nine_bits = subject.take_bits(9).unwrap();
        assert_eq!(subject.len(), 0);

        assert_eq!(seven_bits, 0b1100111);
        assert_eq!(nine_bits, 0b010101100);
    }

    #[test]
    fn seven_and_nine_then_nine_and_seven() {
        let mut subject = BitQueue::new();

        subject.add_bits(0b0101100, 7);
        subject.add_bits(0b110011101, 9);
        let nine_bits = subject.take_bits(9).unwrap();
        let seven_bits = subject.take_bits(7).unwrap();

        assert_eq!(nine_bits, 0b010101100);
        assert_eq!(seven_bits, 0b1100111);
        assert_eq!(subject.len(), 0);
    }

    #[test]
    fn queues_and_unqueues_32_bits() {
        let value: u64 = 0xDEADBEEF;
        let mut subject = BitQueue::new();

        subject.add_bits(value, 32);
        let result = subject.take_bits(32).unwrap();

        assert_eq!(result, value, "Should have been {:08X}, but was {:08X}", value, result);
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
