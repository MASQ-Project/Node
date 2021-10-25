// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[derive(Default)]
pub struct Sequencer {
    current_sequence_number: u64,
}

impl Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_sequence_number(&mut self) -> u64 {
        let sn = self.current_sequence_number;
        self.current_sequence_number += 1;
        sn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequencer_generates_consecutive_sequence_numbers() {
        let mut subject = Sequencer::new();

        for i in 0..10 {
            assert_eq!(subject.next_sequence_number(), i);
        }
    }
}
