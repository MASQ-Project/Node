// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::accountant::MSG_ID_INCREMENTER;
use std::sync::atomic::Ordering;

pub trait MessageIdGenerator {
    fn new_id(&self) -> u32;
    fn last_used_id(&self) -> u32;
    as_any_ref_in_trait!();
}

#[derive(Default)]
pub struct MessageIdGeneratorReal {}

impl MessageIdGenerator for MessageIdGeneratorReal {
    fn new_id(&self) -> u32 {
        MSG_ID_INCREMENTER.fetch_add(1, Ordering::Relaxed)
    }
    fn last_used_id(&self) -> u32 {
        MSG_ID_INCREMENTER.load(Ordering::Relaxed) - 1
    }
    as_any_ref_in_trait_impl!();
}

pub enum MsgIdRequested {
    New,
    LastUsed,
}

#[cfg(test)]
mod tests {
    use crate::accountant::logging_utils::msg_id_generator::{
        MessageIdGenerator, MessageIdGeneratorReal,
    };
    use crate::sub_lib::accountant::MSG_ID_INCREMENTER;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    static MSG_ID_GENERATOR_TEST_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn msg_id_generator_increments_by_one_with_every_call() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        let subject = MessageIdGeneratorReal::default();

        let id1 = subject.new_id();
        let id2 = subject.new_id();
        let id3 = subject.new_id();

        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1)
    }

    #[test]
    fn msg_id_generator_wraps_around_max_value() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        MSG_ID_INCREMENTER.store(u32::MAX, Ordering::Relaxed);
        let subject = MessageIdGeneratorReal::default();
        // First call: gets u32::MAX; then increments the global counter to 0 (wraparound)
        subject.new_id();

        let id = subject.new_id();

        assert_eq!(id, 0)
    }

    #[test]
    fn msg_id_generator_last_used_id() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        let subject = MessageIdGeneratorReal::default();
        let new_id = subject.new_id();

        let same_id_1 = subject.last_used_id();
        let same_id_2 = subject.last_used_id();
        let new_id_2 = subject.new_id();

        assert_eq!(new_id, same_id_1);
        assert_eq!(new_id, same_id_2);
        assert_eq!(new_id_2, same_id_2 + 1);
    }
}
