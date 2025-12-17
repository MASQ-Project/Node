// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::accountant::MSG_ID_INCREMENTER;
use std::sync::atomic::Ordering;

pub trait MessageIdGenerator {
    fn id(&self) -> u32;
    as_any_ref_in_trait!();
}

#[derive(Default)]
pub struct MessageIdGeneratorReal {}

impl MessageIdGenerator for MessageIdGeneratorReal {
    fn id(&self) -> u32 {
        MSG_ID_INCREMENTER.fetch_add(1, Ordering::Relaxed)
    }
    as_any_ref_in_trait_impl!();
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

        let id1 = subject.id();
        let id2 = subject.id();
        let id3 = subject.id();

        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1)
    }

    #[test]
    fn msg_id_generator_wraps_around_max_value() {
        let _guard = MSG_ID_GENERATOR_TEST_GUARD.lock().unwrap();
        MSG_ID_INCREMENTER.store(u32::MAX, Ordering::Relaxed);
        let subject = MessageIdGeneratorReal::default();
        subject.id(); // This returns the previous value, not the newly incremented

        let id = subject.id();

        assert_eq!(id, 0)
    }
}
