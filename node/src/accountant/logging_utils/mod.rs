// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod accounting_msgs_debug;
pub mod msg_id_generator;

use crate::accountant::logging_utils::accounting_msgs_debug::AccountingMessageTracker;
use crate::accountant::logging_utils::msg_id_generator::{
    MessageIdGenerator, MessageIdGeneratorReal,
};

pub struct LoggingUtils {
    pub debug_stats: AccountingMessageTracker,
    pub msg_id_generator: Box<dyn MessageIdGenerator>,
}

impl Default for LoggingUtils {
    fn default() -> Self {
        Self {
            debug_stats: AccountingMessageTracker::default(),
            msg_id_generator: Box::new(MessageIdGeneratorReal::default()),
        }
    }
}
