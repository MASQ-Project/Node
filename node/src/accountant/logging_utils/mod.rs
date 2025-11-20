// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod accounting_msgs_debug;
pub mod msg_id_generator;

use crate::accountant::logging_utils::accounting_msgs_debug::AccountingMsgsDebugStats;
use crate::accountant::logging_utils::msg_id_generator::{
    MessageIdGenerator, MessageIdGeneratorReal,
};

pub struct LoggingUtils {
    pub accounting_msgs_stats: AccountingMsgsDebugStats,
    pub msg_id_generator: Box<dyn MessageIdGenerator>,
}

impl Default for LoggingUtils {
    fn default() -> Self {
        Self {
            accounting_msgs_stats: AccountingMsgsDebugStats::default(),
            msg_id_generator: Box::new(MessageIdGeneratorReal::default()),
        }
    }
}
