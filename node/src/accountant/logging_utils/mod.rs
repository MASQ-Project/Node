// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod accounting_msgs_debug;
pub mod msg_id_generator;

use crate::accountant::logging_utils::accounting_msgs_debug::AccountingMessageTracker;
use crate::accountant::logging_utils::msg_id_generator::{
    MessageIdGenerator, MessageIdGeneratorReal,
};

const ACCOUNTING_MSG_LOG_WINDOW: u16 = 50;

pub struct LoggingUtils {
    pub debug_stats: AccountingMessageTracker,
    pub accounting_msg_log_window: u16,
    pub msg_id_generator: Box<dyn MessageIdGenerator>,
}

impl Default for LoggingUtils {
    fn default() -> Self {
        Self {
            debug_stats: AccountingMessageTracker::default(),
            accounting_msg_log_window: ACCOUNTING_MSG_LOG_WINDOW,
            msg_id_generator: Box::new(MessageIdGeneratorReal::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::ACCOUNTING_MSG_LOG_WINDOW;
    use crate::accountant::logging_utils::LoggingUtils;

    #[test]
    fn constants_have_right_values(){
        assert_eq!(ACCOUNTING_MSG_LOG_WINDOW, 50);
    }
    
    #[test]
    fn default_log_window(){
        let subject = LoggingUtils::default();
        
        assert_eq!(subject.accounting_msg_log_window, ACCOUNTING_MSG_LOG_WINDOW)
    }
}
