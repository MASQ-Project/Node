// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[derive(Default)]
pub struct MessageCounter {
    report_routing_service_provided_processed: SingleMsgStats,
    report_exit_service_provided_processed: SingleMsgStats,
    report_services_consumed_processed: SingleMsgStats,
}

impl MessageCounter {
    pub fn manage_log(
        &mut self,
        gap_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LogInstruction> {
        self.increment_total(msg_type);

        self.request_log_instruction(gap_size, msg_type)
    }

    fn increment_total(&mut self, msg_type: AccountingMsgType) {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => {
                self.report_routing_service_provided_processed.total += 1
            }
            AccountingMsgType::ExitServiceProvided => {
                self.report_exit_service_provided_processed.total += 1
            }
            AccountingMsgType::ServicesConsumed => {
                self.report_services_consumed_processed.total += 1
            }
        }
    }

    fn request_log_instruction(
        &mut self,
        gap_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LogInstruction> {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => self
                .report_routing_service_provided_processed
                .loggable_count(gap_size),
            AccountingMsgType::ExitServiceProvided => self
                .report_exit_service_provided_processed
                .loggable_count(gap_size),
            AccountingMsgType::ServicesConsumed => self
                .report_services_consumed_processed
                .loggable_count(gap_size),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct LogInstruction {
    pub msg_total_count: u64,
    pub used_gap: u16,
}

#[derive(Default)]
struct SingleMsgStats {
    total: u64,
    last_logged_at: u64,
}

impl SingleMsgStats {
    fn loggable_count(&mut self, gap_size: u16) -> Option<LogInstruction> {
        if (self.last_logged_at + gap_size as u64) == self.total {
            self.last_logged_at += gap_size as u64;

            Some(LogInstruction {
                msg_total_count: self.total,
                used_gap: gap_size,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
pub enum AccountingMsgType {
    RoutingServiceProvided,
    ExitServiceProvided,
    ServicesConsumed,
}

#[cfg(test)]
mod tests {
    use crate::accountant::message_counter::{AccountingMsgType, LogInstruction, MessageCounter};

    #[test]
    fn test_loggable_count_works_for_routing_service_provided() {
        test_manage_log(
            AccountingMsgType::RoutingServiceProvided,
            6,
            |subject| subject.report_routing_service_provided_processed.total,
            |subject| {
                subject
                    .report_routing_service_provided_processed
                    .last_logged_at
            },
        );
    }

    #[test]
    fn test_loggable_count_works_for_exit_service_provided() {
        test_manage_log(
            AccountingMsgType::ExitServiceProvided,
            3,
            |subject| subject.report_exit_service_provided_processed.total,
            |subject| {
                subject
                    .report_exit_service_provided_processed
                    .last_logged_at
            },
        );
    }

    #[test]
    fn test_loggable_count_works_for_services_consumed() {
        test_manage_log(
            AccountingMsgType::ServicesConsumed,
            8,
            |subject| subject.report_services_consumed_processed.total,
            |subject| subject.report_services_consumed_processed.last_logged_at,
        );
    }

    fn test_manage_log(
        msg_type: AccountingMsgType,
        gap_size: u16,
        fetch_total: fn(&MessageCounter) -> u64,
        fetch_last_logged_at: fn(&MessageCounter) -> u64,
    ) {
        let mut subject = MessageCounter::default();

        let initial_state_total_count = fetch_total(&subject);
        let initial_state_last_logged_at = fetch_last_logged_at(&subject);
        assert_eq!(initial_state_total_count, 0);
        assert_eq!(initial_state_last_logged_at, 0);

        let first_log_instruction =
            (0..gap_size - 1).fold(None, |_, _| subject.manage_log(gap_size, msg_type));
        let first_actual_inner_count = fetch_total(&subject);
        let first_state_last_logged_at = fetch_last_logged_at(&subject);
        assert_eq!(first_log_instruction, None);
        assert_eq!(first_actual_inner_count, (gap_size - 1) as u64);
        assert_eq!(first_state_last_logged_at, 0);

        let second_log_instruction = subject.manage_log(gap_size, msg_type);
        let second_actual_inner_count = fetch_total(&subject);
        let second_state_last_logged_at = fetch_last_logged_at(&subject);
        assert_eq!(
            second_log_instruction,
            Some(LogInstruction {
                msg_total_count: gap_size as u64,
                used_gap: gap_size
            })
        );
        assert_eq!(second_actual_inner_count, gap_size as u64);
        assert_eq!(second_state_last_logged_at, gap_size as u64);

        let third_log_instruction = subject.manage_log(gap_size, msg_type);
        let third_actual_inner_count = fetch_total(&subject);
        let third_state_last_logged_at = fetch_last_logged_at(&subject);
        assert_eq!(third_log_instruction, None);
        assert_eq!(third_actual_inner_count, gap_size as u64 + 1);
        assert_eq!(third_state_last_logged_at, gap_size as u64);
    }
}
