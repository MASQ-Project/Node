// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use web3::types::Address;

#[derive(Default)]
pub struct AccountingMsgsDebugStats {
    report_routing_service_provided_processed: AccountingMsgStats,
    report_exit_service_provided_processed: AccountingMsgStats,
    report_services_consumed_processed: AccountingMsgStats,
}

impl AccountingMsgsDebugStats {
    pub fn manage_debug_log(
        &mut self,
        logger: &Logger,
        msg_type: AccountingMsgType,
        log_window_size: u16,
        new_postings: Vec<NewPosting>,
    ) {
        if logger.debug_enabled() {
            if let Some(loggable_stats) = self.manage_log(msg_type, new_postings, log_window_size) {
                debug!(logger, "{}", loggable_stats);
            }
        }
    }

    fn manage_log(
        &mut self,
        msg_type: AccountingMsgType,
        new_postings: Vec<NewPosting>,
        log_window_size: u16,
    ) -> Option<LoggableStats> {
        self.record(new_postings, msg_type);
        self.request_log_instruction(log_window_size, msg_type)
    }

    fn record(&mut self, new_postings: Vec<NewPosting>, msg_type: AccountingMsgType) {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => {
                self.report_routing_service_provided_processed
                    .handle_new_postings(new_postings);
            }
            AccountingMsgType::ExitServiceProvided => {
                self.report_exit_service_provided_processed
                    .handle_new_postings(new_postings);
            }
            AccountingMsgType::ServicesConsumed => {
                self.report_services_consumed_processed
                    .handle_new_postings(new_postings);
            }
        }
    }

    fn request_log_instruction(
        &mut self,
        gap_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableStats> {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => self
                .report_routing_service_provided_processed
                .loggable_stats(gap_size),
            AccountingMsgType::ExitServiceProvided => self
                .report_exit_service_provided_processed
                .loggable_stats(gap_size),
            AccountingMsgType::ServicesConsumed => self
                .report_services_consumed_processed
                .loggable_stats(gap_size),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct NewPosting {
    address: Address,
    amount_wei: u128,
}

impl NewPosting {
    pub fn new(address: Address, amount_wei: u128) -> Self {
        Self {
            address,
            amount_wei,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct LoggableStats {
    msg_type: AccountingMsgType,
    accounting_msg_stats: HashMap<Address, u128>,
    log_window_in_pcs_of_msgs: u16,
}

impl Display for LoggableStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Default)]
struct AccountingMsgStats {
    stats: HashMap<Address, u128>,
    msg_count_since_last_logged: usize,
}

impl AccountingMsgStats {
    fn loggable_stats(&mut self, log_window_size: u16) -> Option<LoggableStats> {
        if self.msg_count_since_last_logged == log_window_size as usize {
            self.msg_count_since_last_logged = 0;

            Some(LoggableStats {
                msg_type: AccountingMsgType::RoutingServiceProvided,
                accounting_msg_stats: self.stats.drain().collect(),
                log_window_in_pcs_of_msgs: log_window_size,
            })
        } else {
            None
        }
    }

    fn handle_new_postings(&mut self, new_postings: Vec<NewPosting>) {
        for new_posting in &new_postings {
            *self.stats.entry(new_posting.address).or_default() += new_posting.amount_wei;
        }
        self.msg_count_since_last_logged += 1;
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum AccountingMsgType {
    RoutingServiceProvided,
    ExitServiceProvided,
    ServicesConsumed,
}

pub struct NewPostingsDebugContainer {
    debug_enabled: bool,
    vec: Vec<NewPosting>,
}

impl NewPostingsDebugContainer {
    pub fn new(logger: &Logger) -> Self {
        Self {
            debug_enabled: logger.debug_enabled(),
            vec: vec![],
        }
    }

    pub fn add(mut self, address: Address, sum_wei: u128) -> Self {
        if self.debug_enabled {
            self.vec.push(NewPosting::new(address, sum_wei));
        }
        self
    }
}

impl Into<Vec<NewPosting>> for NewPostingsDebugContainer {
    fn into(self) -> Vec<NewPosting> {
        self.vec
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountingMsgType, AccountingMsgsDebugStats, LoggableStats, NewPosting,
        NewPostingsDebugContainer,
    };
    use crate::blockchain::test_utils::make_address;
    use itertools::Itertools;
    use log::Level;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use std::collections::HashMap;
    use web3::types::Address;

    #[test]
    fn test_loggable_count_works_for_routing_service_provided() {
        test_manage_debug_log(
            AccountingMsgType::RoutingServiceProvided,
            6,
            |subject| {
                subject
                    .report_routing_service_provided_processed
                    .stats
                    .clone()
            },
            |subject| {
                subject
                    .report_routing_service_provided_processed
                    .msg_count_since_last_logged
            },
        );
    }

    #[test]
    fn test_loggable_count_works_for_exit_service_provided() {
        test_manage_debug_log(
            AccountingMsgType::ExitServiceProvided,
            3,
            |subject| subject.report_exit_service_provided_processed.stats.clone(),
            |subject| {
                subject
                    .report_exit_service_provided_processed
                    .msg_count_since_last_logged
            },
        );
    }

    #[test]
    fn test_loggable_count_works_for_services_consumed() {
        test_manage_debug_log(
            AccountingMsgType::ServicesConsumed,
            8,
            |subject| subject.report_services_consumed_processed.stats.clone(),
            |subject| {
                subject
                    .report_services_consumed_processed
                    .msg_count_since_last_logged
            },
        );
    }

    fn test_manage_debug_log(
        msg_type: AccountingMsgType,
        gap_size: u16,
        fetch_stats: fn(&AccountingMsgsDebugStats) -> HashMap<Address, u128>,
        fetch_msg_count_processed: fn(&AccountingMsgsDebugStats) -> usize,
    ) {
        let initial_new_postings_feeds = (0..gap_size - 1)
            .map(|idx| NewPosting::new(make_address(idx as u32), (idx as u128 + 1) * 1234567))
            .collect::<Vec<_>>();
        let mut subject = AccountingMsgsDebugStats::default();

        let initial_state_total_count = fetch_stats(&subject);
        let initial_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(initial_state_total_count, hashmap!());
        assert_eq!(initial_msg_count_processed, 0);

        let first_log_instruction_opt = initial_new_postings_feeds
            .iter()
            .fold(None, |_, new_posting| {
                subject.manage_log(msg_type, vec![*new_posting], gap_size)
            });
        let first_expected_stats = Vec::from_iter(
            initial_new_postings_feeds
                .iter()
                .map(|new_posting| (new_posting.address, new_posting.amount_wei)),
        );
        let first_actual_stats = fetch_stats(&subject);
        let first_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(first_log_instruction_opt, None);
        assert_eq!(
            first_actual_stats.into_iter().sorted().collect_vec(),
            first_expected_stats
        );
        assert_eq!(first_msg_count_processed, gap_size as usize - 1);

        let second_new_posting = initial_new_postings_feeds.first().unwrap().clone();
        let second_log_instruction_opt =
            subject.manage_log(msg_type, vec![second_new_posting], gap_size);
        let second_actual_stats = fetch_stats(&subject);
        let second_msg_count_processed = fetch_msg_count_processed(&subject);
        let mut second_expected_stats = first_expected_stats.clone();
        second_expected_stats.get_mut(0).unwrap().1 += second_new_posting.amount_wei;
        let loggable_stats = second_log_instruction_opt.unwrap();
        assert_eq!(
            loggable_stats
                .accounting_msg_stats
                .into_iter()
                .sorted()
                .collect_vec(),
            second_expected_stats,
        );
        assert_eq!(loggable_stats.log_window_in_pcs_of_msgs, gap_size,);
        assert_eq!(second_actual_stats, hashmap!());
        assert_eq!(second_msg_count_processed, 0);

        let third_new_posting = initial_new_postings_feeds.last().unwrap().clone();
        let third_log_instruction = subject.manage_log(msg_type, vec![third_new_posting], gap_size);
        let third_actual_stats = fetch_stats(&subject);
        let third_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(third_log_instruction, None);
        assert_eq!(
            third_actual_stats,
            hashmap!(third_new_posting.address => third_new_posting.amount_wei)
        );
        assert_eq!(third_msg_count_processed, 1);
    }

    #[test]
    fn new_posting_debug_container_for_debug_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Debug);
        let container = NewPostingsDebugContainer::new(&logger);
        let new_posting_1 = NewPosting::new(make_address(1), 1234567);
        let new_posting_2 = NewPosting::new(make_address(2), 7654321);

        let container = container.add(new_posting_1.address, new_posting_1.amount_wei);
        let container = container.add(new_posting_1.address, new_posting_1.amount_wei);
        let container = container.add(new_posting_2.address, new_posting_2.amount_wei);

        let stats: Vec<NewPosting> = container.into();
        assert_eq!(stats, vec![new_posting_1, new_posting_1, new_posting_2]);
    }

    #[test]
    fn new_posting_debug_container_for_debug_not_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Info);
        let container = NewPostingsDebugContainer::new(&logger);
        let new_posting_1 = NewPosting::new(make_address(1), 1234567);
        let new_posting_2 = NewPosting::new(make_address(2), 7654321);

        let container = container.add(new_posting_1.address, new_posting_1.amount_wei);
        let container = container.add(new_posting_1.address, new_posting_1.amount_wei);
        let container = container.add(new_posting_2.address, new_posting_2.amount_wei);

        let stats: Vec<NewPosting> = container.into();
        assert_eq!(stats, vec![]);
    }

    #[test]
    fn accounts_stats_are_logged_only_if_debug_enabled() {
        init_test_logging();
        let test_name = "accounts_stats_are_logged_only_if_debug_enabled";
        let mut logger = Logger::new(test_name);
        logger.set_level_for_test(Level::Debug);
        let mut subject = AccountingMsgsDebugStats::default();
        let new_posting_1 = NewPosting::new(make_address(1), 1234567);
        let new_posting_2 = NewPosting::new(make_address(2), 7654321);

        subject.manage_debug_log(
            &logger,
            AccountingMsgType::ServicesConsumed,
            1,
            vec![new_posting_1, new_posting_2],
        );

        TestLogHandler::new()
            .exists_log_containing(&format!("DEBUG: {test_name}: Account debits in last"));
    }

    #[test]
    fn accounts_stats_are_not_logged_if_debug_is_not_enabled() {
        init_test_logging();
        let test_name = "accounts_stats_are_not_logged_if_debug_is_not_enabled";
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Info);
        let mut subject = AccountingMsgsDebugStats::default();
        let new_posting_1 = NewPosting::new(make_address(1), 1234567);
        let new_posting_2 = NewPosting::new(make_address(2), 7654321);

        subject.manage_debug_log(
            &logger,
            AccountingMsgType::ServicesConsumed,
            1,
            vec![new_posting_1, new_posting_2],
        );

        TestLogHandler::new().exists_no_log_containing(&format!("DEBUG: {test_name}:"));
    }

    #[test]
    fn display_loggable_stats() {
        let loggable_stats = LoggableStats {
            msg_type: AccountingMsgType::RoutingServiceProvided,
            accounting_msg_stats: hashmap!(make_address(1) => 1234567, make_address(2) => 7654321),
            log_window_in_pcs_of_msgs: 15,
        };
        let expected_display = "\
        Account debits in last 15 RoutingServiceProvided messages (wei):\n\
        0x0000000000000000000000000000000000000001: 1234567,\
        0x0000000000000000000000000000000000000002: 7654321";
        assert_eq!(format!("{}", loggable_stats), expected_display);
    }
}
