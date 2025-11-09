// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use itertools::Itertools;
use masq_lib::logger::Logger;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::iter::once;
use web3::types::Address;

// An attempt to provide somewhat useful debug stats for the accounting messages after we have
// decreased the log level for lots of them, and it drastically reduced the observability
// of the Accountant.

#[derive(Default)]
pub struct AccountingMessageTracker {
    routing_provided_stats: AccountingMsgStats,
    exit_provided_stats: AccountingMsgStats,
    consumed_stats: AccountingMsgStats,
}

impl AccountingMessageTracker {
    pub fn process_debug_stats(
        &mut self,
        msg_type: AccountingMsgType,
        new_charges: Vec<NewCharge>,
        log_window_size: u16,
    ) -> Option<LoggableStats> {
        self.record_new_charges_by_msg_type(new_charges, msg_type);

        self.maybe_dump_stats_by_msg_type(log_window_size, msg_type)
    }

    fn record_new_charges_by_msg_type(
        &mut self,
        new_charges: Vec<NewCharge>,
        msg_type: AccountingMsgType,
    ) {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => {
                self.routing_provided_stats.record_new_charges(new_charges);
            }
            AccountingMsgType::ExitServiceProvided => {
                self.exit_provided_stats.record_new_charges(new_charges);
            }
            AccountingMsgType::ServicesConsumed => {
                self.consumed_stats.record_new_charges(new_charges);
            }
        }
    }

    fn maybe_dump_stats_by_msg_type(
        &mut self,
        gap_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableStats> {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => self
                .routing_provided_stats
                .maybe_dump_stats(gap_size, msg_type),
            AccountingMsgType::ExitServiceProvided => self
                .exit_provided_stats
                .maybe_dump_stats(gap_size, msg_type),
            AccountingMsgType::ServicesConsumed => {
                self.consumed_stats.maybe_dump_stats(gap_size, msg_type)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NewCharge {
    pub address: Address,
    pub amount_wei: u128,
}

impl NewCharge {
    pub fn new(address: Address, amount_wei: u128) -> Self {
        Self {
            address,
            amount_wei,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LoggableStats {
    msg_type: AccountingMsgType,
    accounting_msg_stats: HashMap<Address, u128>,
    log_window_in_pcs_of_msgs: u16,
}
impl Display for LoggableStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = format!(
            "Total debits across last {} {:?} messages (wei):",
            self.log_window_in_pcs_of_msgs, self.msg_type
        );
        let stats = self
            .accounting_msg_stats
            .iter()
            .sorted()
            .map(|(address, sum)| format!("{:?}: {}", address, sum))
            .collect_vec();
        once(label).chain(stats).join("\n").fmt(f)
    }
}

#[derive(Default)]
struct AccountingMsgStats {
    stats: HashMap<Address, u128>,
    msg_count_since_last_logged: usize,
}

impl AccountingMsgStats {
    fn maybe_dump_stats(
        &mut self,
        log_window_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableStats> {
        if self.should_log_stats(log_window_size) {
            self.msg_count_since_last_logged = 0;

            Some(LoggableStats {
                msg_type,
                accounting_msg_stats: self.stats.drain().collect(),
                log_window_in_pcs_of_msgs: log_window_size,
            })
        } else {
            None
        }
    }

    fn should_log_stats(&self, log_window_size: u16) -> bool {
        self.msg_count_since_last_logged >= log_window_size as usize
    }

    fn record_new_charges(&mut self, new_charges_vec: Vec<NewCharge>) {
        new_charges_vec.iter().for_each(|new_charges| {
            *self.stats.entry(new_charges.address).or_default() += new_charges.amount_wei;
        });
        self.msg_count_since_last_logged += 1;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AccountingMsgType {
    RoutingServiceProvided,
    ExitServiceProvided,
    ServicesConsumed,
}

pub struct NewChargessDebugContainer {
    debug_enabled: bool,
    vec: Vec<NewCharge>,
}

impl NewChargessDebugContainer {
    pub fn new(logger: &Logger) -> Self {
        Self {
            debug_enabled: logger.debug_enabled(),
            vec: vec![],
        }
    }

    pub fn add(mut self, new_charge_opt: Option<NewCharge>) -> Self {
        if self.debug_enabled {
            if let Some(new_charge) = new_charge_opt {
                self.vec.push(new_charge);
            }
        }
        self
    }
}

impl From<NewChargessDebugContainer> for Vec<NewCharge> {
    fn from(postings: NewChargessDebugContainer) -> Self {
        postings.vec
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountingMessageTracker, AccountingMsgType, LoggableStats, NewCharge,
        NewChargessDebugContainer,
    };
    use crate::blockchain::test_utils::make_address;
    use itertools::Itertools;
    use log::Level;
    use masq_lib::logger::Logger;
    use std::collections::HashMap;
    use web3::types::Address;

    #[test]
    fn test_loggable_count_works_for_routing_service_provided() {
        test_process_debug_stats(
            AccountingMsgType::RoutingServiceProvided,
            6,
            |subject| subject.routing_provided_stats.stats.clone(),
            |subject| subject.routing_provided_stats.msg_count_since_last_logged,
        );
    }

    #[test]
    fn test_loggable_count_works_for_exit_service_provided() {
        test_process_debug_stats(
            AccountingMsgType::ExitServiceProvided,
            3,
            |subject| subject.exit_provided_stats.stats.clone(),
            |subject| subject.exit_provided_stats.msg_count_since_last_logged,
        );
    }

    #[test]
    fn test_loggable_count_works_for_services_consumed() {
        test_process_debug_stats(
            AccountingMsgType::ServicesConsumed,
            8,
            |subject| subject.consumed_stats.stats.clone(),
            |subject| subject.consumed_stats.msg_count_since_last_logged,
        );
    }

    fn test_process_debug_stats(
        msg_type: AccountingMsgType,
        gap_size: u16,
        fetch_stats: fn(&AccountingMessageTracker) -> HashMap<Address, u128>,
        fetch_msg_count_processed: fn(&AccountingMessageTracker) -> usize,
    ) {
        // We begin the test by recording N - 1 msgs. Then we add one more and match the gap_size
        // condition which should release the debug stats. After that happens, the stats are cleared
        // and the process can start again.
        let new_posting_feeds_per_msg = generate_posting_feeds_representing_msgs(gap_size);
        let mut subject = AccountingMessageTracker::default();

        let initial_state_total_count = fetch_stats(&subject);
        let initial_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(initial_state_total_count, hashmap!());
        assert_eq!(initial_msg_count_processed, 0);

        let first_feed_remembered = new_posting_feeds_per_msg.first().unwrap().clone();
        let last_feed_remembered = new_posting_feeds_per_msg.last().unwrap().clone();

        let first_expected_stats =
            compute_expected_stats_from_new_posting_feeds(&new_posting_feeds_per_msg);
        let first_loggable_stats_opt = new_posting_feeds_per_msg
            .into_iter()
            .fold(None, |_, new_postings| {
                subject.process_debug_stats(msg_type, gap_size, new_postings)
            });
        let first_actual_stats = fetch_stats(&subject);
        let first_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(first_loggable_stats_opt, None);
        assert_eq!(
            first_actual_stats.into_iter().sorted().collect_vec(),
            first_expected_stats
        );
        assert_eq!(first_msg_count_processed, gap_size as usize - 1);

        let posting_fulfilling_the_msg_count_requirement = first_feed_remembered;
        let second_loggable_stats_opt = subject.manage_log(
            msg_type,
            posting_fulfilling_the_msg_count_requirement.clone(),
            gap_size,
        );
        let second_actual_stats = fetch_stats(&subject);
        let second_msg_count_processed = fetch_msg_count_processed(&subject);
        let second_expected_stats = record_new_posting_feed_in(
            first_expected_stats,
            posting_fulfilling_the_msg_count_requirement,
        );
        let loggable_stats = second_loggable_stats_opt.unwrap();
        assert_eq!(loggable_stats.msg_type, msg_type);
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

        let new_posting_after_stats_dumping = last_feed_remembered;
        let third_loggable_stats_opt =
            subject.manage_log(msg_type, new_posting_after_stats_dumping.clone(), gap_size);
        let third_actual_stats = fetch_stats(&subject);
        let third_msg_count_processed = fetch_msg_count_processed(&subject);
        assert_eq!(third_loggable_stats_opt, None);
        assert_eq!(
            third_actual_stats.into_iter().sorted().collect_vec(),
            new_posting_after_stats_dumping
                .into_iter()
                .map(|posting| (posting.address, posting.amount_wei))
                .sorted()
                .collect_vec(),
        );
        assert_eq!(third_msg_count_processed, 1);
    }

    fn record_new_posting_feed_in(
        first_expected_stats: Vec<(Address, u128)>,
        second_new_posting: Vec<NewCharge>,
    ) -> Vec<(Address, u128)> {
        let second_expected_stats = first_expected_stats
            .into_iter()
            .map(|(address, sum)| {
                let updated_sum = second_new_posting.iter().fold(sum, |acc, posting| {
                    if posting.address == address {
                        acc + posting.amount_wei
                    } else {
                        acc
                    }
                });
                (address, updated_sum)
            })
            .collect_vec();
        second_expected_stats
    }

    fn generate_posting_feeds_representing_msgs(gap_size: u16) -> Vec<Vec<NewCharge>> {
        let new_postings_feeds = (0..gap_size - 1)
            .map(|outer_idx| {
                (0..outer_idx + 1)
                    .map(|inner_idx| {
                        NewCharge::new(
                            make_address(inner_idx as u32),
                            (inner_idx as u128 + 1) * 1234567,
                        )
                    })
                    .collect_vec()
            })
            .collect_vec();
        new_postings_feeds
    }

    fn compute_expected_stats_from_new_posting_feeds(
        new_postings_feeds: &Vec<Vec<NewCharge>>,
    ) -> Vec<(Address, u128)> {
        let first_expected_stats = {
            let all_postings_flattened = new_postings_feeds.iter().flatten().collect_vec();
            let all_unique_addresses = new_postings_feeds.last().unwrap();
            all_unique_addresses
                .iter()
                .map(|unique_account_posting| {
                    let sum = all_postings_flattened.iter().fold(0, |acc, posting| {
                        if posting.address == unique_account_posting.address {
                            acc + posting.amount_wei
                        } else {
                            acc
                        }
                    });
                    (unique_account_posting.address, sum)
                })
                .collect_vec()
        };
        first_expected_stats
    }

    #[test]
    fn new_posting_debug_container_for_debug_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Debug);
        let container = NewChargessDebugContainer::new(&logger);
        let new_charge_1 = NewCharge::new(make_address(1), 1234567);
        let new_charge_2 = NewCharge::new(make_address(2), 7654321);

        let container = container.add(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add(None);
        let container = container.add(Some(NewCharge::new(
            new_charge_2.address,
            new_charge_2.amount_wei,
        )));

        let stats: Vec<NewCharge> = container.into();
        assert_eq!(stats, vec![new_charge_1, new_charge_1, new_charge_2]);
    }

    #[test]
    fn new_posting_debug_container_for_debug_not_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Info);
        let container = NewChargessDebugContainer::new(&logger);
        let new_charge_1 = NewCharge::new(make_address(1), 1234567);
        let new_charge_2 = NewCharge::new(make_address(2), 7654321);

        let container = container.add(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add(None);
        let container = container.add(Some(NewCharge::new(
            new_charge_2.address,
            new_charge_2.amount_wei,
        )));

        let stats: Vec<NewCharge> = container.into();
        assert_eq!(stats, vec![]);
    }

    #[test]
    fn display_loggable_stats() {
        let loggable_stats = LoggableStats {
            msg_type: AccountingMsgType::RoutingServiceProvided,
            accounting_msg_stats: hashmap!(make_address(1) => 1234567, make_address(2) => 7654321),
            log_window_in_pcs_of_msgs: 15,
        };
        let expected_display = "\
        Total debits across last 15 RoutingServiceProvided messages (wei):\n\
        0x0000000000000000000001000000001000000001: 1234567\n\
        0x0000000000000000000002000000002000000002: 7654321";
        assert_eq!(format!("{}", loggable_stats), expected_display);
    }
}
