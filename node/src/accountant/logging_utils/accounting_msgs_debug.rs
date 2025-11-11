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
        log_window_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableStats> {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => self
                .routing_provided_stats
                .maybe_dump_stats(log_window_size, msg_type),
            AccountingMsgType::ExitServiceProvided => self
                .exit_provided_stats
                .maybe_dump_stats(log_window_size, msg_type),
            AccountingMsgType::ServicesConsumed => self
                .consumed_stats
                .maybe_dump_stats(log_window_size, msg_type),
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

    pub fn add_new_charge(mut self, new_charge_opt: Option<NewCharge>) -> Self {
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
        test_process_debug_stats(AccountingMsgType::RoutingServiceProvided, 6);
    }

    #[test]
    fn test_loggable_count_works_for_exit_service_provided() {
        test_process_debug_stats(AccountingMsgType::ExitServiceProvided, 3);
    }

    #[test]
    fn test_loggable_count_works_for_services_consumed() {
        test_process_debug_stats(AccountingMsgType::ServicesConsumed, 8);
    }

    fn test_process_debug_stats(msg_type: AccountingMsgType, log_window_size: u16) {
        let mut new_charge_feeds_per_msg =
            generate_new_charge_feeds_representing_msgs(log_window_size);
        let expected_sorted_stats =
            construct_expected_sorted_stats_from_generated_new_charges(&new_charge_feeds_per_msg);
        let mut subject = AccountingMessageTracker::default();
        assert_empty_stats(&subject);
        let charge_msg_matching_the_window_size =
            new_charge_feeds_per_msg.remove(log_window_size as usize - 1 - 1);
        let initial_charge_msgs = new_charge_feeds_per_msg;

        test_msgs_of_count_window_size_minus_one(
            &mut subject,
            msg_type,
            log_window_size,
            initial_charge_msgs,
        );

        let result = subject
            .process_debug_stats(
                msg_type,
                charge_msg_matching_the_window_size,
                log_window_size,
            )
            .expect("first try: expected stats dump");

        assert_provided_loggable_stats(result, msg_type, log_window_size, expected_sorted_stats);
        assert_empty_stats(&subject);

        retest_after_emptied(&mut subject, msg_type);
    }

    fn test_msgs_of_count_window_size_minus_one(
        subject: &mut AccountingMessageTracker,
        msg_type: AccountingMsgType,
        log_window_size: u16,
        initial_charge_msgs: Vec<Vec<NewCharge>>,
    ) {
        initial_charge_msgs
            .into_iter()
            .enumerate()
            .for_each(|(idx, new_charges)| {
                let result = subject.process_debug_stats(msg_type, new_charges, log_window_size);

                assert_eq!(
                    result,
                    None,
                    "We expected the first {} msgs to be just recorded and not to stimulate stats \
                     as happened with msg {}",
                    log_window_size - 1,
                    idx + 1
                )
            });
    }

    fn assert_empty_stats(subject: &AccountingMessageTracker) {
        assert!(subject.consumed_stats.stats.is_empty());
        assert_eq!(subject.consumed_stats.msg_count_since_last_logged, 0);
        assert!(subject.exit_provided_stats.stats.is_empty());
        assert_eq!(subject.exit_provided_stats.msg_count_since_last_logged, 0);
        assert!(subject.routing_provided_stats.stats.is_empty());
        assert_eq!(
            subject.routing_provided_stats.msg_count_since_last_logged,
            0
        )
    }

    fn assert_provided_loggable_stats(
        actual_loggable_stats: LoggableStats,
        msg_type: AccountingMsgType,
        log_window_size: u16,
        expected_sorted_stats: Vec<(Address, u128)>,
    ) {
        assert_eq!(actual_loggable_stats.msg_type, msg_type);
        assert_eq!(
            actual_loggable_stats
                .accounting_msg_stats
                .into_iter()
                .sorted()
                .collect_vec(),
            expected_sorted_stats
        );
        assert_eq!(
            actual_loggable_stats.log_window_in_pcs_of_msgs,
            log_window_size
        );
    }

    fn retest_after_emptied(subject: &mut AccountingMessageTracker, msg_type: AccountingMsgType) {
        const QUICK_RETEST_WINDOW_SIZE: u16 = 2;
        let mut new_charges_feeds_per_msg =
            generate_new_charge_feeds_representing_msgs(QUICK_RETEST_WINDOW_SIZE);
        let expected_sorted_stats =
            construct_expected_sorted_stats_from_generated_new_charges(&new_charges_feeds_per_msg);

        let result = subject.process_debug_stats(
            msg_type,
            new_charges_feeds_per_msg.remove(0),
            QUICK_RETEST_WINDOW_SIZE,
        );

        assert_eq!(result, None);

        let result = subject
            .process_debug_stats(
                msg_type,
                new_charges_feeds_per_msg.remove(0),
                QUICK_RETEST_WINDOW_SIZE,
            )
            .expect("second try: expected stats dump");

        assert_provided_loggable_stats(
            result,
            msg_type,
            QUICK_RETEST_WINDOW_SIZE,
            expected_sorted_stats,
        );
    }

    fn generate_new_charge_feeds_representing_msgs(log_window_size: u16) -> Vec<Vec<NewCharge>> {
        (0..log_window_size)
            .map(|msg_number| {
                (0..msg_number)
                    .map(|new_charge_idx| {
                        let address = make_address(new_charge_idx as u32);
                        let charge = (new_charge_idx as u128 + 1) * 1234567;
                        NewCharge::new(address, charge)
                    })
                    .collect_vec()
            })
            .collect_vec()
    }

    fn construct_expected_sorted_stats_from_generated_new_charges(
        msg_batches: &[Vec<NewCharge>],
    ) -> Vec<(Address, u128)> {
        msg_batches
            .iter()
            .flatten()
            .fold(HashMap::new(), |mut totals, posting| {
                *totals.entry(posting.address).or_default() += posting.amount_wei;
                totals
            })
            .into_iter()
            .sorted()
            .collect()
    }

    #[test]
    fn new_posting_debug_container_for_debug_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Debug);
        let container = NewChargessDebugContainer::new(&logger);
        let new_charge_1 = NewCharge::new(make_address(1), 1234567);
        let new_charge_2 = NewCharge::new(make_address(2), 7654321);

        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add_new_charge(None);
        let container = container.add_new_charge(Some(NewCharge::new(
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

        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
        )));
        let container = container.add_new_charge(None);
        let container = container.add_new_charge(Some(NewCharge::new(
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
