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
pub struct AccountingMsgTracker {
    routing_provided_stats: AccountingMsgDebugStats,
    exit_provided_stats: AccountingMsgDebugStats,
    consumed_stats: AccountingMsgDebugStats,
}

impl AccountingMsgTracker {
    pub fn process_another_msg(
        &mut self,
        msg_type: AccountingMsgType,
        new_charges: Vec<NewCharge>,
        log_window_size: u16,
    ) -> Option<LoggableDebugStats> {
        self.record_charges_by_msg_type(new_charges, msg_type);
        self.consider_logging(log_window_size, msg_type)
    }

    fn record_charges_by_msg_type(
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

    fn consider_logging(
        &mut self,
        log_window_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableDebugStats> {
        match msg_type {
            AccountingMsgType::RoutingServiceProvided => self
                .routing_provided_stats
                .log_if(log_window_size, msg_type),
            AccountingMsgType::ExitServiceProvided => {
                self.exit_provided_stats.log_if(log_window_size, msg_type)
            }
            AccountingMsgType::ServicesConsumed => {
                self.consumed_stats.log_if(log_window_size, msg_type)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NewCharge {
    pub address: Address,
    pub amount_wei: u128,
    pub bytes: usize,
}

impl NewCharge {
    pub fn new(address: Address, amount_wei: u128, bytes: usize) -> Self {
        Self {
            address,
            amount_wei,
            bytes,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct LoggableDebugStats {
    msg_type: AccountingMsgType,
    accounting_msg_stats: HashMap<Address, AddressStats>,
    log_window_size: u16,
}

impl LoggableDebugStats {
    pub fn stats(&self) -> Vec<String> {
        self.accounting_msg_stats
            .iter()
            .sorted_by(|(address_a, stats_a), (address_b, stats_b)| {
                Ord::cmp(&stats_b.wei, &stats_a.wei).then(Ord::cmp(&address_b, &address_a))
            })
            .map(|(address, stats)| format!("{:?}: {} | {}", address, stats.wei, stats.bytes))
            .collect()
    }
}

impl Display for LoggableDebugStats {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let init_label = format!(
            "Debits from last {} {:?} messages [wei | bytes]:",
            self.log_window_size, self.msg_type
        );

        let stats = self.stats();

        once(init_label).chain(stats).join("\n").fmt(f)
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AddressStats {
    bytes: usize,
    wei: u128,
}

#[derive(Default)]
struct AccountingMsgDebugStats {
    stats: HashMap<Address, AddressStats>,
    msg_count_since_last_logged: usize,
}

impl AccountingMsgDebugStats {
    fn log_if(
        &mut self,
        log_window_size: u16,
        msg_type: AccountingMsgType,
    ) -> Option<LoggableDebugStats> {
        if self.should_log_stats(log_window_size) {
            self.msg_count_since_last_logged = 0;

            let accounting_msg_stats = self.stats.drain().collect();

            Some(LoggableDebugStats {
                msg_type,
                accounting_msg_stats,
                log_window_size,
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
            let mut entry = self.stats.entry(new_charges.address).or_default();
            entry.wei += new_charges.amount_wei;
            entry.bytes += new_charges.bytes;
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

pub struct NewChargesDebugContainer {
    debug_enabled: bool,
    vec: Vec<NewCharge>,
}

impl NewChargesDebugContainer {
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

impl From<NewChargesDebugContainer> for Vec<NewCharge> {
    fn from(postings: NewChargesDebugContainer) -> Self {
        postings.vec
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccountingMsgDebugStats, AccountingMsgTracker, AccountingMsgType, AddressStats,
        LoggableDebugStats, NewCharge, NewChargesDebugContainer,
    };
    use crate::blockchain::test_utils::make_address;
    use itertools::Itertools;
    use log::Level;
    use masq_lib::logger::Logger;
    use std::collections::HashMap;
    use web3::types::Address;

    #[test]
    fn should_log_stats_when_one_msg_less() {
        let log_window = 5;
        let mut subject = AccountingMsgDebugStats::default();
        subject.msg_count_since_last_logged = 4;

        assert_eq!(subject.should_log_stats(log_window), false);
    }

    #[test]
    fn should_log_stats_when_equal() {
        let log_window = 5;
        let mut subject = AccountingMsgDebugStats::default();
        subject.msg_count_since_last_logged = 5;

        assert_eq!(subject.should_log_stats(log_window), true);
    }

    #[test]
    fn should_log_stats_when_one_over() {
        // This situation is not expected in reality; just hardening
        let log_window = 5;
        let mut subject = AccountingMsgDebugStats::default();
        subject.msg_count_since_last_logged = 6;

        assert_eq!(subject.should_log_stats(log_window), true);
    }

    #[test]
    fn test_loggable_count_works_for_routing_service_provided() {
        test_process_another_msg(AccountingMsgType::RoutingServiceProvided, 6);
    }

    #[test]
    fn test_loggable_count_works_for_exit_service_provided() {
        test_process_another_msg(AccountingMsgType::ExitServiceProvided, 3);
    }

    #[test]
    fn test_loggable_count_works_for_services_consumed() {
        test_process_another_msg(AccountingMsgType::ServicesConsumed, 8);
    }

    fn test_process_another_msg(msg_type: AccountingMsgType, log_window_size: u16) {
        let mut msgs_with_charges = generate_msgs(log_window_size);
        let expected_sorted_stats = derive_expected_sorted_stats(&msgs_with_charges);
        let mut subject = AccountingMsgTracker::default();

        assert_empty_stats(&subject);

        let msg_matching_the_window_size = msgs_with_charges.remove(log_window_size as usize - 1);
        let initial_few_charge_msgs = msgs_with_charges;

        assert_msg_window_size_minus_one(
            &mut subject,
            msg_type,
            log_window_size,
            initial_few_charge_msgs,
        );

        test_matching_the_log_window(
            &mut subject,
            msg_type,
            msg_matching_the_window_size,
            log_window_size,
            expected_sorted_stats,
        );

        assert_empty_stats(&subject);

        retest_after_emptied(&mut subject, msg_type);
    }

    fn assert_msg_window_size_minus_one(
        subject: &mut AccountingMsgTracker,
        msg_type: AccountingMsgType,
        log_window_size: u16,
        initial_charge_msgs: Vec<Vec<NewCharge>>,
    ) {
        initial_charge_msgs
            .into_iter()
            .enumerate()
            .for_each(|(idx, new_charges)| {
                let result = subject.process_another_msg(msg_type, new_charges, log_window_size);

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

    fn assert_empty_stats(subject: &AccountingMsgTracker) {
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

    fn test_matching_the_log_window(
        subject: &mut AccountingMsgTracker,
        msg_type: AccountingMsgType,
        another_msg_with_charges: Vec<NewCharge>,
        log_window_size: u16,
        expected_sorted_stats: Vec<(Address, AddressStats)>,
    ) {
        let result = subject
            .process_another_msg(msg_type, another_msg_with_charges, log_window_size)
            .expect("first try: expected stats dump");

        assert_produced_loggable_stats(result, msg_type, log_window_size, expected_sorted_stats);
    }

    fn assert_produced_loggable_stats(
        actual_loggable_stats: LoggableDebugStats,
        msg_type: AccountingMsgType,
        log_window_size: u16,
        expected_sorted_stats: Vec<(Address, AddressStats)>,
    ) {
        assert_eq!(actual_loggable_stats.msg_type, msg_type);
        assert_eq!(
            actual_loggable_stats
                .accounting_msg_stats
                .into_iter()
                .sorted_by_key(|(address, _)| *address)
                .collect_vec(),
            expected_sorted_stats
        );
        assert_eq!(actual_loggable_stats.log_window_size, log_window_size);
    }

    fn retest_after_emptied(subject: &mut AccountingMsgTracker, msg_type: AccountingMsgType) {
        const QUICK_RETEST_WINDOW_SIZE: u16 = 2;
        let mut new_charges_feeds_per_msg = generate_msgs(QUICK_RETEST_WINDOW_SIZE);
        let expected_sorted_stats = derive_expected_sorted_stats(&new_charges_feeds_per_msg);

        let result = subject.process_another_msg(
            msg_type,
            new_charges_feeds_per_msg.remove(0),
            QUICK_RETEST_WINDOW_SIZE,
        );

        assert_eq!(result, None);

        let result = subject
            .process_another_msg(
                msg_type,
                new_charges_feeds_per_msg.remove(0),
                QUICK_RETEST_WINDOW_SIZE,
            )
            .expect("second try: expected stats dump");

        assert_produced_loggable_stats(
            result,
            msg_type,
            QUICK_RETEST_WINDOW_SIZE,
            expected_sorted_stats,
        );
    }

    fn generate_msgs(log_window_size: u16) -> Vec<Vec<NewCharge>> {
        (0..log_window_size)
            .map(|msg_number| {
                (0..msg_number)
                    .map(|new_charge_idx| {
                        let discriminant = msg_number + new_charge_idx;
                        let address = make_address(discriminant as u32);
                        let charge = (discriminant as u128 + 1) * 1234567;
                        let bytes = (discriminant as usize + 1) * 321;
                        NewCharge::new(address, charge, bytes)
                    })
                    .collect_vec()
            })
            .collect_vec()
    }

    fn derive_expected_sorted_stats(
        msg_batches: &[Vec<NewCharge>],
    ) -> Vec<(Address, AddressStats)> {
        msg_batches
            .iter()
            .flatten()
            .fold(HashMap::new(), |mut totals, posting| {
                let mut entry: &mut AddressStats = totals.entry(posting.address).or_default();
                entry.wei += posting.amount_wei;
                entry.bytes += posting.bytes;
                totals
            })
            .into_iter()
            .sorted_by_key(|(address, _)| *address)
            .collect()
    }

    #[test]
    fn new_charge_debug_container_when_debug_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Debug);
        let address_1 = make_address(1);
        let address_2 = make_address(2);
        let container = NewChargesDebugContainer::new(&logger);
        let new_charge_1 = NewCharge::new(address_1, 1234567, 5432);
        let new_charge_2 = NewCharge::new(address_1, 7654321, 7890);
        let new_charge_3 = NewCharge::new(address_2, 3232323, 7890);

        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
            new_charge_1.bytes,
        )));
        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_2.address,
            new_charge_2.amount_wei,
            new_charge_2.bytes,
        )));
        let container = container.add_new_charge(None);
        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_3.address,
            new_charge_3.amount_wei,
            new_charge_3.bytes,
        )));

        let collected_charges: Vec<NewCharge> = container.into();
        assert_eq!(
            collected_charges,
            vec![new_charge_1, new_charge_2, new_charge_3]
        );
    }

    #[test]
    fn new_charge_debug_container_when_debug_not_enabled() {
        let mut logger = Logger::new("test");
        logger.set_level_for_test(Level::Info);
        let container = NewChargesDebugContainer::new(&logger);
        let new_charge_1 = NewCharge::new(make_address(1), 1234567, 2323);
        let new_charge_2 = NewCharge::new(make_address(2), 7654321, 4545);

        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_1.address,
            new_charge_1.amount_wei,
            new_charge_1.bytes,
        )));
        let container = container.add_new_charge(None);
        let container = container.add_new_charge(Some(NewCharge::new(
            new_charge_2.address,
            new_charge_2.amount_wei,
            new_charge_2.bytes,
        )));

        let collected_charges: Vec<NewCharge> = container.into();
        assert_eq!(collected_charges, vec![]);
    }

    #[test]
    fn display_loggable_stats() {
        let accounting_msg_stats = hashmap!(make_address(1) => AddressStats {wei: 987654, bytes: 4567}, make_address(2) => AddressStats{wei: 123456, bytes: 1234}, make_address(3) => AddressStats {wei: 987654, bytes: 1111});
        let loggable_stats = LoggableDebugStats {
            msg_type: AccountingMsgType::RoutingServiceProvided,
            accounting_msg_stats,
            log_window_size: 15,
        };

        let result = format!("{}", loggable_stats);

        // Sorted first by the amount of wei, then by the address. Both in the descending order
        let expected_display = "\
        Debits from last 15 RoutingServiceProvided messages [wei | bytes]:\n\
        0x0000000000000000000003000000003000000003: 987654 | 1111\n\
        0x0000000000000000000001000000001000000001: 987654 | 4567\n\
        0x0000000000000000000002000000002000000002: 123456 | 1234";
        assert_eq!(result, expected_display);
    }
}
