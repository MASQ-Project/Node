// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::payable_dao::PayableDao;
use super::receivable_dao::ReceivableDao;
use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::receivable_dao::ReceivableAccount;
use crate::banned_dao::BannedDao;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::accountant::AccountantSubs;
use crate::sub_lib::accountant::ReportExitServiceConsumedMessage;
use crate::sub_lib::accountant::ReportExitServiceProvidedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
use crate::sub_lib::accountant::ReportRoutingServiceProvidedMessage;
use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::utils::NODE_MAILBOX_CAPACITY;
use crate::sub_lib::wallet::Wallet;
use actix::Actor;
use actix::Addr;
use actix::AsyncContext;
use actix::Context;
use actix::Handler;
use actix::Recipient;
use lazy_static::lazy_static;
use std::time::{Duration, SystemTime};

pub const DEFAULT_PAYABLE_SCAN_INTERVAL: u64 = 3600; // one hour

const SECONDS_PER_DAY: i64 = 86_400;

lazy_static! {
    pub static ref PAYMENT_CURVES: PaymentCurves = PaymentCurves {
        payment_suggested_after_sec: SECONDS_PER_DAY,
        payment_grace_before_ban_sec: SECONDS_PER_DAY,
        permanent_debt_allowed_gwub: 10_000_000,
        balance_to_decrease_from_gwub: 1_000_000_000,
        balance_decreases_for_sec: 30 * SECONDS_PER_DAY,
        unban_when_balance_below_gwub: 10_000_000,
    };
}

#[derive(PartialEq, Debug, Clone)]
pub struct PaymentCurves {
    pub payment_suggested_after_sec: i64,
    pub payment_grace_before_ban_sec: i64,
    pub permanent_debt_allowed_gwub: i64,
    pub balance_to_decrease_from_gwub: i64,
    pub balance_decreases_for_sec: i64,
    pub unban_when_balance_below_gwub: i64,
}

impl PaymentCurves {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - self.payment_suggested_after_sec - self.payment_grace_before_ban_sec
    }

    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - self.balance_decreases_for_sec
    }
}

pub struct Accountant {
    config: AccountantConfig,
    payable_dao: Box<PayableDao>,
    receivable_dao: Box<ReceivableDao>,
    banned_dao: Box<BannedDao>,
    report_accounts_payable_sub: Option<Recipient<ReportAccountsPayable>>,
    logger: Logger,
}

impl Actor for Accountant {
    type Context = Context<Self>;
}

impl Handler<BindMessage> for Accountant {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, ctx: &mut Self::Context) -> Self::Result {
        self.report_accounts_payable_sub =
            Some(msg.peer_actors.blockchain_bridge.report_accounts_payable);
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        ctx.run_interval(self.config.payable_scan_interval, |act, _| {
            act.periodic_scans();
        });
        self.logger.info(String::from("Accountant bound"));
    }
}

impl Handler<ReportRoutingServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.debug(format!(
            "Charging routing of {} bytes to wallet {}",
            msg.payload_size, msg.consuming_wallet.address
        ));
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.consuming_wallet,
        );
    }
}

impl Handler<ReportExitServiceProvidedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceProvidedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.debug(format!(
            "Charging exit service for {} bytes to wallet {} at {} per service and {} per byte",
            msg.payload_size, msg.consuming_wallet.address, msg.service_rate, msg.byte_rate
        ));
        self.record_service_provided(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.consuming_wallet,
        );
    }
}

impl Handler<ReportRoutingServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportRoutingServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.debug(format!(
            "Accruing debt to wallet {} for consuming routing service {} bytes",
            msg.earning_wallet.address, msg.payload_size
        ));
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }
}

impl Handler<ReportExitServiceConsumedMessage> for Accountant {
    type Result = ();

    fn handle(
        &mut self,
        msg: ReportExitServiceConsumedMessage,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        self.logger.debug(format!(
            "Accruing debt to wallet {} for consuming exit service {} bytes",
            msg.earning_wallet.address, msg.payload_size
        ));
        self.record_service_consumed(
            msg.service_rate,
            msg.byte_rate,
            msg.payload_size,
            &msg.earning_wallet,
        );
    }
}

impl Accountant {
    pub fn new(
        config: AccountantConfig,
        payable_dao: Box<PayableDao>,
        receivable_dao: Box<ReceivableDao>,
        banned_dao: Box<BannedDao>,
    ) -> Accountant {
        Accountant {
            config,
            payable_dao,
            receivable_dao,
            banned_dao,
            report_accounts_payable_sub: None,
            logger: Logger::new("Accountant"),
        }
    }

    pub fn make_subs_from(addr: &Addr<Accountant>) -> AccountantSubs {
        AccountantSubs {
            bind: addr.clone().recipient::<BindMessage>(),
            report_routing_service_provided: addr
                .clone()
                .recipient::<ReportRoutingServiceProvidedMessage>(),
            report_exit_service_provided: addr
                .clone()
                .recipient::<ReportExitServiceProvidedMessage>(),
            report_routing_service_consumed: addr
                .clone()
                .recipient::<ReportRoutingServiceConsumedMessage>(),
            report_exit_service_consumed: addr
                .clone()
                .recipient::<ReportExitServiceConsumedMessage>(),
        }
    }

    fn periodic_scans(&mut self) {
        self.scan_for_payables();
        self.scan_for_delinquencies();
    }

    fn scan_for_payables(&mut self) {
        self.logger.debug("Scanning for payables".to_string());
        let payables = self
            .payable_dao
            .non_pending_payables()
            .into_iter()
            .filter(Accountant::should_pay)
            .collect::<Vec<PayableAccount>>();

        if !payables.is_empty() {
            self.report_accounts_payable_sub
                .as_ref()
                .expect("BlockchainBridge is unbound")
                .try_send(ReportAccountsPayable { accounts: payables })
                .expect("BlockchainBridge is dead");
        }
    }

    fn scan_for_delinquencies(&mut self) {
        let now = SystemTime::now();
        self.receivable_dao
            .new_delinquencies(now.clone(), &PAYMENT_CURVES)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.ban(&account.wallet_address);
                let (balance, age) = Self::balance_and_age(&account);
                self.logger.info(format!(
                    "Wallet {} (balance: {} SUB, age: {} sec) banned for delinquency",
                    account.wallet_address,
                    balance,
                    age.as_secs()
                ))
            });

        self.receivable_dao
            .paid_delinquencies(&PAYMENT_CURVES)
            .into_iter()
            .for_each(|account| {
                self.banned_dao.unban(&account.wallet_address);
                let (balance, age) = Self::balance_and_age(&account);
                self.logger.info(format!(
                    "Wallet {} (balance: {} SUB, age: {} sec) is no longer delinquent: unbanned",
                    account.wallet_address,
                    balance,
                    age.as_secs()
                ))
            });
    }

    fn balance_and_age(account: &ReceivableAccount) -> (String, Duration) {
        let balance = format!("{}", (account.balance as f64) / 1_000_000_000.0);
        let age = account
            .last_received_timestamp
            .elapsed()
            .unwrap_or(Duration::new(0, 0));
        (balance, age)
    }

    fn should_pay(payable: &PayableAccount) -> bool {
        // TODO: This calculation should be done in the database, if possible
        let time_since_last_paid = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if time_since_last_paid <= PAYMENT_CURVES.payment_suggested_after_sec as u64 {
            return false;
        }

        if payable.balance <= PAYMENT_CURVES.permanent_debt_allowed_gwub {
            return false;
        }

        let threshold = Accountant::calculate_payout_threshold(time_since_last_paid);
        payable.balance as f64 > threshold
    }

    fn calculate_payout_threshold(x: u64) -> f64 {
        let m = -((PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - PAYMENT_CURVES.permanent_debt_allowed_gwub as f64)
            / (PAYMENT_CURVES.balance_decreases_for_sec as f64
                - PAYMENT_CURVES.payment_suggested_after_sec as f64));
        let b = PAYMENT_CURVES.balance_to_decrease_from_gwub as f64
            - m * PAYMENT_CURVES.payment_suggested_after_sec as f64;
        m * x as f64 + b
    }

    fn record_service_provided(
        &self,
        service_rate: u64,
        byte_rate: u64,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        self.receivable_dao
            .as_ref()
            .more_money_receivable(wallet, total_charge);
    }

    fn record_service_consumed(
        &self,
        service_rate: u64,
        byte_rate: u64,
        payload_size: usize,
        wallet: &Wallet,
    ) {
        let byte_charge = byte_rate * (payload_size as u64);
        let total_charge = service_rate + byte_charge;
        self.payable_dao
            .as_ref()
            .more_money_payable(wallet, total_charge);
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::payable_dao::PayableAccount;
    use super::*;
    use crate::accountant::receivable_dao::ReceivableAccount;
    use crate::accountant::test_utils::make_receivable_account;
    use crate::database::dao_utils::from_time_t;
    use crate::database::dao_utils::to_time_t;
    use crate::sub_lib::accountant::ReportRoutingServiceConsumedMessage;
    use crate::sub_lib::blockchain_bridge::ReportAccountsPayable;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::logging::init_test_logging;
    use crate::test_utils::logging::TestLogHandler;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::recorder::peer_actors_builder;
    use crate::test_utils::recorder::Recorder;
    use actix::System;
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::sync::{Arc, MutexGuard};
    use std::thread;
    use std::time::Duration;
    use std::time::SystemTime;

    #[derive(Debug)]
    pub struct PayableDaoMock {
        more_money_payable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
    }

    impl PayableDao for PayableDaoMock {
        fn more_money_payable(&self, wallet_address: &Wallet, amount: u64) {
            self.more_money_payable_parameters
                .lock()
                .unwrap()
                .push((wallet_address.clone(), amount));
        }

        fn payment_sent(&self, _wallet_address: &Wallet, _pending_payment_transaction: &str) {
            unimplemented!()
        }

        fn payment_confirmed(
            &self,
            _wallet_address: &Wallet,
            _amount: u64,
            _confirmation_noticed_timestamp: &SystemTime,
        ) {
            unimplemented!()
        }

        fn account_status(&self, _wallet_address: &Wallet) -> Option<PayableAccount> {
            unimplemented!()
        }

        fn non_pending_payables(&self) -> Vec<PayableAccount> {
            self.non_pending_payables_results.borrow_mut().remove(0)
        }
    }

    impl PayableDaoMock {
        pub fn new() -> PayableDaoMock {
            PayableDaoMock {
                more_money_payable_parameters: Arc::new(Mutex::new(vec![])),
                non_pending_payables_results: RefCell::new(vec![]),
            }
        }

        fn more_money_payable_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_payable_parameters = parameters;
            self
        }

        fn non_pending_payables_result(self, result: Vec<PayableAccount>) -> Self {
            self.non_pending_payables_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Debug)]
    pub struct ReceivableDaoMock {
        more_money_receivable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_received_parameters: Arc<Mutex<Vec<(Wallet, u64, SystemTime)>>>,
        new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
        paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentCurves>>>,
        paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    }

    impl ReceivableDao for ReceivableDaoMock {
        fn more_money_receivable(&self, wallet_address: &Wallet, amount: u64) {
            self.more_money_receivable_parameters
                .lock()
                .unwrap()
                .push((wallet_address.clone(), amount));
        }

        fn more_money_received(
            &self,
            wallet_address: &Wallet,
            amount: u64,
            timestamp: &SystemTime,
        ) {
            self.more_money_received_parameters.lock().unwrap().push((
                wallet_address.clone(),
                amount,
                timestamp.clone(),
            ));
        }

        fn account_status(&self, _wallet_address: &Wallet) -> Option<ReceivableAccount> {
            unimplemented!()
        }

        fn receivables(&self) -> Vec<ReceivableAccount> {
            unimplemented!()
        }

        fn new_delinquencies(
            &self,
            now: SystemTime,
            payment_curves: &PaymentCurves,
        ) -> Vec<ReceivableAccount> {
            self.new_delinquencies_parameters
                .lock()
                .unwrap()
                .push((now, payment_curves.clone()));
            self.new_delinquencies_results.borrow_mut().remove(0)
        }

        fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount> {
            self.paid_delinquencies_parameters
                .lock()
                .unwrap()
                .push(payment_curves.clone());
            self.paid_delinquencies_results.borrow_mut().remove(0)
        }
    }

    impl ReceivableDaoMock {
        pub fn new() -> ReceivableDaoMock {
            ReceivableDaoMock {
                more_money_receivable_parameters: Arc::new(Mutex::new(vec![])),
                more_money_received_parameters: Arc::new(Mutex::new(vec![])),
                new_delinquencies_results: RefCell::new(vec![]),
                new_delinquencies_parameters: Arc::new(Mutex::new(vec![])),
                paid_delinquencies_results: RefCell::new(vec![]),
                paid_delinquencies_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        fn more_money_receivable_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        ) -> Self {
            self.more_money_receivable_parameters = parameters;
            self
        }

        fn _more_money_received_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<(Wallet, u64, SystemTime)>>>,
        ) -> Self {
            self.more_money_received_parameters = parameters;
            self
        }

        fn new_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
        ) -> Self {
            self.new_delinquencies_parameters = parameters.clone();
            self
        }

        fn new_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.new_delinquencies_results.borrow_mut().push(result);
            self
        }

        fn paid_delinquencies_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<PaymentCurves>>>,
        ) -> Self {
            self.paid_delinquencies_parameters = parameters.clone();
            self
        }

        fn paid_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
            self.paid_delinquencies_results.borrow_mut().push(result);
            self
        }
    }

    struct BannedDaoMock {
        ban_list_parameters: Arc<Mutex<Vec<()>>>,
        ban_list_results: RefCell<Vec<Vec<Wallet>>>,
        ban_parameters: Arc<Mutex<Vec<Wallet>>>,
        unban_parameters: Arc<Mutex<Vec<Wallet>>>,
    }

    impl BannedDao for BannedDaoMock {
        fn ban_list(&self) -> Vec<Wallet> {
            self.ban_list_parameters.lock().unwrap().push(());
            self.ban_list_results.borrow_mut().remove(0)
        }

        fn ban(&self, wallet_address: &Wallet) {
            self.ban_parameters
                .lock()
                .unwrap()
                .push(wallet_address.clone());
        }

        fn unban(&self, wallet_address: &Wallet) {
            self.unban_parameters
                .lock()
                .unwrap()
                .push(wallet_address.clone());
        }
    }

    impl BannedDaoMock {
        pub fn new() -> BannedDaoMock {
            BannedDaoMock {
                ban_list_parameters: Arc::new(Mutex::new(vec![])),
                ban_list_results: RefCell::new(vec![]),
                ban_parameters: Arc::new(Mutex::new(vec![])),
                unban_parameters: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn ban_list_result(self, result: Vec<Wallet>) -> Self {
            self.ban_list_results.borrow_mut().push(result);
            self
        }

        pub fn ban_parameters(mut self, parameters: &Arc<Mutex<Vec<Wallet>>>) -> Self {
            self.ban_parameters = parameters.clone();
            self
        }

        pub fn unban_parameters(mut self, parameters: &Arc<Mutex<Vec<Wallet>>>) -> Self {
            self.unban_parameters = parameters.clone();
            self
        }
    }

    #[test]
    fn accountant_timer_triggers_periodic_scanning() {
        init_test_logging();
        let (blockchain_bridge, blockchain_bridge_awaiter, _) = make_recorder();
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let ban_parameters_arc_inner = ban_parameters_arc.clone();
        thread::spawn(move || {
            let system = System::new("accountant_timer_triggers_scanning_for_payables");
            let config = AccountantConfig {
                payable_scan_interval: Duration::from_millis(100),
            };
            let now = to_time_t(&SystemTime::now());
            // slightly above minimum balance, to the right of the curve (time intersection)
            let account0 = PayableAccount {
                wallet_address: Wallet::new("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
            };
            let account1 = PayableAccount {
                wallet_address: Wallet::new("wallet1"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 2,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 12,
                ),
                pending_payment_transaction: None,
            };
            let payable_dao = Box::new(
                PayableDaoMock::new().non_pending_payables_result(vec![account0, account1]),
            );
            let receivable_dao = Box::new(
                ReceivableDaoMock::new()
                    .new_delinquencies_result(vec![make_receivable_account(1234, true)])
                    .paid_delinquencies_result(vec![]),
            );
            let banned_dao = Box::new(
                BannedDaoMock::new()
                    .ban_list_result(vec![])
                    .ban_parameters(&ban_parameters_arc_inner),
            );
            let subject = Accountant::new(config, payable_dao, receivable_dao, banned_dao);
            let peer_actors = peer_actors_builder()
                .blockchain_bridge(blockchain_bridge)
                .build();
            let subject_addr: Addr<Accountant> = subject.start();
            let subject_subs = Accountant::make_subs_from(&subject_addr);

            subject_subs
                .bind
                .try_send(BindMessage { peer_actors })
                .unwrap();

            system.run();
        });

        blockchain_bridge_awaiter.await_message_count(1);
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Scanning for payables");
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert_eq!("wallet1234d", &ban_parameters[0].address);
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let now = to_time_t(&SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet_address: Wallet::new("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub - 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet_address: Wallet::new("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec + 10,
                ),
                pending_payment_transaction: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet_address: Wallet::new("wallet2"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub - 1000,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 1,
                ),
                pending_payment_transaction: None,
            },
        ];
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(accounts.clone());
        let receivable_dao = ReceivableDaoMock::new();
        let banned_dao = BannedDaoMock::new();
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub =
            blockchain_bridge_addr.recipient::<ReportAccountsPayable>();
        let mut subject = Accountant::new(
            config,
            Box::new(payable_dao),
            Box::new(receivable_dao),
            Box::new(banned_dao),
        );
        subject.report_accounts_payable_sub = Some(report_accounts_payable_sub);

        subject.scan_for_payables();

        System::current().stop_with_code(0);
        system.run();

        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }
    #[test]
    fn scan_for_payables_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let now = to_time_t(&SystemTime::now());
        let accounts = vec![
            // slightly above minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet_address: Wallet::new("wallet0"),
                balance: PAYMENT_CURVES.permanent_debt_allowed_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.balance_decreases_for_sec - 10,
                ),
                pending_payment_transaction: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet_address: Wallet::new("wallet1"),
                balance: PAYMENT_CURVES.balance_to_decrease_from_gwub + 1,
                last_paid_timestamp: from_time_t(
                    now - PAYMENT_CURVES.payment_suggested_after_sec - 10,
                ),
                pending_payment_transaction: None,
            },
        ];
        let payable_dao = PayableDaoMock::new().non_pending_payables_result(accounts.clone());
        let receivable_dao = ReceivableDaoMock::new();
        let banned_dao = BannedDaoMock::new();
        let (blockchain_bridge, blockchain_bridge_awaiter, blockchain_bridge_recordings_arc) =
            make_recorder();
        let system =
            System::new("scan_for_payables_message_triggers_payment_for_balances_over_the_curve");
        let blockchain_bridge_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub =
            blockchain_bridge_addr.recipient::<ReportAccountsPayable>();
        let mut subject = Accountant::new(
            config,
            Box::new(payable_dao),
            Box::new(receivable_dao),
            Box::new(banned_dao),
        );
        subject.report_accounts_payable_sub = Some(report_accounts_payable_sub);

        subject.scan_for_payables();

        System::current().stop_with_code(0);
        system.run();

        blockchain_bridge_awaiter.await_message_count(1);
        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(
            blockchain_bridge_recordings.get_record::<ReportAccountsPayable>(0),
            &ReportAccountsPayable { accounts }
        );
    }

    #[test]
    fn scan_for_delinquencies_triggers_bans_and_unbans() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let newly_banned_1 = make_receivable_account(1234, true);
        let newly_banned_2 = make_receivable_account(2345, true);
        let newly_unbanned_1 = make_receivable_account(3456, false);
        let newly_unbanned_2 = make_receivable_account(4567, false);
        let payable_dao = PayableDaoMock::new();
        let new_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let paid_delinquencies_parameters_arc = Arc::new(Mutex::new(vec![]));
        let receivable_dao = ReceivableDaoMock::new()
            .new_delinquencies_parameters(&new_delinquencies_parameters_arc)
            .new_delinquencies_result(vec![newly_banned_1.clone(), newly_banned_2.clone()])
            .paid_delinquencies_parameters(&paid_delinquencies_parameters_arc)
            .paid_delinquencies_result(vec![newly_unbanned_1.clone(), newly_unbanned_2.clone()]);
        let ban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unban_parameters_arc = Arc::new(Mutex::new(vec![]));
        let banned_dao = BannedDaoMock::new()
            .ban_list_result(vec![])
            .ban_parameters(&ban_parameters_arc)
            .unban_parameters(&unban_parameters_arc);
        let mut subject = Accountant::new(
            config,
            Box::new(payable_dao),
            Box::new(receivable_dao),
            Box::new(banned_dao),
        );

        subject.scan_for_delinquencies();

        let new_delinquencies_parameters: MutexGuard<Vec<(SystemTime, PaymentCurves)>> =
            new_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), new_delinquencies_parameters[0].1);
        let paid_delinquencies_parameters: MutexGuard<Vec<PaymentCurves>> =
            paid_delinquencies_parameters_arc.lock().unwrap();
        assert_eq!(PAYMENT_CURVES.clone(), paid_delinquencies_parameters[0]);
        let ban_parameters = ban_parameters_arc.lock().unwrap();
        assert!(ban_parameters.contains(&newly_banned_1.wallet_address));
        assert!(ban_parameters.contains(&newly_banned_2.wallet_address));
        assert_eq!(2, ban_parameters.len());
        let unban_parameters = unban_parameters_arc.lock().unwrap();
        assert!(unban_parameters.contains(&newly_unbanned_1.wallet_address));
        assert!(unban_parameters.contains(&newly_unbanned_2.wallet_address));
        assert_eq!(2, unban_parameters.len());
        let tlh = TestLogHandler::new();
        tlh.exists_log_matching ("INFO: Accountant: Wallet wallet1234d \\(balance: 1234 SUB, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching ("INFO: Accountant: Wallet wallet2345d \\(balance: 2345 SUB, age: \\d+ sec\\) banned for delinquency");
        tlh.exists_log_matching ("INFO: Accountant: Wallet wallet3456n \\(balance: 3456 SUB, age: \\d+ sec\\) is no longer delinquent: unbanned");
        tlh.exists_log_matching ("INFO: Accountant: Wallet wallet4567n \\(balance: 4567 SUB, age: \\d+ sec\\) is no longer delinquent: unbanned");
    }

    #[test]
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = Box::new(PayableDaoMock::new());
        let receivable_dao_mock = Box::new(
            ReceivableDaoMock::new()
                .more_money_receivable_parameters(more_money_receivable_parameters_arc.clone()),
        );
        let banned_dao_mock = Box::new(BannedDaoMock::new());
        let subject = Accountant::new(
            config,
            payable_dao_mock,
            receivable_dao_mock,
            banned_dao_mock,
        );
        let system = System::new("report_routing_service_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceProvidedMessage {
                consuming_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (Wallet::new("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Charging routing of 1234 bytes to wallet booga",
        );
    }

    #[test]
    fn report_routing_service_consumed_message_is_received() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = Box::new(
            PayableDaoMock::new()
                .more_money_payable_parameters(more_money_payable_parameters_arc.clone()),
        );
        let receivable_dao_mock = Box::new(ReceivableDaoMock::new());
        let banned_dao_mock = Box::new(BannedDaoMock::new());
        let subject = Accountant::new(
            config,
            payable_dao_mock,
            receivable_dao_mock,
            banned_dao_mock,
        );
        let system = System::new("report_routing_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportRoutingServiceConsumedMessage {
                earning_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (Wallet::new("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Accruing debt to wallet booga for consuming routing service 1234 bytes",
        );
    }

    #[test]
    fn report_exit_service_provided_message_is_received() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = Box::new(PayableDaoMock::new());
        let receivable_dao_mock = Box::new(
            ReceivableDaoMock::new()
                .more_money_receivable_parameters(more_money_receivable_parameters_arc.clone()),
        );
        let banned_dao_mock = Box::new(BannedDaoMock::new());
        let subject = Accountant::new(
            config,
            payable_dao_mock,
            receivable_dao_mock,
            banned_dao_mock,
        );
        let system = System::new("report_exit_service_provided_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceProvidedMessage {
                consuming_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_receivable_parameters = more_money_receivable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_receivable_parameters[0],
            (Wallet::new("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Charging exit service for 1234 bytes to wallet booga",
        );
    }

    #[test]
    fn report_exit_service_consumed_message_is_received() {
        init_test_logging();
        let config = AccountantConfig {
            payable_scan_interval: Duration::from_secs(100),
        };
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let payable_dao_mock = Box::new(
            PayableDaoMock::new()
                .more_money_payable_parameters(more_money_payable_parameters_arc.clone()),
        );
        let receivable_dao_mock = Box::new(ReceivableDaoMock::new());
        let banned_dao_mock = Box::new(BannedDaoMock::new());
        let subject = Accountant::new(
            config,
            payable_dao_mock,
            receivable_dao_mock,
            banned_dao_mock,
        );
        let system = System::new("report_exit_service_consumed_message_is_received");
        let subject_addr: Addr<Accountant> = subject.start();
        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        subject_addr
            .try_send(ReportExitServiceConsumedMessage {
                earning_wallet: Wallet::new("booga"),
                payload_size: 1234,
                service_rate: 42,
                byte_rate: 24,
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (Wallet::new("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Accruing debt to wallet booga for consuming exit service 1234 bytes",
        );
    }
}
