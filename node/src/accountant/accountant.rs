// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use super::db_initializer::DbInitializer;
use super::db_initializer::DbInitializerReal;
use super::payable_dao::PayableDao;
use super::receivable_dao::ReceivableDao;
use crate::accountant::payable_dao::PayableAccount;
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
use std::fs;
use std::time::SystemTime;

pub const PAYMENT_CURVE_MINIMUM_TIME: i64 = 86400; // one day
pub const PAYMENT_CURVE_TIME_INTERSECTION: i64 = 2592000; // thirty days
pub const PAYMENT_CURVE_MINIMUM_BALANCE: i64 = 10000000; // ten million
pub const PAYMENT_CURVE_BALANCE_INTERSECTION: i64 = 1000000000; // one billion
pub const DEFAULT_PAYABLE_SCAN_INTERVAL: u64 = 3600; // one hour

pub struct Accountant {
    config: AccountantConfig,
    db_initializer: Box<DbInitializer>,
    payable_dao: Option<Box<PayableDao>>,
    receivable_dao: Option<Box<ReceivableDao>>,
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
        self.establish_data_directory();
        ctx.set_mailbox_capacity(NODE_MAILBOX_CAPACITY);
        ctx.run_interval(self.config.payable_scan_interval, |act, _ctx| {
            act.logger.debug("Scanning for payables".to_string());
            Accountant::scan_for_payables(
                act.payable_dao.as_ref().expect("PayableDao is unbound"),
                act.report_accounts_payable_sub
                    .as_ref()
                    .expect("BlockchainBridge is unbound"),
            );
        });
        self.logger.info(String::from("Accountant bound"));
        ()
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
        ()
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
        ()
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
        ()
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
        ()
    }
}

impl Accountant {
    pub fn new(config: AccountantConfig) -> Accountant {
        Accountant {
            config,
            db_initializer: Box::new(DbInitializerReal::new()),
            payable_dao: None,
            receivable_dao: None,
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

    fn scan_for_payables(
        payable_dao: &Box<PayableDao>,
        report_accounts_payable_sub: &Recipient<ReportAccountsPayable>,
    ) {
        let payables = payable_dao
            .non_pending_payables()
            .into_iter()
            .filter(Accountant::should_pay)
            .collect::<Vec<PayableAccount>>();

        if payables.len() > 0 {
            report_accounts_payable_sub
                .try_send(ReportAccountsPayable { accounts: payables })
                .expect("BlockchainBridge is dead");
        }
    }

    fn should_pay(payable: &PayableAccount) -> bool {
        let time_since_last_paid = SystemTime::now()
            .duration_since(payable.last_paid_timestamp)
            .expect("Internal error")
            .as_secs();

        if time_since_last_paid <= PAYMENT_CURVE_MINIMUM_TIME as u64 {
            return false;
        }

        if payable.balance <= PAYMENT_CURVE_MINIMUM_BALANCE {
            return false;
        }

        let threshold = Accountant::calculate_payout_threshold(time_since_last_paid);
        payable.balance as f64 > threshold
    }

    fn calculate_payout_threshold(x: u64) -> f64 {
        let m = -((PAYMENT_CURVE_BALANCE_INTERSECTION as f64
            - PAYMENT_CURVE_MINIMUM_BALANCE as f64)
            / (PAYMENT_CURVE_TIME_INTERSECTION as f64 - PAYMENT_CURVE_MINIMUM_TIME as f64));
        let b = PAYMENT_CURVE_BALANCE_INTERSECTION as f64 - m * PAYMENT_CURVE_MINIMUM_TIME as f64;
        m * x as f64 + b
    }

    fn establish_data_directory(&mut self) {
        self.create_data_directory_if_necessary();
        let daos = self
            .db_initializer
            .initialize(&self.config.data_directory)
            .expect("Could not initialize database");
        self.payable_dao = Some(daos.payable);
        self.receivable_dao = Some(daos.receivable);
    }

    fn create_data_directory_if_necessary(&self) {
        match fs::read_dir(&self.config.data_directory) {
            Ok(_) => (),
            Err(_) => fs::create_dir_all(&self.config.data_directory).expect(
                format!(
                    "Cannot create specified data directory at {:?}",
                    self.config.data_directory
                )
                .as_str(),
            ),
        }
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
            .expect("Accountant not bound")
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
            .expect("Accountant not bound")
            .more_money_payable(wallet, total_charge);
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::db_initializer::Daos;
    use super::super::db_initializer::InitializationError;
    use super::super::local_test_utils::BASE_TEST_DIR;
    use super::super::payable_dao::PayableAccount;
    use super::*;
    use crate::accountant::dao_utils::from_time_t;
    use crate::accountant::dao_utils::to_time_t;
    use crate::accountant::receivable_dao::ReceivableAccount;
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
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use std::time::SystemTime;

    struct DbInitializerMock {
        initialize_parameters: Arc<Mutex<Vec<PathBuf>>>,
        initialize_results: RefCell<Vec<Result<Daos, InitializationError>>>,
    }

    impl DbInitializer for DbInitializerMock {
        fn initialize(&self, path: &PathBuf) -> Result<Daos, InitializationError> {
            self.initialize_parameters
                .lock()
                .unwrap()
                .push(path.clone());
            self.initialize_results.borrow_mut().remove(0)
        }
    }

    impl DbInitializerMock {
        fn new() -> DbInitializerMock {
            DbInitializerMock {
                initialize_parameters: Arc::new(Mutex::new(vec![])),
                initialize_results: RefCell::new(vec![]),
            }
        }

        fn initialize_parameters(
            mut self,
            parameters: Arc<Mutex<Vec<PathBuf>>>,
        ) -> DbInitializerMock {
            self.initialize_parameters = parameters;
            self
        }

        fn initialize_result(self, result: Result<Daos, InitializationError>) -> DbInitializerMock {
            self.initialize_results.borrow_mut().push(result);
            self
        }
    }

    #[derive(Debug)]
    struct PayableDaoMock {
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
        fn new() -> PayableDaoMock {
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
    struct ReceivableDaoMock {
        more_money_receivable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
        more_money_received_parameters: Arc<Mutex<Vec<(Wallet, u64, SystemTime)>>>,
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
    }

    impl ReceivableDaoMock {
        fn new() -> ReceivableDaoMock {
            ReceivableDaoMock {
                more_money_receivable_parameters: Arc::new(Mutex::new(vec![])),
                more_money_received_parameters: Arc::new(Mutex::new(vec![])),
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
    }

    #[test]
    fn accountant_timer_triggers_scanning_for_payables() {
        init_test_logging();
        let (blockchain_bridge, blockchain_bridge_awaiter, _) = make_recorder();
        thread::spawn(move || {
            let system = System::new("accountant_timer_triggers_scanning_for_payables");
            let data_dir = PathBuf::from(format!(
                "{}/accountant_timer_triggers_scanning_for_payables/home",
                BASE_TEST_DIR
            ));
            let config = AccountantConfig {
                data_directory: data_dir.clone(),
                payable_scan_interval: Duration::from_millis(100),
            };
            let now = to_time_t(&SystemTime::now());
            let accounts = vec![
                // slightly above minimum balance, to the right of the curve (time intersection)
                PayableAccount {
                    wallet_address: Wallet::new("wallet0"),
                    balance: PAYMENT_CURVE_MINIMUM_BALANCE + 1,
                    last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_TIME_INTERSECTION - 10),
                    pending_payment_transaction: None,
                },
            ];
            let daos = Daos {
                payable: Box::new(
                    PayableDaoMock::new()
                        .non_pending_payables_result(accounts.clone())
                        .non_pending_payables_result(accounts),
                ),
                receivable: Box::new(ReceivableDaoMock::new()),
            };
            let db_initializer = DbInitializerMock::new().initialize_result(Ok(daos));
            let mut subject = Accountant::new(config);
            subject.db_initializer = Box::new(db_initializer);
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

        blockchain_bridge_awaiter.await_message_count(2);
        TestLogHandler::new().exists_log_containing("DEBUG: Accountant: Scanning for payables");
    }

    #[test]
    fn scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve() {
        init_test_logging();
        let now = to_time_t(&SystemTime::now());
        let accounts = vec![
            // below minimum balance, to the right of time intersection (inside buffer zone)
            PayableAccount {
                wallet_address: Wallet::new("wallet0"),
                balance: PAYMENT_CURVE_MINIMUM_BALANCE - 1,
                last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_TIME_INTERSECTION - 10),
                pending_payment_transaction: None,
            },
            // above balance intersection, to the left of minimum time (inside buffer zone)
            PayableAccount {
                wallet_address: Wallet::new("wallet1"),
                balance: PAYMENT_CURVE_BALANCE_INTERSECTION + 1,
                last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_MINIMUM_TIME + 10),
                pending_payment_transaction: None,
            },
            // above minimum balance, to the right of minimum time (not in buffer zone, below the curve)
            PayableAccount {
                wallet_address: Wallet::new("wallet2"),
                balance: PAYMENT_CURVE_BALANCE_INTERSECTION - 1000,
                last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_MINIMUM_TIME - 1),
                pending_payment_transaction: None,
            },
        ];
        let payable_dao: Box<PayableDao> =
            Box::new(PayableDaoMock::new().non_pending_payables_result(accounts.clone()));
        let (blockchain_bridge, _, blockchain_bridge_recordings_arc) = make_recorder();
        let system = System::new(
            "scan_for_payables_message_does_not_trigger_payment_for_balances_below_the_curve",
        );
        let subject_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub = subject_addr.recipient::<ReportAccountsPayable>();

        Accountant::scan_for_payables(&payable_dao, &report_accounts_payable_sub);

        System::current().stop_with_code(0);
        system.run();

        let blockchain_bridge_recordings = blockchain_bridge_recordings_arc.lock().unwrap();
        assert_eq!(blockchain_bridge_recordings.len(), 0);
    }

    #[test]
    fn scan_for_payables_message_triggers_payment_for_balances_over_the_curve() {
        init_test_logging();
        let now = to_time_t(&SystemTime::now());
        let accounts = vec![
            // slightly above minimum balance, to the right of the curve (time intersection)
            PayableAccount {
                wallet_address: Wallet::new("wallet0"),
                balance: PAYMENT_CURVE_MINIMUM_BALANCE + 1,
                last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_TIME_INTERSECTION - 10),
                pending_payment_transaction: None,
            },
            // slightly above the curve (balance intersection), to the right of minimum time
            PayableAccount {
                wallet_address: Wallet::new("wallet1"),
                balance: PAYMENT_CURVE_BALANCE_INTERSECTION + 1,
                last_paid_timestamp: from_time_t(now - PAYMENT_CURVE_MINIMUM_TIME - 10),
                pending_payment_transaction: None,
            },
        ];
        let payable_dao: Box<PayableDao> =
            Box::new(PayableDaoMock::new().non_pending_payables_result(accounts.clone()));
        let (blockchain_bridge, blockchain_bridge_awaiter, blockchain_bridge_recordings_arc) =
            make_recorder();
        let system =
            System::new("scan_for_payables_message_triggers_payment_for_balances_over_the_curve");
        let subject_addr: Addr<Recorder> = blockchain_bridge.start();
        let report_accounts_payable_sub = subject_addr.recipient::<ReportAccountsPayable>();

        Accountant::scan_for_payables(&payable_dao, &report_accounts_payable_sub);

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
    fn report_routing_service_provided_message_is_received() {
        init_test_logging();
        let data_dir = PathBuf::from(format!(
            "{}/report_routing_service_provided_message_is_received/home",
            BASE_TEST_DIR
        ));
        let config = AccountantConfig {
            data_directory: data_dir.clone(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let dbi_initialize_parameters_arc = Arc::new(Mutex::new(vec![]));
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let daos = Daos {
            payable: Box::new(PayableDaoMock::new()),
            receivable: Box::new(
                ReceivableDaoMock::new()
                    .more_money_receivable_parameters(more_money_receivable_parameters_arc.clone()),
            ),
        };
        let db_initializer = DbInitializerMock::new()
            .initialize_parameters(dbi_initialize_parameters_arc.clone())
            .initialize_result(Ok(daos));
        let mut subject = Accountant::new(config);
        subject.db_initializer = Box::new(db_initializer);
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
        let dbi_initialize_parameters = dbi_initialize_parameters_arc.lock().unwrap();
        assert_eq!(dbi_initialize_parameters[0], data_dir);
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
        let data_dir = PathBuf::from(format!(
            "{}/report_routing_service_consumed_message_is_received/home",
            BASE_TEST_DIR
        ));
        let config = AccountantConfig {
            data_directory: data_dir.clone(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let dbi_initialize_parameters_arc = Arc::new(Mutex::new(vec![]));
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let daos = Daos {
            payable: Box::new(
                PayableDaoMock::new()
                    .more_money_payable_parameters(more_money_payable_parameters_arc.clone()),
            ),
            receivable: Box::new(ReceivableDaoMock::new()),
        };
        let db_initializer = DbInitializerMock::new()
            .initialize_parameters(dbi_initialize_parameters_arc.clone())
            .initialize_result(Ok(daos));
        let mut subject = Accountant::new(config);
        subject.db_initializer = Box::new(db_initializer);
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
        let dbi_initialize_parameters = dbi_initialize_parameters_arc.lock().unwrap();
        assert_eq!(dbi_initialize_parameters[0], data_dir);
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
            data_directory: PathBuf::new(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let more_money_receivable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let daos = Daos {
            payable: Box::new(PayableDaoMock::new()),
            receivable: Box::new(
                ReceivableDaoMock::new()
                    .more_money_receivable_parameters(more_money_receivable_parameters_arc.clone()),
            ),
        };
        let db_initializer = DbInitializerMock::new().initialize_result(Ok(daos));
        let mut subject = Accountant::new(config);
        subject.db_initializer = Box::new(db_initializer);
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
        let data_dir = PathBuf::from(format!(
            "{}/report_exit_service_consumed_message_is_received/home",
            BASE_TEST_DIR
        ));
        let config = AccountantConfig {
            data_directory: data_dir.clone(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let dbi_initialize_parameters_arc = Arc::new(Mutex::new(vec![]));
        let more_money_payable_parameters_arc = Arc::new(Mutex::new(vec![]));
        let daos = Daos {
            payable: Box::new(
                PayableDaoMock::new()
                    .more_money_payable_parameters(more_money_payable_parameters_arc.clone()),
            ),
            receivable: Box::new(ReceivableDaoMock::new()),
        };
        let db_initializer = DbInitializerMock::new()
            .initialize_parameters(dbi_initialize_parameters_arc.clone())
            .initialize_result(Ok(daos));
        let mut subject = Accountant::new(config);
        subject.db_initializer = Box::new(db_initializer);
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
        let dbi_initialize_parameters = dbi_initialize_parameters_arc.lock().unwrap();
        assert_eq!(dbi_initialize_parameters[0], PathBuf::from(data_dir));
        let more_money_payable_parameters = more_money_payable_parameters_arc.lock().unwrap();
        assert_eq!(
            more_money_payable_parameters[0],
            (Wallet::new("booga"), (1 * 42) + (1234 * 24))
        );
        TestLogHandler::new().exists_log_containing(
            "DEBUG: Accountant: Accruing debt to wallet booga for consuming exit service 1234 bytes",
        );
    }

    #[test]
    fn nonexistent_directory_is_created_when_possible() {
        let data_dir = PathBuf::from(format!(
            "{}/nonexistent_directory_is_created_when_possible/home",
            BASE_TEST_DIR
        ));
        fs::remove_dir_all(&data_dir).is_ok();
        let config = AccountantConfig {
            data_directory: data_dir.clone(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let subject = Accountant::new(config);

        subject.create_data_directory_if_necessary();

        // If .unwrap() succeeds, test passes! (If not, it gives a better failure message than .is_ok())
        fs::read_dir(data_dir).unwrap();
    }

    #[test]
    fn directory_is_unmolested_if_present() {
        let data_dir = PathBuf::from(format!(
            "{}/directory_is_unmolested_if_present/home",
            BASE_TEST_DIR
        ));
        fs::remove_dir_all(&data_dir).is_ok();
        fs::create_dir_all(&data_dir).is_ok();
        {
            let mut file = File::create(data_dir.join("booga.txt")).unwrap();
            file.write(b"unmolested").unwrap();
        }
        let config = AccountantConfig {
            data_directory: data_dir.clone(),
            payable_scan_interval: Duration::from_secs(100),
        };
        let subject = Accountant::new(config);

        subject.create_data_directory_if_necessary();

        let mut file = File::open(data_dir.join("booga.txt")).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, String::from("unmolested"));
    }

    #[test]
    #[should_panic(expected = "Could not initialize database")]
    fn failed_initialization_produces_panic() {
        let data_dir = PathBuf::from(format!(
            "{}/failed_initialization_produces_panic/home",
            BASE_TEST_DIR
        ));
        let config = AccountantConfig {
            data_directory: data_dir,
            payable_scan_interval: Duration::from_secs(100),
        };
        let mut subject = Accountant::new(config);
        let db_initializer = DbInitializerMock::new()
            .initialize_result(Err(InitializationError::IncompatibleVersion));
        subject.db_initializer = Box::new(db_initializer);
        let system = System::new("failed_initialization_produces_panic");
        let subject_addr: Addr<Accountant> = subject.start();

        subject_addr
            .try_send(BindMessage {
                peer_actors: peer_actors_builder().build(),
            })
            .unwrap();

        System::current().stop_with_code(0);
        system.run();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[should_panic(
        expected = "Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }"
    )]
    fn linux_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[should_panic(
        expected = "Os { code: 13, kind: PermissionDenied, message: \"Permission denied\" }"
    )]
    fn macos_panic_if_directory_is_nonexistent_and_cant_be_created() {
        panic_if_directory_is_nonexistent_and_cant_be_created(&create_read_only_directory())
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[should_panic(
        expected = "Custom { kind: Other, error: StringError(\"failed to create whole tree\") }"
    )]
    fn windows_panic_if_directory_is_nonexistent_and_cant_be_created() {
        let base_path = PathBuf::from("M:\\nonexistent");
        panic_if_directory_is_nonexistent_and_cant_be_created(&base_path);
    }

    fn panic_if_directory_is_nonexistent_and_cant_be_created(base_path: &PathBuf) {
        let config = AccountantConfig {
            data_directory: base_path.join("home"),
            payable_scan_interval: Duration::from_secs(100),
        };
        let subject = Accountant::new(config);

        subject.create_data_directory_if_necessary();
    }

    #[cfg(not(target_os = "windows"))]
    fn create_read_only_directory() -> PathBuf {
        let data_dir = PathBuf::from(format!(
            "{}/panic_if_directory_is_nonexistent_and_cant_be_created/home",
            BASE_TEST_DIR
        ));
        let parent_dir = data_dir.parent().unwrap();
        match fs::metadata(parent_dir) {
            Err(_) => (),
            Ok(metadata) => {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                fs::set_permissions(parent_dir, permissions).unwrap();
            }
        }
        fs::remove_dir_all(&data_dir).is_ok();
        fs::create_dir_all(parent_dir).unwrap();
        let mut permissions = fs::metadata(parent_dir).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(parent_dir, permissions).unwrap();
        PathBuf::from(parent_dir)
    }
}
