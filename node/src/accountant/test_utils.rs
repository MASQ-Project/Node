// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoFactory};
use crate::accountant::pending_payable_dao::{
    PendingPayableDao, PendingPayableDaoError, PendingPayableDaoFactory,
};
use crate::accountant::receivable_dao::{ReceivableAccount, ReceivableDao, ReceivableDaoFactory};
use crate::accountant::{Accountant, DebtRecordingError, PaymentCurves, PaymentError, TransactionId};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::PaymentFingerprint;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::{from_time_t, to_time_t};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
use actix::System;
use ethereum_types::{BigEndianHash, H256, U256};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use crate::blockchain::blockchain_interface::Transaction;

pub fn make_receivable_account(n: u64, expected_delinquent: bool) -> ReceivableAccount {
    let now = to_time_t(SystemTime::now());
    ReceivableAccount {
        wallet: make_wallet(&format!(
            "wallet{}{}",
            n,
            if expected_delinquent { "d" } else { "n" }
        )),
        balance: (n * 1_000_000_000) as i64,
        last_received_timestamp: from_time_t(now - (n as i64)),
    }
}

pub fn make_payable_account(n: u64) -> PayableAccount {
    let now = to_time_t(SystemTime::now());
    let timestamp = from_time_t(now - (n as i64));
    make_payable_account_with_recipient_and_balance_and_timestamp_opt(
        make_wallet(&format!("wallet{}", n)),
        (n * 1_000_000_000) as i64,
        Some(timestamp),
    )
}

pub fn make_payable_account_with_recipient_and_balance_and_timestamp_opt(
    recipient: Wallet,
    balance: i64,
    timestamp_opt: Option<SystemTime>,
) -> PayableAccount {
    PayableAccount {
        wallet: recipient,
        balance,
        last_paid_timestamp: timestamp_opt.unwrap_or(SystemTime::now()),
        pending_payable_rowid_opt: None,
    }
}

//TODO should I replace this with the builder?
pub fn make_accountant(
    config_opt: Option<BootstrapperConfig>,
    payable_dao_opt: Option<PayableDaoMock>,
    receivable_dao_opt: Option<ReceivableDaoMock>,
    pending_payable_dao_opt: Option<PendingPayableDaoMock>,
    banned_dao_opt: Option<BannedDaoMock>,
    persistent_config_opt: Option<PersistentConfigurationMock>,
) -> Accountant {
    let payable_dao_factory =
        PayableDaoFactoryMock::new(Box::new(payable_dao_opt.unwrap_or(PayableDaoMock::new())));
    let receivable_dao_factory =
        ReceivableDaoFactoryMock::new(receivable_dao_opt.unwrap_or(ReceivableDaoMock::new()));
    let pending_payable_dao_factory = PendingPaymentsDaoFactoryMock::new(
        pending_payable_dao_opt.unwrap_or(PendingPayableDaoMock::default()),
    );
    let banned_dao_factory =
        BannedDaoFactoryMock::new(banned_dao_opt.unwrap_or(BannedDaoMock::new()));
    let mut subject = Accountant::new(
        &config_opt.unwrap_or(BootstrapperConfig::new()),
        Box::new(payable_dao_factory),
        Box::new(receivable_dao_factory),
        Box::new(pending_payable_dao_factory),
        Box::new(banned_dao_factory),
        Box::new(ConfigDaoFactoryMock::new(ConfigDaoMock::new())),
    );
    subject.persistent_configuration = if let Some(persistent_config) = persistent_config_opt {
        Box::new(persistent_config)
    } else {
        Box::new(PersistentConfigurationMock::new())
    };
    subject
}

pub struct AccountantBuilder {
    config: BootstrapperConfig,
    payable_dao_factory: Box<dyn PayableDaoFactory>,
    receivable_dao_factory: Box<dyn ReceivableDaoFactory>,
    pending_payable_dao_factory: Box<dyn PendingPayableDaoFactory>,
    banned_dao_factory: Box<dyn BannedDaoFactory>,
    config_dao_factory: Box<dyn ConfigDaoFactory>,
}

impl Default for AccountantBuilder {
    fn default() -> Self {
        Self {
            config: Default::default(),
            payable_dao_factory: Box::new(PayableDaoFactoryMock::new(Box::new(
                PayableDaoMock::new(),
            ))),
            receivable_dao_factory: Box::new(ReceivableDaoFactoryMock::new(
                ReceivableDaoMock::new(),
            )),
            pending_payable_dao_factory: Box::new(PendingPaymentsDaoFactoryMock::new(
                PendingPayableDaoMock::default(),
            )),
            banned_dao_factory: Box::new(BannedDaoFactoryMock::new(BannedDaoMock::new())),
            config_dao_factory: Box::new(ConfigDaoFactoryMock::new(ConfigDaoMock::new())),
        }
    }
}

impl AccountantBuilder {
    pub fn bootstrapper_config(mut self, config: BootstrapperConfig) -> Self {
        self.config = config;
        self
    }
    pub fn payable_dao_factory(mut self, payable_dao: Box<dyn PayableDaoFactory>) -> Self {
        self.payable_dao_factory = payable_dao;
        self
    }
    pub fn receivable_dao_factory(mut self, receivable_dao: Box<dyn ReceivableDaoFactory>) -> Self {
        self.receivable_dao_factory = receivable_dao;
        self
    }

    pub fn pending_payable_dao_factory(
        mut self,
        pending_payable_dao: Box<dyn PendingPayableDaoFactory>,
    ) -> Self {
        self.pending_payable_dao_factory = pending_payable_dao;
        self
    }

    pub fn banned_dao_factory(mut self, banned_dao: Box<dyn BannedDaoFactory>) -> Self {
        self.banned_dao_factory = banned_dao;
        self
    }
    pub fn persistent_config_dao_factory(
        mut self,
        persistent_config_dao: Box<dyn ConfigDaoFactory>,
    ) -> Self {
        self.config_dao_factory = persistent_config_dao;
        self
    }
    pub fn build(self) -> Accountant {
        Accountant::new(
            &self.config,
            self.payable_dao_factory,
            self.receivable_dao_factory,
            self.pending_payable_dao_factory,
            self.banned_dao_factory,
            self.config_dao_factory,
        )
    }
}

pub struct PayableDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Vec<Box<dyn PayableDao>>>,
}

impl PayableDaoFactory for PayableDaoFactoryMock {
    fn make(&self) -> Box<dyn PayableDao> {
        *self.called.borrow_mut() = true;
        self.mock.borrow_mut().remove(0)
    }
}

impl PayableDaoFactoryMock {
    pub fn new(mock: Box<dyn PayableDao>) -> Self {
        Self {
            called: Rc::new(RefCell::new(false)),
            mock: RefCell::new(vec![mock]),
        }
    }

    pub fn called(mut self, called: &Rc<RefCell<bool>>) -> Self {
        self.called = called.clone();
        self
    }
}

pub struct ReceivableDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Option<ReceivableDaoMock>>,
}

impl ReceivableDaoFactory for ReceivableDaoFactoryMock {
    fn make(&self) -> Box<dyn ReceivableDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().take().unwrap())
    }
}

impl ReceivableDaoFactoryMock {
    pub fn new(mock: ReceivableDaoMock) -> Self {
        Self {
            called: Rc::new(RefCell::new(false)),
            mock: RefCell::new(Some(mock)),
        }
    }

    pub fn called(mut self, called: &Rc<RefCell<bool>>) -> Self {
        self.called = called.clone();
        self
    }
}

pub struct BannedDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Option<BannedDaoMock>>,
}

impl BannedDaoFactory for BannedDaoFactoryMock {
    fn make(&self) -> Box<dyn BannedDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().take().unwrap())
    }
}

impl BannedDaoFactoryMock {
    pub fn new(mock: BannedDaoMock) -> Self {
        Self {
            called: Rc::new(RefCell::new(false)),
            mock: RefCell::new(Some(mock)),
        }
    }

    pub fn called(mut self, called: &Rc<RefCell<bool>>) -> Self {
        self.called = called.clone();
        self
    }
}

pub struct ConfigDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Option<ConfigDaoMock>>,
}

impl ConfigDaoFactory for ConfigDaoFactoryMock {
    fn make(&self) -> Box<dyn ConfigDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().take().unwrap())
    }
}

impl ConfigDaoFactoryMock {
    pub fn new(mock: ConfigDaoMock) -> Self {
        Self {
            called: Rc::new(RefCell::new(false)),
            mock: RefCell::new(Some(mock)),
        }
    }

    pub fn called(mut self, called: &Rc<RefCell<bool>>) -> Self {
        self.called = called.clone();
        self
    }
}

#[derive(Debug, Default)]
pub struct PayableDaoMock {
    account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
    account_status_results: RefCell<Vec<Option<PayableAccount>>>,
    more_money_payable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    more_money_payable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
    non_pending_payables_params: Arc<Mutex<Vec<()>>>,
    non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
    mark_pending_payable_rowid_parameters: Arc<Mutex<Vec<(Wallet, TransactionId)>>>,
    mark_pending_payable_rowid_results: RefCell<Vec<Result<(), PaymentError>>>,
    transaction_confirmed_params: Arc<Mutex<Vec<PaymentFingerprint>>>,
    transaction_confirmed_results: RefCell<Vec<Result<(), PaymentError>>>,
    transaction_canceled_params: Arc<Mutex<Vec<TransactionId>>>,
    transaction_canceled_results: RefCell<Vec<Result<(), PaymentError>>>,
    top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
    top_records_results: RefCell<Vec<Vec<PayableAccount>>>,
    total_results: RefCell<Vec<u64>>,
    pub have_non_pending_payables_shut_down_the_system: bool,
}

impl PayableDao for PayableDaoMock {
    fn more_money_payable(
        &self,
        wallet: &Wallet,
        amount: u64,
    ) -> Result<(), DebtRecordingError> {
        self.more_money_payable_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), amount));
        self.more_money_payable_results.borrow_mut().remove(0)
    }

    fn mark_pending_payable_rowid(
        &self,
        wallet: &Wallet,
        transaction_id: TransactionId,
    ) -> Result<(), PaymentError> {
        self.mark_pending_payable_rowid_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), transaction_id));
        self.mark_pending_payable_rowid_results
            .borrow_mut()
            .remove(0)
    }

    fn transaction_confirmed(&self, payment: &PaymentFingerprint) -> Result<(), PaymentError> {
        self.transaction_confirmed_params
            .lock()
            .unwrap()
            .push(payment.clone());
        self.transaction_confirmed_results.borrow_mut().remove(0)
    }

    fn transaction_canceled(&self, transaction_id: TransactionId) -> Result<(), PaymentError> {
        self.transaction_canceled_params
            .lock()
            .unwrap()
            .push(transaction_id);
        self.transaction_canceled_results.borrow_mut().remove(0)
    }

    fn account_status(&self, wallet: &Wallet) -> Option<PayableAccount> {
        self.account_status_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());
        self.account_status_results.borrow_mut().remove(0)
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        self.non_pending_payables_params.lock().unwrap().push(());
        if self.have_non_pending_payables_shut_down_the_system
            && self.non_pending_payables_results.borrow().is_empty()
        {
            System::current().stop();
            return vec![];
        }
        self.non_pending_payables_results.borrow_mut().remove(0)
    }

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<PayableAccount> {
        self.top_records_parameters
            .lock()
            .unwrap()
            .push((minimum_amount, maximum_age));
        self.top_records_results.borrow_mut().remove(0)
    }

    fn total(&self) -> u64 {
        self.total_results.borrow_mut().remove(0)
    }
}

impl PayableDaoMock {
    pub fn new() -> PayableDaoMock {
        PayableDaoMock::default()
    }

    pub fn more_money_payable_parameters(
        mut self,
        parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    ) -> Self {
        self.more_money_payable_parameters = parameters;
        self
    }

    pub fn more_money_payable_result(self, result: Result<(), DebtRecordingError>) -> Self {
        self.more_money_payable_results.borrow_mut().push(result);
        self
    }

    pub fn non_pending_payables_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.non_pending_payables_params = params.clone();
        self
    }

    pub fn non_pending_payables_result(self, result: Vec<PayableAccount>) -> Self {
        self.non_pending_payables_results.borrow_mut().push(result);
        self
    }

    pub fn mark_pending_payment_params(
        mut self,
        parameters: &Arc<Mutex<Vec<(Wallet, TransactionId)>>>,
    ) -> Self {
        self.mark_pending_payable_rowid_parameters = parameters.clone();
        self
    }

    pub fn mark_pending_payment_result(self, result: Result<(), PaymentError>) -> Self {
        self.mark_pending_payable_rowid_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn transaction_confirmed_params(
        mut self,
        params: &Arc<Mutex<Vec<PaymentFingerprint>>>,
    ) -> Self {
        self.transaction_confirmed_params = params.clone();
        self
    }

    pub fn transaction_confirmed_result(self, result: Result<(), PaymentError>) -> Self {
        self.transaction_confirmed_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_canceled_params(
        mut self,
        params: &Arc<Mutex<Vec<TransactionId>>>,
    ) -> Self {
        self.transaction_canceled_params = params.clone();
        self
    }

    pub fn transaction_canceled_result(self, result: Result<(), PaymentError>) -> Self {
        self.transaction_canceled_results.borrow_mut().push(result);
        self
    }

    pub fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
        self.top_records_parameters = parameters.clone();
        self
    }

    pub fn top_records_result(self, result: Vec<PayableAccount>) -> Self {
        self.top_records_results.borrow_mut().push(result);
        self
    }

    pub fn total_result(self, result: u64) -> Self {
        self.total_results.borrow_mut().push(result);
        self
    }
}

#[derive(Debug, Default)]
pub struct ReceivableDaoMock {
    account_status_parameters: Arc<Mutex<Vec<Wallet>>>,
    account_status_results: RefCell<Vec<Option<ReceivableAccount>>>,
    more_money_receivable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    more_money_receivable_results: RefCell<Vec<Result<(), DebtRecordingError>>>,
    more_money_received_parameters: Arc<Mutex<Vec<Vec<Transaction>>>>,
    more_money_received_results: RefCell<Vec<Result<(), PaymentError>>>,
    receivables_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
    new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentCurves>>>,
    paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
    top_records_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    total_results: RefCell<Vec<u64>>,
    pub have_new_delinquencies_shutdown_the_system: bool,
}

impl ReceivableDao for ReceivableDaoMock {
    fn more_money_receivable(
        &self,
        wallet: &Wallet,
        amount: u64,
    ) -> Result<(), DebtRecordingError> {
        self.more_money_receivable_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), amount));
        self.more_money_receivable_results.borrow_mut().remove(0)
    }

    fn more_money_received(&mut self, transactions: Vec<Transaction>) {
        self.more_money_received_parameters
            .lock()
            .unwrap()
            .push(transactions);
    }

    fn account_status(&self, wallet: &Wallet) -> Option<ReceivableAccount> {
        self.account_status_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());

        self.account_status_results.borrow_mut().remove(0)
    }

    fn receivables(&self) -> Vec<ReceivableAccount> {
        self.receivables_results.borrow_mut().remove(0)
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
        if self.new_delinquencies_results.borrow().is_empty()
            && self.have_new_delinquencies_shutdown_the_system
        {
            System::current().stop();
            return vec![];
        }
        self.new_delinquencies_results.borrow_mut().remove(0)
    }

    fn paid_delinquencies(&self, payment_curves: &PaymentCurves) -> Vec<ReceivableAccount> {
        self.paid_delinquencies_parameters
            .lock()
            .unwrap()
            .push(payment_curves.clone());
        self.paid_delinquencies_results.borrow_mut().remove(0)
    }

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
        self.top_records_parameters
            .lock()
            .unwrap()
            .push((minimum_amount, maximum_age));
        self.top_records_results.borrow_mut().remove(0)
    }

    fn total(&self) -> u64 {
        self.total_results.borrow_mut().remove(0)
    }
}

impl ReceivableDaoMock {
    pub fn new() -> ReceivableDaoMock {
        Self::default()
    }

    pub fn more_money_receivable_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(Wallet, u64)>>>,
    ) -> Self {
        self.more_money_receivable_parameters = parameters.clone();
        self
    }

    pub fn more_money_receivable_result(self, result: Result<(), DebtRecordingError>) -> Self {
        self.more_money_receivable_results.borrow_mut().push(result);
        self
    }

    pub fn more_money_received_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<Vec<Transaction>>>>,
    ) -> Self {
        self.more_money_received_parameters = parameters.clone();
        self
    }

    pub fn more_money_received_result(self, result: Result<(), PaymentError>) -> Self {
        self.more_money_received_results.borrow_mut().push(result);
        self
    }

    pub fn new_delinquencies_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(SystemTime, PaymentCurves)>>>,
    ) -> Self {
        self.new_delinquencies_parameters = parameters.clone();
        self
    }

    pub fn new_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
        self.new_delinquencies_results.borrow_mut().push(result);
        self
    }

    pub fn paid_delinquencies_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<PaymentCurves>>>,
    ) -> Self {
        self.paid_delinquencies_parameters = parameters.clone();
        self
    }

    pub fn paid_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
        self.paid_delinquencies_results.borrow_mut().push(result);
        self
    }

    pub fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
        self.top_records_parameters = parameters.clone();
        self
    }

    pub fn top_records_result(self, result: Vec<ReceivableAccount>) -> Self {
        self.top_records_results.borrow_mut().push(result);
        self
    }

    pub fn total_result(self, result: u64) -> Self {
        self.total_results.borrow_mut().push(result);
        self
    }
}

#[derive(Debug, Default)]
pub struct BannedDaoMock {
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

    fn ban(&self, wallet: &Wallet) {
        self.ban_parameters.lock().unwrap().push(wallet.clone());
    }

    fn unban(&self, wallet: &Wallet) {
        self.unban_parameters.lock().unwrap().push(wallet.clone());
    }
}

impl BannedDaoMock {
    pub fn new() -> Self {
        Self {
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

pub fn bc_from_ac_plus_earning_wallet(
    ac: AccountantConfig,
    earning_wallet: Wallet,
) -> BootstrapperConfig {
    let mut bc = BootstrapperConfig::new();
    bc.accountant_config = ac;
    bc.earning_wallet = earning_wallet;
    bc
}

pub fn bc_from_ac_plus_wallets(
    ac: AccountantConfig,
    consuming_wallet: Wallet,
    earning_wallet: Wallet,
) -> BootstrapperConfig {
    let mut bc = BootstrapperConfig::new();
    bc.accountant_config = ac;
    bc.consuming_wallet_opt = Some(consuming_wallet);
    bc.earning_wallet = earning_wallet;
    bc
}

#[derive(Default)]
pub struct PendingPayableDaoMock {
    pending_payable_fingerprint_exists_params: Arc<Mutex<Vec<H256>>>,
    pending_payable_fingerprint_exists_results: RefCell<Vec<Option<u64>>>,
    delete_pending_payable_fingerprint_params: Arc<Mutex<Vec<u64>>>,
    delete_pending_payable_fingerprint_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    insert_pending_payable_fingerprint_params: Arc<Mutex<Vec<(H256, u64, SystemTime)>>>,
    insert_pending_payable_fingerprint_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    update_backup_after_scan_cycle_params: Arc<Mutex<Vec<u64>>>,
    update_backup_after_scan_cycle_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    hash_params: Arc<Mutex<Vec<u64>>>,
    hash_results: RefCell<Vec<Result<H256, PendingPayableDaoError>>>,
    mark_failure_params: Arc<Mutex<Vec<u64>>>,
    mark_failure_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    return_all_pending_payable_fingerprints_params: Arc<Mutex<Vec<()>>>,
    return_all_pending_payable_fingerprints_results: RefCell<Vec<Vec<PaymentFingerprint>>>,
    pub have_return_all_pending_payable_fingerprints_shut_down_the_system: bool,
}

impl PendingPayableDao for PendingPayableDaoMock {
    fn pending_payable_fingerprint_exists(&self, transaction_hash: H256) -> Option<u64> {
        self.pending_payable_fingerprint_exists_params
            .lock()
            .unwrap()
            .push(transaction_hash);
        self.pending_payable_fingerprint_exists_results
            .borrow_mut()
            .remove(0)
    }

    fn return_all_pending_payable_fingerprints(&self) -> Vec<PaymentFingerprint> {
        self.return_all_pending_payable_fingerprints_params
            .lock()
            .unwrap()
            .push(());
        if self.have_return_all_pending_payable_fingerprints_shut_down_the_system
            && self
                .return_all_pending_payable_fingerprints_results
                .borrow()
                .is_empty()
        {
            System::current().stop();
            return vec![];
        }
        self.return_all_pending_payable_fingerprints_results
            .borrow_mut()
            .remove(0)
    }

    fn insert_new_pending_payable_fingerprint(
        &self,
        transaction_hash: H256,
        amount: u64,
        timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        self.insert_pending_payable_fingerprint_params
            .lock()
            .unwrap()
            .push((transaction_hash, amount, timestamp));
        self.insert_pending_payable_fingerprint_results
            .borrow_mut()
            .remove(0)
    }

    fn hash(&self, id: u64) -> Result<H256, PendingPayableDaoError> {
        self.hash_params.lock().unwrap().push(id);
        self.hash_results.borrow_mut().remove(0)
    }

    fn delete_pending_payable_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        self.delete_pending_payable_fingerprint_params
            .lock()
            .unwrap()
            .push(id);
        self.delete_pending_payable_fingerprint_results
            .borrow_mut()
            .remove(0)
    }

    fn update_pending_payable_fingerprint_after_scan_cycle(
        &self,
        id: u64,
    ) -> Result<(), PendingPayableDaoError> {
        self.update_backup_after_scan_cycle_params
            .lock()
            .unwrap()
            .push(id);
        self.update_backup_after_scan_cycle_results
            .borrow_mut()
            .remove(0)
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        self.mark_failure_params.lock().unwrap().push(id);
        self.mark_failure_results.borrow_mut().remove(0)
    }
}

impl PendingPayableDaoMock {
    pub fn pending_payable_fingerprint_exists_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
        self.pending_payable_fingerprint_exists_params = params.clone();
        self
    }

    pub fn pending_payable_fingerprint_exists_result(self, result: Option<u64>) -> Self {
        self.pending_payable_fingerprint_exists_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn insert_pending_payable_fingerprint_params(
        mut self,
        params: &Arc<Mutex<Vec<(H256, u64, SystemTime)>>>,
    ) -> Self {
        self.insert_pending_payable_fingerprint_params = params.clone();
        self
    }

    pub fn insert_pending_payable_fingerprint_result(
        self,
        result: Result<(), PendingPayableDaoError>,
    ) -> Self {
        self.insert_pending_payable_fingerprint_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn delete_pending_payable_fingerprint_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.delete_pending_payable_fingerprint_params = params.clone();
        self
    }

    pub fn delete_pending_payable_fingerprint_result(
        self,
        result: Result<(), PendingPayableDaoError>,
    ) -> Self {
        self.delete_pending_payable_fingerprint_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn return_all_pending_payable_fingerprints_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.return_all_pending_payable_fingerprints_params = params.clone();
        self
    }

    pub fn return_all_pending_payable_fingerprints_result(self, result: Vec<PaymentFingerprint>) -> Self {
        self.return_all_pending_payable_fingerprints_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn hash_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.hash_params = params.clone();
        self
    }

    pub fn hash_result(self, result: Result<H256, PendingPayableDaoError>) -> Self {
        self.hash_results.borrow_mut().push(result);
        self
    }

    pub fn mark_failure_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.mark_failure_params = params.clone();
        self
    }

    pub fn mark_failure_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.mark_failure_results.borrow_mut().push(result);
        self
    }

    pub fn update_backup_after_scan_cycle_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.update_backup_after_scan_cycle_params = params.clone();
        self
    }

    pub fn update_backup_after_scan_cycle_results(
        self,
        result: Result<(), PendingPayableDaoError>,
    ) -> Self {
        self.update_backup_after_scan_cycle_results
            .borrow_mut()
            .push(result);
        self
    }
}

pub struct PendingPaymentsDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Option<PendingPayableDaoMock>>,
}

impl PendingPayableDaoFactory for PendingPaymentsDaoFactoryMock {
    fn make(&self) -> Box<dyn PendingPayableDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().take().unwrap())
    }
}

impl PendingPaymentsDaoFactoryMock {
    pub fn new(mock: PendingPayableDaoMock) -> Self {
        Self {
            called: Rc::new(RefCell::new(false)),
            mock: RefCell::new(Some(mock)),
        }
    }

    pub fn called(mut self, called: &Rc<RefCell<bool>>) -> Self {
        self.called = called.clone();
        self
    }
}

pub fn make_pending_payable_fingerprint() -> PaymentFingerprint {
    PaymentFingerprint {
        rowid: 33,
        timestamp: from_time_t(222_222_222),
        hash: H256::from_uint(&U256::from(456)),
        attempt: 0,
        amount: 12345,
        process_error: None,
    }
}
