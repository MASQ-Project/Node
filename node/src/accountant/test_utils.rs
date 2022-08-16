// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::big_int_db_processor::{
    BigIntDbError, BigIntDbProcessor, BigIntSqlConfig, DAOTableIdentifier,
};
use crate::accountant::dao_utils::{from_time_t, to_time_t, CustomQuery};
use crate::accountant::payable_dao::{
    PayableAccount, PayableDao, PayableDaoError, PayableDaoFactory,
};
use crate::accountant::pending_payable_dao::{
    PendingPayableDao, PendingPayableDaoError, PendingPayableDaoFactory,
};
use crate::accountant::receivable_dao::{
    ReceivableAccount, ReceivableDao, ReceivableDaoError, ReceivableDaoFactory,
};
use crate::accountant::{Accountant, PendingPayableId};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::blockchain::blockchain_interface::BlockchainTransaction;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::{AccountantConfig, PaymentThresholds, WEIS_OF_GWEI};
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::unshared_test_utils::{
    make_populated_accountant_config_with_defaults, ArbitraryIdStamp,
};
use actix::System;
use ethereum_types::{BigEndianHash, H256, U256};
use itertools::Either;
use rusqlite::{Connection, Row, Transaction as RusqliteTransaction};
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

pub fn make_receivable_account(n: u64, expected_delinquent: bool) -> ReceivableAccount {
    let now = to_time_t(SystemTime::now());
    ReceivableAccount {
        wallet: make_wallet(&format!(
            "wallet{}{}",
            n,
            if expected_delinquent { "d" } else { "n" }
        )),
        balance_wei: (n * 1_000_000_000) as i128,
        last_received_timestamp: from_time_t(now - (n as i64)),
    }
}

pub fn make_payable_account(n: u64) -> PayableAccount {
    let now = to_time_t(SystemTime::now());
    let timestamp = from_time_t(now - (n as i64));
    make_payable_account_with_recipient_and_balance_and_timestamp_opt(
        make_wallet(&format!("wallet{}", n)),
        (n * 1_000_000_000) as u128,
        Some(timestamp),
    )
}

pub fn make_payable_account_with_recipient_and_balance_and_timestamp_opt(
    recipient: Wallet,
    balance: u128,
    timestamp_opt: Option<SystemTime>,
) -> PayableAccount {
    PayableAccount {
        wallet: recipient,
        balance_wei: balance,
        last_paid_timestamp: timestamp_opt.unwrap_or(SystemTime::now()),
        pending_payable_opt: None,
    }
}

pub struct AccountantBuilder {
    config: Option<BootstrapperConfig>,
    payable_dao_factory: Option<Box<dyn PayableDaoFactory>>,
    receivable_dao_factory: Option<Box<dyn ReceivableDaoFactory>>,
    pending_payable_dao_factory: Option<Box<dyn PendingPayableDaoFactory>>,
    banned_dao_factory: Option<Box<dyn BannedDaoFactory>>,
    config_dao_factory: Option<Box<dyn ConfigDaoFactory>>,
}

impl Default for AccountantBuilder {
    fn default() -> Self {
        Self {
            config: None,
            payable_dao_factory: None,
            receivable_dao_factory: None,
            pending_payable_dao_factory: None,
            banned_dao_factory: None,
            config_dao_factory: None,
        }
    }
}

impl AccountantBuilder {
    pub fn bootstrapper_config(mut self, config: BootstrapperConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> Self {
        self.payable_dao_factory = Some(Box::new(PayableDaoFactoryMock::new(payable_dao)));
        self
    }

    pub fn receivable_dao(mut self, receivable_dao: ReceivableDaoMock) -> Self {
        self.receivable_dao_factory = Some(Box::new(ReceivableDaoFactoryMock::new(receivable_dao)));
        self
    }

    pub fn pending_payable_dao(mut self, pending_payable_dao: PendingPayableDaoMock) -> Self {
        self.pending_payable_dao_factory = Some(Box::new(PendingPayableDaoFactoryMock::new(
            pending_payable_dao,
        )));
        self
    }

    pub fn banned_dao(mut self, banned_dao: BannedDaoMock) -> Self {
        self.banned_dao_factory = Some(Box::new(BannedDaoFactoryMock::new(banned_dao)));
        self
    }

    pub fn config_dao(mut self, config_dao: ConfigDaoMock) -> Self {
        self.config_dao_factory = Some(Box::new(ConfigDaoFactoryMock::new(config_dao)));
        self
    }

    pub fn build(self) -> Accountant {
        let config = self.config.unwrap_or({
            let mut config = BootstrapperConfig::default();
            config.accountant_config_opt = Some(make_populated_accountant_config_with_defaults());
            config
        });
        let payable_dao_factory = self
            .payable_dao_factory
            .unwrap_or(Box::new(PayableDaoFactoryMock::new(PayableDaoMock::new())));
        let receivable_dao_factory =
            self.receivable_dao_factory
                .unwrap_or(Box::new(ReceivableDaoFactoryMock::new(
                    ReceivableDaoMock::new(),
                )));
        let pending_payable_dao_factory = self.pending_payable_dao_factory.unwrap_or(Box::new(
            PendingPayableDaoFactoryMock::new(PendingPayableDaoMock::default()),
        ));
        let banned_dao_factory = self
            .banned_dao_factory
            .unwrap_or(Box::new(BannedDaoFactoryMock::new(BannedDaoMock::new())));
        let accountant = Accountant::new(
            &config,
            payable_dao_factory,
            receivable_dao_factory,
            pending_payable_dao_factory,
            banned_dao_factory,
        );
        accountant
    }
}

pub struct PayableDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Vec<PayableDaoMock>>,
}

impl PayableDaoFactory for PayableDaoFactoryMock {
    fn make(&self) -> Box<dyn PayableDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().remove(0))
    }
}

impl PayableDaoFactoryMock {
    pub fn new(mock: PayableDaoMock) -> Self {
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
    mock: RefCell<Vec<ReceivableDaoMock>>,
}

impl ReceivableDaoFactory for ReceivableDaoFactoryMock {
    fn make(&self) -> Box<dyn ReceivableDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().remove(0))
    }
}

impl ReceivableDaoFactoryMock {
    pub fn new(mock: ReceivableDaoMock) -> Self {
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
    more_money_payable_parameters: Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    more_money_payable_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    non_pending_payable_params: Arc<Mutex<Vec<()>>>,
    non_pending_payable_results: RefCell<Vec<Vec<PayableAccount>>>,
    mark_pending_payable_rowid_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    mark_pending_payable_rowid_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    transaction_confirmed_params: Arc<Mutex<Vec<PendingPayableFingerprint>>>,
    transaction_confirmed_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    transaction_canceled_params: Arc<Mutex<Vec<PendingPayableId>>>,
    transaction_canceled_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    custom_query_params: Arc<Mutex<Vec<CustomQuery<u64>>>>,
    custom_query_result: RefCell<Vec<Option<Vec<PayableAccount>>>>,
    total_results: RefCell<Vec<u128>>,
    pub have_non_pending_payable_shut_down_the_system: bool,
}

impl PayableDao for PayableDaoMock {
    fn more_money_payable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), PayableDaoError> {
        self.more_money_payable_parameters
            .lock()
            .unwrap()
            .push((now, wallet.clone(), amount));
        self.more_money_payable_results.borrow_mut().remove(0)
    }

    fn mark_pending_payable_rowid(
        &self,
        wallet: &Wallet,
        pending_payable_rowid: u64,
    ) -> Result<(), PayableDaoError> {
        self.mark_pending_payable_rowid_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), pending_payable_rowid));
        self.mark_pending_payable_rowid_results
            .borrow_mut()
            .remove(0)
    }

    fn transaction_confirmed(
        &self,
        payment: &PendingPayableFingerprint,
    ) -> Result<(), PayableDaoError> {
        self.transaction_confirmed_params
            .lock()
            .unwrap()
            .push(payment.clone());
        self.transaction_confirmed_results.borrow_mut().remove(0)
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        self.non_pending_payable_params.lock().unwrap().push(());
        if self.have_non_pending_payable_shut_down_the_system
            && self.non_pending_payable_results.borrow().is_empty()
        {
            System::current().stop();
            return vec![];
        }
        self.non_pending_payable_results.borrow_mut().remove(0)
    }

    fn custom_query(&self, custom_query: CustomQuery<u64>) -> Option<Vec<PayableAccount>> {
        self.custom_query_params.lock().unwrap().push(custom_query);
        self.custom_query_result.borrow_mut().remove(0)
    }

    fn total(&self) -> u128 {
        self.total_results.borrow_mut().remove(0)
    }

    fn account_status(&self, _wallet: &Wallet) -> Option<PayableAccount> {
        //test-only trait member
        intentionally_blank!()
    }
}

impl PayableDaoMock {
    pub fn new() -> PayableDaoMock {
        PayableDaoMock::default()
    }

    pub fn more_money_payable_parameters(
        mut self,
        parameters: Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    ) -> Self {
        self.more_money_payable_parameters = parameters;
        self
    }

    pub fn more_money_payable_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.more_money_payable_results.borrow_mut().push(result);
        self
    }

    pub fn non_pending_payables_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.non_pending_payable_params = params.clone();
        self
    }

    pub fn non_pending_payables_result(self, result: Vec<PayableAccount>) -> Self {
        self.non_pending_payable_results.borrow_mut().push(result);
        self
    }

    pub fn mark_pending_payable_rowid_params(
        mut self,
        parameters: &Arc<Mutex<Vec<(Wallet, u64)>>>,
    ) -> Self {
        self.mark_pending_payable_rowid_parameters = parameters.clone();
        self
    }

    pub fn mark_pending_payable_rowid_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.mark_pending_payable_rowid_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn transaction_confirmed_params(
        mut self,
        params: &Arc<Mutex<Vec<PendingPayableFingerprint>>>,
    ) -> Self {
        self.transaction_confirmed_params = params.clone();
        self
    }

    pub fn transaction_confirmed_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.transaction_confirmed_results.borrow_mut().push(result);
        self
    }

    pub fn transaction_canceled_params(
        mut self,
        params: &Arc<Mutex<Vec<PendingPayableId>>>,
    ) -> Self {
        self.transaction_canceled_params = params.clone();
        self
    }

    pub fn transaction_canceled_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.transaction_canceled_results.borrow_mut().push(result);
        self
    }

    pub fn custom_query_params(mut self, params: &Arc<Mutex<Vec<CustomQuery<u64>>>>) -> Self {
        self.custom_query_params = params.clone();
        self
    }

    pub fn custom_query_result(self, result: Option<Vec<PayableAccount>>) -> Self {
        self.custom_query_result.borrow_mut().push(result);
        self
    }

    pub fn total_result(self, result: u128) -> Self {
        self.total_results.borrow_mut().push(result);
        self
    }
}

#[derive(Debug, Default)]
pub struct ReceivableDaoMock {
    more_money_receivable_parameters: Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    more_money_receivable_results: RefCell<Vec<Result<(), ReceivableDaoError>>>,
    more_money_received_parameters: Arc<Mutex<Vec<(SystemTime, Vec<BlockchainTransaction>)>>>,
    more_money_received_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentThresholds)>>>,
    new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentThresholds>>>,
    paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    custom_query_params: Arc<Mutex<Vec<CustomQuery<i64>>>>,
    custom_query_result: RefCell<Vec<Option<Vec<ReceivableAccount>>>>,
    total_results: RefCell<Vec<i128>>,
    pub have_new_delinquencies_shutdown_the_system: bool,
}

impl ReceivableDao for ReceivableDaoMock {
    fn more_money_receivable(
        &self,
        now: SystemTime,
        wallet: &Wallet,
        amount: u128,
    ) -> Result<(), ReceivableDaoError> {
        self.more_money_receivable_parameters
            .lock()
            .unwrap()
            .push((now, wallet.clone(), amount));
        self.more_money_receivable_results.borrow_mut().remove(0)
    }

    fn more_money_received(&mut self, now: SystemTime, transactions: Vec<BlockchainTransaction>) {
        self.more_money_received_parameters
            .lock()
            .unwrap()
            .push((now, transactions));
    }

    fn new_delinquencies(
        &self,
        now: SystemTime,
        payment_thresholds: &PaymentThresholds,
    ) -> Vec<ReceivableAccount> {
        self.new_delinquencies_parameters
            .lock()
            .unwrap()
            .push((now, payment_thresholds.clone()));
        if self.new_delinquencies_results.borrow().is_empty()
            && self.have_new_delinquencies_shutdown_the_system
        {
            System::current().stop();
            return vec![];
        }
        self.new_delinquencies_results.borrow_mut().remove(0)
    }

    fn paid_delinquencies(&self, payment_thresholds: &PaymentThresholds) -> Vec<ReceivableAccount> {
        self.paid_delinquencies_parameters
            .lock()
            .unwrap()
            .push(payment_thresholds.clone());
        self.paid_delinquencies_results.borrow_mut().remove(0)
    }

    fn custom_query(&self, custom_query: CustomQuery<i64>) -> Option<Vec<ReceivableAccount>> {
        self.custom_query_params.lock().unwrap().push(custom_query);
        self.custom_query_result.borrow_mut().remove(0)
    }

    fn total(&self) -> i128 {
        self.total_results.borrow_mut().remove(0)
    }

    fn account_status(&self, _wallet: &Wallet) -> Option<ReceivableAccount> {
        //test-only trait member
        intentionally_blank!()
    }
}

impl ReceivableDaoMock {
    pub fn new() -> ReceivableDaoMock {
        Self::default()
    }

    pub fn more_money_receivable_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    ) -> Self {
        self.more_money_receivable_parameters = parameters.clone();
        self
    }

    pub fn more_money_receivable_result(self, result: Result<(), ReceivableDaoError>) -> Self {
        self.more_money_receivable_results.borrow_mut().push(result);
        self
    }

    pub fn more_money_received_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(SystemTime, Vec<BlockchainTransaction>)>>>,
    ) -> Self {
        self.more_money_received_parameters = parameters.clone();
        self
    }

    pub fn more_money_received_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.more_money_received_results.borrow_mut().push(result);
        self
    }

    pub fn new_delinquencies_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<(SystemTime, PaymentThresholds)>>>,
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
        parameters: &Arc<Mutex<Vec<PaymentThresholds>>>,
    ) -> Self {
        self.paid_delinquencies_parameters = parameters.clone();
        self
    }

    pub fn paid_delinquencies_result(self, result: Vec<ReceivableAccount>) -> ReceivableDaoMock {
        self.paid_delinquencies_results.borrow_mut().push(result);
        self
    }

    pub fn custom_query_params(mut self, params: &Arc<Mutex<Vec<CustomQuery<i64>>>>) -> Self {
        self.custom_query_params = params.clone();
        self
    }

    pub fn custom_query_result(self, result: Option<Vec<ReceivableAccount>>) -> Self {
        self.custom_query_result.borrow_mut().push(result);
        self
    }

    pub fn total_result(self, result: i128) -> Self {
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
    bc.accountant_config_opt = Some(ac);
    bc.earning_wallet = earning_wallet;
    bc
}

pub fn bc_from_ac_plus_wallets(
    ac: AccountantConfig,
    consuming_wallet: Wallet,
    earning_wallet: Wallet,
) -> BootstrapperConfig {
    let mut bc = BootstrapperConfig::new();
    bc.accountant_config_opt = Some(ac);
    bc.consuming_wallet_opt = Some(consuming_wallet);
    bc.earning_wallet = earning_wallet;
    bc
}

#[derive(Default)]
pub struct PendingPayableDaoMock {
    fingerprint_rowid_params: Arc<Mutex<Vec<H256>>>,
    fingerprint_rowid_results: RefCell<Vec<Option<u64>>>,
    delete_fingerprint_params: Arc<Mutex<Vec<u64>>>,
    delete_fingerprint_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    insert_fingerprint_params: Arc<Mutex<Vec<(H256, u128, SystemTime)>>>,
    insert_fingerprint_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    update_fingerprint_params: Arc<Mutex<Vec<u64>>>,
    update_fingerprint_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    mark_failure_params: Arc<Mutex<Vec<u64>>>,
    mark_failure_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    return_all_fingerprints_params: Arc<Mutex<Vec<()>>>,
    return_all_fingerprints_results: RefCell<Vec<Vec<PendingPayableFingerprint>>>,
    pub have_return_all_fingerprints_shut_down_the_system: bool,
}

impl PendingPayableDao for PendingPayableDaoMock {
    fn fingerprint_rowid(&self, transaction_hash: H256) -> Option<u64> {
        self.fingerprint_rowid_params
            .lock()
            .unwrap()
            .push(transaction_hash);
        self.fingerprint_rowid_results.borrow_mut().remove(0)
    }

    fn return_all_fingerprints(&self) -> Vec<PendingPayableFingerprint> {
        self.return_all_fingerprints_params.lock().unwrap().push(());
        if self.have_return_all_fingerprints_shut_down_the_system
            && self.return_all_fingerprints_results.borrow().is_empty()
        {
            System::current().stop();
            return vec![];
        }
        self.return_all_fingerprints_results.borrow_mut().remove(0)
    }

    fn insert_new_fingerprint(
        &self,
        transaction_hash: H256,
        amount: u128,
        timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        self.insert_fingerprint_params
            .lock()
            .unwrap()
            .push((transaction_hash, amount, timestamp));
        self.insert_fingerprint_results.borrow_mut().remove(0)
    }

    fn delete_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        self.delete_fingerprint_params.lock().unwrap().push(id);
        self.delete_fingerprint_results.borrow_mut().remove(0)
    }

    fn update_fingerprint(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        self.update_fingerprint_params.lock().unwrap().push(id);
        self.update_fingerprint_results.borrow_mut().remove(0)
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPayableDaoError> {
        self.mark_failure_params.lock().unwrap().push(id);
        self.mark_failure_results.borrow_mut().remove(0)
    }
}

impl PendingPayableDaoMock {
    pub fn fingerprint_rowid_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
        self.fingerprint_rowid_params = params.clone();
        self
    }

    pub fn fingerprint_rowid_result(self, result: Option<u64>) -> Self {
        self.fingerprint_rowid_results.borrow_mut().push(result);
        self
    }

    pub fn insert_fingerprint_params(
        mut self,
        params: &Arc<Mutex<Vec<(H256, u128, SystemTime)>>>,
    ) -> Self {
        self.insert_fingerprint_params = params.clone();
        self
    }

    pub fn insert_fingerprint_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.insert_fingerprint_results.borrow_mut().push(result);
        self
    }

    pub fn delete_fingerprint_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.delete_fingerprint_params = params.clone();
        self
    }

    pub fn delete_fingerprint_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.delete_fingerprint_results.borrow_mut().push(result);
        self
    }

    pub fn return_all_fingerprints_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.return_all_fingerprints_params = params.clone();
        self
    }

    pub fn return_all_fingerprints_result(self, result: Vec<PendingPayableFingerprint>) -> Self {
        self.return_all_fingerprints_results
            .borrow_mut()
            .push(result);
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

    pub fn update_fingerprint_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.update_fingerprint_params = params.clone();
        self
    }

    pub fn update_fingerprint_results(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.update_fingerprint_results.borrow_mut().push(result);
        self
    }
}

pub struct PendingPayableDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Vec<PendingPayableDaoMock>>,
}

impl PendingPayableDaoFactory for PendingPayableDaoFactoryMock {
    fn make(&self) -> Box<dyn PendingPayableDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().remove(0))
    }
}

impl PendingPayableDaoFactoryMock {
    pub fn new(mock: PendingPayableDaoMock) -> Self {
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

pub fn make_pending_payable_fingerprint() -> PendingPayableFingerprint {
    PendingPayableFingerprint {
        rowid_opt: Some(33),
        timestamp: from_time_t(222_222_222),
        hash: H256::from_uint(&U256::from(456)),
        attempt_opt: Some(0),
        amount: 12345,
        process_error: None,
    }
}

#[derive(Default, Debug)]
pub struct BigIntDbProcessorMock {
    update_params: Arc<Mutex<Vec<(Option<ArbitraryIdStamp>, SQLConfigAbstract, String)>>>, //trait-object-like params tested specially
    update_results: RefCell<Vec<Result<(), BigIntDbError>>>,
    execute_params: Arc<Mutex<Vec<(Option<ArbitraryIdStamp>, SQLConfigAbstract, String)>>>,
    execute_results: RefCell<Vec<Result<(), BigIntDbError>>>,
}

impl<T: DAOTableIdentifier> BigIntDbProcessor<T> for BigIntDbProcessorMock {
    fn execute<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &RusqliteTransaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let config_characteristics = config.config_characteristics_for_assertion();
        self.execute_params.lock().unwrap().push((
            if let Either::Left(conn) = conn {
                Some(conn.arbitrary_id_stamp())
            } else {
                None
            },
            config_characteristics,
            T::table_name(),
        ));
        self.execute_results.borrow_mut().remove(0)
    }

    fn update_threatened_by_overflow<'a>(
        &self,
        conn: Either<&dyn ConnectionWrapper, &RusqliteTransaction>,
        config: BigIntSqlConfig<'a, T>,
    ) -> Result<(), BigIntDbError> {
        let config_characteristics = config.config_characteristics_for_assertion();
        self.update_params.lock().unwrap().push((
            if let Either::Left(conn) = conn {
                Some(conn.arbitrary_id_stamp())
            } else {
                None
            },
            config_characteristics,
            T::table_name(),
        ));
        self.update_results.borrow_mut().remove(0)
    }
}

#[derive(Debug)]
pub struct SQLConfigAbstract {
    pub main_stm: String,
    pub select_stm: String,
    pub overflow_update_stm: String,
    //further only params alone
    pub table_key_name: String,
    pub wei_change_params: [(String, i64); 2],
    pub remaining_params: Vec<(String, String)>,
}

impl BigIntDbProcessorMock {
    pub fn update_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<ArbitraryIdStamp>, SQLConfigAbstract, String)>>>,
    ) -> Self {
        self.update_params = params.clone();
        self
    }

    pub fn update_result(self, result: Result<(), BigIntDbError>) -> Self {
        self.update_results.borrow_mut().push(result);
        self
    }

    pub fn execute_params(
        mut self,
        params: &Arc<Mutex<Vec<(Option<ArbitraryIdStamp>, SQLConfigAbstract, String)>>>,
    ) -> Self {
        self.execute_params = params.clone();
        self
    }

    pub fn execute_result(self, result: Result<(), BigIntDbError>) -> Self {
        self.execute_results.borrow_mut().push(result);
        self
    }
}

pub fn convert_to_all_string_values(str_args: Vec<(&str, &str)>) -> Vec<(String, String)> {
    str_args
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

pub fn assert_on_sloped_segment_of_payment_thresholds_and_its_proper_alignment<F>(
    tested_fn: F,
    payment_thresholds: PaymentThresholds,
    higher_corner_timestamp: u64,
    middle_point_timestamp: u64,
    lower_corner_timestamp: u64,
) where
    F: Fn(&PaymentThresholds, u64) -> i128,
{
    let higher_corner_point = tested_fn(&payment_thresholds, higher_corner_timestamp);
    let middle_point = tested_fn(&payment_thresholds, middle_point_timestamp);
    let lower_corner_point = tested_fn(&payment_thresholds, lower_corner_timestamp);

    let allowed_imprecision = 1 * WEIS_OF_GWEI;
    let ideal_template_higher = payment_thresholds.debt_threshold_gwei as i128 * WEIS_OF_GWEI;
    let ideal_template_middle = ((payment_thresholds.debt_threshold_gwei
        - payment_thresholds.permanent_debt_allowed_gwei)
        / 2
        + payment_thresholds.permanent_debt_allowed_gwei) as i128
        * WEIS_OF_GWEI;
    let ideal_template_lower =
        payment_thresholds.permanent_debt_allowed_gwei as i128 * WEIS_OF_GWEI;
    assert!(
        higher_corner_point <= ideal_template_higher + allowed_imprecision
            && ideal_template_higher - allowed_imprecision <= higher_corner_point,
        "ideal: {}, real: {}",
        ideal_template_higher,
        higher_corner_point
    );
    assert!(
        middle_point <= ideal_template_middle + allowed_imprecision
            && ideal_template_middle - allowed_imprecision <= middle_point,
        "ideal: {}, real: {}",
        ideal_template_middle,
        middle_point
    );
    assert!(
        lower_corner_point <= ideal_template_lower + allowed_imprecision
            && ideal_template_lower - allowed_imprecision <= lower_corner_point,
        "ideal: {}, real: {}",
        ideal_template_lower,
        lower_corner_point
    );
}

pub fn assert_database_blows_up_on_an_unexpected_error<F, R>(tested_fn: F)
where
    F: Fn(&Row) -> rusqlite::Result<R>,
{
    let conn = Connection::open_in_memory().unwrap();
    conn.execute("create table whatever (exclamations text)", [])
        .unwrap();
    conn.execute("insert into whatever (exclamations) values ('Gosh')", [])
        .unwrap();

    conn.query_row("select exclamations from whatever", [], tested_fn)
        .unwrap();
}
