// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

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
use crate::database::dao_utils;
use crate::database::dao_utils::{from_time_t, to_time_t};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::{AccountantConfig, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::unshared_test_utils::{
    make_payment_thresholds_with_defaults, make_populated_accountant_config_with_defaults,
};
use actix::System;
use ethereum_types::{BigEndianHash, H256, U256};
use rusqlite::{Connection, Error, OptionalExtension};
use std::cell::RefCell;
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
        pending_payable_opt: None,
    }
}

pub struct AccountantBuilder {
    config: Option<BootstrapperConfig>,
    payable_dao_factory: Option<PayableDaoFactoryMock>,
    receivable_dao_factory: Option<ReceivableDaoFactoryMock>,
    pending_payable_dao_factory: Option<PendingPayableDaoFactoryMock>,
    banned_dao_factory: Option<BannedDaoFactoryMock>,
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
        match self.payable_dao_factory {
            None => {
                self.payable_dao_factory =
                    Some(PayableDaoFactoryMock::new().make_result(payable_dao))
            }
            Some(payable_dao_factory) => {
                self.payable_dao_factory = Some(payable_dao_factory.make_result(payable_dao))
            }
        }
        self
    }

    pub fn receivable_dao(mut self, receivable_dao: ReceivableDaoMock) -> Self {
        match self.receivable_dao_factory {
            None => {
                self.receivable_dao_factory =
                    Some(ReceivableDaoFactoryMock::new().make_result(receivable_dao))
            }
            Some(receivable_dao_factory) => {
                self.receivable_dao_factory =
                    Some(receivable_dao_factory.make_result(receivable_dao))
            }
        }
        self
    }

    pub fn pending_payable_dao(mut self, pending_payable_dao: PendingPayableDaoMock) -> Self {
        match self.pending_payable_dao_factory {
            None => {
                self.pending_payable_dao_factory =
                    Some(PendingPayableDaoFactoryMock::new().make_result(pending_payable_dao))
            }
            Some(pending_payable_dao_factory) => {
                self.pending_payable_dao_factory =
                    Some(pending_payable_dao_factory.make_result(pending_payable_dao))
            }
        }
        self
    }

    pub fn banned_dao(mut self, banned_dao: BannedDaoMock) -> Self {
        match self.banned_dao_factory {
            None => {
                self.banned_dao_factory = Some(BannedDaoFactoryMock::new().make_result(banned_dao))
            }
            Some(banned_dao_factory) => {
                self.banned_dao_factory = Some(banned_dao_factory.make_result(banned_dao))
            }
        }
        self
    }

    pub fn config_dao(mut self, config_dao: ConfigDaoMock) -> Self {
        self.config_dao_factory = Some(Box::new(ConfigDaoFactoryMock::new(config_dao)));
        self
    }

    pub fn build(self) -> Accountant {
        let mut config = self.config.unwrap_or({
            let mut config = BootstrapperConfig::default();
            config.accountant_config_opt = Some(make_populated_accountant_config_with_defaults());
            config.payment_thresholds_opt = Some(make_payment_thresholds_with_defaults());
            config
        });
        let payable_dao_factory = self.payable_dao_factory.unwrap_or(
            PayableDaoFactoryMock::new()
                .make_result(PayableDaoMock::new())
                .make_result(PayableDaoMock::new()),
        );
        let receivable_dao_factory = self.receivable_dao_factory.unwrap_or(
            ReceivableDaoFactoryMock::new()
                .make_result(ReceivableDaoMock::new())
                .make_result(ReceivableDaoMock::new()),
        );
        let pending_payable_dao_factory = self.pending_payable_dao_factory.unwrap_or(
            PendingPayableDaoFactoryMock::new()
                .make_result(PendingPayableDaoMock::new())
                .make_result(PendingPayableDaoMock::new()),
        );
        let banned_dao_factory = self.banned_dao_factory.unwrap_or(
            BannedDaoFactoryMock::new()
                .make_result(BannedDaoMock::new())
                .make_result(BannedDaoMock::new()),
        );
        let accountant = Accountant::new(
            &mut config,
            Box::new(payable_dao_factory),
            Box::new(receivable_dao_factory),
            Box::new(pending_payable_dao_factory),
            Box::new(banned_dao_factory),
        );
        accountant
    }
}

pub struct PayableDaoFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn PayableDao>>>,
}

impl PayableDaoFactory for PayableDaoFactoryMock {
    fn make(&self) -> Box<dyn PayableDao> {
        if self.make_results.borrow().len() == 0 {
            panic!(
                "PayableDao Missing. This problem mostly occurs when PayableDao is only supplied for Accountant and not for the Scanner while building Accountant."
            )
        };
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl PayableDaoFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: PayableDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
        self
    }
}

pub struct ReceivableDaoFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn ReceivableDao>>>,
}

impl ReceivableDaoFactory for ReceivableDaoFactoryMock {
    fn make(&self) -> Box<dyn ReceivableDao> {
        if self.make_results.borrow().len() == 0 {
            panic!(
                "ReceivableDao Missing. This problem mostly occurs when ReceivableDao is only supplied for Accountant and not for the Scanner while building Accountant."
            )
        };
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl ReceivableDaoFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: ReceivableDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
        self
    }
}

pub struct BannedDaoFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn BannedDao>>>,
}

impl BannedDaoFactory for BannedDaoFactoryMock {
    fn make(&self) -> Box<dyn BannedDao> {
        if self.make_results.borrow().len() == 0 {
            panic!(
                "BannedDao Missing. This problem mostly occurs when ReceivableDao is only supplied for Accountant and not for the Scanner while building Accountant."
            )
        };
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl BannedDaoFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: BannedDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
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
    more_money_payable_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    more_money_payable_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    non_pending_payables_params: Arc<Mutex<Vec<()>>>,
    non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
    mark_pending_payable_rowid_parameters: Arc<Mutex<Vec<(Wallet, u64)>>>,
    mark_pending_payable_rowid_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    transaction_confirmed_params: Arc<Mutex<Vec<PendingPayableFingerprint>>>,
    transaction_confirmed_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    transaction_canceled_params: Arc<Mutex<Vec<PendingPayableId>>>,
    transaction_canceled_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
    top_records_results: RefCell<Vec<Vec<PayableAccount>>>,
    total_results: RefCell<Vec<u64>>,
    pub have_non_pending_payables_shut_down_the_system: bool,
}

impl PayableDao for PayableDaoMock {
    fn more_money_payable(&self, wallet: &Wallet, amount: u64) -> Result<(), PayableDaoError> {
        self.more_money_payable_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), amount));
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

    pub fn more_money_payable_result(self, result: Result<(), PayableDaoError>) -> Self {
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
    more_money_receivable_results: RefCell<Vec<Result<(), ReceivableDaoError>>>,
    more_money_received_parameters: Arc<Mutex<Vec<Vec<BlockchainTransaction>>>>,
    more_money_received_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    receivables_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    new_delinquencies_parameters: Arc<Mutex<Vec<(SystemTime, PaymentThresholds)>>>,
    new_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    paid_delinquencies_parameters: Arc<Mutex<Vec<PaymentThresholds>>>,
    paid_delinquencies_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    top_records_parameters: Arc<Mutex<Vec<(u64, u64)>>>,
    top_records_results: RefCell<Vec<Vec<ReceivableAccount>>>,
    total_results: RefCell<Vec<i64>>,
    pub have_new_delinquencies_shutdown_the_system: bool,
}

impl ReceivableDao for ReceivableDaoMock {
    fn more_money_receivable(
        &self,
        wallet: &Wallet,
        amount: u64,
    ) -> Result<(), ReceivableDaoError> {
        self.more_money_receivable_parameters
            .lock()
            .unwrap()
            .push((wallet.clone(), amount));
        self.more_money_receivable_results.borrow_mut().remove(0)
    }

    fn more_money_received(&mut self, transactions: Vec<BlockchainTransaction>) {
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

    fn top_records(&self, minimum_amount: u64, maximum_age: u64) -> Vec<ReceivableAccount> {
        self.top_records_parameters
            .lock()
            .unwrap()
            .push((minimum_amount, maximum_age));
        self.top_records_results.borrow_mut().remove(0)
    }

    fn total(&self) -> i64 {
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

    pub fn more_money_receivable_result(self, result: Result<(), ReceivableDaoError>) -> Self {
        self.more_money_receivable_results.borrow_mut().push(result);
        self
    }

    pub fn more_money_received_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<Vec<BlockchainTransaction>>>>,
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

    pub fn top_records_parameters(mut self, parameters: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
        self.top_records_parameters = parameters.clone();
        self
    }

    pub fn top_records_result(self, result: Vec<ReceivableAccount>) -> Self {
        self.top_records_results.borrow_mut().push(result);
        self
    }

    pub fn total_result(self, result: i64) -> Self {
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
    accountant_config: AccountantConfig,
    payment_thresholds: PaymentThresholds,
    earning_wallet: Wallet,
) -> BootstrapperConfig {
    let mut bc = BootstrapperConfig::new();
    bc.accountant_config_opt = Some(accountant_config);
    bc.payment_thresholds_opt = Some(payment_thresholds);
    bc.earning_wallet = earning_wallet;
    bc
}

pub fn bc_from_ac_plus_wallets(
    accountant_config: AccountantConfig,
    payment_thresholds: PaymentThresholds,
    consuming_wallet: Wallet,
    earning_wallet: Wallet,
) -> BootstrapperConfig {
    let mut bc = BootstrapperConfig::new();
    bc.accountant_config_opt = Some(accountant_config);
    bc.payment_thresholds_opt = Some(payment_thresholds);
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
    insert_fingerprint_params: Arc<Mutex<Vec<(H256, u64, SystemTime)>>>,
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
        amount: u64,
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
    pub fn new() -> Self {
        PendingPayableDaoMock::default()
    }

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
        params: &Arc<Mutex<Vec<(H256, u64, SystemTime)>>>,
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
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn PendingPayableDao>>>,
}

impl PendingPayableDaoFactory for PendingPayableDaoFactoryMock {
    fn make(&self) -> Box<dyn PendingPayableDao> {
        if self.make_results.borrow().len() == 0 {
            panic!(
                "PendingPayableDao Missing. This problem mostly occurs when PendingPayableDao is only supplied for Accountant and not for the Scanner while building Accountant."
            )
        };
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl PendingPayableDaoFactoryMock {
    pub fn new() -> Self {
        Self {
            make_params: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.make_params = params.clone();
        self
    }

    pub fn make_result(self, result: PendingPayableDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
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

pub fn make_payables(
    now: SystemTime,
    payment_thresholds: &PaymentThresholds,
) -> (
    Vec<PayableAccount>,
    Vec<PayableAccount>,
    Vec<PayableAccount>,
) {
    let mut unqualified_payable_accounts = vec![PayableAccount {
        wallet: make_wallet("wallet1"),
        balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
        last_paid_timestamp: from_time_t(
            to_time_t(now) - payment_thresholds.maturity_threshold_sec + 1,
        ),
        pending_payable_opt: None,
    }];
    let mut qualified_payable_accounts = vec![
        PayableAccount {
            wallet: make_wallet("wallet2"),
            balance: payment_thresholds.permanent_debt_allowed_gwei + 1_000_000_000,
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec - 1,
            ),
            pending_payable_opt: None,
        },
        PayableAccount {
            wallet: make_wallet("wallet3"),
            balance: payment_thresholds.permanent_debt_allowed_gwei + 1_200_000_000,
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec - 100,
            ),
            pending_payable_opt: None,
        },
    ];

    let mut all_non_pending_payables = Vec::new();
    all_non_pending_payables.extend(qualified_payable_accounts.clone());
    all_non_pending_payables.extend(unqualified_payable_accounts.clone());

    (
        qualified_payable_accounts,
        unqualified_payable_accounts,
        all_non_pending_payables,
    )
}

//warning: this test function will not tell you anything about the transaction record in the pending_payable table
pub fn account_status(conn: &Connection, wallet: &Wallet) -> Option<PayableAccount> {
    let mut stmt = conn
        .prepare("select balance, last_paid_timestamp, pending_payable_rowid from payable where wallet_address = ?")
        .unwrap();
    stmt.query_row(&[&wallet], |row| {
        let balance_result = row.get(0);
        let last_paid_timestamp_result = row.get(1);
        let pending_payable_rowid_result: Result<Option<i64>, Error> = row.get(2);
        match (
            balance_result,
            last_paid_timestamp_result,
            pending_payable_rowid_result,
        ) {
            (Ok(balance), Ok(last_paid_timestamp), Ok(rowid)) => Ok(PayableAccount {
                wallet: wallet.clone(),
                balance,
                last_paid_timestamp: dao_utils::from_time_t(last_paid_timestamp),
                pending_payable_opt: match rowid {
                    Some(rowid) => Some(PendingPayableId {
                        rowid: u64::try_from(rowid).unwrap(),
                        hash: H256::from_uint(&U256::from(0)), //garbage
                    }),
                    None => None,
                },
            }),
            _ => panic!("Database is corrupt: PAYABLE table columns and/or types"),
        }
    })
    .optional()
    .unwrap()
}
