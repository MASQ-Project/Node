// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

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
use crate::accountant::scanners::{PayableScanner, PendingPayableScanner, ReceivableScanner};
use crate::accountant::scanners_utils::payable_scanner_utils::PayableThresholdsGauge;
use crate::accountant::{gwei_to_wei, Accountant, DEFAULT_PENDING_TOO_LONG_SEC};
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::blockchain::blockchain_interface::BlockchainTransaction;
use crate::blockchain::test_utils::make_tx_hash;
use crate::bootstrapper::BootstrapperConfig;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics};
use crate::sub_lib::accountant::{MessageIdGenerator, PaymentThresholds};
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::unshared_test_utils::make_bc_with_defaults;
use actix::System;
use ethereum_types::H256;
use masq_lib::logger::Logger;
use masq_lib::utils::plus;
use rusqlite::{Connection, Row};
use std::any::type_name;
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
        balance_wei: gwei_to_wei(n),
        last_received_timestamp: from_time_t(now - (n as i64)),
    }
}

pub fn make_payable_account(n: u64) -> PayableAccount {
    let now = to_time_t(SystemTime::now());
    let timestamp = from_time_t(now - (n as i64));
    make_payable_account_with_wallet_and_balance_and_timestamp_opt(
        make_wallet(&format!("wallet{}", n)),
        gwei_to_wei(n),
        Some(timestamp),
    )
}

pub fn make_payable_account_with_wallet_and_balance_and_timestamp_opt(
    wallet: Wallet,
    balance: u128,
    timestamp_opt: Option<SystemTime>,
) -> PayableAccount {
    PayableAccount {
        wallet,
        balance_wei: balance,
        last_paid_timestamp: timestamp_opt.unwrap_or(SystemTime::now()),
        pending_payable_opt: None,
    }
}

pub struct AccountantBuilder {
    config: Option<BootstrapperConfig>,
    logger: Option<Logger>,
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
            logger: None,
            payable_dao_factory: None,
            receivable_dao_factory: None,
            pending_payable_dao_factory: None,
            banned_dao_factory: None,
            config_dao_factory: None,
        }
    }
}

pub enum DaoWithDestination<T> {
    AccountantBodyDest(T),
    PayableScannerDest(T),
    ReceivableScannerDest(T),
    PendingPayableScannerDest(T),
}

enum DestinationMarker {
    AccountantBody,
    PayableScanner,
    ReceivableScanner,
    PendingPayableScanner,
}

impl<T> DaoWithDestination<T> {
    fn matches(&self, dest_marker: &DestinationMarker) -> bool {
        match self {
            Self::AccountantBodyDest(_) => matches!(dest_marker, DestinationMarker::AccountantBody),
            Self::PayableScannerDest(_) => {
                matches!(dest_marker, DestinationMarker::PayableScanner)
            }
            Self::ReceivableScannerDest(_) => {
                matches!(dest_marker, DestinationMarker::ReceivableScanner)
            }
            Self::PendingPayableScannerDest(_) => {
                matches!(dest_marker, DestinationMarker::PendingPayableScanner)
            }
        }
    }
    fn inner_value(self) -> T {
        match self {
            Self::AccountantBodyDest(dao) => dao,
            Self::PayableScannerDest(dao) => dao,
            Self::ReceivableScannerDest(dao) => dao,
            Self::PendingPayableScannerDest(dao) => dao,
        }
    }
}

fn fill_vacancies_with_given_or_default_daos<const N: usize, T: Default>(
    std_dao_initialization_order: [DestinationMarker; N],
    mut customized_dao_set: Vec<DaoWithDestination<T>>,
) -> Vec<Box<T>> {
    let input_count = customized_dao_set.len();

    let fold_init: (Vec<Box<T>>, usize) = (vec![], 0);
    let (factory_make_queue, used_input) = std_dao_initialization_order.into_iter().fold(
        fold_init,
        |(acc, used_input), std_position: DestinationMarker| {
            if let Some(idx) = customized_dao_set
                .iter()
                .position(|customized_dao| customized_dao.matches(&std_position))
            {
                let customized_dao = customized_dao_set.remove(idx).inner_value();
                (plus(acc, Box::new(customized_dao)), used_input + 1)
            } else {
                (plus(acc, Box::new(Default::default())), used_input)
            }
        },
    );
    if input_count != used_input {
        panic!(
            "you supplied DAO for unrealistic destination; look at the destination matrix that \
             describes all proper usages of {:?} and decode those places by the num_rep() function \
             pattern",
            type_name::<T>()
        )
    }
    factory_make_queue
}

macro_rules! init_or_update_factory {
    (
        $dao_set: expr, //Vec<DaoWithDestination<XxxDaoMock>>
        $dao_initialization_order_in_accountant: expr, //[DestinationMarker;N]
        $dao_factory_mock: ident, // XxxDaoFactoryMock
        $factory_field_in_builder: ident, //Option<XxxDaoFactoryMock>
        $dao_trait: ident,
        $self: expr //mut AccountantBuilder
    ) => {{
        let populated_queue = fill_vacancies_with_given_or_default_daos(
            $dao_initialization_order_in_accountant,
            $dao_set,
        );
        let populated_queue: Vec<Box<dyn $dao_trait>> = populated_queue
            .into_iter()
            .map(|elem| elem as Box<dyn $dao_trait>)
            .collect();
        let prepared_factory = match $self.$factory_field_in_builder.take() {
            Some(existing_factory) => {
                existing_factory.make_results.replace(populated_queue);
                existing_factory
            }
            None => {
                let mut new_factory = $dao_factory_mock::new();
                new_factory.make_results = RefCell::new(populated_queue);
                new_factory
            }
        };
        $self.$factory_field_in_builder = Some(prepared_factory);
        $self
    }};
}

impl AccountantBuilder {
    pub fn bootstrapper_config(mut self, config: BootstrapperConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn logger(mut self, logger: Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn payable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<PayableDaoMock>>,
    ) -> Self {
        let initialization_order_in_accountant = [
            DestinationMarker::AccountantBody,
            DestinationMarker::PayableScanner,
            DestinationMarker::PendingPayableScanner,
        ];
        init_or_update_factory!(
            specially_configured_daos,
            initialization_order_in_accountant,
            PayableDaoFactoryMock,
            payable_dao_factory,
            PayableDao,
            self
        )
    }

    pub fn receivable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<ReceivableDaoMock>>,
    ) -> Self {
        let initialization_order_in_accountant = [
            DestinationMarker::AccountantBody,
            DestinationMarker::ReceivableScanner,
        ];
        init_or_update_factory!(
            specially_configured_daos,
            initialization_order_in_accountant,
            ReceivableDaoFactoryMock,
            receivable_dao_factory,
            ReceivableDao,
            self
        )
    }

    pub fn pending_payable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<PendingPayableDaoMock>>,
    ) -> Self {
        let initialization_order_in_accountant = [
            DestinationMarker::AccountantBody,
            DestinationMarker::PayableScanner,
            DestinationMarker::PendingPayableScanner,
        ];
        init_or_update_factory!(
            specially_configured_daos,
            initialization_order_in_accountant,
            PendingPayableDaoFactoryMock,
            pending_payable_dao_factory,
            PendingPayableDao,
            self
        )
    }

    //TODO this method seems to be never used?
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
        let config = self.config.unwrap_or(make_bc_with_defaults());
        let payable_dao_factory = self.payable_dao_factory.unwrap_or(
            PayableDaoFactoryMock::new()
                .make_result(PayableDaoMock::new())
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
                .make_result(PendingPayableDaoMock::new())
                .make_result(PendingPayableDaoMock::new()),
        );
        let banned_dao_factory = self
            .banned_dao_factory
            .unwrap_or(BannedDaoFactoryMock::new().make_result(BannedDaoMock::new()));
        let mut accountant = Accountant::new(
            config,
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                pending_payable_dao_factory: Box::new(pending_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
            },
        );
        if let Some(logger) = self.logger {
            accountant.logger = logger;
        }

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
            panic!("BannedDao Missing.")
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
    more_money_payable_parameters: Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    more_money_payable_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    non_pending_payables_params: Arc<Mutex<Vec<()>>>,
    non_pending_payables_results: RefCell<Vec<Vec<PayableAccount>>>,
    mark_pending_payables_rowids_params: Arc<Mutex<Vec<Vec<(Wallet, u64)>>>>,
    mark_pending_payables_rowids_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    transactions_confirmed_params: Arc<Mutex<Vec<Vec<PendingPayableFingerprint>>>>,
    transactions_confirmed_results: RefCell<Vec<Result<(), PayableDaoError>>>,
    custom_query_params: Arc<Mutex<Vec<CustomQuery<u64>>>>,
    custom_query_result: RefCell<Vec<Option<Vec<PayableAccount>>>>,
    total_results: RefCell<Vec<u128>>,
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

    fn mark_pending_payables_rowids(
        &self,
        wallets_and_rowids: &[(&Wallet, u64)],
    ) -> Result<(), PayableDaoError> {
        self.mark_pending_payables_rowids_params
            .lock()
            .unwrap()
            .push(
                wallets_and_rowids
                    .iter()
                    .map(|(wallet, id)| ((*wallet).clone(), *id))
                    .collect(),
            );
        self.mark_pending_payables_rowids_results
            .borrow_mut()
            .remove(0)
    }

    fn transactions_confirmed(
        &self,
        fingerprints: &[PendingPayableFingerprint],
    ) -> Result<(), PayableDaoError> {
        self.transactions_confirmed_params
            .lock()
            .unwrap()
            .push(fingerprints.to_vec());
        self.transactions_confirmed_results.borrow_mut().remove(0)
    }

    fn non_pending_payables(&self) -> Vec<PayableAccount> {
        self.non_pending_payables_params.lock().unwrap().push(());
        self.non_pending_payables_results.borrow_mut().remove(0)
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

    pub fn more_money_payable_params(
        mut self,
        params: Arc<Mutex<Vec<(SystemTime, Wallet, u128)>>>,
    ) -> Self {
        self.more_money_payable_parameters = params;
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

    pub fn mark_pending_payables_rowids_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<(Wallet, u64)>>>>,
    ) -> Self {
        self.mark_pending_payables_rowids_params = params.clone();
        self
    }

    pub fn mark_pending_payables_rowids_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.mark_pending_payables_rowids_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn transactions_confirmed_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<PendingPayableFingerprint>>>>,
    ) -> Self {
        self.transactions_confirmed_params = params.clone();
        self
    }

    pub fn transactions_confirmed_result(self, result: Result<(), PayableDaoError>) -> Self {
        self.transactions_confirmed_results
            .borrow_mut()
            .push(result);
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

pub fn bc_from_earning_wallet(earning_wallet: Wallet) -> BootstrapperConfig {
    let mut bc = make_bc_with_defaults();
    bc.earning_wallet = earning_wallet;
    bc
}

pub fn bc_from_wallets(consuming_wallet: Wallet, earning_wallet: Wallet) -> BootstrapperConfig {
    let mut bc = make_bc_with_defaults();
    bc.consuming_wallet_opt = Some(consuming_wallet);
    bc.earning_wallet = earning_wallet;
    bc
}

#[derive(Default)]
pub struct PendingPayableDaoMock {
    fingerprints_rowids_params: Arc<Mutex<Vec<Vec<H256>>>>,
    fingerprints_rowids_results: RefCell<Vec<Vec<(Option<u64>, H256)>>>,
    delete_fingerprints_params: Arc<Mutex<Vec<Vec<u64>>>>,
    delete_fingerprints_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    insert_new_fingerprints_params: Arc<Mutex<Vec<(Vec<(H256, u128)>, SystemTime)>>>,
    insert_new_fingerprints_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    update_fingerprints_params: Arc<Mutex<Vec<Vec<u64>>>>,
    update_fingerprints_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    mark_failures_params: Arc<Mutex<Vec<Vec<u64>>>>,
    mark_failures_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
    return_all_fingerprints_params: Arc<Mutex<Vec<()>>>,
    return_all_fingerprints_results: RefCell<Vec<Vec<PendingPayableFingerprint>>>,
    pub have_return_all_fingerprints_shut_down_the_system: bool,
}

impl PendingPayableDao for PendingPayableDaoMock {
    fn fingerprints_rowids(&self, hashes: &[H256]) -> Vec<(Option<u64>, H256)> {
        self.fingerprints_rowids_params
            .lock()
            .unwrap()
            .push(hashes.to_vec());
        self.fingerprints_rowids_results.borrow_mut().remove(0)
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

    fn insert_new_fingerprints(
        &self,
        hashes_and_amounts: &[(H256, u128)],
        batch_wide_timestamp: SystemTime,
    ) -> Result<(), PendingPayableDaoError> {
        self.insert_new_fingerprints_params
            .lock()
            .unwrap()
            .push((hashes_and_amounts.to_vec(), batch_wide_timestamp));
        self.insert_new_fingerprints_results.borrow_mut().remove(0)
    }

    fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        self.delete_fingerprints_params
            .lock()
            .unwrap()
            .push(ids.to_vec());
        self.delete_fingerprints_results.borrow_mut().remove(0)
    }

    fn update_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        self.update_fingerprints_params
            .lock()
            .unwrap()
            .push(ids.to_vec());
        self.update_fingerprints_results.borrow_mut().remove(0)
    }

    fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
        self.mark_failures_params.lock().unwrap().push(ids.to_vec());
        self.mark_failures_results.borrow_mut().remove(0)
    }
}

impl PendingPayableDaoMock {
    pub fn new() -> Self {
        PendingPayableDaoMock::default()
    }

    pub fn fingerprints_rowids_params(mut self, params: &Arc<Mutex<Vec<Vec<H256>>>>) -> Self {
        self.fingerprints_rowids_params = params.clone();
        self
    }

    pub fn fingerprints_rowids_result(self, result: Vec<(Option<u64>, H256)>) -> Self {
        self.fingerprints_rowids_results.borrow_mut().push(result);
        self
    }

    pub fn insert_fingerprints_params(
        mut self,
        params: &Arc<Mutex<Vec<(Vec<(H256, u128)>, SystemTime)>>>,
    ) -> Self {
        self.insert_new_fingerprints_params = params.clone();
        self
    }

    pub fn insert_fingerprints_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.insert_new_fingerprints_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn delete_fingerprints_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
        self.delete_fingerprints_params = params.clone();
        self
    }

    pub fn delete_fingerprints_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.delete_fingerprints_results.borrow_mut().push(result);
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

    pub fn mark_failures_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
        self.mark_failures_params = params.clone();
        self
    }

    pub fn mark_failures_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.mark_failures_results.borrow_mut().push(result);
        self
    }

    pub fn update_fingerprints_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
        self.update_fingerprints_params = params.clone();
        self
    }

    pub fn update_fingerprints_results(self, result: Result<(), PendingPayableDaoError>) -> Self {
        self.update_fingerprints_results.borrow_mut().push(result);
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

pub struct PayableScannerBuilder {
    payable_dao: PayableDaoMock,
    pending_payable_dao: PendingPayableDaoMock,
    payment_thresholds: PaymentThresholds,
}

impl PayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            pending_payable_dao: PendingPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> PayableScannerBuilder {
        self.payable_dao = payable_dao;
        self
    }

    pub fn payment_thresholds(mut self, payment_thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds = payment_thresholds;
        self
    }

    pub fn pending_payable_dao(
        mut self,
        pending_payable_dao: PendingPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.pending_payable_dao = pending_payable_dao;
        self
    }

    pub fn build(self) -> PayableScanner {
        PayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.pending_payable_dao),
            Rc::new(self.payment_thresholds),
        )
    }
}

pub struct PendingPayableScannerBuilder {
    payable_dao: PayableDaoMock,
    pending_payable_dao: PendingPayableDaoMock,
    payment_thresholds: PaymentThresholds,
    when_pending_too_long_sec: u64,
    financial_statistics: FinancialStatistics,
}

impl PendingPayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            pending_payable_dao: PendingPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            financial_statistics: FinancialStatistics::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> Self {
        self.payable_dao = payable_dao;
        self
    }

    pub fn pending_payable_dao(mut self, pending_payable_dao: PendingPayableDaoMock) -> Self {
        self.pending_payable_dao = pending_payable_dao;
        self
    }

    pub fn build(self) -> PendingPayableScanner {
        PendingPayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.pending_payable_dao),
            Rc::new(self.payment_thresholds),
            self.when_pending_too_long_sec,
            Rc::new(RefCell::new(self.financial_statistics)),
        )
    }
}

pub struct ReceivableScannerBuilder {
    receivable_dao: ReceivableDaoMock,
    banned_dao: BannedDaoMock,
    payment_thresholds: PaymentThresholds,
    earning_wallet: Wallet,
    financial_statistics: FinancialStatistics,
}

impl ReceivableScannerBuilder {
    pub fn new() -> Self {
        Self {
            receivable_dao: ReceivableDaoMock::new(),
            banned_dao: BannedDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            earning_wallet: make_wallet("earning_default"),
            financial_statistics: FinancialStatistics::default(),
        }
    }

    pub fn receivable_dao(mut self, receivable_dao: ReceivableDaoMock) -> Self {
        self.receivable_dao = receivable_dao;
        self
    }

    pub fn banned_dao(mut self, banned_dao: BannedDaoMock) -> Self {
        self.banned_dao = banned_dao;
        self
    }

    pub fn payment_thresholds(mut self, payment_thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds = payment_thresholds;
        self
    }

    pub fn earning_wallet(mut self, earning_wallet: Wallet) -> Self {
        self.earning_wallet = earning_wallet;
        self
    }

    pub fn build(self) -> ReceivableScanner {
        ReceivableScanner::new(
            Box::new(self.receivable_dao),
            Box::new(self.banned_dao),
            Rc::new(self.payment_thresholds),
            Rc::new(self.earning_wallet),
            Rc::new(RefCell::new(self.financial_statistics)),
        )
    }
}

pub fn make_custom_payment_thresholds() -> PaymentThresholds {
    PaymentThresholds {
        threshold_interval_sec: 2_592_000,
        debt_threshold_gwei: 1_000_000_000,
        payment_grace_period_sec: 86_400,
        maturity_threshold_sec: 86_400,
        permanent_debt_allowed_gwei: 10_000_000,
        unban_below_gwei: 10_000_000,
    }
}

pub fn make_pending_payable_fingerprint() -> PendingPayableFingerprint {
    PendingPayableFingerprint {
        rowid: 33,
        timestamp: from_time_t(222_222_222),
        hash: make_tx_hash(456),
        attempt: 1,
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
    let unqualified_payable_accounts = vec![PayableAccount {
        wallet: make_wallet("wallet1"),
        balance_wei: gwei_to_wei(payment_thresholds.permanent_debt_allowed_gwei + 1),
        last_paid_timestamp: from_time_t(
            to_time_t(now) - payment_thresholds.maturity_threshold_sec as i64 + 1,
        ),
        pending_payable_opt: None,
    }];
    let qualified_payable_accounts = vec![
        PayableAccount {
            wallet: make_wallet("wallet2"),
            balance_wei: gwei_to_wei(
                payment_thresholds.permanent_debt_allowed_gwei + 1_000_000_000,
            ),
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec as i64 - 1,
            ),
            pending_payable_opt: None,
        },
        PayableAccount {
            wallet: make_wallet("wallet3"),
            balance_wei: gwei_to_wei(
                payment_thresholds.permanent_debt_allowed_gwei + 1_200_000_000,
            ),
            last_paid_timestamp: from_time_t(
                to_time_t(now) - payment_thresholds.maturity_threshold_sec as i64 - 100,
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

pub fn convert_to_all_string_values(str_args: Vec<(&str, &str)>) -> Vec<(String, String)> {
    str_args
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

#[derive(Default)]
pub struct MessageIdGeneratorMock {
    ids: RefCell<Vec<u32>>,
}

impl MessageIdGenerator for MessageIdGeneratorMock {
    fn id(&self) -> u32 {
        self.ids.borrow_mut().remove(0)
    }
}

impl MessageIdGeneratorMock {
    pub fn id_result(self, id: u32) -> Self {
        self.ids.borrow_mut().push(id);
        self
    }
}

pub fn assert_account_creation_fn_fails_on_finding_wrong_columns_and_value_types<F, R>(tested_fn: F)
where
    F: Fn(&Row) -> rusqlite::Result<R>,
{
    let conn = Connection::open_in_memory().unwrap();
    let execute = |sql: &str| conn.execute(sql, []).unwrap();
    execute("create table whatever (exclamations text)");
    execute("insert into whatever (exclamations) values ('Gosh')");

    conn.query_row("select exclamations from whatever", [], tested_fn)
        .unwrap();
}

#[derive(Default)]
pub struct PayableThresholdsGaugeMock {
    is_innocent_age_params: Arc<Mutex<Vec<(u64, u64)>>>,
    is_innocent_age_results: RefCell<Vec<bool>>,
    is_innocent_balance_params: Arc<Mutex<Vec<(u128, u128)>>>,
    is_innocent_balance_results: RefCell<Vec<bool>>,
    calculate_payout_threshold_in_gwei_params: Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
    calculate_payout_threshold_in_gwei_results: RefCell<Vec<u128>>,
}

impl PayableThresholdsGauge for PayableThresholdsGaugeMock {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
        self.is_innocent_age_params
            .lock()
            .unwrap()
            .push((age, limit));
        self.is_innocent_age_results.borrow_mut().remove(0)
    }

    fn is_innocent_balance(&self, balance: u128, limit: u128) -> bool {
        self.is_innocent_balance_params
            .lock()
            .unwrap()
            .push((balance, limit));
        self.is_innocent_balance_results.borrow_mut().remove(0)
    }

    fn calculate_payout_threshold_in_gwei(
        &self,
        payment_thresholds: &PaymentThresholds,
        x: u64,
    ) -> u128 {
        self.calculate_payout_threshold_in_gwei_params
            .lock()
            .unwrap()
            .push((*payment_thresholds, x));
        self.calculate_payout_threshold_in_gwei_results
            .borrow_mut()
            .remove(0)
    }
}

impl PayableThresholdsGaugeMock {
    pub fn is_innocent_age_params(mut self, params: &Arc<Mutex<Vec<(u64, u64)>>>) -> Self {
        self.is_innocent_age_params = params.clone();
        self
    }

    pub fn is_innocent_age_result(self, result: bool) -> Self {
        self.is_innocent_age_results.borrow_mut().push(result);
        self
    }

    pub fn is_innocent_balance_params(mut self, params: &Arc<Mutex<Vec<(u128, u128)>>>) -> Self {
        self.is_innocent_balance_params = params.clone();
        self
    }

    pub fn is_innocent_balance_result(self, result: bool) -> Self {
        self.is_innocent_balance_results.borrow_mut().push(result);
        self
    }

    pub fn calculate_payout_threshold_in_gwei_params(
        mut self,
        params: &Arc<Mutex<Vec<(PaymentThresholds, u64)>>>,
    ) -> Self {
        self.calculate_payout_threshold_in_gwei_params = params.clone();
        self
    }

    pub fn calculate_payout_threshold_in_gwei_result(self, result: u128) -> Self {
        self.calculate_payout_threshold_in_gwei_results
            .borrow_mut()
            .push(result);
        self
    }
}
