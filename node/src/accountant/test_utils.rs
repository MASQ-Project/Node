// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::banned_dao::{BannedDao, BannedDaoFactory};
use crate::accountant::db_access_objects::payable_dao::{MarkOfPendingPayable, PayableAccount, PayableDao, PayableDaoError, PayableDaoFactory};
use crate::accountant::db_access_objects::sent_payable_dao::{SentPayableDao, SentPayableDaoFactory};
use crate::accountant::db_access_objects::receivable_dao::{
    ReceivableAccount, ReceivableDao, ReceivableDaoError, ReceivableDaoFactory,
};
use crate::accountant::db_access_objects::utils::{from_unix_timestamp, to_unix_timestamp, CustomQuery, TxHash, TxIdentifiers};
use crate::accountant::payment_adjuster::{Adjustment, AnalysisError, PaymentAdjuster};
use crate::accountant::scanners::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner_extension::PreparedAdjustment;
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableThresholdsGauge;
use crate::accountant::scanners::{PayableScanner, PendingPayableScanner, ReceivableScanner};
use crate::accountant::{gwei_to_wei, Accountant, DEFAULT_PENDING_TOO_LONG_SEC};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::HashAndAmount;
use crate::blockchain::blockchain_interface::data_structures::BlockchainTransaction;
use crate::blockchain::test_utils::make_tx_hash;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::rusqlite_wrappers::TransactionSafeWrapper;
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::{DaoFactories, FinancialStatistics};
use crate::sub_lib::accountant::{MessageIdGenerator, PaymentThresholds};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
use crate::test_utils::unshared_test_utils::make_bc_with_defaults;
use actix::System;
use ethereum_types::H256;
use masq_lib::logger::Logger;
use rusqlite::{Connection, OpenFlags, Row};
use std::any::type_name;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use crate::accountant::db_access_objects::sent_payable_dao::{RetrieveCondition, SentPayableDaoError, SentTx};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock};

pub fn make_receivable_account(n: u64, expected_delinquent: bool) -> ReceivableAccount {
    let now = to_unix_timestamp(SystemTime::now());
    ReceivableAccount {
        wallet: make_wallet(&format!(
            "wallet{}{}",
            n,
            if expected_delinquent { "d" } else { "n" }
        )),
        balance_wei: gwei_to_wei(n),
        last_received_timestamp: from_unix_timestamp(now - (n as i64)),
    }
}

pub fn make_payable_account(n: u64) -> PayableAccount {
    let now = to_unix_timestamp(SystemTime::now());
    let timestamp = from_unix_timestamp(now - (n as i64));
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

pub fn make_sent_tx(num: u64)-> SentTx {
    if num == 0 {
        panic!("num for generating must be greater than 0");
    }
    SentTx{
        hash: make_tx_hash(num as u32),
        receiver_address: make_wallet(&format!("wallet{}", num)).address(),
        amount: gwei_to_wei(num * num),
        timestamp: to_unix_timestamp(SystemTime::now()) - (num as i64 * 60),
        gas_price_wei: gwei_to_wei(num),
        nonce: num,
        block_opt: None,
    }
}

pub struct AccountantBuilder {
    config_opt: Option<BootstrapperConfig>,
    consuming_wallet_opt: Option<Wallet>,
    logger_opt: Option<Logger>,
    payable_dao_factory_opt: Option<PayableDaoFactoryMock>,
    receivable_dao_factory_opt: Option<ReceivableDaoFactoryMock>,
    sent_payable_dao_factory_opt: Option<SentPayableDaoFactoryMock>,
    banned_dao_factory_opt: Option<BannedDaoFactoryMock>,
    config_dao_factory_opt: Option<ConfigDaoFactoryMock>,
}

impl Default for AccountantBuilder {
    fn default() -> Self {
        Self {
            config_opt: None,
            consuming_wallet_opt: None,
            logger_opt: None,
            payable_dao_factory_opt: None,
            receivable_dao_factory_opt: None,
            sent_payable_dao_factory_opt: None,
            banned_dao_factory_opt: None,
            config_dao_factory_opt: None,
        }
    }
}

pub enum DaoWithDestination<T> {
    ForAccountantBody(T),
    ForPendingPayableScanner(T),
    ForPayableScanner(T),
    ForReceivableScanner(T),
}

enum DestinationMarker {
    AccountantBody,
    PendingPayableScanner,
    PayableScanner,
    ReceivableScanner,
}

impl<T> DaoWithDestination<T> {
    fn matches(&self, dest_marker: &DestinationMarker) -> bool {
        match self {
            Self::ForAccountantBody(_) => matches!(dest_marker, DestinationMarker::AccountantBody),
            Self::ForPendingPayableScanner(_) => {
                matches!(dest_marker, DestinationMarker::PendingPayableScanner)
            }
            Self::ForPayableScanner(_) => {
                matches!(dest_marker, DestinationMarker::PayableScanner)
            }
            Self::ForReceivableScanner(_) => {
                matches!(dest_marker, DestinationMarker::ReceivableScanner)
            }
        }
    }
    fn into_inner(self) -> T {
        match self {
            Self::ForAccountantBody(dao) => dao,
            Self::ForPendingPayableScanner(dao) => dao,
            Self::ForPayableScanner(dao) => dao,
            Self::ForReceivableScanner(dao) => dao,
        }
    }
}

fn guts_for_dao_factory_queue_initialization<T: Default>(
    customized_supplied_daos: &mut Vec<DaoWithDestination<T>>,
    mut acc: Vec<Box<T>>,
    used_input: usize,
    position: DestinationMarker,
) -> (Vec<Box<T>>, usize) {
    match customized_supplied_daos
        .iter()
        .position(|customized_dao| customized_dao.matches(&position))
    {
        Some(idx) => {
            let customized_dao = customized_supplied_daos.remove(idx).into_inner();
            let used_input_updated = used_input + 1;
            acc.push(Box::new(customized_dao));
            (acc, used_input_updated)
        }
        None => {
            acc.push(Box::new(Default::default()));
            (acc, used_input)
        }
    }
}

fn fill_vacancies_with_given_or_default_daos<const N: usize, T: Default>(
    correct_daos_initialization_order: [DestinationMarker; N],
    mut customized_supplied_daos: Vec<DaoWithDestination<T>>,
) -> Vec<Box<T>> {
    let initial_input_count = customized_supplied_daos.len();

    let fold_init_values: (Vec<Box<T>>, usize) = (vec![], 0);
    let (make_queue_for_factory, used_input_count) = correct_daos_initialization_order
        .into_iter()
        .fold(fold_init_values, |(acc, used_input), position| {
            guts_for_dao_factory_queue_initialization(
                &mut customized_supplied_daos,
                acc,
                used_input,
                position,
            )
        });
    if initial_input_count != used_input_count {
        panic!(
            "you supplied DAO for incorrect destination; look at the initialization order for \
             the given scanner shown within those XXX_daos() methods of AccountantBuilder; it hints \
             possible usages of {:?}",
            type_name::<T>()
        )
    }
    make_queue_for_factory
}

macro_rules! create_or_update_factory {
    (
        $dao_set: expr, //Vec<DaoWithDestination<XxxDaoMock>>
        $dao_initialization_order_in_regard_to_accountant: expr, //[DestinationMarker;N]
        $factory_field_in_builder: ident, //Option<XxxDaoFactoryMock>
        $dao_factory_mock: ident, // XxxDaoFactoryMock
        $dao_trait: ident,
        $self: expr //mut AccountantBuilder
    ) => {{
        let make_queue_uncast = fill_vacancies_with_given_or_default_daos(
            $dao_initialization_order_in_regard_to_accountant,
            $dao_set,
        );

        let finished_make_queue: Vec<Box<dyn $dao_trait>> = make_queue_uncast
            .into_iter()
            .map(|elem| elem as Box<dyn $dao_trait>)
            .collect();

        let ready_factory = match $self.$factory_field_in_builder.take() {
            Some(existing_factory) => {
                existing_factory.make_results.replace(finished_make_queue);
                existing_factory
            }
            None => {
                let mut new_factory = $dao_factory_mock::new();
                new_factory.make_results = RefCell::new(finished_make_queue);
                new_factory
            }
        };
        $self.$factory_field_in_builder = Some(ready_factory);
        $self
    }};
}

const PAYABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER: [DestinationMarker; 3] = [
    DestinationMarker::AccountantBody,
    DestinationMarker::PayableScanner,
    DestinationMarker::PendingPayableScanner,
];

const PENDING_PAYABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER: [DestinationMarker; 3] = [
    DestinationMarker::AccountantBody,
    DestinationMarker::PayableScanner,
    DestinationMarker::PendingPayableScanner,
];

const RECEIVABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER: [DestinationMarker; 2] = [
    DestinationMarker::AccountantBody,
    DestinationMarker::ReceivableScanner,
];

impl AccountantBuilder {
    pub fn bootstrapper_config(mut self, config: BootstrapperConfig) -> Self {
        self.config_opt = Some(config);
        self
    }

    pub fn consuming_wallet(mut self, consuming_wallet: Wallet) -> Self {
        self.consuming_wallet_opt = Some(consuming_wallet);
        self
    }

    pub fn logger(mut self, logger: Logger) -> Self {
        self.logger_opt = Some(logger);
        self
    }

    pub fn pending_payable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<SentPayableDaoMock>>,
    ) -> Self {
        create_or_update_factory!(
            specially_configured_daos,
            PENDING_PAYABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER,
            sent_payable_dao_factory_opt,
            SentPayableDaoFactoryMock,
            SentPayableDao,
            self
        )
    }

    pub fn payable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<PayableDaoMock>>,
    ) -> Self {
        create_or_update_factory!(
            specially_configured_daos,
            PAYABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER,
            payable_dao_factory_opt,
            PayableDaoFactoryMock,
            PayableDao,
            self
        )
    }

    pub fn receivable_daos(
        mut self,
        specially_configured_daos: Vec<DaoWithDestination<ReceivableDaoMock>>,
    ) -> Self {
        create_or_update_factory!(
            specially_configured_daos,
            RECEIVABLE_DAOS_ACCOUNTANT_INITIALIZATION_ORDER,
            receivable_dao_factory_opt,
            ReceivableDaoFactoryMock,
            ReceivableDao,
            self
        )
    }

    //TODO this method seems to be never used?
    pub fn banned_dao(mut self, banned_dao: BannedDaoMock) -> Self {
        match self.banned_dao_factory_opt {
            None => {
                self.banned_dao_factory_opt =
                    Some(BannedDaoFactoryMock::new().make_result(banned_dao))
            }
            Some(banned_dao_factory) => {
                self.banned_dao_factory_opt = Some(banned_dao_factory.make_result(banned_dao))
            }
        }
        self
    }

    pub fn config_dao(mut self, config_dao: ConfigDaoMock) -> Self {
        self.config_dao_factory_opt = Some(ConfigDaoFactoryMock::new().make_result(config_dao));
        self
    }

    pub fn build(self) -> Accountant {
        let config = self.config_opt.unwrap_or(make_bc_with_defaults());
        let payable_dao_factory = self.payable_dao_factory_opt.unwrap_or(
            PayableDaoFactoryMock::new()
                .make_result(PayableDaoMock::new())
                .make_result(PayableDaoMock::new())
                .make_result(PayableDaoMock::new()),
        );
        let receivable_dao_factory = self.receivable_dao_factory_opt.unwrap_or(
            ReceivableDaoFactoryMock::new()
                .make_result(ReceivableDaoMock::new())
                .make_result(ReceivableDaoMock::new()),
        );
        let sent_payable_dao_factory = self.sent_payable_dao_factory_opt.unwrap_or(
            SentPayableDaoFactoryMock::new()
                .make_result(SentPayableDaoMock::new())
                .make_result(SentPayableDaoMock::new())
                .make_result(SentPayableDaoMock::new()),
        );
        let banned_dao_factory = self
            .banned_dao_factory_opt
            .unwrap_or(BannedDaoFactoryMock::new().make_result(BannedDaoMock::new()));
        let config_dao_factory = self
            .config_dao_factory_opt
            .unwrap_or(ConfigDaoFactoryMock::new().make_result(ConfigDaoMock::new()));
        let mut accountant = Accountant::new(
            config,
            DaoFactories {
                payable_dao_factory: Box::new(payable_dao_factory),
                sent_payable_dao_factory: Box::new(sent_payable_dao_factory),
                receivable_dao_factory: Box::new(receivable_dao_factory),
                banned_dao_factory: Box::new(banned_dao_factory),
                config_dao_factory: Box::new(config_dao_factory),
            },
        );
        if let Some(logger) = self.logger_opt {
            accountant.logger = logger;
        }
        if let Some(consuming_wallet) = self.consuming_wallet_opt {
            accountant.consuming_wallet_opt = Some(consuming_wallet);
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
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn ConfigDao>>>,
}

impl ConfigDaoFactory for ConfigDaoFactoryMock {
    fn make(&self) -> Box<dyn ConfigDao> {
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl ConfigDaoFactoryMock {
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

    pub fn make_result(self, result: ConfigDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
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
    transactions_confirmed_params: Arc<Mutex<Vec<Vec<SentTx>>>>,
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
        mark_instructions: &[MarkOfPendingPayable],
    ) -> Result<(), PayableDaoError> {
        todo!()
        // self.mark_pending_payables_rowids_params
        //     .lock()
        //     .unwrap()
        //     .push(
        //         mark_instructions
        //             .iter()
        //             .map(|(wallet, id)| ((*wallet).clone(), *id))
        //             .collect(),
        //     );
        // self.mark_pending_payables_rowids_results
        //     .borrow_mut()
        //     .remove(0)
    }

    fn transactions_confirmed(
        &self,
        confirmed_payables: &[SentTx],
    ) -> Result<(), PayableDaoError> {
        self.transactions_confirmed_params
            .lock()
            .unwrap()
            .push(confirmed_payables.to_vec());
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
        params: &Arc<Mutex<Vec<Vec<SentTx>>>>,
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
    more_money_received_results: RefCell<Vec<TransactionSafeWrapper<'static>>>,
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

    fn more_money_received(
        &mut self,
        now: SystemTime,
        transactions: &[BlockchainTransaction],
    ) -> TransactionSafeWrapper {
        self.more_money_received_parameters
            .lock()
            .unwrap()
            .push((now, transactions.to_vec()));
        self.more_money_received_results.borrow_mut().remove(0)
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

    pub fn more_money_received_params(
        mut self,
        parameters: &Arc<Mutex<Vec<(SystemTime, Vec<BlockchainTransaction>)>>>,
    ) -> Self {
        self.more_money_received_parameters = parameters.clone();
        self
    }

    pub fn more_money_received_result(self, result: TransactionSafeWrapper<'static>) -> Self {
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
//
// #[derive(Default)]
// pub struct SentPayableDaoMock {
//     fingerprints_rowids_params: Arc<Mutex<Vec<Vec<H256>>>>,
//     fingerprints_rowids_results: RefCell<Vec<TransactionHashes>>,
//     delete_fingerprints_params: Arc<Mutex<Vec<Vec<u64>>>>,
//     delete_fingerprints_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
//     insert_new_fingerprints_params: Arc<Mutex<Vec<(Vec<HashAndAmount>, SystemTime)>>>,
//     insert_new_fingerprints_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
//     increment_scan_attempts_params: Arc<Mutex<Vec<Vec<u64>>>>,
//     increment_scan_attempts_result: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
//     mark_failures_params: Arc<Mutex<Vec<Vec<u64>>>>,
//     mark_failures_results: RefCell<Vec<Result<(), PendingPayableDaoError>>>,
//     return_all_errorless_fingerprints_params: Arc<Mutex<Vec<()>>>,
//     return_all_errorless_fingerprints_results: RefCell<Vec<Vec<SentTx>>>,
//     pub have_return_all_errorless_fingerprints_shut_down_the_system: bool,
// }
//
// impl SentPayableDao for SentPayableDaoMock {
//     fn fingerprints_rowids(&self, hashes: &[H256]) -> TransactionHashes {
//         self.fingerprints_rowids_params
//             .lock()
//             .unwrap()
//             .push(hashes.to_vec());
//         self.fingerprints_rowids_results.borrow_mut().remove(0)
//     }
//
//     fn return_all_errorless_fingerprints(&self) -> Vec<SentTx> {
//         self.return_all_errorless_fingerprints_params
//             .lock()
//             .unwrap()
//             .push(());
//         if self.have_return_all_errorless_fingerprints_shut_down_the_system
//             && self
//                 .return_all_errorless_fingerprints_results
//                 .borrow()
//                 .is_empty()
//         {
//             System::current().stop();
//             return vec![];
//         }
//         self.return_all_errorless_fingerprints_results
//             .borrow_mut()
//             .remove(0)
//     }
//
//     fn insert_new_fingerprints(
//         &self,
//         hashes_and_amounts: &[HashAndAmount],
//         batch_wide_timestamp: SystemTime,
//     ) -> Result<(), PendingPayableDaoError> {
//         self.insert_new_fingerprints_params
//             .lock()
//             .unwrap()
//             .push((hashes_and_amounts.to_vec(), batch_wide_timestamp));
//         self.insert_new_fingerprints_results.borrow_mut().remove(0)
//     }
//
//     fn delete_fingerprints(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
//         self.delete_fingerprints_params
//             .lock()
//             .unwrap()
//             .push(ids.to_vec());
//         self.delete_fingerprints_results.borrow_mut().remove(0)
//     }
//
//     fn increment_scan_attempts(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
//         self.increment_scan_attempts_params
//             .lock()
//             .unwrap()
//             .push(ids.to_vec());
//         self.increment_scan_attempts_result.borrow_mut().remove(0)
//     }
//
//     fn mark_failures(&self, ids: &[u64]) -> Result<(), PendingPayableDaoError> {
//         self.mark_failures_params.lock().unwrap().push(ids.to_vec());
//         self.mark_failures_results.borrow_mut().remove(0)
//     }
// }
//
// impl SentPayableDaoMock {
//     pub fn new() -> Self {
//         SentPayableDaoMock::default()
//     }
//
//     pub fn fingerprints_rowids_params(mut self, params: &Arc<Mutex<Vec<Vec<H256>>>>) -> Self {
//         self.fingerprints_rowids_params = params.clone();
//         self
//     }
//
//     pub fn fingerprints_rowids_result(self, result: TransactionHashes) -> Self {
//         self.fingerprints_rowids_results.borrow_mut().push(result);
//         self
//     }
//
//     pub fn insert_fingerprints_params(
//         mut self,
//         params: &Arc<Mutex<Vec<(Vec<HashAndAmount>, SystemTime)>>>,
//     ) -> Self {
//         self.insert_new_fingerprints_params = params.clone();
//         self
//     }
//
//     pub fn insert_fingerprints_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
//         self.insert_new_fingerprints_results
//             .borrow_mut()
//             .push(result);
//         self
//     }
//
//     pub fn delete_fingerprints_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
//         self.delete_fingerprints_params = params.clone();
//         self
//     }
//
//     pub fn delete_fingerprints_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
//         self.delete_fingerprints_results.borrow_mut().push(result);
//         self
//     }
//
//     pub fn return_all_errorless_fingerprints_params(
//         mut self,
//         params: &Arc<Mutex<Vec<()>>>,
//     ) -> Self {
//         self.return_all_errorless_fingerprints_params = params.clone();
//         self
//     }
//
//     pub fn return_all_errorless_fingerprints_result(
//         self,
//         result: Vec<SentTx>,
//     ) -> Self {
//         self.return_all_errorless_fingerprints_results
//             .borrow_mut()
//             .push(result);
//         self
//     }
//
//     pub fn mark_failures_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
//         self.mark_failures_params = params.clone();
//         self
//     }
//
//     pub fn mark_failures_result(self, result: Result<(), PendingPayableDaoError>) -> Self {
//         self.mark_failures_results.borrow_mut().push(result);
//         self
//     }
//
//     pub fn increment_scan_attempts_params(mut self, params: &Arc<Mutex<Vec<Vec<u64>>>>) -> Self {
//         self.increment_scan_attempts_params = params.clone();
//         self
//     }
//
//     pub fn increment_scan_attempts_result(
//         self,
//         result: Result<(), PendingPayableDaoError>,
//     ) -> Self {
//         self.increment_scan_attempts_result
//             .borrow_mut()
//             .push(result);
//         self
//     }
// }

#[derive(Default)]
pub struct SentPayableDaoMock {
    get_tx_identifiers_params: Arc<Mutex<Vec<HashSet<TxHash>>>>,
    get_tx_identifiers_results: RefCell<Vec<TxIdentifiers>>,
    insert_new_records_params: Arc<Mutex<Vec<Vec<SentTx>>>>,
    insert_new_records_results: RefCell<Vec<Result<(), SentPayableDaoError>>>,
    retrieve_txs_params: Arc<Mutex<Vec<Option<RetrieveCondition>>>>,
    retrieve_txs_results: RefCell<Vec<Vec<SentTx>>>,
    update_tx_block_params: Arc<Mutex<Vec<HashMap<TxHash, TransactionBlock>>>>,
    update_tx_block_results: RefCell<Vec<Result<(), SentPayableDaoError>>>,
    replace_records_params: Arc<Mutex<Vec<Vec<SentTx>>>>,
    replace_records_results: RefCell<Vec<Result<(), SentPayableDaoError>>>,
    delete_records_params: Arc<Mutex<Vec<HashSet<TxHash>>>>,
    delete_records_results: RefCell<Vec<Result<(), SentPayableDaoError>>>,
    // TODO necessary?
    //pub have_return_all_errorless_fingerprints_shut_down_the_system: bool,
}

impl SentPayableDao for SentPayableDaoMock {
    fn get_tx_identifiers(&self, hashes: &HashSet<TxHash>) -> TxIdentifiers{
        self.get_tx_identifiers_params.push(hashes);
        self. get_tx_identifiers_results.borrow_mut().remove(0)
    }
    fn insert_new_records(&self, txs: &[SentTx]) -> Result<(), SentPayableDaoError>{
        self.insert_new_records_params.lock().unwrap().push(txs.to_vec());
        self.insert_new_records_results.borrow_mut().remove(0)
    }
    fn retrieve_txs(&self, condition: Option<RetrieveCondition>) -> Vec<SentTx>{
        self.retrieve_txs_params.lock().unwrap().push(condition);
        self.retrieve_txs_results.borrow_mut().remove(0)
    }
    fn update_tx_blocks(
        &self,
        hash_map: &HashMap<TxHash, TransactionBlock>,
    ) -> Result<(), SentPayableDaoError>{
        self.update_tx_block_params.lock().unwrap().push(hash_map.clone());
        self.update_tx_block_results.borrow_mut().remove(0)
    }
    fn replace_records(&self, new_txs: &[SentTx]) -> Result<(), SentPayableDaoError>{
        self.replace_records_params.lock().unwrap().push(new_txs.to_vec());
        self.replace_records_results.borrow_mut().remove(0)
    }

    fn delete_records(&self, hashes: &HashSet<TxHash>) -> Result<(), SentPayableDaoError>{
        self.delete_records_params.lock().unwrap().push(hashes.clone());
        self.delete_records_results.borrow_mut().remove(0)
    }
}

impl SentPayableDaoMock {
    pub fn new() -> Self {
        SentPayableDaoMock::default()
    }

    pub fn get_tx_identifiers_params(mut self, params: &Arc<Mutex<Vec<HashSet<TxHash>>>>) -> Self {
        self.get_tx_identifiers_params = params.clone();
        self
    }

    pub fn get_tx_identifiers_result(self, result: TxIdentifiers) -> Self {
        self.get_tx_identifiers_results.borrow_mut().push(result);
        self
    }

    pub fn insert_new_records_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<SentTx>>>>,
    ) -> Self {
        self.insert_new_records_params = params.clone();
        self
    }

    pub fn insert_new_records_result(self, result: Result<(), SentPayableDaoError>) -> Self {
        self.insert_new_records_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn retrieve_txs(mut self, params: &Arc<Mutex<Vec<Option<RetrieveCondition>>>>) -> Self {
        self.retrieve_txs_params = params.clone();
        self
    }

    pub fn retrieve_txs_result(self, result: Vec<SentTx>) -> Self {
        self.retrieve_txs_results.borrow_mut().push(result);
        self
    }

    pub fn update_tx_blocks_params(
        mut self,
        params: &Arc<Mutex<Vec<HashMap<TxHash, TransactionBlock>>>>,
    ) -> Self {
        self.update_tx_block_params = params.clone();
        self
    }

    pub fn update_tx_blocks_result(
        self,
        result: Result<(), SentPayableDaoError>,
    ) -> Self {
        self.update_tx_block_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn replace_records_params(mut self, params: &Arc<Mutex<Vec<Vec<SentTx>>>>) -> Self {
        self.replace_records_params = params.clone();
        self
    }

    pub fn replace_records_result(self, result: Result<(), SentPayableDaoError>) -> Self {
        self.replace_records_results.borrow_mut().push(result);
        self
    }

    pub fn delete_records_params(mut self, params: &Arc<Mutex<Vec<HashSet<TxHash>>>>) -> Self {
        self.delete_records_params = params.clone();
        self
    }

    pub fn delete_records_result(
        self,
        result: Result<(), SentPayableDaoError>,
    ) -> Self {
        self.delete_records_results
            .borrow_mut()
            .push(result);
        self
    }
}

pub struct SentPayableDaoFactoryMock {
    make_params: Arc<Mutex<Vec<()>>>,
    make_results: RefCell<Vec<Box<dyn SentPayableDao>>>,
}

impl SentPayableDaoFactory for SentPayableDaoFactoryMock {
    fn make(&self) -> Box<dyn SentPayableDao> {
        if self.make_results.borrow().len() == 0 {
            panic!(
                "SentPayableDao Missing. This problem mostly occurs when SentPayableDao is only supplied for Accountant and not for the Scanner while building Accountant."
            )
        };
        self.make_params.lock().unwrap().push(());
        self.make_results.borrow_mut().remove(0)
    }
}

impl SentPayableDaoFactoryMock {
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

    pub fn make_result(self, result: SentPayableDaoMock) -> Self {
        self.make_results.borrow_mut().push(Box::new(result));
        self
    }
}

pub struct PayableScannerBuilder {
    payable_dao: PayableDaoMock,
    sent_payable_dao: SentPayableDaoMock,
    payment_thresholds: PaymentThresholds,
    payment_adjuster: PaymentAdjusterMock,
}

impl PayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            sent_payable_dao: SentPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            payment_adjuster: PaymentAdjusterMock::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> PayableScannerBuilder {
        self.payable_dao = payable_dao;
        self
    }

    pub fn payment_adjuster(
        mut self,
        payment_adjuster: PaymentAdjusterMock,
    ) -> PayableScannerBuilder {
        self.payment_adjuster = payment_adjuster;
        self
    }

    pub fn payment_thresholds(mut self, payment_thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds = payment_thresholds;
        self
    }

    pub fn sent_payable_dao(
        mut self,
        sent_payable_dao: SentPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.sent_payable_dao = sent_payable_dao;
        self
    }

    pub fn build(self) -> PayableScanner {
        PayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.sent_payable_dao),
            Rc::new(self.payment_thresholds),
            Box::new(self.payment_adjuster),
        )
    }
}

pub struct PendingPayableScannerBuilder {
    payable_dao: PayableDaoMock,
    sent_payable_dao: SentPayableDaoMock,
    payment_thresholds: PaymentThresholds,
    when_pending_too_long_sec: u64,
    financial_statistics: FinancialStatistics,
}

impl PendingPayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            sent_payable_dao: SentPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            when_pending_too_long_sec: DEFAULT_PENDING_TOO_LONG_SEC,
            financial_statistics: FinancialStatistics::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> Self {
        self.payable_dao = payable_dao;
        self
    }

    pub fn sent_payable_dao(mut self, sent_payable_dao: SentPayableDaoMock) -> Self {
        self.sent_payable_dao = sent_payable_dao;
        self
    }

    pub fn when_pending_too_long_sec(mut self, interval: u64) -> Self {
        self.when_pending_too_long_sec = interval;
        self
    }

    pub fn build(self) -> PendingPayableScanner {
        PendingPayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.sent_payable_dao),
            Rc::new(self.payment_thresholds),
            self.when_pending_too_long_sec,
            Rc::new(RefCell::new(self.financial_statistics)),
        )
    }
}

pub struct ReceivableScannerBuilder {
    receivable_dao: ReceivableDaoMock,
    banned_dao: BannedDaoMock,
    persistent_configuration: PersistentConfigurationMock,
    payment_thresholds: PaymentThresholds,
    financial_statistics: FinancialStatistics,
}

impl ReceivableScannerBuilder {
    pub fn new() -> Self {
        Self {
            receivable_dao: ReceivableDaoMock::new(),
            banned_dao: BannedDaoMock::new(),
            persistent_configuration: PersistentConfigurationMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            financial_statistics: FinancialStatistics::default(),
        }
    }

    pub fn receivable_dao(mut self, receivable_dao: ReceivableDaoMock) -> Self {
        self.receivable_dao = receivable_dao;
        self
    }

    pub fn persistent_configuration(
        mut self,
        persistent_config: PersistentConfigurationMock,
    ) -> Self {
        self.persistent_configuration = persistent_config;
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

    pub fn build(self) -> ReceivableScanner {
        ReceivableScanner::new(
            Box::new(self.receivable_dao),
            Box::new(self.banned_dao),
            Box::new(self.persistent_configuration),
            Rc::new(self.payment_thresholds),
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

pub fn make_pending_payable_fingerprint() -> SentTx {
    SentTx {
        rowid: 33,
        timestamp: from_unix_timestamp(222_222_222),
        hash: make_tx_hash(456),
        attempt: 1,
        amount: 12345,
        process_error: None,
    }
}

pub fn make_qualified_and_unqualified_payables(
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
        last_paid_timestamp: from_unix_timestamp(
            to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 + 1,
        ),
        pending_payable_opt: None,
    }];
    let qualified_payable_accounts = vec![
        PayableAccount {
            wallet: make_wallet("wallet2"),
            balance_wei: gwei_to_wei(
                payment_thresholds.permanent_debt_allowed_gwei + 1_000_000_000,
            ),
            last_paid_timestamp: from_unix_timestamp(
                to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 - 1,
            ),
            pending_payable_opt: None,
        },
        PayableAccount {
            wallet: make_wallet("wallet3"),
            balance_wei: gwei_to_wei(
                payment_thresholds.permanent_debt_allowed_gwei + 1_200_000_000,
            ),
            last_paid_timestamp: from_unix_timestamp(
                to_unix_timestamp(now) - payment_thresholds.maturity_threshold_sec as i64 - 100,
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

pub fn trick_rusqlite_with_read_only_conn(
    path: &Path,
    create_table: fn(&Connection),
) -> Connection {
    let db_path = path.join("experiment.db");
    let conn = Connection::open_with_flags(&db_path, OpenFlags::default()).unwrap();
    create_table(&conn);
    conn.close().unwrap();
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    conn
}

#[derive(Default)]
pub struct PaymentAdjusterMock {
    search_for_indispensable_adjustment_params:
        Arc<Mutex<Vec<(BlockchainAgentWithContextMessage, Logger)>>>,
    search_for_indispensable_adjustment_results:
        RefCell<Vec<Result<Option<Adjustment>, AnalysisError>>>,
    adjust_payments_params: Arc<Mutex<Vec<(PreparedAdjustment, SystemTime, Logger)>>>,
    adjust_payments_results: RefCell<Vec<OutboundPaymentsInstructions>>,
}

impl PaymentAdjuster for PaymentAdjusterMock {
    fn search_for_indispensable_adjustment(
        &self,
        msg: &BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Option<Adjustment>, AnalysisError> {
        self.search_for_indispensable_adjustment_params
            .lock()
            .unwrap()
            .push((msg.clone(), logger.clone()));
        self.search_for_indispensable_adjustment_results
            .borrow_mut()
            .remove(0)
    }

    fn adjust_payments(
        &self,
        setup: PreparedAdjustment,
        now: SystemTime,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions {
        self.adjust_payments_params
            .lock()
            .unwrap()
            .push((setup.clone(), now, logger.clone()));
        self.adjust_payments_results.borrow_mut().remove(0)
    }
}

impl PaymentAdjusterMock {
    pub fn is_adjustment_required_params(
        mut self,
        params: &Arc<Mutex<Vec<(BlockchainAgentWithContextMessage, Logger)>>>,
    ) -> Self {
        self.search_for_indispensable_adjustment_params = params.clone();
        self
    }

    pub fn is_adjustment_required_result(
        self,
        result: Result<Option<Adjustment>, AnalysisError>,
    ) -> Self {
        self.search_for_indispensable_adjustment_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn adjust_payments_params(
        mut self,
        params: &Arc<Mutex<Vec<(PreparedAdjustment, SystemTime, Logger)>>>,
    ) -> Self {
        self.adjust_payments_params = params.clone();
        self
    }

    pub fn adjust_payments_result(self, result: OutboundPaymentsInstructions) -> Self {
        self.adjust_payments_results.borrow_mut().push(result);
        self
    }
}
