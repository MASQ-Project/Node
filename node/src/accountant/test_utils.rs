// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::payable_dao::{PayableAccount, PayableDao, PayableDaoFactory};
use crate::accountant::pending_payments_dao::{
    PendingPaymentDaoError, PendingPaymentsDao, PendingPaymentsDaoFactory,
};
use crate::accountant::receivable_dao::{ReceivableAccount, ReceivableDao, ReceivableDaoFactory};
use crate::accountant::tests::{PayableDaoMock, ReceivableDaoMock};
use crate::accountant::Accountant;
use crate::banned_dao::{BannedDao, BannedDaoFactory};
use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::{from_time_t, to_time_t};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
use ethereum_types::{BigEndianHash, H256, U256};
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
    PayableAccount {
        wallet: make_wallet(&format!("wallet{}", n)),
        balance: (n * 1_000_000_000) as i64,
        last_paid_timestamp: from_time_t(now - (n as i64)),
        pending_payment_rowid_opt: None,
    }
}

//TODO should I replace this with the builder?
pub fn make_accountant(
    config_opt: Option<BootstrapperConfig>,
    payable_dao_opt: Option<PayableDaoMock>,
    receivable_dao_opt: Option<ReceivableDaoMock>,
    pending_payments_dao_opt: Option<PendingPaymentsDaoMock>,
    banned_dao_opt: Option<BannedDaoMock>,
    persistent_config_opt: Option<PersistentConfigurationMock>,
) -> Accountant {
    let payable_dao_factory =
        PayableDaoFactoryMock::new(Box::new(payable_dao_opt.unwrap_or(PayableDaoMock::new())));
    let receivable_dao_factory =
        ReceivableDaoFactoryMock::new(receivable_dao_opt.unwrap_or(ReceivableDaoMock::new()));
    let pending_payments_dao_factory = PendingPaymentsDaoFactoryMock::new(
        pending_payments_dao_opt.unwrap_or(PendingPaymentsDaoMock::default()),
    );
    let banned_dao_factory =
        BannedDaoFactoryMock::new(banned_dao_opt.unwrap_or(BannedDaoMock::new()));
    let mut subject = Accountant::new(
        &config_opt.unwrap_or(BootstrapperConfig::new()),
        Box::new(payable_dao_factory),
        Box::new(receivable_dao_factory),
        Box::new(pending_payments_dao_factory),
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
    pending_payments_dao_factory: Box<dyn PendingPaymentsDaoFactory>,
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
            pending_payments_dao_factory: Box::new(PendingPaymentsDaoFactoryMock::new(
                PendingPaymentsDaoMock::default(),
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

    pub fn pending_payments_dao_factory(
        mut self,
        pending_payments_dao: Box<dyn PendingPaymentsDaoFactory>,
    ) -> Self {
        self.pending_payments_dao_factory = pending_payments_dao;
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
            self.pending_payments_dao_factory,
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
    bc.consuming_wallet = Some(consuming_wallet);
    bc.earning_wallet = earning_wallet;
    bc
}

#[derive(Default)]
pub struct PendingPaymentsDaoMock {
    delete_record_params: Arc<Mutex<Vec<u64>>>,
    delete_record_results: RefCell<Vec<Result<(), PendingPaymentDaoError>>>,
    initiate_record_params: Arc<Mutex<Vec<u64>>>,
    initiate_record_results: RefCell<Vec<Result<u64, PendingPaymentDaoError>>>,
    mark_failure_params: Arc<Mutex<Vec<u64>>>,
    mark_failure_results: RefCell<Vec<Result<(), PendingPaymentDaoError>>>,
    read_record_params: Arc<Mutex<Vec<u64>>>,
    read_record_results: RefCell<Vec<Result<PaymentBackupRecord, PendingPaymentDaoError>>>,
    return_all_active_backup_records_params: Arc<Mutex<Vec<()>>>,
    return_all_active_backup_records_results:
        RefCell<Vec<Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError>>>,
}

impl PendingPaymentsDao for PendingPaymentsDaoMock {
    fn read_backup_record(&self, id: u64) -> Result<PaymentBackupRecord, PendingPaymentDaoError> {
        self.read_record_params.lock().unwrap().push(id);
        self.read_record_results.borrow_mut().remove(0)
    }

    fn return_all_active_backup_records(
        &self,
    ) -> Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError> {
        self.return_all_active_backup_records_params
            .lock()
            .unwrap()
            .push(());
        self.return_all_active_backup_records_results
            .borrow_mut()
            .remove(0)
    }

    fn initiate_backup_record(&self, amount: u64) -> Result<u64, PendingPaymentDaoError> {
        self.initiate_record_params.lock().unwrap().push(amount);
        self.initiate_record_results.borrow_mut().remove(0)
    }

    fn complete_backup_record(
        &self,
        id: u64,
        transaction_hash: H256,
    ) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }

    fn delete_backup_record(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        self.delete_record_params.lock().unwrap().push(id);
        self.delete_record_results.borrow_mut().remove(0)
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        self.mark_failure_params.lock().unwrap().push(id);
        self.mark_failure_results.borrow_mut().remove(0)
    }
}

impl PendingPaymentsDaoMock {
    pub fn initiate_backup_record_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.initiate_record_params = params.clone();
        self
    }

    pub fn initiate_backup_record_result(
        self,
        result: Result<u64, PendingPaymentDaoError>,
    ) -> Self {
        self.initiate_record_results.borrow_mut().push(result);
        self
    }

    pub fn delete_backup_record_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.delete_record_params = params.clone();
        self
    }

    pub fn delete_backup_record_result(self, result: Result<(), PendingPaymentDaoError>) -> Self {
        self.delete_record_results.borrow_mut().push(result);
        self
    }

    pub fn read_backup_record_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.read_record_params = params.clone();
        self
    }

    pub fn read_backup_record_result(
        self,
        result: Result<PaymentBackupRecord, PendingPaymentDaoError>,
    ) -> Self {
        self.read_record_results.borrow_mut().push(result);
        self
    }

    pub fn return_all_backup_records_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
        self.return_all_active_backup_records_params = params.clone();
        self
    }

    pub fn return_all_backup_records_result(
        self,
        result: Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError>,
    ) -> Self {
        self.return_all_active_backup_records_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn mark_failure_params(mut self, params: &Arc<Mutex<Vec<u64>>>) -> Self {
        self.mark_failure_params = params.clone();
        self
    }

    pub fn mark_failure_result(self, result: Result<(), PendingPaymentDaoError>) -> Self {
        self.mark_failure_results.borrow_mut().push(result);
        self
    }
}

pub struct PendingPaymentsDaoFactoryMock {
    called: Rc<RefCell<bool>>,
    mock: RefCell<Option<PendingPaymentsDaoMock>>,
}

impl PendingPaymentsDaoFactory for PendingPaymentsDaoFactoryMock {
    fn make(&self) -> Box<dyn PendingPaymentsDao> {
        *self.called.borrow_mut() = true;
        Box::new(self.mock.borrow_mut().take().unwrap())
    }
}

impl PendingPaymentsDaoFactoryMock {
    pub fn new(mock: PendingPaymentsDaoMock) -> Self {
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

pub fn make_payment_backup() -> PaymentBackupRecord {
    PaymentBackupRecord {
        rowid: 33,
        timestamp: from_time_t(222_222_222),
        hash: H256::from_uint(&U256::from(456)),
        attempt: 0,
        amount: None,
    }
}
