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
use crate::blockchain::blockchain_bridge::PendingPaymentBackup;
use crate::blockchain::blockchain_interface::{
    Balance, BlockchainError, BlockchainInterface, BlockchainResult, Nonce, Transaction,
    Transactions, TxReceipt,
};
use crate::blockchain::tool_wrappers::{PaymentBackupRecipientWrapper, SendTransactionToolWrapper};
use crate::bootstrapper::BootstrapperConfig;
use crate::database::dao_utils::{from_time_t, to_time_t};
use crate::db_config::config_dao::{ConfigDao, ConfigDaoFactory};
use crate::db_config::mocks::ConfigDaoMock;
use crate::sub_lib::accountant::AccountantConfig;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
use ethereum_types::{H256, U256};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use web3::types::Address;

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
        pending_payment_transaction: None,
        rowid: 1,
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
    insert_record_params: Arc<Mutex<Vec<PendingPaymentBackup>>>,
    insert_record_results: RefCell<Vec<Result<(), PendingPaymentDaoError>>>,
    delete_record_params: Arc<Mutex<Vec<u16>>>,
    delete_record_results: RefCell<Vec<Result<(), PendingPaymentDaoError>>>,
    read_record_params: Arc<Mutex<Vec<u16>>>,
    read_record_results: RefCell<Vec<Result<PendingPaymentBackup, PendingPaymentDaoError>>>,
}

impl PendingPaymentsDao for PendingPaymentsDaoMock {
    fn read_backup_record(&self, id: u16) -> Result<PendingPaymentBackup, PendingPaymentDaoError> {
        self.read_record_params.lock().unwrap().push(id);
        self.read_record_results.borrow_mut().remove(0)
    }

    fn insert_backup_record(
        &self,
        pending_payment: PendingPaymentBackup,
    ) -> Result<(), PendingPaymentDaoError> {
        self.insert_record_params
            .lock()
            .unwrap()
            .push(pending_payment);
        self.insert_record_results.borrow_mut().remove(0)
    }

    fn delete_backup_record(&self, id: u16) -> Result<(), PendingPaymentDaoError> {
        self.delete_record_params.lock().unwrap().push(id);
        self.delete_record_results.borrow_mut().remove(0)
    }
}

impl PendingPaymentsDaoMock {
    pub fn insert_backup_record_params(
        mut self,
        params: &Arc<Mutex<Vec<PendingPaymentBackup>>>,
    ) -> Self {
        self.insert_record_params = params.clone();
        self
    }

    pub fn insert_backup_record_result(self, result: Result<(), PendingPaymentDaoError>) -> Self {
        self.insert_record_results.borrow_mut().push(result);
        self
    }

    pub fn delete_backup_record_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
        self.delete_record_params = params.clone();
        self
    }

    pub fn delete_backup_record_result(self, result: Result<(), PendingPaymentDaoError>) -> Self {
        self.delete_record_results.borrow_mut().push(result);
        self
    }

    pub fn read_backup_record_params(mut self, params: &Arc<Mutex<Vec<u16>>>) -> Self {
        self.read_record_params = params.clone();
        self
    }

    pub fn read_backup_record_result(
        self,
        result: Result<PendingPaymentBackup, PendingPaymentDaoError>,
    ) -> Self {
        self.read_record_results.borrow_mut().push(result);
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

#[derive(Default)]
pub struct BlockchainInterfaceMock {
    retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
    retrieve_transactions_results: RefCell<Vec<BlockchainResult<Vec<Transaction>>>>,
    send_transaction_parameters: Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    send_transaction_results: RefCell<Vec<BlockchainResult<(H256, SystemTime)>>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results: RefCell<Vec<TxReceipt>>,
    send_transaction_tools_results: RefCell<Vec<Box<dyn SendTransactionToolWrapper>>>,
    contract_address_results: RefCell<Vec<Address>>,
    get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(mut self, params: &Arc<Mutex<Vec<(u64, Wallet)>>>) -> Self {
        self.retrieve_transactions_parameters = params.clone();
        self
    }

    pub fn retrieve_transactions_result(
        self,
        result: Result<Vec<Transaction>, BlockchainError>,
    ) -> Self {
        self.retrieve_transactions_results.borrow_mut().push(result);
        self
    }

    pub fn send_transaction_params(
        mut self,
        params: &Arc<Mutex<Vec<(Wallet, Wallet, u64, U256, u64)>>>,
    ) -> Self {
        self.send_transaction_parameters = params.clone();
        self
    }

    pub fn send_transaction_result(self, result: BlockchainResult<(H256, SystemTime)>) -> Self {
        self.send_transaction_results.borrow_mut().push(result);
        self
    }

    pub fn contract_address_result(self, address: Address) -> Self {
        self.contract_address_results.borrow_mut().push(address);
        self
    }

    pub fn get_transaction_count_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_count_parameters = params.clone();
        self
    }

    pub fn get_transaction_count_result(self, result: BlockchainResult<U256>) -> Self {
        self.get_transaction_count_results.borrow_mut().push(result);
        self
    }

    pub fn get_transaction_receipt_params(mut self, params: &Arc<Mutex<Vec<H256>>>) -> Self {
        self.get_transaction_receipt_params = params.clone();
        self
    }

    pub fn get_transaction_receipt_result(self, result: TxReceipt) -> Self {
        self.get_transaction_receipt_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn send_transaction_tools_result(
        self,
        result: Box<dyn SendTransactionToolWrapper>,
    ) -> Self {
        self.send_transaction_tools_results
            .borrow_mut()
            .push(result);
        self
    }
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        self.contract_address_results.borrow_mut().remove(0)
    }

    fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
        self.retrieve_transactions_parameters
            .lock()
            .unwrap()
            .push((start_block, recipient.clone()));
        self.retrieve_transactions_results.borrow_mut().remove(0)
    }

    fn send_transaction<'a>(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
        rowid_payables: u16,
        _send_transaction_tools: &'a dyn SendTransactionToolWrapper,
    ) -> BlockchainResult<(H256, SystemTime)> {
        self.send_transaction_parameters.lock().unwrap().push((
            consuming_wallet.clone(),
            recipient.clone(),
            amount,
            nonce,
            gas_price,
        ));
        self.send_transaction_results.borrow_mut().remove(0)
    }

    fn get_eth_balance(&self, _address: &Wallet) -> Balance {
        unimplemented!()
    }

    fn get_token_balance(&self, _address: &Wallet) -> Balance {
        unimplemented!()
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
        self.get_transaction_count_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());
        self.get_transaction_count_results.borrow_mut().remove(0)
    }

    fn get_transaction_receipt(&self, hash: H256) -> TxReceipt {
        self.get_transaction_receipt_params
            .lock()
            .unwrap()
            .push(hash);
        self.get_transaction_receipt_results.borrow_mut().remove(0)
    }

    fn send_transaction_tools<'a>(
        &'a self,
        backup_recipient: &dyn PaymentBackupRecipientWrapper,
    ) -> Box<dyn SendTransactionToolWrapper + 'a> {
        self.send_transaction_tools_results.borrow_mut().remove(0)
    }
}

pub fn earlier_in_seconds(seconds: u64) -> SystemTime {
    SystemTime::now()
        .checked_sub(Duration::from_secs(seconds))
        .unwrap()
}
