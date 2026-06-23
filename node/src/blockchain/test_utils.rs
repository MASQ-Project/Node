// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::batch_payable_tools::{BatchPayableTools, SecP256K1SecretsKeySecretKey};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainResult, PayableTransactionError,
    ProcessedPayableFallible, ResultForBalance, ResultForNonce, ResultForReceipt,
};
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::{BigEndianHash, H256};
use futures_util::future::BoxFuture;
use jsonrpc_core as rpc;
use lazy_static::lazy_static;
use serde_json::Value;
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::to_string;
use serde::Serialize;
use serde_derive::Deserialize;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use web3::transports::Batch;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, U256};
use web3::{BatchTransport, Error as Web3Error, Web3};
use web3::{RequestId, Transport};

use crate::blockchain::blockchain_interface::RetrievedBlockchainTransactions;

lazy_static! {
    static ref BIG_MEANINGLESS_PHRASE: Vec<&'static str> = vec![
        "parent", "prevent", "vehicle", "tooth", "crazy", "cruel", "update", "mango", "female",
        "mad", "spread", "plunge", "tiny", "inch", "under", "engine", "enforce", "film", "awesome",
        "plunge", "cloud", "spell", "empower", "pipe",
    ];
}

pub fn make_meaningless_phrase_words() -> Vec<String> {
    BIG_MEANINGLESS_PHRASE.iter().map(to_string).collect()
}

pub fn make_meaningless_phrase() -> String {
    make_meaningless_phrase_words().join(" ").to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}

pub fn make_blockchain_interface_web3(port: u16) -> BlockchainInterfaceWeb3 {
    let chain = Chain::PolyMainnet;
    let (event_loop_handle, transport) = Http::with_max_parallel(
        &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
        REQUESTS_IN_PARALLEL,
    )
    .unwrap();

    BlockchainInterfaceWeb3::new(transport, event_loop_handle, chain)
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RpcResponse<S: Serialize> {
    #[serde(rename = "jsonrpc")]
    json_rpc: String,
    id: u8,
    result: S,
}

#[derive(Default)]
pub struct ReceiptResponseBuilder {
    transaction_hash_opt: Option<Hash>,
    transaction_index_opt: Option<Index>,
    block_hash_opt: Option<Hash>,
    block_number_opt: Option<U64>,
    cumulative_gas_used_opt: Option<U256>,
    gas_used_opt: Option<U256>,
    contract_address_opt: Option<H160>,
    logs_opt: Option<Vec<Log>>,
    status_opt: Option<U64>,
    root_opt: Option<Hash>,
    logs_bloom_opt: Option<H2048>,
}

impl ReceiptResponseBuilder {
    pub fn transaction_hash(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.transaction_hash_opt = Some(hash);
        self
    }

    pub fn transaction_index(mut self, index: Index) -> ReceiptResponseBuilder {
        self.transaction_index_opt = Some(index);
        self
    }

    pub fn block_hash(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.block_hash_opt = Some(hash);
        self
    }

    pub fn block_number(mut self, number: U64) -> ReceiptResponseBuilder {
        self.block_number_opt = Some(number);
        self
    }

    pub fn cumulative_gas_used(mut self, number: U256) -> ReceiptResponseBuilder {
        self.cumulative_gas_used_opt = Some(number);
        self
    }

    pub fn get_transaction_fee_balance_result(self, result: ResultForBalance) -> Self {
        self.get_transaction_fee_balance_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_token_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_token_balance_params = params.clone();
        self
    }

    pub fn get_token_balance_result(self, result: ResultForBalance) -> Self {
        self.get_token_balance_results.borrow_mut().push(result);
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

    pub fn get_transaction_receipt_result(self, result: ResultForReceipt) -> Self {
        self.get_transaction_receipt_results
            .borrow_mut()
            .push(result);
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestTransport {
    // neither prepare_results or send_results can be effectively implemented the traditional way,
    // their queue would never progress and would return always the first prepared result despite
    // taking multiple calls; the reason is that the Web3 library tends to clone (!!) the transport
    // and by doing that, removing one element affects just the current clone, and next time an intact
    // version of the same full queue will come in again as another individualistic clone
    prepare_params: Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>,
    send_params: Arc<Mutex<Vec<(RequestId, rpc::Call)>>>,
    send_results: RefCell<VecDeque<rpc::Value>>,
    send_batch_params: Arc<Mutex<Vec<Vec<(RequestId, rpc::Call)>>>>,
    send_batch_results: RefCell<Vec<Vec<Result<rpc::Value, web3::Error>>>>,
    //to check inheritance from a certain descendant, be proving a relation with reference counting
    reference_counter_opt: Option<Arc<()>>,
}

impl Transport for TestTransport {
    type Out = BoxFuture<'static, web3::Result<Value>>;

    fn prepare(&self, method: &str, params: Vec<rpc::Value>) -> (RequestId, rpc::Call) {
        let request = web3::helpers::build_request(1, method, params.clone());
        let mut prepare_params = self.prepare_params.lock().unwrap();
        prepare_params.push((method.to_string(), params));
        (prepare_params.len(), request)
    }

    fn send(&self, _id: RequestId, _request: rpc::Call) -> Self::Out {
        todo!("this structure has been removed in GH-744");
        // self.send_params.lock().unwrap().push((id, request.clone()));
        // match self.send_results.borrow_mut().pop_front() {
        //     Some(response) => Ok(response),
        //     None => {
        //         println!("Unexpected request (id: {:?}): {:?}", id, request);
        //         Err(Web3Error::Unreachable)
        //     }
        // }
    }
}

impl BatchTransport for TestTransport {
    type Batch = BoxFuture<'static, web3::Result<Vec<web3::Result<Value>>>>;

    fn send_batch<T>(&self, _requests: T) -> Self::Batch
    where
        T: IntoIterator<Item = (RequestId, rpc::Call)>,
    {
        todo!("This code will disappear once GH-744 gets in.")
        // self.send_batch_params
        //     .lock()
        //     .unwrap()
        //     .push(requests.into_iter().collect());
        // let response = self.send_batch_results.borrow_mut().remove(0);
        // Ok(response)
    }
}

impl TestTransport {
    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    pub fn contract_address(mut self, hash: H160) -> ReceiptResponseBuilder {
        self.contract_address_opt = Some(hash);
        self
    }

    pub fn logs(mut self, logs: Vec<Log>) -> ReceiptResponseBuilder {
        self.logs_opt = Some(logs);
        self
    }

    pub fn status(mut self, number: U64) -> ReceiptResponseBuilder {
        self.status_opt = Some(number);
        self
    }

    pub fn root(mut self, hash: Hash) -> ReceiptResponseBuilder {
        self.root_opt = Some(hash);
        self
    }

    pub fn logs_bloom(mut self, bloom: H2048) -> ReceiptResponseBuilder {
        self.logs_bloom_opt = Some(bloom);
        self
    }

    pub fn build(self) -> String {
        let mut transaction_receipt = TransactionReceipt::default();

        if let Some(transaction_hash) = self.transaction_hash_opt {
            transaction_receipt.transaction_hash = transaction_hash;
        }

        if let Some(index) = self.transaction_index_opt {
            transaction_receipt.transaction_index = index;
        }

        if let Some(cumulative_gas_used) = self.cumulative_gas_used_opt {
            transaction_receipt.cumulative_gas_used = cumulative_gas_used;
        }

        if let Some(logs) = self.logs_opt {
            transaction_receipt.logs = logs;
        }

        if let Some(bloom) = self.logs_bloom_opt {
            transaction_receipt.logs_bloom = bloom;
        }

        transaction_receipt.block_hash = self.block_hash_opt;
        transaction_receipt.block_number = self.block_number_opt;
        transaction_receipt.gas_used = self.gas_used_opt;
        transaction_receipt.contract_address = self.contract_address_opt;
        transaction_receipt.status = self.status_opt;
        transaction_receipt.root = self.root_opt;

        let rpc_response = RpcResponse {
            json_rpc: "2.0".to_string(),
            id: 1,
            result: transaction_receipt,
        };
        serde_json::to_string(&rpc_response).unwrap()
    }
}

#[derive(Default)]
pub struct BatchPayableToolsFactoryMock<T> {
    make_results: RefCell<Vec<Box<dyn BatchPayableTools<T>>>>,
}

impl<T> BatchPayableToolsFactoryMock<T> {
    pub fn make_result(self, result: Box<dyn BatchPayableTools<T>>) -> Self {
        self.make_results.borrow_mut().push(result);
        self
    }
}

#[derive(Default)]
pub struct BatchPayableToolsMock<T: BatchTransport> {
    sign_transaction_params: Arc<
        Mutex<
            Vec<(
                TransactionParameters,
                Web3<Batch<T>>,
                SecP256K1SecretsKeySecretKey,
            )>,
        >,
    >,
    sign_transaction_results: RefCell<Vec<Result<SignedTransaction, Web3Error>>>,
    append_transaction_to_batch_params: Arc<Mutex<Vec<(Bytes, Web3<Batch<T>>)>>>,
    //append_transaction_to_batch returns just the unit type
    //batch_wide_timestamp doesn't have params
    batch_wide_timestamp_results: RefCell<Vec<SystemTime>>,
    send_new_payable_fingerprints_seeds_params: Arc<
        Mutex<
            Vec<(
                SystemTime,
                Recipient<PendingPayableFingerprintSeeds>,
                Vec<(H256, u128)>,
            )>,
        >,
    >,
    //new_payable_fingerprints returns just the unit type
    submit_batch_params: Arc<Mutex<Vec<Web3<Batch<T>>>>>,
    // submit_batch_results:
    //     RefCell<Vec<Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>>>,
}

impl<T: BatchTransport> BatchPayableTools<T> for BatchPayableToolsMock<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &SecP256K1SecretsKeySecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.sign_transaction_params.lock().unwrap().push((
            transaction_params.clone(),
            web3.clone(),
            key.clone(),
        ));
        self.sign_transaction_results.borrow_mut().remove(0)
    }

    fn append_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>) {
        self.append_transaction_to_batch_params
            .lock()
            .unwrap()
            .push((signed_transaction, web3.clone()));
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        self.batch_wide_timestamp_results.borrow_mut().remove(0)
    }

    fn send_new_payable_fingerprints_seeds(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprintSeeds>,
        hashes_and_balances: &[(H256, u128)],
    ) {
        self.send_new_payable_fingerprints_seeds_params
            .lock()
            .unwrap()
            .push((
                batch_wide_timestamp,
                (*pp_fingerprint_sub).clone(),
                hashes_and_balances.to_vec(),
            ));
    }

    fn submit_batch(&self, _web3: &Web3<Batch<T>>) -> Result<Vec<()>, Web3Error> {
        todo!("this structure has been removed in GH-744")
        // self.submit_batch_params.lock().unwrap().push(web3.clone());
        // self.submit_batch_results.borrow_mut().remove(0)
    }
}

impl<T: BatchTransport> BatchPayableToolsMock<T> {
    pub fn sign_transaction_params(
        self,
        _params: &Arc<
            Mutex<
                Vec<(
                    TransactionParameters,
                    Web3<Batch<T>>,
                    secp256k1secrets::SecretKey,
                )>,
            >,
        >,
    ) -> Self {
        todo!("this structure has been removed in GH-744");
        // self.sign_transaction_params = params.clone();
        // self
    }
    pub fn sign_transaction_result(self, result: Result<SignedTransaction, Web3Error>) -> Self {
        self.sign_transaction_results.borrow_mut().push(result);
        self
    }

    pub fn batch_wide_timestamp_result(self, result: SystemTime) -> Self {
        self.batch_wide_timestamp_results.borrow_mut().push(result);
        self
    }

    pub fn send_new_payable_fingerprint_credentials_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    SystemTime,
                    Recipient<PendingPayableFingerprintSeeds>,
                    Vec<(H256, u128)>,
                )>,
            >,
        >,
    ) -> Self {
        self.send_new_payable_fingerprints_seeds_params = params.clone();
        self
    }

    pub fn append_transaction_to_batch_params(
        mut self,
        params: &Arc<Mutex<Vec<(Bytes, Web3<Batch<T>>)>>>,
    ) -> Self {
        self.append_transaction_to_batch_params = params.clone();
        self
    }

    pub fn submit_batch_params(mut self, params: &Arc<Mutex<Vec<Web3<Batch<T>>>>>) -> Self {
        self.submit_batch_params = params.clone();
        self
    }
    pub fn submit_batch_result(self, _result: Result<Vec<()>, Web3Error>) -> Self {
        todo!("this structure has been removed in GH-744");
        // self.submit_batch_results.borrow_mut().push(result);
        // self
    }
}

pub fn make_default_signed_transaction() -> SignedTransaction {
    SignedTransaction {
        message_hash: Default::default(),
        v: 0,
        r: Default::default(),
        s: Default::default(),
        raw_transaction: Default::default(),
        transaction_hash: Default::default(),
    }
}

fn make_hash(base: u32) -> H256 {
    H256::from_uint(&U256::from(base))
}

pub fn make_tx_hash(base: u32) -> H256 {
    make_hash(base)
}

pub fn make_block_hash(base: u32) -> H256 {
    make_hash(base + 1000000000)
}

pub fn make_address(base: u32) -> Address {
    let base = base % 0xfff;
    let value = U256::from(base * 3);
    let shifted = value << 72;
    let value = U256::from(value) << 24;
    let value = value | shifted;
    let mut full_bytes = [0u8; 32];
    value.to_big_endian(&mut full_bytes);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&full_bytes[12..]);
    H160(bytes)
}

pub fn all_chains() -> [Chain; 4] {
    [
        Chain::EthMainnet,
        Chain::PolyMainnet,
        Chain::PolyAmoy,
        Chain::Dev,
    ]
}

pub fn transport_error_code() -> u16 {
    if cfg!(target_os = "windows") {
        10061
    } else if cfg!(target_os = "macos") {
        61
    } else if cfg!(target_os = "linux") {
        111
    } else {
        0
    }
}

pub fn transport_error_message() -> String {
    if cfg!(target_os = "windows") {
        "No connection could be made because the target machine actively refused it.".to_string()
    } else {
        "Connection refused".to_string()
    }
}

pub struct TransactionReceiptBuilder {
    status_opt: Option<U64>,
    block_hash_opt: Option<H256>,
    block_number_opt: Option<U64>,
    transaction_hash: H256,
}

impl TransactionReceiptBuilder {
    pub fn new(transaction_hash: H256) -> Self {
        Self {
            status_opt: None,
            block_hash_opt: None,
            block_number_opt: None,
            transaction_hash,
        }
    }

    pub fn status(mut self, status: U64) -> Self {
        self.status_opt = Some(status);
        self
    }

    pub fn block_hash(mut self, block_hash: H256) -> Self {
        self.block_hash_opt = Some(block_hash);
        self
    }

    pub fn block_number(mut self, block_number: U64) -> Self {
        self.block_number_opt = Some(block_number);
        self
    }

    pub fn build(self) -> TransactionReceipt {
        TransactionReceipt {
            status: self.status_opt,
            root: None,
            block_hash: self.block_hash_opt,
            block_number: self.block_number_opt,
            cumulative_gas_used: Default::default(),
            gas_used: None,
            contract_address: None,
            transaction_hash: self.transaction_hash,
            transaction_index: Default::default(),
            logs: vec![],
            logs_bloom: Default::default(),
        }
    }
}
