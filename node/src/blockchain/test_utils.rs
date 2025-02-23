// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{
    BlockchainError, BlockchainInterface, BlockchainResult, PayableTransactionError,
    ProcessedPayableFallible, ResultForBalance, ResultForNonce, ResultForReceipt,
};
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use bip39::{Language, Mnemonic, Seed};
use ethereum_types::{BigEndianHash, H256};
use jsonrpc_core as rpc;
use lazy_static::lazy_static;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::future;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::batch_payable_tools::{BatchPayableTools, SecP256K1SecretsKeySecretKey};
use web3::transports::Batch;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, U256};
use web3::{BatchTransport, Error as Web3Error, Error, Web3};
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
    BIG_MEANINGLESS_PHRASE
        .iter()
        .map(|word| word.to_string())
        .collect()
}

pub fn make_meaningless_phrase() -> String {
    make_meaningless_phrase_words().join(" ").to_string()
}

pub fn make_meaningless_seed() -> Seed {
    let mnemonic = Mnemonic::from_phrase(&make_meaningless_phrase(), Language::English).unwrap();
    Seed::new(&mnemonic, "passphrase")
}

#[derive(Default)]
pub struct BlockchainInterfaceMock {
    retrieve_transactions_parameters: Arc<Mutex<Vec<(u64, Wallet)>>>,
    retrieve_transactions_results:
        RefCell<Vec<Result<RetrievedBlockchainTransactions, BlockchainError>>>,
    send_payables_within_batch_params: Arc<
        Mutex<
            Vec<(
                Wallet,
                u64,
                U256,
                Recipient<PendingPayableFingerprintSeeds>,
                Vec<PayableAccount>,
            )>,
        >,
    >,
    send_payables_within_batch_results:
        RefCell<Vec<Result<Vec<ProcessedPayableFallible>, PayableTransactionError>>>,
    get_transaction_fee_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_fee_balance_results: RefCell<Vec<ResultForBalance>>,
    get_token_balance_params: Arc<Mutex<Vec<Wallet>>>,
    get_token_balance_results: RefCell<Vec<ResultForBalance>>,
    get_transaction_receipt_params: Arc<Mutex<Vec<H256>>>,
    get_transaction_receipt_results: RefCell<Vec<ResultForReceipt>>,
    contract_address_results: RefCell<Vec<Address>>,
    get_transaction_count_parameters: Arc<Mutex<Vec<Wallet>>>,
    get_transaction_count_results: RefCell<Vec<BlockchainResult<U256>>>,
}

impl BlockchainInterface for BlockchainInterfaceMock {
    fn contract_address(&self) -> Address {
        self.contract_address_results.borrow_mut().remove(0)
    }

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        self.retrieve_transactions_parameters
            .lock()
            .unwrap()
            .push((start_block, recipient.clone()));
        self.retrieve_transactions_results.borrow_mut().remove(0)
    }

    fn send_payables_within_batch(
        &self,
        consuming_wallet: &Wallet,
        gas_price: u64,
        last_nonce: U256,
        new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
        self.send_payables_within_batch_params
            .lock()
            .unwrap()
            .push((
                consuming_wallet.clone(),
                gas_price,
                last_nonce,
                new_fingerprints_recipient.clone(),
                accounts.to_vec(),
            ));
        self.send_payables_within_batch_results
            .borrow_mut()
            .remove(0)
    }

    fn get_transaction_fee_balance(&self, address: &Wallet) -> ResultForBalance {
        self.get_transaction_fee_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        self.get_transaction_fee_balance_results
            .borrow_mut()
            .remove(0)
    }

    fn get_token_balance(&self, address: &Wallet) -> ResultForBalance {
        self.get_token_balance_params
            .lock()
            .unwrap()
            .push(address.clone());
        self.get_token_balance_results.borrow_mut().remove(0)
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> ResultForNonce {
        self.get_transaction_count_parameters
            .lock()
            .unwrap()
            .push(wallet.clone());
        self.get_transaction_count_results.borrow_mut().remove(0)
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.get_transaction_receipt_params
            .lock()
            .unwrap()
            .push(hash);
        self.get_transaction_receipt_results.borrow_mut().remove(0)
    }
}

impl BlockchainInterfaceMock {
    pub fn retrieve_transactions_params(mut self, params: &Arc<Mutex<Vec<(u64, Wallet)>>>) -> Self {
        self.retrieve_transactions_parameters = params.clone();
        self
    }

    pub fn retrieve_transactions_result(
        self,
        result: Result<RetrievedBlockchainTransactions, BlockchainError>,
    ) -> Self {
        self.retrieve_transactions_results.borrow_mut().push(result);
        self
    }

    pub fn send_payables_within_batch_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    Wallet,
                    u64,
                    U256,
                    Recipient<PendingPayableFingerprintSeeds>,
                    Vec<PayableAccount>,
                )>,
            >,
        >,
    ) -> Self {
        self.send_payables_within_batch_params = params.clone();
        self
    }

    pub fn send_payables_within_batch_result(
        self,
        result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
    ) -> Self {
        self.send_payables_within_batch_results
            .borrow_mut()
            .push(result);
        self
    }

    pub fn get_transaction_fee_balance_params(mut self, params: &Arc<Mutex<Vec<Wallet>>>) -> Self {
        self.get_transaction_fee_balance_params = params.clone();
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

// impl Transport for TestTransport {
//     type Out = web3::Result<rpc::Value>;
//
//     fn prepare(&self, method: &str, params: Vec<rpc::Value>) -> (RequestId, rpc::Call) {
//         let request = web3::helpers::build_request(1, method, params.clone());
//         let mut prepare_params = self.prepare_params.lock().unwrap();
//         prepare_params.push((method.to_string(), params));
//         (prepare_params.len(), request)
//     }
//
//     fn send(&self, id: RequestId, request: rpc::Call) -> Self::Out {
//         todo!()
//         self.send_params.lock().unwrap().push((id, request.clone()));
//         match self.send_results.borrow_mut().pop_front() {
//             Some(response) => Ok(response),
//             None => {
//                 println!("Unexpected request (id: {:?}): {:?}", id, request);
//                 Err(Web3Error::Unreachable)
//             }
//         }
//     }
// }

// impl BatchTransport for TestTransport {
//     type Batch = web3::Result<Vec<Result<rpc::Value, web3::Error>>>;
//
//     fn send_batch<T>(&self, requests: T) -> Self::Batch
//     where
//         T: IntoIterator<Item = (RequestId, rpc::Call)>,
//     {
//         todo!()
//         self.send_batch_params
//             .lock()
//             .unwrap()
//             .push(requests.into_iter().collect());
//         let response = self.send_batch_results.borrow_mut().remove(0);
//         Ok(response)
//     }
// }

impl TestTransport {
    pub fn prepare_params(mut self, params: &Arc<Mutex<Vec<(String, Vec<rpc::Value>)>>>) -> Self {
        self.prepare_params = params.clone();
        self
    }

    //why prepare_result missing? Look up for a comment at the struct

    pub fn send_params(mut self, params: &Arc<Mutex<Vec<(RequestId, rpc::Call)>>>) -> Self {
        self.send_params = params.clone();
        self
    }

    pub fn send_result(self, rpc_call_response: rpc::Value) -> Self {
        self.send_results.borrow_mut().push_back(rpc_call_response);
        self
    }

    pub fn send_batch_params(
        mut self,
        params: &Arc<Mutex<Vec<Vec<(RequestId, rpc::Call)>>>>,
    ) -> Self {
        self.send_batch_params = params.clone();
        self
    }

    pub fn send_batch_result(
        self,
        batched_responses: Vec<Result<rpc::Value, web3::Error>>,
    ) -> Self {
        self.send_batch_results.borrow_mut().push(batched_responses);
        self
    }

    pub fn initiate_reference_counter(mut self, reference_arc: &Arc<()>) -> Self {
        self.reference_counter_opt = Some(reference_arc.clone());
        self
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

    // fn submit_batch(
    //     &self,
    //     web3: &Web3<Batch<T>>,
    // ) -> Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error> {
    //     self.submit_batch_params.lock().unwrap().push(web3.clone());
    //     self.submit_batch_results.borrow_mut().remove(0)
    // }
}

impl<T: BatchTransport> BatchPayableToolsMock<T> {
    pub fn sign_transaction_params(
        mut self,
        params: &Arc<
            Mutex<
                Vec<(
                    TransactionParameters,
                    Web3<Batch<T>>,
                    secp256k1secrets::SecretKey,
                )>,
            >,
        >,
    ) -> Self {
        todo!();
        // self.sign_transaction_params = params.clone();
        self
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
    // pub fn submit_batch_result(
    //     self,
    //     result: Result<Vec<web3::transports::Result<rpc::Value>>, Web3Error>,
    // ) -> Self {
    //     self.submit_batch_results.borrow_mut().push(result);
    //     self
    // }
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

pub fn make_tx_hash(base: u32) -> H256 {
    H256::from_uint(&U256::from(base))
}
