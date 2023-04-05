// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use crate::blockchain::tool_wrappers::{
    SendTransactionToolWrapperReal, SendTransactionToolsWrapper, SendTransactionToolsWrapperNull,
};
use crate::sub_lib::wallet::Wallet;
use actix::{Message, Recipient};
use futures::{future, Future};
use masq_lib::blockchains::chains::{Chain, ChainFamily};
use masq_lib::constants::DEFAULT_CHAIN;
use masq_lib::logger::Logger;
use std::convert::{From, TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::time::SystemTime;
use thousands::Separable;
use web3::contract::{Contract, Options};
use web3::transports::EventLoopHandle;
use web3::types::{
    Address, BlockNumber, Bytes, FilterBuilder, Log, SignedTransaction, TransactionParameters,
    TransactionReceipt, H160, H256, U256,
};
use web3::{Transport, Web3};

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub const CONTRACT_ABI: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;

const TRANSACTION_LITERAL: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Clone, Debug, Eq, Message, PartialEq)]
pub struct BlockchainTransaction {
    pub block_number: u64,
    pub from: Wallet,
    pub wei_amount: u128,
}

impl fmt::Display for BlockchainTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}gw from {} ({})",
            self.wei_amount, self.from, self.block_number
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed(String),
    SignedValueConversion(i128),
    TransactionFailed { msg: String, hash_opt: Option<H256> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockchainTransactionError {
    UnusableWallet(String),
    Signing(String),
    Sending(String, H256),
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Blockchain {:?}.", self)
    }
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;
pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<web3::types::U256>;
pub type ResultForReceipt = BlockchainResult<Option<TransactionReceipt>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievedBlockchainTransactions {
    pub new_start_block: u64,
    pub transactions: Vec<BlockchainTransaction>,
}

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError>;

    fn send_transaction(
        &self,
        inputs: BlockchainTxnInputs,
    ) -> Result<(H256, SystemTime), BlockchainTransactionError>;

    fn get_gas_balance(&self, address: &Wallet) -> ResultForBalance;

    fn get_token_balance(&self, address: &Wallet) -> ResultForBalance;

    fn get_transaction_count(&self, address: &Wallet) -> ResultForNonce;

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt;

    fn send_transaction_tools<'a>(
        &'a self,
        _fingerprint_request_recipient: &'a Recipient<PendingPayableFingerprint>,
    ) -> Box<dyn SendTransactionToolsWrapper + 'a>;
}

// TODO: This probably should go away
pub struct BlockchainInterfaceClandestine {
    logger: Logger,
    chain: Chain,
}

impl BlockchainInterfaceClandestine {
    pub fn new(chain: Chain) -> Self {
        BlockchainInterfaceClandestine {
            logger: Logger::new("BlockchainInterface"),
            chain,
        }
    }
}

impl Default for BlockchainInterfaceClandestine {
    fn default() -> Self {
        Self::new(DEFAULT_CHAIN)
    }
}

impl BlockchainInterface for BlockchainInterfaceClandestine {
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn retrieve_transactions(
        &self,
        _start_block: u64,
        _recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        let msg = "Can't retrieve transactions clandestinely yet".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::QueryFailed(msg))
    }

    fn send_transaction<'a>(
        &self,
        _inputs: BlockchainTxnInputs,
    ) -> Result<(H256, SystemTime), BlockchainTransactionError> {
        let msg = "Can't send transactions clandestinely yet".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainTransactionError::Sending(msg, H256::default()))
    }

    fn get_gas_balance(&self, _address: &Wallet) -> ResultForBalance {
        error!(self.logger, "Can't get eth balance clandestinely yet",);
        Ok(0.into())
    }

    fn get_token_balance(&self, _address: &Wallet) -> ResultForBalance {
        error!(self.logger, "Can't get token balance clandestinely yet",);
        Ok(0.into())
    }

    fn get_transaction_count(&self, _address: &Wallet) -> ResultForNonce {
        error!(self.logger, "Can't get transaction count clandestinely yet",);
        Ok(0.into())
    }

    fn get_transaction_receipt(&self, _hash: H256) -> ResultForReceipt {
        error!(
            self.logger,
            "Can't get transaction receipt clandestinely yet",
        );
        Ok(None)
    }

    //TODO if it turns out that we don't need this method for the clandestine interface, we can create a supplemental trait to be implemented just for the version that needs it
    fn send_transaction_tools<'a>(
        &'a self,
        _fingerprint_request_recipient: &'a Recipient<PendingPayableFingerprint>,
    ) -> Box<dyn SendTransactionToolsWrapper + 'a> {
        error!(
            self.logger,
            "Nonsense, we haven't implemented the clandestine version yet",
        );
        Box::new(SendTransactionToolsWrapperNull)
    }
}

pub struct BlockchainInterfaceNonClandestine<T: Transport + Debug> {
    logger: Logger,
    chain: Chain,
    // This must not be dropped for Web3 requests to be completed
    _event_loop_handle: EventLoopHandle,
    web3: Web3<T>,
    contract: Contract<T>,
}

const GWEI: U256 = U256([1_000_000_000u64, 0, 0, 0]);

pub fn to_wei(gwub: u64) -> U256 {
    let subgwei = U256::from(gwub);
    subgwei.full_mul(GWEI).try_into().expect("Internal Error")
}

impl<T> BlockchainInterface for BlockchainInterfaceNonClandestine<T>
where
    T: Transport + Debug + 'static,
{
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Result<RetrievedBlockchainTransactions, BlockchainError> {
        debug!(
            self.logger,
            "Retrieving transactions from start block: {} for: {} chain_id: {} contract: {:#x}",
            start_block,
            recipient,
            self.chain.rec().num_chain_id,
            self.contract_address()
        );
        let filter = FilterBuilder::default()
            .address(vec![self.contract_address()])
            .from_block(BlockNumber::Number(ethereum_types::U64::from(start_block)))
            .to_block(BlockNumber::Latest)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.address().into()]),
                None,
            )
            .build();

        let log_request = self.web3.eth().logs(filter);
        let logger = self.logger.clone();
        log_request
            .then(|logs| {
                debug!(logger, "Transaction retrieval completed: {:?}", logs);
                future::result::<RetrievedBlockchainTransactions, BlockchainError>(match logs {
                    Ok(logs) => {
                        if logs
                            .iter()
                            .any(|log| log.topics.len() < 2 || log.data.0.len() > 32)
                        {
                            warning!(
                                logger,
                                "Invalid response from blockchain server: {:?}",
                                logs
                            );
                            Err(BlockchainError::InvalidResponse)
                        } else {
                            let transactions: Vec<BlockchainTransaction> = logs
                                .iter()
                                .filter_map(|log: &Log| match log.block_number {
                                    Some(block_number) => {
                                        let amount: U256 = U256::from(log.data.0.as_slice());
                                        let wei_amount_result = u128::try_from(amount);
                                        wei_amount_result.ok().map(|wei_amount| {
                                            BlockchainTransaction {
                                                block_number: u64::try_from(block_number)
                                                    .expect("Internal Error"),
                                                from: Wallet::from(log.topics[1]),
                                                wei_amount,
                                            }
                                        })
                                    }
                                    None => None,
                                })
                                .collect();
                            debug!(logger, "Retrieved transactions: {:?}", transactions);
                            // Get the largest transaction block number, unless there are no
                            // transactions, in which case use start_block.
                            let last_transaction_block =
                                transactions.iter().fold(start_block, |so_far, elem| {
                                    if elem.block_number > so_far {
                                        elem.block_number
                                    } else {
                                        so_far
                                    }
                                });
                            Ok(RetrievedBlockchainTransactions {
                                new_start_block: last_transaction_block + 1,
                                transactions,
                            })
                        }
                    }
                    Err(e) => Err(BlockchainError::QueryFailed(e.to_string())),
                })
            })
            .wait()
    }

    fn send_transaction<'a>(
        &self,
        inputs: BlockchainTxnInputs,
    ) -> Result<(H256, SystemTime), BlockchainTransactionError> {
        self.logger.debug(|| self.preparation_log(&inputs));
        let signed_transaction = self.prepare_signed_transaction(&inputs)?;
        let payable_timestamp = inputs
            .tools
            .request_new_payable_fingerprint(signed_transaction.transaction_hash, inputs.amount);
        self.logger
            .info(|| self.transmission_log(inputs.recipient, inputs.amount));
        match inputs
            .tools
            .send_raw_transaction(signed_transaction.raw_transaction)
        {
            Ok(hash) => Ok((hash, payable_timestamp)),
            Err(e) => Err(BlockchainTransactionError::Sending(
                e.to_string(),
                signed_transaction.transaction_hash,
            )),
        }
    }

    fn get_gas_balance(&self, wallet: &Wallet) -> ResultForBalance {
        self.web3
            .eth()
            .balance(wallet.address(), None)
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn get_token_balance(&self, wallet: &Wallet) -> ResultForBalance {
        self.contract
            .query(
                "balanceOf",
                wallet.address(),
                None,
                Options::default(),
                None,
            )
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> ResultForNonce {
        self.web3
            .eth()
            .transaction_count(wallet.address(), Some(BlockNumber::Pending))
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.web3
            .eth()
            .transaction_receipt(hash)
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn send_transaction_tools<'a>(
        &'a self,
        fingerprint_request_recipient: &'a Recipient<PendingPayableFingerprint>,
    ) -> Box<dyn SendTransactionToolsWrapper + 'a> {
        Box::new(SendTransactionToolWrapperReal::new(
            &self.web3,
            fingerprint_request_recipient,
        ))
    }
}

impl<T> BlockchainInterfaceNonClandestine<T>
where
    T: Transport + Debug + 'static,
{
    pub fn new(transport: T, event_loop_handle: EventLoopHandle, chain: Chain) -> Self {
        let web3 = Web3::new(transport);
        let contract =
            Contract::from_json(web3.eth(), chain.rec().contract, CONTRACT_ABI.as_bytes())
                .expect("Unable to initialize contract.");
        Self {
            logger: Logger::new("BlockchainInterface"),
            chain,
            _event_loop_handle: event_loop_handle,
            web3,
            contract,
        }
    }

    fn prepare_signed_transaction(
        &self,
        inputs: &BlockchainTxnInputs,
    ) -> Result<SignedTransaction, BlockchainTransactionError> {
        let mut data = [0u8; 4 + 32 + 32];
        data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
        data[16..36].copy_from_slice(&inputs.recipient.address().0[..]);
        U256::try_from(inputs.amount)
            .expect("shouldn't overflow")
            .to_big_endian(&mut data[36..68]);
        let base_gas_limit = Self::base_gas_limit(self.chain);
        let gas_limit =
            ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
                acc + if v == &0u8 { 4 } else { 68 }
            }))
            .expect("Internal error");
        let converted_nonce = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(inputs.nonce).expect("Internal error"),
        )
        .expect("Internal error");
        let gas_price = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(to_wei(inputs.gas_price)).expect("Internal error"),
        )
        .expect("Internal error");

        let transaction_parameters = TransactionParameters {
            nonce: Some(converted_nonce),
            to: Some(H160(self.contract_address().0)),
            gas: gas_limit,
            gas_price: Some(gas_price),
            value: ethereum_types::U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(self.chain.rec().num_chain_id),
        };

        let key = match inputs.consuming_wallet.prepare_secp256k1_secret() {
            Ok(secret) => secret,
            Err(e) => return Err(BlockchainTransactionError::UnusableWallet(e.to_string())),
        };

        match inputs.tools.sign_transaction(transaction_parameters, &key) {
            Ok(tx) => Ok(tx),
            Err(e) => Err(BlockchainTransactionError::Signing(e.to_string())),
        }
    }

    fn preparation_log(&self, inputs: &BlockchainTxnInputs) -> String {
        format!("Preparing transaction for {} wei to {} from {} (chain: {}, contract: {:#x}, gas price: {})",
        inputs.amount.separate_with_commas(),
        inputs.recipient,
        inputs.consuming_wallet,
        self.chain.rec().literal_identifier,
        self.contract_address(),
        inputs.gas_price)
    }

    fn transmission_log(&self, recipient: &Wallet, amount: u128) -> String {
        format!(
            "About to send transaction:\n\
        recipient: {},\n\
        amount: {} wei,\n\
        (chain: {}, contract: {:#x})",
            recipient,
            amount.separate_with_commas(),
            self.chain.rec().literal_identifier,
            self.contract_address()
        )
    }

    fn base_gas_limit(chain: Chain) -> u64 {
        match chain.rec().chain_family {
            ChainFamily::Polygon => 70_000,
            ChainFamily::Eth => 55_000,
            ChainFamily::Dev => 55_000,
        }
    }

    #[cfg(test)]
    fn web3(&self) -> &Web3<T> {
        &self.web3
    }
}

#[derive(Debug, Clone)]
pub struct BlockchainTxnInputs<'a> {
    tools: &'a dyn SendTransactionToolsWrapper,
    recipient: &'a Wallet,
    consuming_wallet: &'a Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
}

impl<'a> BlockchainTxnInputs<'a> {
    pub fn new(
        account: &'a PayableAccount,
        consuming_wallet: &'a Wallet,
        nonce: U256,
        gas_price: u64,
        tools: &'a dyn SendTransactionToolsWrapper,
    ) -> Self {
        Self {
            tools,
            recipient: &account.wallet,
            consuming_wallet,
            amount: account.balance_wei,
            nonce,
            gas_price,
        }
    }

    #[cfg(test)]
    pub fn abstract_for_assertions(self) -> (Wallet, Wallet, u128, U256, u64) {
        (
            self.consuming_wallet.clone(),
            self.recipient.clone(),
            self.amount,
            self.nonce,
            self.gas_price,
        )
    }
}

impl BlockchainError {
    pub fn carries_transaction_hash(&self) -> Option<H256> {
        match self {
            Self::TransactionFailed {
                msg: _,
                hash_opt: None,
            } => None,
            Self::TransactionFailed {
                msg: _,
                hash_opt: Some(hash),
            } => Some(*hash),
            _ => None,
        }
    }
}

impl Display for BlockchainTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusableWallet(msg) => write!(f, "UnusableWallet: {}", msg),
            Self::Signing(msg) => write!(f, "Signing: {}", msg),
            Self::Sending(msg, _) => write!(f, "Sending: {}", msg),
        }
    }
}

impl From<BlockchainTransactionError> for BlockchainError {
    fn from(error: BlockchainTransactionError) -> Self {
        match error {
            BlockchainTransactionError::UnusableWallet(_) => BlockchainError::TransactionFailed {
                msg: error.to_string(),
                hash_opt: None,
            },
            BlockchainTransactionError::Signing(_) => BlockchainError::TransactionFailed {
                msg: error.to_string(),
                hash_opt: None,
            },
            BlockchainTransactionError::Sending(_, hash) => BlockchainError::TransactionFailed {
                msg: error.to_string(),
                hash_opt: Some(hash),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::test_utils::{
        make_payable_account, make_payable_account_with_recipient_and_balance_and_timestamp_opt,
    };
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::{
        make_default_signed_transaction, make_fake_event_loop_handle,
        SendTransactionToolsWrapperMock, TestTransport,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::unshared_test_utils::decode_hex;
    use crate::test_utils::{make_wallet, TestRawTransaction};
    use actix::{Actor, System};
    use crossbeam_channel::{unbounded, Receiver};
    use ethereum_types::{BigEndianHash, U64};
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_derive::Deserialize;
    use serde_json::json;
    use serde_json::Value;
    use simple_server::{Request, Server};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::ops::Add;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use web3::transports::Http;
    use web3::types::H2048;
    use web3::Error as Web3Error;

    #[test]
    fn constants_have_correct_values() {
        let contract_abi_expected: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;
        let transaction_literal_expected: H256 = H256 {
            0: [
                0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37,
                0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d,
                0xf5, 0x23, 0xb3, 0xef,
            ],
        };
        assert_eq!(REQUESTS_IN_PARALLEL, 1);
        assert_eq!(CONTRACT_ABI, contract_abi_expected);
        assert_eq!(TRANSACTION_LITERAL, transaction_literal_expected);
        assert_eq!(TRANSFER_METHOD_ID, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(GWEI, U256([1_000_000_000u64, 0, 0, 0]));
    }

    struct TestServer {
        port: u16,
        rx: Receiver<Request<Vec<u8>>>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    impl TestServer {
        fn start(port: u16, bodies: Vec<Vec<u8>>) -> Self {
            std::env::set_var("SIMPLESERVER_THREADS", "1");
            let (tx, rx) = unbounded();
            let _ = thread::spawn(move || {
                let bodies_arc = Arc::new(Mutex::new(bodies));
                Server::new(move |req, mut rsp| {
                    if req.headers().get("X-Quit").is_some() {
                        panic!("Server stop requested");
                    }
                    tx.send(req).unwrap();
                    let body = bodies_arc.lock().unwrap().remove(0);
                    Ok(rsp.body(body)?)
                })
                .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
            });
            let deadline = Instant::now().add(Duration::from_secs(5));
            loop {
                thread::sleep(Duration::from_millis(10));
                match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)) {
                    Ok(_) => break,
                    Err(e) => eprintln!("No: {:?}", e),
                }
                if Instant::now().gt(&deadline) {
                    panic!("TestServer still not started after 5sec");
                }
            }
            TestServer { port, rx }
        }

        fn requests_so_far(&self) -> Vec<Request<Vec<u8>>> {
            let mut requests = vec![];
            while let Ok(request) = self.rx.try_recv() {
                requests.push(request);
            }
            return requests;
        }

        fn stop(&mut self) {
            let mut stream = match TcpStream::connect(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                self.port,
            )) {
                Ok(s) => s,
                Err(_) => return,
            };
            stream
                .write(b"DELETE /irrelevant.htm HTTP/1.1\r\nX-Quit: Yes")
                .unwrap();
        }
    }

    #[test]
    fn blockchain_interface_non_clandestine_handles_no_retrieved_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();
        let test_server = TestServer::start(
            port,
            vec![br#"{"jsonrpc":"2.0","id":3,"result":[]}"#.to_vec()],
        );

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        let requests = test_server.requests_so_far();
        let bodies: Vec<Value> = requests
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body()).unwrap())
            .collect();
        assert_eq!(
            format!("\"0x000000000000000000000000{}\"", &to[2..]),
            bodies[0]["params"][0]["topics"][2].to_string(),
        );
        assert_eq!(
            result,
            RetrievedBlockchainTransactions {
                new_start_block: 42 + 1,
                transactions: vec![]
            }
        )
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieves_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();
        #[rustfmt::skip]
        let test_server = TestServer::start (port, vec![
            br#"{
                "jsonrpc":"2.0",
                "id":3,
                "result":[
                    {
                        "address":"0xcd6c588e005032dd882cd43bf53a32129be81302",
                        "blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a",
                        "blockNumber":"0x4be663",
                        "data":"0x0000000000000000000000000000000000000000000000000010000000000000",
                        "logIndex":"0x0",
                        "removed":false,
                        "topics":[
                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                            "0x0000000000000000000000003ab28ecedea6cdb6feed398e93ae8c7b316b1182",
                            "0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"
                        ],
                        "transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681",
                        "transactionIndex":"0x0"
                    },
                    {
                        "address":"0xcd6c588e005032dd882cd43bf53a32129be81302",
                        "blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732b",
                        "blockNumber":"0x4be662",
                        "data":"0x0000000000000000000000000000000000000000000000000010000000000000",
                        "logIndex":"0x0",
                        "removed":false,
                        "topics":[
                            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                            "0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc",
                            "0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"
                        ],
                        "transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0680",
                        "transactionIndex":"0x0"
                    }
                ]
            }"#.to_vec(),
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        let requests = test_server.requests_so_far();
        let bodies: Vec<Value> = requests
            .into_iter()
            .map(|request| serde_json::from_slice(&request.body()).unwrap())
            .collect();
        assert_eq!(
            format!("\"0x000000000000000000000000{}\"", &to[2..]),
            bodies[0]["params"][0]["topics"][2].to_string(),
        );
        assert_eq!(
            result,
            RetrievedBlockchainTransactions {
                new_start_block: 0x4be663 + 1,
                transactions: vec![
                    BlockchainTransaction {
                        block_number: 0x4be663,
                        from: Wallet::from_str("0x3ab28ecedea6cdb6feed398e93ae8c7b316b1182")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496,
                    },
                    BlockchainTransaction {
                        block_number: 0x4be662,
                        from: Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496,
                    },
                ]
            }
        )
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_retrieve_transactions_returns_an_error_if_the_to_address_is_invalid(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .retrieve_transactions(42, &Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc"));

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidAddress
        );
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieve_transactions_returns_an_error_if_a_response_with_too_few_topics_is_returned(
    ) {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d63100000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec()
        ]);
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidResponse
        );
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieve_transactions_returns_an_error_if_a_response_with_data_that_is_too_long_is_returned(
    ) {
        let port = find_free_port();
        let _test_server = TestServer::start(port, vec![
            br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d6310000001","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec()
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(result, Err(BlockchainError::InvalidResponse));
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieve_transactions_ignores_transaction_logs_that_have_no_block_number(
    ) {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec()
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 43,
                transactions: vec![]
            })
        );
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_retrieve_eth_balance_of_a_wallet() {
        let port = find_free_port();
        let _test_server = TestServer::start(
            port,
            vec![br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFF"}"#.to_vec()],
        );

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .get_gas_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_eth_balance_of_an_invalid_wallet(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result =
            subject.get_gas_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();
        let _test_server = TestServer::start(
            port,
            vec![br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFQ"}"#.to_vec()],
        );

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.get_gas_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_error_for_unintelligible_response_to_gas_balance(
    ) {
        let act = |subject: &BlockchainInterfaceNonClandestine<Http>, wallet: &Wallet| {
            subject.get_gas_balance(wallet)
        };

        assert_error_during_requesting_balance(act, "invalid hex character");
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}"#.to_vec()
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .get_token_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_token_balance_of_an_invalid_wallet(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result =
            subject.get_token_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_error_for_unintelligible_response_to_token_balance(
    ) {
        let act = |subject: &BlockchainInterfaceNonClandestine<Http>, wallet: &Wallet| {
            subject.get_token_balance(wallet)
        };

        assert_error_during_requesting_balance(act, "Invalid hex");
    }

    fn assert_error_during_requesting_balance<F>(act: F, expected_err_msg_fragment: &str)
    where
        F: FnOnce(&BlockchainInterfaceNonClandestine<Http>, &Wallet) -> ResultForBalance,
    {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFQ"}"#.to_vec()
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );

        let result = act(
            &subject,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        let err_msg = match result {
            Err(BlockchainError::QueryFailed(msg)) => msg,
            x => panic!("Expected BlockchainError::QueryFailed, but got {:?}", x),
        };
        assert!(
            err_msg.contains(expected_err_msg_fragment),
            "Expected this fragment {} in this err msg: {}",
            expected_err_msg_fragment,
            err_msg
        )
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_transfer_tokens() {
        init_test_logging();
        let mut transport = TestTransport::default();
        transport.add_response(json!(
            "0xe26f2f487f5dd06c38860d410cdcede0d6e860dab2c971c7d518928c17034c8f"
        ));
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let actor_addr = accountant.start();
        let recipient_of_pending_payable_fingerprint =
            recipient!(actor_addr, PendingPayableFingerprint);
        let subject = BlockchainInterfaceNonClandestine::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            TEST_DEFAULT_CHAIN,
        );
        let amount = 9_000_000_000_000;
        let gas_price = 120;
        let account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            amount,
            None,
        );
        let consuming_wallet = make_paying_wallet(b"gdasgsa");
        let tools = subject.send_transaction_tools(&recipient_of_pending_payable_fingerprint);
        let inputs = BlockchainTxnInputs::new(
            &account,
            &consuming_wallet,
            U256::from(1),
            gas_price,
            tools.as_ref(),
        );
        let test_timestamp_before = SystemTime::now();

        let result = subject.send_transaction(inputs).unwrap();

        let test_timestamp_after = SystemTime::now();
        let system = System::new("can transfer tokens test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        transport.assert_request("eth_sendRawTransaction", &[String::from(r#""0xf8a901851bf08eb00082dbe894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb00000000000000000000000000000000000000000000000000626c61683132330000000000000000000000000000000000000000000000000000082f79cd900029a0d4ecb2865f6a0370689be2e956cc272f7718cb360160f5a51756264ba1cc23fca005a3920e27680135e032bb23f4026a2e91c680866047cf9bbadee23ab8ab5ca2""#)]);
        transport.assert_no_more_requests();
        let (hash, timestamp) = result;
        assert_eq!(
            hash,
            H256::from_str("e26f2f487f5dd06c38860d410cdcede0d6e860dab2c971c7d518928c17034c8f")
                .unwrap()
        );
        assert!(test_timestamp_before <= timestamp && timestamp <= test_timestamp_after);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let sent_backup = accountant_recording.get_record::<PendingPayableFingerprint>(0);
        let expected_pending_payable_fingerprint = PendingPayableFingerprint {
            rowid_opt: None,
            timestamp,
            hash,
            attempt_opt: None,
            amount,
            process_error: None,
        };
        assert_eq!(sent_backup, &expected_pending_payable_fingerprint);
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: BlockchainInterface: Preparing transaction for 9,000,000,000,000 wei to 0x00000000000000000000000000626c6168313233 from 0x5c361ba8d82fcf0e5538b2a823e9d457a2296725 (chain: eth-ropsten, contract: 0x384dec25e03f94931767ce4c3556168468ba24c3, gas price: 120)" );
        log_handler.exists_log_containing(
            "INFO: BlockchainInterface: About to send transaction:\n\
        recipient: 0x00000000000000000000000000626c6168313233,\n\
        amount: 9,000,000,000,000 wei,\n\
        (chain: eth-ropsten, contract: 0x384dec25e03f94931767ce4c3556168468ba24c3)",
        );
    }

    #[test]
    fn non_clandestine_interface_components_of_send_transactions_work_together_properly() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::EthMainnet,
        );
        let sign_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let request_new_pending_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let send_raw_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let payable_timestamp = SystemTime::now();
        let transaction_parameters_expected = TransactionParameters {
            nonce: Some(U256::from(5)),
            to: Some(subject.contract_address()),
            gas: U256::from(56296),
            gas_price: Some(U256::from(123000000000_u64)),
            value: Default::default(),
            data: Bytes(vec![
                169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 98, 108, 97, 104, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 45, 121, 136, 61, 32, 0,
            ]),
            chain_id: Some(1),
        };
        let consuming_wallet_secret_raw_bytes = b"my-wallet+++++++++++++++++++++++";
        let secret = (&Bip32ECKeyProvider::from_raw_secret(consuming_wallet_secret_raw_bytes)
            .unwrap())
            .into();
        let signed_transaction = subject
            .web3
            .accounts()
            .sign_transaction(transaction_parameters_expected.clone(), &secret)
            .wait()
            .unwrap();
        let hash = signed_transaction.transaction_hash;
        let nonce = U256::from(5);
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_params(&sign_transaction_params_arc)
            .sign_transaction_result(Ok(signed_transaction.clone()))
            .request_new_pending_payable_fingerprint_params(
                &request_new_pending_payable_fingerprint_params_arc,
            )
            .request_new_pending_payable_fingerprint_result(payable_timestamp)
            .send_raw_transaction_params(&send_raw_transaction_params_arc)
            .send_raw_transaction_result(Ok(hash));
        let amount_of_wei = 50_000_000_000_000;
        let account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            amount_of_wei,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let inputs = BlockchainTxnInputs::new(
            &account,
            &consuming_wallet,
            nonce,
            123,
            send_transaction_tools,
        );

        let result = subject.send_transaction(inputs);

        assert_eq!(result, Ok((hash, payable_timestamp)));
        let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        let (transaction_params, secret) = sign_transaction_params.remove(0);
        assert!(sign_transaction_params.is_empty());
        assert_eq!(transaction_params, transaction_parameters_expected);
        assert_eq!(
            secret,
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret_raw_bytes.keccak256())
                .unwrap())
                .into()
        );
        let request_new_pending_payable_fingerprint_params =
            request_new_pending_payable_fingerprint_params_arc
                .lock()
                .unwrap();
        assert_eq!(
            *request_new_pending_payable_fingerprint_params,
            vec![(hash, amount_of_wei)]
        );
        let send_raw_transaction = send_raw_transaction_params_arc.lock().unwrap();
        assert_eq!(
            *send_raw_transaction,
            vec![signed_transaction.raw_transaction]
        )
    }

    #[test]
    fn non_clandestine_base_gas_limit_is_properly_set() {
        assert_eq!(
            BlockchainInterfaceNonClandestine::<Http>::base_gas_limit(Chain::PolyMainnet),
            70_000
        );
        assert_eq!(
            BlockchainInterfaceNonClandestine::<Http>::base_gas_limit(Chain::PolyMumbai),
            70_000
        );
        assert_eq!(
            BlockchainInterfaceNonClandestine::<Http>::base_gas_limit(Chain::EthMainnet),
            55_000
        );
        assert_eq!(
            BlockchainInterfaceNonClandestine::<Http>::base_gas_limit(Chain::EthRopsten),
            55_000
        );
        assert_eq!(
            BlockchainInterfaceNonClandestine::<Http>::base_gas_limit(Chain::Dev),
            55_000
        );
    }

    #[test]
    fn non_clandestine_gas_limit_for_polygon_mainnet_starts_on_70000_as_the_base() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::PolyMainnet,
        );

        assert_gas_limit_is_between(subject, 70000, u64::MAX)
    }

    #[test]
    fn non_clandestine_gas_limit_for_dev_lies_within_limits() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::Dev,
        );

        assert_gas_limit_is_between(subject, 55000, 65000)
    }

    #[test]
    fn non_clandestine_gas_limit_for_eth_mainnet_lies_within_limits() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::EthMainnet,
        );

        assert_gas_limit_is_between(subject, 55000, 65000)
    }

    fn assert_gas_limit_is_between<T: Transport + Debug + 'static>(
        subject: BlockchainInterfaceNonClandestine<T>,
        not_under_this_value: u64,
        not_above_this_value: u64,
    ) {
        let sign_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let consuming_wallet_secret_raw_bytes = b"my-wallet";
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_params(&sign_transaction_params_arc)
            //I don't want to set up all the mocks - I want see just the params coming in
            .sign_transaction_result(Err(Web3Error::Internal));
        let payable_account = make_payable_account(1);
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let inputs = BlockchainTxnInputs::new(
            &payable_account,
            &consuming_wallet,
            U256::from(5),
            123,
            send_transaction_tools,
        );

        let _ = subject.send_transaction(inputs);

        let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        let (transaction_params, secret) = sign_transaction_params.remove(0);
        assert!(sign_transaction_params.is_empty());
        assert!(transaction_params.gas >= U256::from(not_under_this_value));
        assert!(transaction_params.gas <= U256::from(not_above_this_value));
        assert_eq!(
            secret,
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret_raw_bytes.keccak256())
                .unwrap())
                .into()
        );
    }

    #[test]
    fn send_transaction_fails_on_badly_prepared_consuming_wallet_without_secret() {
        let transport = TestTransport::default();
        let address_only_wallet =
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            TEST_DEFAULT_CHAIN,
        );
        let system = System::new("test");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let account_addr = accountant.start();
        let recipient = recipient!(account_addr, PendingPayableFingerprint);
        let account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let tools = subject.send_transaction_tools(&recipient);
        let inputs = BlockchainTxnInputs::new(
            &account,
            &address_only_wallet,
            U256::from(1),
            123,
            tools.as_ref(),
        );

        let result = subject.send_transaction(inputs);

        System::current().stop();
        system.run();
        assert_eq!(result,
                   Err(BlockchainTransactionError::UnusableWallet(
                       "Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()
                   ))
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0)
    }

    #[test]
    fn send_transaction_fails_on_signing_transaction() {
        let transport = TestTransport::default();
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_result(Err(Web3Error::Signing(
                secp256k1secrets::Error::InvalidSecretKey,
            )));
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::PolyMumbai,
        );
        let account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let inputs = BlockchainTxnInputs::new(
            &account,
            &consuming_wallet,
            U256::from(1),
            123,
            send_transaction_tools,
        );

        let result = subject.send_transaction(inputs);

        assert_eq!(
            result,
            Err(BlockchainTransactionError::Signing(
                "Signing error: secp: malformed or out-of-range secret key".to_string()
            ))
        );
    }

    #[test]
    fn send_transaction_fails_on_sending_raw_transaction() {
        let transport = TestTransport::default();
        let signed_transaction = make_default_signed_transaction();
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_result(Ok(signed_transaction))
            .request_new_pending_payable_fingerprint_result(SystemTime::now())
            .send_raw_transaction_result(Err(Web3Error::Transport(
                "Transaction crashed".to_string(),
            )));
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::PolyMumbai,
        );
        let account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            5000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let inputs = BlockchainTxnInputs::new(
            &account,
            &consuming_wallet,
            U256::from(1),
            123,
            send_transaction_tools,
        );

        let result = subject.send_transaction(inputs);

        assert_eq!(
            result,
            Err(BlockchainTransactionError::Sending(
                "Transport error: Transaction crashed".to_string(),
                H256::default()
            ))
        );
    }

    fn test_consuming_wallet_with_secret() -> Wallet {
        let key_pair = Bip32ECKeyProvider::from_raw_secret(
            &decode_hex("97923d8fd8de4a00f912bfb77ef483141dec551bd73ea59343ef5c4aac965d04")
                .unwrap(),
        )
        .unwrap();
        Wallet::from(key_pair)
    }

    fn test_recipient_wallet() -> Wallet {
        let hex_part = &"0x7788df76BBd9a0C7c3e5bf0f77bb28C60a167a7b"[2..];
        let recipient_address_bytes = decode_hex(hex_part).unwrap();
        let address = Address::from_slice(&recipient_address_bytes);
        Wallet::from(address)
    }

    const TEST_PAYMENT_AMOUNT: u128 = 1_000_000_000_000;
    const TEST_GAS_PRICE_ETH: u64 = 110;
    const TEST_GAS_PRICE_POLYGON: u64 = 50;

    fn assert_that_signed_transactions_agrees_with_template(
        chain: Chain,
        nonce: u64,
        template: &[u8],
    ) {
        let recipient = {
            let (accountant, _, _) = make_recorder();
            let account_addr = accountant.start();
            recipient!(account_addr, PendingPayableFingerprint)
        };
        let transport = TestTransport::default();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let send_transaction_tools = subject.send_transaction_tools(&recipient);
        let consuming_wallet = test_consuming_wallet_with_secret();
        let recipient_wallet = test_recipient_wallet();
        let nonce_correct_type = U256::from(nonce);
        let gas_price = match chain.rec().chain_family {
            ChainFamily::Eth => TEST_GAS_PRICE_ETH,
            ChainFamily::Polygon => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };
        let payable_account = make_payable_account_with_recipient_and_balance_and_timestamp_opt(
            recipient_wallet,
            TEST_PAYMENT_AMOUNT,
            None,
        );
        let inputs = BlockchainTxnInputs::new(
            &payable_account,
            &consuming_wallet,
            nonce_correct_type,
            gas_price,
            send_transaction_tools.as_ref(),
        );

        let signed_transaction = subject.prepare_signed_transaction(&inputs).unwrap();

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(&byte_set_to_compare, template)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn non_clandestine_signing_a_transaction_works_for_polygon_mumbai() {
        let chain = Chain::PolyMumbai;
        let nonce = 5;
        // signed_transaction_data changed after we changed the contract address of polygon matic
        let signed_transaction_data = "f8ad05850ba43b740083011980949b27034acabd44223fb23d628ba4849867ce1db280b844a9059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000000e8d4a5100083027126a09fdbbd7064d3b7240f5422b2164aaa13d62f0946a683d82ee26f97f242570d90a077b49dbb408c20d73e0666ba0a77ac888bf7a9cb14824a5f35c97217b9bc0a5a";

        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn non_clandestine_signing_a_transaction_works_for_eth_ropsten() {
        let chain = Chain::EthRopsten;
        let nonce = 1; //must stay like this!
        let signed_transaction_data = "f8a90185199c82cc0082dee894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000000e8d4a510002aa0635fbb3652e1c3063afac6ffdf47220e0431825015aef7daff9251694e449bfca00b2ed6d556bd030ac75291bf58817da15a891cd027a4c261bb80b51f33b78adf";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //not confirmed on the real network
    #[test]
    fn non_clandestine_signing_a_transaction_for_polygon_mainnet() {
        let chain = Chain::PolyMainnet;
        let nonce = 10;
        //generated locally
        let signed_transaction_data = [
            248, 172, 10, 133, 11, 164, 59, 116, 0, 131, 1, 25, 128, 148, 238, 154, 53, 47, 106,
            172, 74, 241, 165, 185, 244, 103, 246, 169, 62, 15, 251, 233, 221, 53, 128, 184, 68,
            169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 136, 223, 118, 187, 217,
            160, 199, 195, 229, 191, 15, 119, 187, 40, 198, 10, 22, 122, 123, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 212, 165, 16, 0, 130,
            1, 53, 160, 7, 203, 40, 44, 202, 233, 15, 5, 64, 218, 199, 239, 94, 126, 152, 2, 108,
            30, 157, 75, 124, 129, 117, 27, 109, 163, 132, 27, 11, 123, 137, 10, 160, 18, 170, 130,
            198, 73, 190, 158, 235, 0, 77, 118, 213, 244, 229, 225, 143, 156, 214, 219, 204, 193,
            155, 199, 164, 162, 31, 134, 51, 139, 130, 152, 104,
        ];

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &signed_transaction_data)
    }

    //not confirmed on the real network
    #[test]
    fn non_clandestine_signing_a_transaction_for_eth_mainnet() {
        let chain = Chain::EthMainnet;
        let nonce = 10;
        //generated locally
        let signed_transaction_data = [
            248, 169, 10, 133, 25, 156, 130, 204, 0, 130, 222, 232, 148, 6, 243, 195, 35, 240, 35,
            140, 114, 191, 53, 1, 16, 113, 242, 181, 183, 244, 58, 5, 76, 128, 184, 68, 169, 5,
            156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 119, 136, 223, 118, 187, 217, 160, 199,
            195, 229, 191, 15, 119, 187, 40, 198, 10, 22, 122, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 212, 165, 16, 0, 38, 160, 199,
            155, 76, 106, 39, 227, 3, 151, 90, 117, 245, 211, 86, 98, 187, 117, 120, 103, 165, 131,
            99, 72, 36, 211, 10, 224, 252, 104, 51, 200, 230, 158, 160, 84, 18, 140, 248, 119, 22,
            193, 14, 148, 253, 48, 59, 185, 11, 38, 152, 103, 150, 120, 60, 74, 56, 159, 206, 22,
            15, 73, 173, 153, 11, 76, 74,
        ];

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &signed_transaction_data)
    }

    //an adapted test from old times when we had our own signing method
    //I don't have data for the new chains so I omit them in this kind of tests
    #[test]
    fn signs_various_transaction_for_eth_mainnet() {
        let signatures = &[
            &[
                248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167,
                100, 0, 0, 128, 37, 160, 40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117,
                103, 134, 96, 3, 225, 161, 93, 60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118,
                160, 103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245,
                85, 201, 243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128, 37, 160, 9, 235, 182, 202, 5, 122, 5, 53, 214, 24, 100, 98,
                188, 11, 70, 91, 86, 28, 148, 162, 149, 189, 176, 98, 31, 193, 146, 8, 171, 20,
                154, 156, 160, 68, 15, 253, 119, 92, 233, 26, 131, 58, 180, 16, 119, 114, 4, 213,
                52, 26, 111, 159, 169, 18, 22, 166, 243, 238, 44, 5, 31, 234, 106, 4, 40,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87, 38, 160, 122, 155, 12, 58, 133, 108, 183, 145, 181,
                210, 141, 44, 236, 17, 96, 40, 55, 87, 204, 250, 142, 83, 122, 168, 250, 5, 113,
                172, 203, 5, 12, 181, 160, 9, 100, 95, 141, 167, 178, 53, 101, 115, 131, 83, 172,
                199, 242, 208, 96, 246, 121, 25, 18, 211, 89, 60, 94, 165, 169, 71, 3, 176, 157,
                167, 50,
            ][..],
        ];
        assert_signature(Chain::EthMainnet, signatures)
    }

    //an adapted test from old times when we had our own signing method
    //I don't have data for the new chains so I omit them in this kind of tests
    #[test]
    fn signs_various_transactions_for_ropsten() {
        let signatures = &[
            &[
                248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167,
                100, 0, 0, 128, 41, 160, 8, 220, 80, 201, 100, 41, 178, 35, 151, 227, 210, 85, 27,
                41, 27, 82, 217, 176, 64, 92, 205, 10, 195, 169, 66, 91, 213, 199, 124, 52, 3, 192,
                160, 94, 220, 102, 179, 128, 78, 150, 78, 230, 117, 10, 10, 32, 108, 241, 50, 19,
                148, 198, 6, 147, 110, 175, 70, 157, 72, 31, 216, 193, 229, 151, 115,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128, 41, 160, 186, 65, 161, 205, 173, 93, 185, 43, 220, 161, 63,
                65, 19, 229, 65, 186, 247, 197, 132, 141, 184, 196, 6, 117, 225, 181, 8, 81, 198,
                102, 150, 198, 160, 112, 126, 42, 201, 234, 236, 168, 183, 30, 214, 145, 115, 201,
                45, 191, 46, 3, 113, 53, 80, 203, 164, 210, 112, 42, 182, 136, 223, 125, 232, 21,
                205,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87, 41, 160, 146, 204, 57, 32, 218, 236, 59, 94, 106, 72,
                174, 211, 223, 160, 122, 186, 126, 44, 200, 41, 222, 117, 117, 177, 189, 78, 203,
                8, 172, 155, 219, 66, 160, 83, 82, 37, 6, 243, 61, 188, 102, 176, 132, 102, 74,
                111, 180, 105, 33, 122, 106, 109, 73, 180, 65, 10, 117, 175, 190, 19, 196, 17, 128,
                193, 75,
            ][..],
        ];
        assert_signature(Chain::EthRopsten, signatures)
    }

    #[derive(Deserialize)]
    struct Signing {
        signed: Vec<u8>,
        private_key: H256,
    }

    fn assert_signature(chain: Chain, slice_of_sclices: &[&[u8]]) {
        let first_part_tx_1 = r#"[{"nonce": "0x9", "gasPrice": "0x4a817c800", "gasLimit": "0x5208", "to": "0x3535353535353535353535353535353535353535", "value": "0xde0b6b3a7640000", "data": []}, {"private_key": "0x4646464646464646464646464646464646464646464646464646464646464646", "signed": "#;
        let first_part_tx_2 = r#"[{"nonce": "0x0", "gasPrice": "0xd55698372431", "gasLimit": "0x1e8480", "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": "0x3b9aca00", "data": []}, {"private_key": "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "signed": "#;
        let first_part_tx_3 = r#"[{"nonce": "0x00", "gasPrice": "0x09184e72a000", "gasLimit": "0x2710", "to": null, "value": "0x00", "data": [127,116,101,115,116,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,87]}, {"private_key": "0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109", "signed": "#;
        fn compose(first_part: &str, slice: &[u8]) -> String {
            let third_part_jrc = "}]";
            format!("{}{:?}{}", first_part, slice, third_part_jrc)
        }
        let all_transactions = format!(
            "[{}]",
            vec![first_part_tx_1, first_part_tx_2, first_part_tx_3]
                .iter()
                .zip(slice_of_sclices.iter())
                .zip(0usize..2)
                .fold(String::new(), |so_far, actual| [
                    so_far,
                    compose(actual.0 .0, actual.0 .1)
                ]
                .join(if actual.1 == 0 { "" } else { ", " }))
        );
        let txs: Vec<(TestRawTransaction, Signing)> =
            serde_json::from_str(&all_transactions).unwrap();
        let constant_parts = &[
            &[
                248u8, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53,
                53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179,
                167, 100, 0, 0, 128,
            ][..],
            &[
                248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159,
                200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132,
                59, 154, 202, 0, 128,
            ][..],
            &[
                248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116,
                101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 96, 0, 87,
            ][..],
        ];
        let transport = TestTransport::default();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let lengths_of_constant_parts: Vec<usize> =
            constant_parts.iter().map(|part| part.len()).collect();
        for (((tx, signed), length), constant_part) in txs
            .iter()
            .zip(lengths_of_constant_parts)
            .zip(constant_parts)
        {
            let secret = Wallet::from(
                Bip32ECKeyProvider::from_raw_secret(&signed.private_key.0.as_ref()).unwrap(),
            )
            .prepare_secp256k1_secret()
            .unwrap();
            let tx_params = convert_from_raw_transaction_to_transaction_parameters(tx, chain);
            let sign = subject
                .web3()
                .accounts()
                .sign_transaction(tx_params, &secret)
                .wait()
                .unwrap();
            let signed_data_bytes = sign.raw_transaction.0;
            assert_eq!(signed_data_bytes, signed.signed);
            assert_eq!(signed_data_bytes[..length], **constant_part)
        }
    }

    fn convert_from_raw_transaction_to_transaction_parameters(
        raw_transaction: &TestRawTransaction,
        chain: Chain,
    ) -> TransactionParameters {
        TransactionParameters {
            nonce: Some(raw_transaction.nonce),
            to: raw_transaction.to,
            gas: raw_transaction.gas_limit,
            gas_price: Some(raw_transaction.gas_price),
            value: raw_transaction.value,
            data: Bytes(raw_transaction.data.clone()),
            chain_id: Some(chain.rec().num_chain_id),
        }
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_fetch_nonce() {
        let mut transport = TestTransport::default();
        transport.add_response(json!(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let subject = BlockchainInterfaceNonClandestine::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.get_transaction_count(&make_paying_wallet(b"gdasgsa"));

        transport.assert_request(
            "eth_getTransactionCount",
            &[
                String::from(r#""0x5c361ba8d82fcf0e5538b2a823e9d457a2296725""#),
                String::from(r#""pending""#),
            ],
        );
        transport.assert_no_more_requests();
        assert_eq!(result, Ok(U256::from(1)));
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_fetch_transaction_receipt() {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":2,"result":{"transactionHash":"0xa128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e","blockHash":"0x6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18","blockNumber":"0xb0328d","contractAddress":null,"cumulativeGasUsed":"0x60ef","effectiveGasPrice":"0x22ecb25c00","from":"0x7424d05b59647119b01ff81e2d3987b6c358bf9c","gasUsed":"0x60ef","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000","status":"0x0","to":"0x384dec25e03f94931767ce4c3556168468ba24c3","transactionIndex":"0x0","type":"0x0"}}"#
                .to_vec()
        ]);
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );
        let tx_hash =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();

        let result = subject.get_transaction_receipt(tx_hash);

        let expected_receipt = TransactionReceipt{
            transaction_hash: tx_hash,
            transaction_index: Default::default(),
            block_hash: Some(H256::from_str("6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18").unwrap()),
            block_number:Some(U64::from_str("b0328d").unwrap()),
            cumulative_gas_used: U256::from_str("60ef").unwrap(),
            gas_used: Some(U256::from_str("60ef").unwrap()),
            contract_address: None,
            logs: vec![],
            status: Some(U64::from(0)),
            root: None,
            logs_bloom: H2048::from_str("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000").unwrap()
        };
        assert_eq!(result, Ok(Some(expected_receipt)));
    }

    #[test]
    fn get_transaction_receipt_handles_errors() {
        let port = find_free_port();
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            event_loop_handle,
            TEST_DEFAULT_CHAIN,
        );
        let tx_hash = H256::from_uint(&U256::from(4564546));

        let result = subject.get_transaction_receipt(tx_hash);

        match result {
            Err(BlockchainError::QueryFailed(err_message)) => assert!(
                err_message.contains("Transport error: Error(Connect, Os"),
                "we got this error msg: {}",
                err_message
            ),
            Err(e) => panic!("we expected a different error than: {}", e),
            Ok(x) => panic!("we expected an error, but got: {:?}", x),
        };
    }

    #[test]
    fn to_wei_converts_units_properly_for_max_value() {
        let converted_wei = to_wei(u64::MAX);

        assert_eq!(
            converted_wei,
            U256::from_dec_str(format!("{}000000000", u64::MAX).as_str()).unwrap()
        );
    }

    #[test]
    fn to_wei_converts_units_properly_for_one() {
        let converted_wei = to_wei(1);

        assert_eq!(converted_wei, U256::from_dec_str("1000000000").unwrap());
    }

    #[test]
    fn constant_gwei_matches_calculated_value() {
        let value = U256::from(1_000_000_000);
        assert_eq!(value.0[0], 1_000_000_000);
        assert_eq!(value.0[1], 0);
        assert_eq!(value.0[2], 0);
        assert_eq!(value.0[3], 0);

        let gwei = U256([1_000_000_000u64, 0, 0, 0]);
        assert_eq!(value, gwei);
        assert_eq!(gwei, GWEI);
        assert_eq!(value, GWEI);
    }

    #[test]
    fn hash_the_smartcontract_transfer_function_signature() {
        assert_eq!(
            TRANSFER_METHOD_ID,
            "transfer(address,uint256)".keccak256()[0..4]
        );
    }

    #[test]
    fn conversion_between_errors_work() {
        let hash = H256::from_uint(&U256::from(4555));
        let original_errors = [
            BlockchainTransactionError::UnusableWallet("wallet error".to_string()),
            BlockchainTransactionError::Signing("signature error".to_string()),
            BlockchainTransactionError::Sending("sending error".to_string(), hash),
        ];

        let check: Vec<_> = original_errors
            .clone()
            .into_iter()
            .zip(original_errors.into_iter())
            .map(|(to_resolve, to_assert)| match to_resolve {
                BlockchainTransactionError::UnusableWallet(..) => {
                    assert_eq!(
                        BlockchainError::from(to_assert),
                        BlockchainError::TransactionFailed {
                            msg: "UnusableWallet: wallet error".to_string(),
                            hash_opt: None
                        }
                    );
                    11
                }
                BlockchainTransactionError::Signing(..) => {
                    assert_eq!(
                        BlockchainError::from(to_assert),
                        BlockchainError::TransactionFailed {
                            msg: "Signing: signature error".to_string(),
                            hash_opt: None
                        }
                    );
                    22
                }
                BlockchainTransactionError::Sending(..) => {
                    assert_eq!(
                        BlockchainError::from(to_assert),
                        BlockchainError::TransactionFailed {
                            msg: "Sending: sending error".to_string(),
                            hash_opt: Some(hash)
                        }
                    );
                    33
                }
            })
            .collect();

        assert_eq!(check, vec![11, 22, 33])
    }

    #[test]
    fn carries_transaction_hash_works() {
        let hash = H256::from_uint(&U256::from(999));
        let original_errors = [
            BlockchainError::InvalidUrl,
            BlockchainError::InvalidAddress,
            BlockchainError::InvalidResponse,
            BlockchainError::QueryFailed("blah".to_string()),
            BlockchainError::SignedValueConversion(33333333333333),
            BlockchainError::TransactionFailed {
                msg: "Voila".to_string(),
                hash_opt: None,
            },
            BlockchainError::TransactionFailed {
                msg: "Hola".to_string(),
                hash_opt: Some(hash),
            },
        ];

        let check: Vec<_> = original_errors
            .clone()
            .into_iter()
            .zip(original_errors.into_iter())
            .map(|(to_resolve, to_assert)| match to_resolve {
                BlockchainError::InvalidUrl => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    11
                }
                BlockchainError::InvalidAddress => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    22
                }
                BlockchainError::InvalidResponse => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    33
                }
                BlockchainError::QueryFailed(..) => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    44
                }
                BlockchainError::SignedValueConversion(..) => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    55
                }
                BlockchainError::TransactionFailed { hash_opt: None, .. } => {
                    assert_eq!(to_assert.carries_transaction_hash(), None);
                    66
                }
                BlockchainError::TransactionFailed {
                    hash_opt: Some(_), ..
                } => {
                    assert_eq!(to_assert.carries_transaction_hash(), Some(hash));
                    77
                }
            })
            .collect();

        assert_eq!(check, vec![11, 22, 33, 44, 55, 66, 77])
    }
}
