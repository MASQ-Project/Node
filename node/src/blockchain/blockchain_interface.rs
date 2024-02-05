// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::comma_joined_stringifiable;
use crate::accountant::db_access_objects::payable_dao::PendingPayable;
use crate::blockchain::blockchain_interface;
use crate::blockchain::blockchain_interface::BlockchainError::{
    InvalidAddress, InvalidResponse, InvalidUrl, QueryFailed, UninitializedBlockchainInterface,
};
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use futures::future::err;
use futures::{future, Future};
use indoc::indoc;
use itertools::Either::{Left, Right};
use masq_lib::blockchains::chains::{Chain, ChainFamily};
use masq_lib::logger::Logger;
use std::convert::{From, TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use variant_count::VariantCount;
use web3::contract::{Contract, Options};
use web3::transports::{Batch, EventLoopHandle, Http};
use web3::types::{
    Address, BlockNumber, Bytes, FilterBuilder, Log, TransactionParameters, TransactionReceipt,
    H160, H256, U256,
};
use web3::{BatchTransport, Error as Web3Error, Web3};

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub const CONTRACT_ABI: &str = indoc!(
    r#"[{
    "constant":true,
    "inputs":[{"name":"owner","type":"address"}],
    "name":"balanceOf",
    "outputs":[{"name":"","type":"uint256"}],
    "payable":false,
    "stateMutability":"view",
    "type":"function"
    },{
    "constant":false,
    "inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],
    "name":"transfer",
    "outputs":[{"name":"","type":"bool"}],
    "payable":false,
    "stateMutability":"nonpayable",
    "type":"function"
    }]"#
);

pub const TRANSACTION_LITERAL: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

pub const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub const BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED: &str =
    "To avoid being delinquency-banned, you should \
restart the Node with a value for blockchain-service-url";

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

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed(String),
    UninitializedBlockchainInterface,
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let description = match self {
            InvalidUrl => Left("Invalid url"),
            InvalidAddress => Left("Invalid address"),
            InvalidResponse => Left("Invalid response"),
            QueryFailed(msg) => Right(format!("Query failed: {}", msg)),
            UninitializedBlockchainInterface => Left(BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED),
        };
        write!(f, "Blockchain error: {}", description)
    }
}

impl BlockchainInterfaceUninitializedError for BlockchainError {
    fn error() -> Self {
        Self::UninitializedBlockchainInterface
    }
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;
pub type ResultForBalance = BlockchainResult<web3::types::U256>;
pub type ResultForBothBalances = BlockchainResult<(web3::types::U256, web3::types::U256)>;
pub type ResultForNonce = BlockchainResult<web3::types::U256>;
pub type ResultForReceipt = BlockchainResult<Option<TransactionReceipt>>;

#[derive(Clone, Debug, PartialEq, Eq, VariantCount)]
pub enum PayableTransactionError {
    MissingConsumingWallet,
    GasPriceQueryFailed(String),
    TransactionCount(BlockchainError),
    UnusableWallet(String),
    Signing(String),
    Sending { msg: String, hashes: Vec<H256> },
    UninitializedBlockchainInterface,
}

impl Display for PayableTransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::MissingConsumingWallet => Left("Missing consuming wallet to pay payable from"),
            Self::GasPriceQueryFailed(msg) => {
                Right(format!("Unsuccessful gas price query: \"{}\"", msg))
            }
            Self::TransactionCount(blockchain_err) => Right(format!(
                "Transaction count fetching failed for: {}",
                blockchain_err
            )),
            Self::UnusableWallet(msg) => Right(format!(
                "Unusable wallet for signing payable transactions: \"{}\"",
                msg
            )),
            Self::Signing(msg) => Right(format!("Signing phase: \"{}\"", msg)),
            Self::Sending { msg, hashes } => Right(format!(
                "Sending phase: \"{}\". Signed and hashed transactions: {}",
                msg,
                comma_joined_stringifiable(hashes, |hash| format!("{:?}", hash))
            )),
            Self::UninitializedBlockchainInterface => Left(BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED),
        };
        write!(f, "{}", description)
    }
}

impl BlockchainInterfaceUninitializedError for PayableTransactionError {
    fn error() -> Self {
        Self::UninitializedBlockchainInterface
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetrievedBlockchainTransactions {
    pub new_start_block: u64,
    pub transactions: Vec<BlockchainTransaction>,
}

pub trait BlockchainInterface<T: BatchTransport = Http> {
    fn contract_address(&self) -> Address;

    fn get_chain(&self) -> Chain;

    fn get_batch_web3(&self) -> Web3<Batch<T>>;

    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>>;

    fn get_transaction_fee_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_token_balance(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_transaction_count(
        &self,
        address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>>;

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt;
}

pub struct BlockchainInterfaceNull {
    logger: Logger,
}

impl Default for BlockchainInterfaceNull {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockchainInterface<Http> for BlockchainInterfaceNull {
    fn contract_address(&self) -> Address {
        self.log_uninitialized_for_operation("get contract address");
        H160::zero()
    }

    fn get_chain(&self) -> Chain {
        todo!("FIX ME GH-744")
    }

    fn get_batch_web3(&self) -> Web3<Batch<Http>> {
        // self.
        todo!("FIX ME GH-744")
    }

    fn retrieve_transactions(
        &self,
        _start_block: u64,
        _recipient: &Wallet,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        Box::new(err(self
            .handle_uninitialized_interface::<RetrievedBlockchainTransactions, blockchain_interface::BlockchainError>(
                "retrieve transactions",
            )
            .unwrap_err()))
    }

    fn get_transaction_fee_balance(
        &self,
        _address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(err(self
            .handle_uninitialized_interface::<U256, _>("get transaction fee balance")
            .unwrap_err()))
    }

    fn get_token_balance(
        &self,
        _address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(err(self
            .handle_uninitialized_interface::<U256, _>("get token balance")
            .unwrap_err()))
    }

    fn get_transaction_count(
        &self,
        _address: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(err(self
            .handle_uninitialized_interface::<BlockchainError, _>("get transaction count")
            .unwrap_err()))
    }

    fn get_transaction_receipt(&self, _hash: H256) -> ResultForReceipt {
        self.handle_uninitialized_interface("get transaction receipt")
    }
}

trait BlockchainInterfaceUninitializedError {
    fn error() -> Self;
}

impl BlockchainInterfaceNull {
    pub fn new() -> Self {
        BlockchainInterfaceNull {
            logger: Logger::new("BlockchainInterfaceNull"),
        }
    }

    fn handle_uninitialized_interface<Irrelevant, E>(
        &self,
        operation: &str,
    ) -> Result<Irrelevant, E>
    where
        E: BlockchainInterfaceUninitializedError,
    {
        self.log_uninitialized_for_operation(operation);
        let err = E::error();
        Err(err)
    }

    fn log_uninitialized_for_operation(&self, operation: &str) {
        error!(
            self.logger,
            "Failed to {} with uninitialized blockchain \
            interface. Parameter blockchain-service-url is missing.",
            operation
        )
    }
}

pub struct BlockchainInterfaceWeb3<T: BatchTransport + Debug> {
    logger: Logger, // *
    chain: Chain,   // *
    // This must not be dropped for Web3 requests to be completed
    _event_loop_handle: EventLoopHandle,
    web3: Web3<T>,
    contract: Contract<T>,
}

pub const GWEI: U256 = U256([1_000_000_000u64, 0, 0, 0]);

pub fn to_wei(gwub: u64) -> U256 {
    let subgwei = U256::from(gwub);
    subgwei.full_mul(GWEI).try_into().expect("Internal Error")
}

impl<T> BlockchainInterface for BlockchainInterfaceWeb3<T>
where
    T: BatchTransport + Debug + 'static,
{
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn get_chain(&self) -> Chain {
        self.chain
    }

    fn get_batch_web3(&self) -> Web3<Batch<Http>> {
        // self.
        todo!("FIX ME GH-744")
    }

    // Result<RetrievedBlockchainTransactions, BlockchainError>
    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
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

        Box::new(
            log_request.then(move |logs| {
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
            }), // .wait()
        )
    }

    fn get_transaction_fee_balance(
        &self,
        wallet: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .balance(wallet.address(), None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_token_balance(
        &self,
        wallet: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.contract
                .query(
                    "balanceOf",
                    wallet.address(),
                    None,
                    Options::default(),
                    None,
                )
                .map_err(|e| BlockchainError::QueryFailed(e.to_string())),
        )
        // .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
        // .wait()
    }

    fn get_transaction_count(
        &self,
        wallet: &Wallet,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .transaction_count(wallet.address(), Some(BlockNumber::Pending))
                .map_err(|e| BlockchainError::QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.web3
            .eth()
            .transaction_receipt(hash)
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProcessedPayableFallible {
    Correct(PendingPayable),
    Failed(RpcPayableFailure),
}

#[derive(Debug, PartialEq, Clone)]
pub struct RpcPayableFailure {
    pub rpc_error: Web3Error,
    pub recipient_wallet: Wallet,
    pub hash: H256,
}

pub type HashAndAmountResult = Result<Vec<(H256, u128)>, PayableTransactionError>;
pub type HashesAndAmounts = Vec<(H256, u128)>;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct HashAndAmount {
    pub hash: H256,
    pub amount: u128,
}

impl<T> BlockchainInterfaceWeb3<T>
where
    T: BatchTransport + Debug + 'static,
{
    pub fn new(transport: T, event_loop_handle: EventLoopHandle, chain: Chain) -> Self {
        let web3 = Web3::new(transport.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::test_utils::{make_fake_event_loop_handle, make_tx_hash, TestTransport};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::TestRawTransaction;
    use crossbeam_channel::{unbounded, Receiver};
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::{find_free_port, slice_of_strs_to_vec_of_strings};
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

    #[test]
    fn constants_have_correct_values() {
        let contract_abi_expected: &str = indoc!(
            r#"[{
            "constant":true,
            "inputs":[{"name":"owner","type":"address"}],
            "name":"balanceOf",
            "outputs":[{"name":"","type":"uint256"}],
            "payable":false,
            "stateMutability":"view",
            "type":"function"
            },{
            "constant":false,
            "inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],
            "name":"transfer",
            "outputs":[{"name":"","type":"bool"}],
            "payable":false,
            "stateMutability":"nonpayable",
            "type":"function"
            }]"#
        );
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
        assert_eq!(
            BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED,
            "To avoid being delinquency-banned, you \
        should restart the Node with a value for blockchain-service-url"
        )
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
    fn blockchain_interface_web3_handles_no_retrieved_transactions() {
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait()
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
    fn blockchain_interface_web3_retrieves_transactions() {
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait()
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
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_the_to_address_is_invalid(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(42, &Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc"))
            .wait();

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidAddress
        );
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_a_response_with_too_few_topics_is_returned(
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait();

        assert_eq!(
            result.expect_err("Expected an Err, got Ok"),
            BlockchainError::InvalidResponse
        );
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_a_response_with_data_that_is_too_long_is_returned(
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

        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait();

        assert_eq!(result, Err(BlockchainError::InvalidResponse));
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_ignores_transaction_logs_that_have_no_block_number(
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

        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait();

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: 43,
                transactions: vec![]
            })
        );
    }

    #[test]
    fn blockchain_interface_web3_can_retrieve_eth_balance_of_a_wallet() {
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

        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .get_transaction_fee_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait()
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_web3_returns_an_error_when_requesting_eth_balance_of_an_invalid_wallet()
    {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .get_transaction_fee_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"))
            .wait();

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_web3_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .get_transaction_fee_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait();

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("invalid hex character: Q") => {
                ()
            }
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        };
    }

    #[test]
    fn blockchain_interface_web3_returns_error_for_unintelligible_response_to_gas_balance() {
        let act = |subject: &BlockchainInterfaceWeb3<Http>, wallet: &Wallet| {
            subject.get_transaction_fee_balance(wallet).wait()
        };

        assert_error_during_requesting_balance(act, "invalid hex character");
    }

    #[test]
    fn blockchain_interface_web3_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();
        let _test_server = TestServer::start (port, vec![
            br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}"#.to_vec()
        ]);

        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .get_token_balance(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            )
            .wait()
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_web3_returns_an_error_when_requesting_token_balance_of_an_invalid_wallet(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .get_token_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"))
            .wait();

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_web3_returns_error_for_unintelligible_response_to_token_balance() {
        let act = |subject: &BlockchainInterfaceWeb3<Http>, wallet: &Wallet| {
            subject.get_token_balance(wallet).wait()
        };

        assert_error_during_requesting_balance(act, "Invalid hex");
    }

    fn assert_error_during_requesting_balance<F>(act: F, expected_err_msg_fragment: &str)
    where
        F: FnOnce(&BlockchainInterfaceWeb3<Http>, &Wallet) -> ResultForBalance,
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

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
    fn web3_interface_base_gas_limit_is_properly_set() {
        assert_eq!(
            BlockchainInterfaceWeb3::<Http>::base_gas_limit(Chain::PolyMainnet),
            70_000
        );
        assert_eq!(
            BlockchainInterfaceWeb3::<Http>::base_gas_limit(Chain::PolyMumbai),
            70_000
        );
        assert_eq!(
            BlockchainInterfaceWeb3::<Http>::base_gas_limit(Chain::EthMainnet),
            55_000
        );
        assert_eq!(
            BlockchainInterfaceWeb3::<Http>::base_gas_limit(Chain::EthRopsten),
            55_000
        );
        assert_eq!(
            BlockchainInterfaceWeb3::<Http>::base_gas_limit(Chain::Dev),
            55_000
        );
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
        let subject = BlockchainInterfaceWeb3::new(transport, make_fake_event_loop_handle(), chain);
        let lengths_of_constant_parts: Vec<usize> =
            constant_parts.iter().map(|part| part.len()).collect();
        for (((tx, signed), length), constant_part) in txs
            .iter()
            .zip(lengths_of_constant_parts)
            .zip(constant_parts)
        {
            let secret = Wallet::from(
                Bip32EncryptionKeyProvider::from_raw_secret(&signed.private_key.0.as_ref())
                    .unwrap(),
            )
            .prepare_secp256k1_secret()
            .unwrap();
            let tx_params = from_raw_transaction_to_transaction_parameters(tx, chain);
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

    fn from_raw_transaction_to_transaction_parameters(
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
    fn blockchain_interface_web3_can_fetch_nonce() {
        let prepare_params_arc = Arc::new(Mutex::new(vec![]));
        let send_params_arc = Arc::new(Mutex::new(vec![]));
        let transport = TestTransport::default()
            .prepare_params(&prepare_params_arc)
            .send_params(&send_params_arc)
            .send_result(json!(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ));
        let subject = BlockchainInterfaceWeb3::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            TEST_DEFAULT_CHAIN,
        );

        let result = subject
            .get_transaction_count(&make_paying_wallet(b"gdasgsa"))
            .wait();

        assert_eq!(result, Ok(U256::from(1)));
        let mut prepare_params = prepare_params_arc.lock().unwrap();
        let (method_name, actual_arguments) = prepare_params.remove(0);
        assert!(prepare_params.is_empty());
        let actual_arguments: Vec<String> = actual_arguments
            .into_iter()
            .map(|arg| serde_json::to_string(&arg).unwrap())
            .collect();
        assert_eq!(method_name, "eth_getTransactionCount".to_string());
        assert_eq!(
            actual_arguments,
            vec![
                String::from(r#""0x5c361ba8d82fcf0e5538b2a823e9d457a2296725""#),
                String::from(r#""pending""#),
            ]
        );
        let send_params = send_params_arc.lock().unwrap();
        let rpc_call_params = vec![
            Value::String(String::from("0x5c361ba8d82fcf0e5538b2a823e9d457a2296725")),
            Value::String(String::from("pending")),
        ];
        let expected_request =
            web3::helpers::build_request(1, "eth_getTransactionCount", rpc_call_params);
        assert_eq!(*send_params, vec![(1, expected_request)])
    }

    #[test]
    fn blockchain_interface_web3_can_fetch_transaction_receipt() {
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);
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
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);
        let tx_hash = make_tx_hash(4564546);

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
    fn blockchain_error_implements_display() {
        let original_errors = [
            BlockchainError::InvalidUrl,
            BlockchainError::InvalidAddress,
            BlockchainError::InvalidResponse,
            BlockchainError::QueryFailed(
                "Don't query so often, it gives me a headache".to_string(),
            ),
            BlockchainError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors
            .iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            BlockchainError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Blockchain error: Invalid url",
                "Blockchain error: Invalid address",
                "Blockchain error: Invalid response",
                "Blockchain error: Query failed: Don't query so often, it gives me a headache",
                &format!("Blockchain error: {}", BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED)
            ])
        );
    }

    #[test]
    fn payable_payment_error_implements_display() {
        let original_errors = [
            PayableTransactionError::MissingConsumingWallet,
            PayableTransactionError::GasPriceQueryFailed(
                "Gas halves shut, no drop left".to_string(),
            ),
            PayableTransactionError::TransactionCount(BlockchainError::InvalidResponse),
            PayableTransactionError::UnusableWallet(
                "This is a LEATHER wallet, not LEDGER wallet, stupid.".to_string(),
            ),
            PayableTransactionError::Signing(
                "You cannot sign with just three crosses here, clever boy".to_string(),
            ),
            PayableTransactionError::Sending {
                msg: "Sending to cosmos belongs elsewhere".to_string(),
                hashes: vec![make_tx_hash(0x6f), make_tx_hash(0xde)],
            },
            PayableTransactionError::UninitializedBlockchainInterface,
        ];

        let actual_error_msgs = original_errors
            .iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            original_errors.len(),
            PayableTransactionError::VARIANT_COUNT,
            "you forgot to add all variants in this test"
        );
        assert_eq!(
            actual_error_msgs,
            slice_of_strs_to_vec_of_strings(&[
                "Missing consuming wallet to pay payable from",
                "Unsuccessful gas price query: \"Gas halves shut, no drop left\"",
                "Transaction count fetching failed for: Blockchain error: Invalid response",
                "Unusable wallet for signing payable transactions: \"This is a LEATHER wallet, not \
                LEDGER wallet, stupid.\"",
                "Signing phase: \"You cannot sign with just three crosses here, clever boy\"",
                "Sending phase: \"Sending to cosmos belongs elsewhere\". Signed and hashed \
                transactions: 0x000000000000000000000000000000000000000000000000000000000000006f, \
                0x00000000000000000000000000000000000000000000000000000000000000de",
                BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED
            ])
        )
    }

    #[test]
    fn blockchain_interface_null_error_is_implemented_for_blockchain_error() {
        assert_eq!(
            BlockchainError::error(),
            BlockchainError::UninitializedBlockchainInterface
        )
    }

    #[test]
    fn blockchain_interface_null_error_is_implemented_for_payable_transaction_error() {
        assert_eq!(
            PayableTransactionError::error(),
            PayableTransactionError::UninitializedBlockchainInterface
        )
    }
}
