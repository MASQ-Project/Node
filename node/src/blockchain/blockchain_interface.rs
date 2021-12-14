// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::tool_wrappers::{
    SendTransactionToolsWrapper, SendTransactionToolsWrapperReal,
};
use crate::sub_lib::logger::Logger;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use futures::{future, Future};
use masq_lib::blockchains::chains::{Chain, ChainFamily};
use masq_lib::constants::DEFAULT_CHAIN;
use std::convert::{From, TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use web3::contract::{Contract, Options};
use web3::transports::EventLoopHandle;
use web3::types::{
    Address, BlockNumber, Bytes, FilterBuilder, Log, SignedTransaction, TransactionParameters,
    H256, U256,
};
use web3::{Transport, Web3};

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub const CONTRACT_ABI: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;

const TRANSACTION_LITERAL: H256 = H256 {
    0: [
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ],
};

const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Clone, Debug, Eq, Message, PartialEq)]
pub struct Transaction {
    pub block_number: u64,
    pub from: Wallet,
    pub gwei_amount: u64,
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}gw from {} ({})",
            self.gwei_amount, self.from, self.block_number
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    UnusableWallet(String),
    QueryFailed(String),
    TransactionFailed(String),
}

impl Display for BlockchainError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Blockchain {:?}.", self)
    }
}

pub type BlockchainResult<T> = Result<T, BlockchainError>;
pub type Balance = BlockchainResult<web3::types::U256>;
pub type Nonce = BlockchainResult<web3::types::U256>;
pub type Transactions = BlockchainResult<Vec<Transaction>>;

pub trait BlockchainInterface {
    fn contract_address(&self) -> Address;

    fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions;

    fn send_transaction<'a>(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
        send_transaction_tools: &'a dyn SendTransactionToolsWrapper,
    ) -> BlockchainResult<H256>;

    fn get_eth_balance(&self, address: &Wallet) -> Balance;

    fn get_token_balance(&self, address: &Wallet) -> Balance;

    fn get_balances(&self, address: &Wallet) -> (Balance, Balance) {
        (
            self.get_eth_balance(address),
            self.get_token_balance(address),
        )
    }

    fn get_transaction_count(&self, address: &Wallet) -> Nonce;

    fn send_transaction_tools<'a>(&'a self) -> Box<dyn SendTransactionToolsWrapper + 'a> {
        intentionally_blank!()
    }
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

    fn retrieve_transactions(&self, _start_block: u64, _recipient: &Wallet) -> Transactions {
        let msg = "Can't retrieve transactions clandestinely yet".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::TransactionFailed(msg))
    }

    fn send_transaction<'a>(
        &self,
        _consuming_wallet: &Wallet,
        _recipient: &Wallet,
        _amount: u64,
        _nonce: U256,
        _gas_price: u64,
        _send_transaction_tools: &'a dyn SendTransactionToolsWrapper,
    ) -> BlockchainResult<H256> {
        let msg = "Can't send transactions clandestinely yet".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::TransactionFailed(msg))
    }

    fn get_eth_balance(&self, _address: &Wallet) -> Balance {
        error!(self.logger, "Can't get eth balance clandestinely yet",);
        Ok(0.into())
    }

    fn get_token_balance(&self, _address: &Wallet) -> Balance {
        error!(self.logger, "Can't get token balance clandestinely yet",);
        Ok(0.into())
    }

    fn get_transaction_count(&self, _address: &Wallet) -> Nonce {
        error!(self.logger, "Can't get transaction count clandestinely yet",);
        Ok(0.into())
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

pub fn to_gwei(wei: U256) -> Option<u64> {
    u64::try_from(wei / GWEI).ok()
}

pub fn to_wei(gwub: u64) -> U256 {
    let subgwei = U256::from(gwub);
    subgwei.full_mul(GWEI).try_into().expect("Internal Error")
}

impl<T> BlockchainInterface for BlockchainInterfaceNonClandestine<T>
where
    T: Transport + Debug,
{
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
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
                future::result::<Vec<Transaction>, BlockchainError>(match logs {
                    Ok(logs) => {
                        if logs
                            .iter()
                            .any(|log| log.topics.len() < 2 || log.data.0.len() > 32)
                        {
                            Err(BlockchainError::InvalidResponse)
                        } else {
                            let transactions = logs
                                .iter()
                                .filter_map(|log: &Log| match log.block_number {
                                    Some(block_number) => {
                                        let amount: U256 = U256::from(log.data.0.as_slice());
                                        let gwei_amount = to_gwei(amount);
                                        gwei_amount.map(|gwei_amount| Transaction {
                                            block_number: u64::try_from(block_number)
                                                .expect("Internal Error"), // TODO: back to testing for overflow
                                            from: Wallet::from(log.topics[1]),
                                            gwei_amount,
                                        })
                                    }
                                    None => None,
                                })
                                .collect();
                            debug!(logger, "Retrieved transactions: {:?}", transactions);
                            Ok(transactions)
                        }
                    }
                    Err(e) => Err(BlockchainError::QueryFailed(e.to_string())),
                })
            })
            .wait()
    }

    fn send_transaction<'a>(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
        send_transaction_tools: &'a dyn SendTransactionToolsWrapper,
    ) -> BlockchainResult<H256> {
        debug!(
            self.logger,
            "Sending transaction for {} Gwei to {} from {}: (chain_id: {} contract: {:#x})",
            amount,
            recipient,
            consuming_wallet,
            self.chain.rec().num_chain_id,
            self.contract_address()
        );
        let signed_transaction = self.prepare_signed_transaction(
            consuming_wallet,
            recipient,
            amount,
            nonce,
            gas_price,
            send_transaction_tools,
        )?;
        match send_transaction_tools.send_raw_transaction(signed_transaction.raw_transaction) {
            Ok(hash) => Ok(hash),
            Err(e) => Err(BlockchainError::TransactionFailed(e.to_string())),
        }
    }

    fn get_eth_balance(&self, wallet: &Wallet) -> Balance {
        self.web3
            .eth()
            .balance(wallet.address(), None)
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn get_token_balance(&self, wallet: &Wallet) -> Balance {
        self.contract
            .query(
                "balanceOf",
                wallet.address(),
                None,
                Options::with(|_| {}),
                None,
            )
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
        self.web3
            .eth()
            .transaction_count(wallet.address(), Some(BlockNumber::Pending))
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn send_transaction_tools<'a>(&'a self) -> Box<dyn SendTransactionToolsWrapper + 'a> {
        Box::new(SendTransactionToolsWrapperReal::new(&self.web3))
    }
}

impl<T> BlockchainInterfaceNonClandestine<T>
where
    T: Transport + Debug,
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

    fn prepare_signed_transaction<'a>(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
        send_transaction_tools: &'a dyn SendTransactionToolsWrapper,
    ) -> Result<SignedTransaction, BlockchainError> {
        let mut data = [0u8; 4 + 32 + 32];
        data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
        data[16..36].copy_from_slice(&recipient.address().0[..]);
        to_wei(amount).to_big_endian(&mut data[36..68]);
        let base_gas_limit = Self::base_gas_limit(self.chain);
        let gas_limit =
            ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
                acc + if v == &0u8 { 4 } else { 68 }
            }))
            .expect("Internal error");
        let converted_nonce = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(nonce).expect("Internal error"),
        )
        .expect("Internal error");
        let gas_price = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(to_wei(gas_price)).expect("Internal error"),
        )
        .expect("Internal error");

        let transaction_parameters = TransactionParameters {
            nonce: Some(converted_nonce),
            to: Some(ethereum_types::Address {
                0: self.contract_address().0,
            }),
            gas: gas_limit,
            gas_price: Some(gas_price),
            value: ethereum_types::U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(self.chain.rec().num_chain_id),
        };

        let key = match consuming_wallet.prepare_secp256k1_secret() {
            Ok(secret) => secret,
            Err(e) => return Err(BlockchainError::UnusableWallet(e.to_string())),
        };

        match send_transaction_tools.sign_transaction(transaction_parameters, &key) {
            Ok(tx) => Ok(tx),
            Err(e) => Err(BlockchainError::TransactionFailed(e.to_string())),
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
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::test_utils::TestTransport;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::pure_test_utils::decode_hex;
    use crate::test_utils::{await_value, make_paying_wallet};
    use crate::test_utils::{make_wallet, TestRawTransaction};
    use crossbeam_channel::unbounded;
    use ethereum_types::BigEndianHash;
    use ethsign_crypto::Keccak256;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_derive::Deserialize;
    use serde_json::json;
    use serde_json::Value;
    use simple_server::Server;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use web3::transports::Http;
    use web3::types::SignedTransaction;
    use web3::Error as Web3Error;

    fn make_fake_event_loop_handle() -> EventLoopHandle {
        Http::with_max_parallel("http://86.75.30.9", REQUESTS_IN_PARALLEL)
            .unwrap()
            .0
    }

    #[derive(Default)]
    struct SendTransactionToolsWrapperMock {
        sign_transaction_params:
            Arc<Mutex<Vec<(TransactionParameters, secp256k1secrets::key::SecretKey)>>>,
        sign_transaction_results: RefCell<Vec<Result<SignedTransaction, Web3Error>>>,
        send_raw_transaction_params: Arc<Mutex<Vec<Bytes>>>,
        send_raw_transaction_results: RefCell<Vec<Result<H256, Web3Error>>>,
    }

    impl SendTransactionToolsWrapper for SendTransactionToolsWrapperMock {
        fn sign_transaction(
            &self,
            transaction_params: TransactionParameters,
            key: &secp256k1secrets::key::SecretKey,
        ) -> Result<SignedTransaction, Web3Error> {
            self.sign_transaction_params
                .lock()
                .unwrap()
                .push((transaction_params.clone(), key.clone()));
            self.sign_transaction_results.borrow_mut().remove(0)
        }

        fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
            self.send_raw_transaction_params.lock().unwrap().push(rlp);
            self.send_raw_transaction_results.borrow_mut().remove(0)
        }
    }

    impl SendTransactionToolsWrapperMock {
        pub fn sign_transaction_params(
            mut self,
            params: &Arc<Mutex<Vec<(TransactionParameters, secp256k1secrets::key::SecretKey)>>>,
        ) -> Self {
            self.sign_transaction_params = params.clone();
            self
        }
        pub fn sign_transaction_result(self, result: Result<SignedTransaction, Web3Error>) -> Self {
            self.sign_transaction_results.borrow_mut().push(result);
            self
        }
        pub fn send_raw_transaction_params(mut self, params: &Arc<Mutex<Vec<Bytes>>>) -> Self {
            self.send_raw_transaction_params = params.clone();
            self
        }
        pub fn send_raw_transaction_result(self, result: Result<H256, Web3Error>) -> Self {
            self.send_raw_transaction_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieves_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();

        let (tx, rx) = unbounded();
        thread::spawn(move || {
            Server::new(move |req, mut rsp| {
                tx.send(req.body().clone()).unwrap();
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec())?)
            }).listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        let body: Value = serde_json::from_slice(&rx.recv().unwrap()).unwrap();
        assert_eq!(
            format!("\"0x000000000000000000000000{}\"", &to[2..]),
            body["params"][0]["topics"][2].to_string(),
        );
        assert_eq!(
            result,
            vec![Transaction {
                block_number: 4_974_179u64,
                from: Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
                gwei_amount: 4_503_599u64,
            }]
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

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d63100000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec())?)
            }).listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        thread::spawn(move || {
            Server::new(move |_req, mut rsp| {
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d6310000001","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec())?)
            }).listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec())?)
            })
                .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        assert_eq!(result, Ok(vec![]));
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_retrieve_eth_balance_of_a_wallet() {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFF"}"#.to_vec())?)
            })
            .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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
            .get_eth_balance(
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
            subject.get_eth_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));

        assert_eq!(result, Err(BlockchainError::InvalidAddress));
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":0,"result":"0xFFFQ"}"#.to_vec())?)
            })
            .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        let result = subject.get_eth_balance(
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
    fn blockchain_interface_non_clandestine_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(
                    br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFF"}"#
                        .to_vec(),
                )?)
            })
                .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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
    fn blockchain_interface_non_clandestine_returns_an_error_for_unintelligible_response_when_requesting_token_balance(
    ) {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(
                    br#"{"jsonrpc":"2.0","id":0,"result":"0x000000000000000000000000000000000000000000000000000000000000FFFQ"}"#
                        .to_vec(),
                )?)
            })
            .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        let result = subject.get_token_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        match result {
            Err(BlockchainError::QueryFailed(msg)) if msg.contains("Invalid hex") => (),
            x => panic!("Expected complaint about hex character, but got {:?}", x),
        }
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_request_both_eth_and_token_balances_happy_path() {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(
                    br#"{"jsonrpc":"2.0","id":0,"result":"0x0000000000000000000000000000000000000000000000000000000000000001"}"#
                        .to_vec(),
                )?)
            })
            .listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

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

        let results: (Balance, Balance) = await_value(None, || {
            match subject.get_balances(
                &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
            ) {
                (Ok(a), Ok(b)) => Ok((Ok(a), Ok(b))),
                (Err(a), _) => Err(a),
                (_, Err(b)) => Err(b),
            }
        })
        .unwrap();

        let eth_balance = results.0.unwrap();
        let token_balance = results.1.unwrap();

        assert_eq!(eth_balance, U256::from(1),);
        assert_eq!(token_balance, U256::from(1))
    }

    //test with real web3
    #[test]
    fn blockchain_interface_non_clandestine_can_transfer_tokens() {
        let mut transport = TestTransport::default();
        transport.add_response(json!(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let subject = BlockchainInterfaceNonClandestine::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            TEST_DEFAULT_CHAIN,
        );

        let result = subject.send_transaction(
            &make_paying_wallet(b"gdasgsa"),
            &make_wallet("blah123"),
            9000,
            U256::from(1),
            2u64,
            subject.send_transaction_tools().as_ref(),
        );

        transport.assert_request("eth_sendRawTransaction", &[String::from(r#""0xf8a801847735940082dbe894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb00000000000000000000000000000000000000000000000000626c61683132330000000000000000000000000000000000000000000000000000082f79cd900029a0b8e83e714af8bf1685b496912ee4aeff7007ba0f4c29ae50f513bc71ce6a18f4a06a923088306b4ee9cbfcdc62c9b396385f9b1c380134bf046d6c9ae47dea6578""#)]);
        transport.assert_no_more_requests();
        assert_eq!(result, Ok(H256::from_uint(&U256::from(1))));
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
        let send_raw_transaction_params_arc = Arc::new(Mutex::new(vec![]));
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
        let consuming_wallet_secret_raw_bytes = b"my-wallet";
        let secret =
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret_raw_bytes.keccak256())
                .unwrap())
                .into();
        let signed_transaction = subject
            .web3
            .accounts()
            .sign_transaction(transaction_parameters_expected.clone(), &secret)
            .wait()
            .unwrap();
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_params(&sign_transaction_params_arc)
            .sign_transaction_result(Ok(signed_transaction.clone()))
            .send_raw_transaction_params(&send_raw_transaction_params_arc)
            .send_raw_transaction_result(Ok(H256::from_uint(&U256::from(5))));
        let recipient_wallet = make_wallet("blah123");

        let result = subject.send_transaction(
            &make_paying_wallet(consuming_wallet_secret_raw_bytes),
            &recipient_wallet,
            50000,
            U256::from(5),
            123u64,
            send_transaction_tools,
        );

        assert_eq!(result, Ok(H256::from_uint(&U256::from(5))));
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

        assert_gas_limit_is_not_under(subject, 70000, u64::MAX)
    }

    #[test]
    fn non_clandestine_gas_limit_for_dev_lies_within_limits() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::Dev,
        );

        assert_gas_limit_is_not_under(subject, 55000, 65000)
    }

    #[test]
    fn non_clandestine_gas_limit_for_eth_mainnet_lies_within_limits() {
        let transport = TestTransport::default();
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::EthMainnet,
        );

        assert_gas_limit_is_not_under(subject, 55000, 65000)
    }

    fn assert_gas_limit_is_not_under<T: Transport + Debug>(
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
        let recipient_wallet = make_wallet("blah123");

        let _ = subject.send_transaction(
            &make_paying_wallet(consuming_wallet_secret_raw_bytes),
            &recipient_wallet,
            50000,
            U256::from(5),
            123u64,
            send_transaction_tools,
        );

        let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        let (transaction_params, secret) = sign_transaction_params.remove(0);
        assert!(sign_transaction_params.is_empty());
        assert!(transaction_params.gas > U256::from(not_under_this_value));
        assert!(transaction_params.gas < U256::from(not_above_this_value));
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

        let result = subject.send_transaction(
            &address_only_wallet,
            &make_wallet("blah123"),
            9000,
            U256::from(1),
            2u64,
            subject.send_transaction_tools().as_ref(),
        );

        assert_eq!(result,
                   Err(BlockchainError::UnusableWallet(
                       "Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()
                   ))
        )
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

        let result = subject.send_transaction(
            &make_paying_wallet(consuming_wallet_secret_raw_bytes),
            &make_wallet("blah123"),
            9000,
            U256::from(1),
            2u64,
            send_transaction_tools,
        );

        assert_eq!(
            result,
            Err(BlockchainError::TransactionFailed(
                "Signing error: secp: malformed or out-of-range secret key".to_string()
            ))
        );
    }

    #[test]
    fn send_transaction_fails_on_sending_raw_tx() {
        let transport = TestTransport::default();
        let signed_transaction = SignedTransaction {
            message_hash: Default::default(),
            v: 0,
            r: Default::default(),
            s: Default::default(),
            raw_transaction: Default::default(),
            transaction_hash: Default::default(),
        };
        let send_transaction_tools = &SendTransactionToolsWrapperMock::default()
            .sign_transaction_result(Ok(signed_transaction))
            .send_raw_transaction_result(Err(Web3Error::Transport(
                "Transaction crashed".to_string(),
            )));
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let subject = BlockchainInterfaceNonClandestine::new(
            transport,
            make_fake_event_loop_handle(),
            Chain::PolyMumbai,
        );

        let result = subject.send_transaction(
            &make_paying_wallet(consuming_wallet_secret_raw_bytes),
            &make_wallet("blah123"),
            5000,
            U256::from(1),
            2u64,
            send_transaction_tools,
        );

        assert_eq!(
            result,
            Err(BlockchainError::TransactionFailed(
                "Transport error: Transaction crashed".to_string()
            ))
        );
    }

    fn test_consuming_wallet_with_secret() -> Wallet {
        let key_provider = Bip32ECKeyProvider::from_raw_secret(
            &decode_hex("97923d8fd8de4a00f912bfb77ef483141dec551bd73ea59343ef5c4aac965d04")
                .unwrap(),
        )
        .unwrap();
        Wallet::from(key_provider)
    }

    fn test_recipient_wallet() -> Wallet {
        let hex_part = &"0x7788df76BBd9a0C7c3e5bf0f77bb28C60a167a7b"[2..];
        let recipient_address_bytes = decode_hex(hex_part).unwrap();
        let address = Address::from_slice(&recipient_address_bytes);
        Wallet::from(address)
    }

    const TEST_PAYMENT_AMOUNT: u64 = 1000;
    const TEST_GAS_PRICE_ETH: u64 = 110;
    const TEST_GAS_PRICE_POLYGON: u64 = 50;

    fn assert_that_signed_transactions_agrees_with_template(
        chain: Chain,
        nonce: u64,
        template: &[u8],
    ) {
        let transport = TestTransport::default();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let send_transaction_tools = subject.send_transaction_tools();
        let consuming_wallet = test_consuming_wallet_with_secret();
        let recipient_wallet = test_recipient_wallet();
        let nonce_of_the_real_transaction = U256::from(nonce);
        let gas_price = match chain.rec().chain_family {
            ChainFamily::Eth => TEST_GAS_PRICE_ETH,
            ChainFamily::Polygon => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };

        let signed_transaction = subject
            .prepare_signed_transaction(
                &consuming_wallet,
                &recipient_wallet,
                TEST_PAYMENT_AMOUNT,
                nonce_of_the_real_transaction,
                gas_price,
                send_transaction_tools.as_ref(),
            )
            .unwrap();

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(&byte_set_to_compare, template)
    }

    //with a real confirmation on a transaction sent with this data to the network
    #[test]
    fn non_clandestine_signing_a_transaction_works_for_polygon_mumbai() {
        let chain = Chain::PolyMumbai;
        let nonce = 5; //must stay like this!
        let signed_transaction_data = "f8ad05850ba43b740083011980944dfeee01f17e23632b15851717b811720af82e0f80b844a9059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000000e8d4a5100083027126a07ef7ca63022eb309f63e3e28bc5b33494c274f293383da21df7f884fae0a9906a03217dab00d8bf2ad5f37263b82c8ba174ff13d9266cd853b4dbb69459880d40b";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //with a real confirmation on a transaction sent with this data to the network
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
    fn to_gwei_truncates_units_smaller_than_gwei() {
        assert_eq!(Some(1), to_gwei(U256::from(1_999_999_999)));
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
}
