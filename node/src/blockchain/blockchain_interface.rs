// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::blockchain::raw_transaction::RawTransaction;
use crate::sub_lib::logger::Logger;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use futures::{future, Future};
use std::convert::{From, TryFrom, TryInto};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use web3::contract::{Contract, Options};
use web3::transports::EventLoopHandle;
use web3::types::{Address, BlockNumber, Bytes, FilterBuilder, Log, H256, U256};
use web3::{Transport, Web3};

// HOT (Ropsten)
pub const TESTNET_CONTRACT_ADDRESS: Address = Address {
    0: [
        0xcd, 0x6c, 0x58, 0x8e, 0x00, 0x50, 0x32, 0xdd, 0x88, 0x2c, 0xd4, 0x3b, 0xf5, 0x3a, 0x32,
        0x12, 0x9b, 0xe8, 0x13, 0x02,
    ],
};

pub const MULTINODE_TESTNET_CONTRACT_ADDRESS: Address = Address {
    0: [
        0x59, 0x88, 0x2e, 0x4a, 0x8f, 0x5d, 0x24, 0x64, 0x3d, 0x4d, 0xda, 0x42, 0x29, 0x22, 0xa8,
        0x70, 0xf1, 0xb3, 0xe6, 0x64,
    ],
};

pub const MAINNET_CONTRACT_ADDRESS: Address = Address {
    0: [
        0x8d, 0x75, 0x95, 0x9f, 0x1e, 0x61, 0xec, 0x25, 0x71, 0xaa, 0x72, 0x79, 0x82, 0x37, 0x10,
        0x1f, 0x08, 0x4d, 0xe6, 0x3a,
    ],
};

const CONTRACTS: [Address; 4] = [
    Address { 0: [0u8; 20] },
    MAINNET_CONTRACT_ADDRESS,
    MULTINODE_TESTNET_CONTRACT_ADDRESS,
    TESTNET_CONTRACT_ADDRESS,
];

pub const MAINNET_CONTRACT_CREATION_BLOCK: u64 = 6_905_550;
pub const ROPSTEN_CONTRACT_CREATION_BLOCK: u64 = 4_647_463;

pub const CONTRACT_CREATION_BLOCK: [u64; 4] = [
    0,
    MAINNET_CONTRACT_CREATION_BLOCK,
    0,
    ROPSTEN_CONTRACT_CREATION_BLOCK,
];

pub const CHAIN_NAMES: [&str; 4] = ["", "mainnet", "dev", "ropsten"];

pub fn contract_address(chain_id: u8) -> Address {
    match chain_id {
        1u8 | 2u8 | 3u8 => CONTRACTS[usize::from(chain_id)], // IDEA/CLion is wrong: This is copy
        _ => CONTRACTS[0],                                   // IDEA/CLion is wrong: This is copy
    }
}

pub fn chain_name(chain_id: u8) -> &'static str {
    match chain_id {
        1u8 | 2u8 | 3u8 => CHAIN_NAMES[chain_id as usize],
        _ => CHAIN_NAMES[3],
    }
}

pub fn chain_id_from_name(name: &str) -> u8 {
    match name.to_lowercase().as_str() {
        "mainnet" => 1u8,
        "dev" => 2u8,
        _ => 3u8,
    }
}

pub fn chain_name_from_id(chain_id: u8) -> &'static str {
    match chain_id {
        1u8 | 2u8 | 3u8 => CHAIN_NAMES[usize::from(chain_id)],
        _ => CHAIN_NAMES[3],
    }
}

pub fn contract_creation_block_from_chain_id(chain_id: u8) -> u64 {
    match chain_id {
        1u8 | 2u8 | 3u8 => CONTRACT_CREATION_BLOCK[usize::from(chain_id)],
        _ => CONTRACT_CREATION_BLOCK[3],
    }
}

pub const CONTRACT_ABI: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;

const TRANSACTION_LITERAL: H256 = H256 {
    0: [
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ],
};

const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub const DEFAULT_GAS_PRICE: &str = "1";
pub const DEFAULT_CHAIN_NAME: &str = "ropsten"; //TODO: SC-501/GH-115: Change this to "mainnet" when it's time

#[derive(Clone, Debug, Eq, Message, PartialEq)]
pub struct Transaction {
    pub block_number: u64,
    pub from: Wallet,
    pub gwei_amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed,
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

    fn send_transaction(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
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
}

pub struct BlockchainInterfaceClandestine {
    logger: Logger,
    chain_id: u8,
}

impl BlockchainInterfaceClandestine {
    pub fn new(chain_id: u8) -> Self {
        BlockchainInterfaceClandestine {
            logger: Logger::new("BlockchainInterface"),
            chain_id,
        }
    }
}

impl Default for BlockchainInterfaceClandestine {
    fn default() -> Self {
        Self::new(chain_id_from_name(DEFAULT_CHAIN_NAME))
    }
}

impl BlockchainInterface for BlockchainInterfaceClandestine {
    fn contract_address(&self) -> Address {
        contract_address(self.chain_id)
    }

    fn retrieve_transactions(&self, _start_block: u64, _recipient: &Wallet) -> Transactions {
        let msg = "Could not retrieve transactions since blockchain_service_url was not specified"
            .to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::TransactionFailed(msg))
    }

    fn send_transaction(
        &self,
        _consuming_wallet: &Wallet,
        _recipient: &Wallet,
        _amount: u64,
        _nonce: U256,
        _gas_price: u64,
    ) -> BlockchainResult<H256> {
        let msg =
            "Could not send transaction since blockchain_service_url was not specified".to_string();
        error!(self.logger, "{}", &msg);
        Err(BlockchainError::TransactionFailed(msg))
    }

    fn get_eth_balance(&self, address: &Wallet) -> Balance {
        error!(
            self.logger,
            "Could not get eth balance for {:?} since blockchain_service_url was not specified",
            address
        );
        Ok(0.into())
    }

    fn get_token_balance(&self, address: &Wallet) -> Balance {
        error!(
            self.logger,
            "Could not get token balance for {:?} since blockchain_service_url was not specified",
            address
        );
        Ok(0.into())
    }

    fn get_transaction_count(&self, _address: &Wallet) -> Nonce {
        unimplemented!()
    }
}

pub struct BlockchainInterfaceNonClandestine<T: Transport + Debug> {
    logger: Logger,
    chain_id: u8,
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
        contract_address(self.chain_id)
    }

    fn retrieve_transactions(&self, start_block: u64, recipient: &Wallet) -> Transactions {
        debug!(
            self.logger,
            "Retrieving transactions from start block: {} for: {} chain_id: {} contract: {:#x}",
            start_block,
            recipient,
            self.chain_id,
            self.contract_address()
        );
        let filter = FilterBuilder::default()
            .address(vec![self.contract_address()])
            .from_block(BlockNumber::Number(start_block))
            .to_block(BlockNumber::Latest)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.address().into()]),
                None,
            )
            .build();

        let log_request = self.web3.eth().logs(filter);
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
                            Ok(logs
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
                                .collect())
                        }
                    }
                    Err(_) => Err(BlockchainError::QueryFailed),
                })
            })
            .wait()
    }

    fn send_transaction(
        &self,
        consuming_wallet: &Wallet,
        recipient: &Wallet,
        amount: u64,
        nonce: U256,
        gas_price: u64,
    ) -> BlockchainResult<H256> {
        debug!(
            self.logger,
            "Sending transaction for {} Gwei to {} from {}: (chain_id: {} contract: {:#x})",
            amount,
            recipient,
            consuming_wallet,
            self.chain_id,
            self.contract_address()
        );
        let mut data = [0u8; 4 + 32 + 32];
        data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
        data[16..36].copy_from_slice(&recipient.address().0[..]);
        to_wei(amount).to_big_endian(&mut data[36..68]);
        let gas_limit = ethereum_types::U256::try_from(
            data.iter()
                .fold(55_000u64, |acc, v| acc + if v == &0u8 { 4 } else { 68 }),
        )
        .expect("Internal error");

        let converted_nonce = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(nonce).expect("Internal error"),
        )
        .expect("Internal error");
        let gas_price = serde_json::from_value::<ethereum_types::U256>(
            serde_json::to_value(to_wei(gas_price)).expect("Internal error"),
        )
        .expect("Internal error");

        let tx = RawTransaction {
            nonce: converted_nonce,
            to: Some(ethereum_types::Address {
                0: self.contract_address().0,
            }),
            value: ethereum_types::U256::zero(),
            gas_price,
            gas_limit,
            data: data.to_vec(),
        };
        match self
            .web3
            .eth()
            .send_raw_transaction(Bytes(tx.sign(&consuming_wallet, self.chain_id)))
            .wait()
        {
            Ok(result) => Ok(result),
            Err(e) => Err(BlockchainError::TransactionFailed(format!("{:?}", e))),
        }
    }

    fn get_eth_balance(&self, wallet: &Wallet) -> Balance {
        self.web3
            .eth()
            .balance(wallet.address(), None)
            .map_err(|_| BlockchainError::QueryFailed)
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
            .map_err(|_| BlockchainError::QueryFailed)
            .wait()
    }

    fn get_transaction_count(&self, wallet: &Wallet) -> Nonce {
        self.web3
            .eth()
            .transaction_count(wallet.address(), Some(BlockNumber::Pending))
            .map_err(|_| BlockchainError::QueryFailed)
            .wait()
    }
}

impl<T> BlockchainInterfaceNonClandestine<T>
where
    T: Transport + Debug,
{
    pub fn new(transport: T, event_loop_handle: EventLoopHandle, chain_id: u8) -> Self {
        let web3 = Web3::new(transport);
        let contract = Contract::from_json(
            web3.eth(),
            contract_address(chain_id),
            CONTRACT_ABI.as_bytes(),
        )
        .expect("Unable to initialize contract.");
        Self {
            logger: Logger::new("BlockchainInterface"),
            chain_id,
            _event_loop_handle: event_loop_handle,
            web3,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::{find_free_port, make_paying_wallet, make_wallet, DEFAULT_CHAIN_ID};
    use ethereum_types::BigEndianHash;
    use ethsign_crypto::Keccak256;
    use jsonrpc_core as rpc;
    use serde_json::json;
    use serde_json::Value;
    use simple_server::Server;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::rc::Rc;
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::thread;
    use web3::{transports::Http, Error, RequestId, Transport};

    #[derive(Debug, Default, Clone)]
    pub struct TestTransport {
        asserted: usize,
        requests: Rc<RefCell<Vec<(String, Vec<rpc::Value>)>>>,
        responses: Rc<RefCell<VecDeque<rpc::Value>>>,
    }

    impl Transport for TestTransport {
        type Out = web3::Result<rpc::Value>;

        fn prepare(&self, method: &str, params: Vec<rpc::Value>) -> (RequestId, rpc::Call) {
            let request = web3::helpers::build_request(1, method, params.clone());
            self.requests.borrow_mut().push((method.into(), params));
            (self.requests.borrow().len(), request)
        }

        fn send(&self, id: RequestId, request: rpc::Call) -> Self::Out {
            match self.responses.borrow_mut().pop_front() {
                Some(response) => Box::new(futures::finished(response)),
                None => {
                    println!("Unexpected request (id: {:?}): {:?}", id, request);
                    Box::new(futures::failed(Error::Unreachable))
                }
            }
        }
    }

    impl TestTransport {
        pub fn add_response(&mut self, value: rpc::Value) {
            self.responses.borrow_mut().push_back(value);
        }

        pub fn assert_request(&mut self, method: &str, params: &[String]) {
            let idx = self.asserted;
            self.asserted += 1;

            let (m, p) = self
                .requests
                .borrow()
                .get(idx)
                .expect("Expected result.")
                .clone();
            assert_eq!(&m, method);
            let p: Vec<String> = p
                .into_iter()
                .map(|p| serde_json::to_string(&p).unwrap())
                .collect();
            assert_eq!(p, params);
        }

        pub fn assert_no_more_requests(&mut self) {
            let requests = self.requests.borrow();
            assert_eq!(
                self.asserted,
                requests.len(),
                "Expected no more requests, got: {:?}",
                &requests[self.asserted..]
            );
        }
    }

    fn make_fake_event_loop_handle() -> EventLoopHandle {
        Http::new("http://86.75.30.9").unwrap().0
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieves_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();

        let (tx, rx) = mpsc::sync_channel(1337);
        thread::spawn(move || {
            Server::new(move |req, mut rsp| {
                tx.send(req.body().clone()).unwrap();
                Ok(rsp.body(br#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_vec())?)
            }).listen(&Ipv4Addr::LOCALHOST.to_string(), &format!("{}", port));
        });

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

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
            vec![Transaction {
                block_number: 4_974_179u64,
                from: Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
                gwei_amount: 4_503_599u64,
            }],
            result,
        )
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_retrieve_transactions_returns_an_error_if_the_to_address_is_invalid(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) =
            Http::new(&format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port)).unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject
            .retrieve_transactions(42, &Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc"));

        assert_eq!(
            BlockchainError::InvalidAddress,
            result.expect_err("Expected an Err, got Ok")
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(
            BlockchainError::InvalidResponse,
            result.expect_err("Expected an Err, got Ok")
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();

        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(Err(BlockchainError::InvalidResponse), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();

        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.retrieve_transactions(
            42,
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(Ok(vec![]), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();

        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.get_eth_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(U256::from(65_535), result.unwrap());
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_eth_balance_of_an_invalid_wallet(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();

        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result =
            subject.get_eth_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));

        assert_eq!(Err(BlockchainError::InvalidAddress), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();

        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.get_eth_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(Err(BlockchainError::QueryFailed), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.get_token_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(U256::from(65_535), result.unwrap());
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn blockchain_interface_non_clandestine_returns_an_error_when_requesting_token_balance_of_an_invalid_wallet(
    ) {
        let port = 8545;
        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result =
            subject.get_token_balance(&Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fQ"));

        assert_eq!(Err(BlockchainError::InvalidAddress), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let result = subject.get_token_balance(
            &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap(),
        );

        assert_eq!(Err(BlockchainError::QueryFailed), result);
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

        let (event_loop_handle, transport) = Http::new(&format!(
            "http://{}:{}",
            &Ipv4Addr::LOCALHOST.to_string(),
            port
        ))
        .unwrap();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, DEFAULT_CHAIN_ID);

        let results = subject
            .get_balances(&Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap());
        let eth_balance = results.0.unwrap();
        let token_balance = results.1.unwrap();

        assert_eq!(U256::from(1), eth_balance);
        assert_eq!(U256::from(1), token_balance)
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_transfer_tokens() {
        let mut transport = TestTransport::default();

        transport.add_response(json!(
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        ));

        let subject = BlockchainInterfaceNonClandestine::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            DEFAULT_CHAIN_ID,
        );

        let result = subject.send_transaction(
            &make_paying_wallet(b"gdasgsa"),
            &make_wallet("blah123"),
            9000,
            U256::from(1),
            2u64,
        );

        transport.assert_request("eth_sendRawTransaction", &[String::from(r#""0xf8a801847735940082dbe894cd6c588e005032dd882cd43bf53a32129be8130280b844a9059cbb00000000000000000000000000000000000000000000000000626c61683132330000000000000000000000000000000000000000000000000000082f79cd90002aa0210a8dc04a802e579493e9c3b0c6aca5d19197af17637e1c5ae61f3332746734a00ad3bddb042061f4ce99800fea66e36a684b1e168d16485dfdb2e4d2254f589e""#)]);
        transport.assert_no_more_requests();
        assert_eq!(result, Ok(H256::from_uint(&U256::from(1))));
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
            DEFAULT_CHAIN_ID,
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
        let converted_wei = to_wei(std::u64::MAX);

        assert_eq!(
            converted_wei,
            U256::from_dec_str(format!("{}000000000", std::u64::MAX).as_str()).unwrap()
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
