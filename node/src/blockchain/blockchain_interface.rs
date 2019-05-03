// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::wallet::Wallet;
use futures::future::{err, ok};
use futures::{future, Future};
use web3::transports::{EventLoopHandle, Http};
use web3::types::{BlockNumber, FilterBuilder, Log, H160, H256, U256};
use web3::Web3;

// HOT (Ropsten)
pub const TESTNET_CONTRACT_ADDRESS: H160 = H160 {
    0: [
        0xcd, 0x6c, 0x58, 0x8e, 0x00, 0x50, 0x32, 0xdd, 0x88, 0x2c, 0xd4, 0x3b, 0xf5, 0x3a, 0x32,
        0x12, 0x9b, 0xe8, 0x13, 0x02,
    ],
};

const TRANSACTION_LITERAL: H256 = H256 {
    0: [
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ],
};

fn remove_0x(s: &str) -> &str {
    if s.starts_with("0x") {
        &s[2..]
    } else {
        s
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Transaction {
    pub block_number: U256,
    pub from: Wallet,
    pub amount: U256,
}

#[derive(Debug, PartialEq)]
pub enum BlockchainError {
    InvalidUrl,
    InvalidAddress,
    InvalidResponse,
    QueryFailed,
}

pub trait BlockchainInterface {
    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Box<dyn Future<Item = Vec<Transaction>, Error = BlockchainError> + Send>;
}

pub struct BlockchainInterfaceClandestine {}

impl BlockchainInterface for BlockchainInterfaceClandestine {
    fn retrieve_transactions(
        &self,
        _start_block: u64,
        _recipient: &Wallet,
    ) -> Box<Future<Item = Vec<Transaction>, Error = BlockchainError> + Send> {
        Box::new(ok(vec![]))
    }
}

#[derive(Debug)]
pub struct BlockchainInterfaceRpc {
    contract_address: H160,
    _event_loop_handle: EventLoopHandle, // This must not be dropped for Web3 requests to be completed
    web3: Web3<Http>,
}

impl BlockchainInterface for BlockchainInterfaceRpc {
    fn retrieve_transactions(
        &self,
        start_block: u64,
        recipient: &Wallet,
    ) -> Box<dyn Future<Item = Vec<Transaction>, Error = BlockchainError> + Send> {
        let to_address = match remove_0x(&recipient.address).parse::<H160>() {
            Ok(x) => x.into(),
            Err(_) => return Box::new(err(BlockchainError::InvalidAddress)),
        };

        let filter = FilterBuilder::default()
            .address(vec![self.contract_address])
            .from_block(BlockNumber::Number(start_block))
            .to_block(BlockNumber::Latest)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![to_address]),
                None,
            )
            .build();

        let log_request = self.web3.eth().logs(filter);
        Box::new(log_request.then(|logs| {
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
                                Some(block_number) => Some(Transaction {
                                    block_number,
                                    from: Wallet::from(log.topics[1]),
                                    amount: U256::from(log.data.0.as_slice()),
                                }),
                                None => None,
                            })
                            .collect())
                    }
                }
                Err(_) => Err(BlockchainError::QueryFailed),
            })
        }))
    }
}

impl BlockchainInterfaceRpc {
    pub fn new(
        blockchain_service_url: String,
        contract_address: H160,
    ) -> Result<BlockchainInterfaceRpc, BlockchainError> {
        match Http::new(&blockchain_service_url) {
            Ok((_loop, http)) => Ok(BlockchainInterfaceRpc {
                contract_address,
                _event_loop_handle: _loop,
                web3: Web3::new(http),
            }),
            Err(_) => Err(BlockchainError::InvalidUrl),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::test_utils::find_free_port;
    use serde_json::Value;
    use simple_server::Server;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn blockchain_interface_rpc_retrieves_transactions() {
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();

        let (tx, rx) = mpsc::sync_channel(1337);
        thread::spawn(move || {
            Server::new(move |req, mut rsp| {
                tx.send(req.body().clone()).unwrap();
                Ok(rsp.body(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.as_bytes().to_vec())?)
            }).listen("127.0.0.1", &format!("{}", port));
        });

        let subject = BlockchainInterfaceRpc::new(
            format!("http://127.0.0.1:{}", port),
            TESTNET_CONTRACT_ADDRESS,
        )
        .unwrap();

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            )
            .wait()
            .unwrap();

        let body: Value = serde_json::de::from_slice(&rx.recv().unwrap()).unwrap();
        assert_eq!(
            format!("\"0x000000000000000000000000{}\"", &to[2..]),
            body["params"][0]["topics"][2].to_string(),
        );
        assert_eq!(
            vec![Transaction {
                block_number: U256::from(4_974_179),
                from: Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
                amount: U256::from(4_503_599_627_370_496u64)
            }],
            result,
        )
    }

    #[test]
    fn blockchain_interface_rpc_returns_an_error_if_the_blockchain_service_url_is_invalid() {
        let subject_result =
            BlockchainInterfaceRpc::new("http://λ:8545".to_string(), TESTNET_CONTRACT_ADDRESS);

        assert_eq!(
            BlockchainError::InvalidUrl,
            subject_result.expect_err("Expected an Err, got Ok")
        );
    }

    #[test]
    fn blockchain_interface_rpc_returns_an_error_if_the_to_address_is_invalid() {
        let subject = BlockchainInterfaceRpc::new(
            "http://127.0.0.1:8545".to_string(),
            TESTNET_CONTRACT_ADDRESS,
        )
        .unwrap();

        let result = subject
            .retrieve_transactions(42, &Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc"))
            .wait();

        assert_eq!(
            BlockchainError::InvalidAddress,
            result.expect_err("Expected an Err, got Ok")
        );
    }

    #[test]
    fn blockchain_interface_rpc_returns_an_error_if_a_response_with_too_few_topics_is_returned() {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d63100000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.as_bytes().to_vec())?)
            })
            .listen("127.0.0.1", &format!("{}", port));
        });

        let subject = BlockchainInterfaceRpc::new(
            format!("http://127.0.0.1:{}", port),
            TESTNET_CONTRACT_ADDRESS,
        )
        .unwrap();

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            )
            .wait();

        assert_eq!(
            BlockchainError::InvalidResponse,
            result.expect_err("Expected an Err, got Ok")
        );
    }

    #[test]
    fn blockchain_interface_rpc_returns_an_error_if_a_response_with_data_that_is_too_long_is_returned(
    ) {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(move |_req, mut rsp| {
                Ok(rsp.body(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d6310000001","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.as_bytes().to_vec())?)
            }).listen("127.0.0.1", &format!("{}", port));
        });

        let subject = BlockchainInterfaceRpc::new(
            format!("http://127.0.0.1:{}", port),
            TESTNET_CONTRACT_ADDRESS,
        )
        .unwrap();

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            )
            .wait();

        assert_eq!(Err(BlockchainError::InvalidResponse), result);
    }

    #[test]
    fn blockchain_interface_rpc_ignores_transaction_logs_that_have_no_block_number() {
        let port = find_free_port();

        thread::spawn(move || {
            Server::new(|_req, mut rsp| {
                Ok(rsp.body(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.as_bytes().to_vec())?)
            })
            .listen("127.0.0.1", &format!("{}", port));
        });

        let subject = BlockchainInterfaceRpc::new(
            format!("http://127.0.0.1:{}", port),
            TESTNET_CONTRACT_ADDRESS,
        )
        .unwrap();

        let result = subject
            .retrieve_transactions(
                42,
                &Wallet::new("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc"),
            )
            .wait();

        assert_eq!(Ok(vec![]), result);
    }
}
