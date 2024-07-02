// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethereum_types::{H256, U256, U64};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{CONTRACT_ABI, ResultForReceipt};
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use futures::Future;
use itertools::Itertools;
use rlp::Prototype::Null;
use serde::Deserializer;
use serde_json::Error;
use web3::contract::{Contract, Options};
use web3::transports::{Batch, Http};
use web3::types::{Address, BlockNumber, TransactionReceipt};
use web3::{Web3};
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
use crate::blockchain::blockchain_interface_utils::merged_output_data;

#[derive(Debug, PartialEq, Clone)]
pub enum TransactionReceiptResult {
    NotPresent,
    Found(TransactionReceipt),
    Error(String),
}

pub struct LowBlockchainIntWeb3 {
    web3: Web3<Http>,
    web3_batch: Web3<Batch<Http>>,
    contract: Contract<Http>,
    // TODO waiting for GH-707 (note: consider to query the balances together with the id)
}

impl LowBlockchainInt for LowBlockchainIntWeb3 {
    fn get_transaction_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .balance(address, None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_service_fee_balance(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.contract
                .query("balanceOf", address, None, Options::default(), None)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_gas_price(&self) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3.eth().gas_price()
                .map_err(|e| QueryFailed(e.to_string()) )
        )
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        Box::new(
            self.web3.eth()
                .block_number()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_id(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3.eth()
                .transaction_count(address, Some(BlockNumber::Pending))
                .map_err(move |e| {
                    QueryFailed(format!("{} for wallet {}", e, address))
                }),
        )
    }

    fn get_transaction_receipt(&self, hash: H256) -> Box<dyn Future<Item = Option<TransactionReceipt>, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .transaction_receipt(hash)
                .map_err(|e| QueryFailed(e.to_string()))
        )
    }

    fn get_transaction_receipt_batch(&self, hash_vec: Vec<H256>) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>> {
        let _ = hash_vec.into_iter().map(|hash| {
            self.web3_batch.eth().transaction_receipt(hash);
        });
        Box::new(
            self.web3_batch
                .transport()
                .submit_batch()
                .map_err(|e| QueryFailed(e.to_string()))
                .and_then(move |batch_response| {
                    Ok(
                        batch_response.into_iter().map(|response| {
                            match response {
                                Ok(result) => {
                                    match serde_json::from_value::<TransactionReceipt>(result) {
                                        Ok(receipt) => {
                                            TransactionReceiptResult::Found(receipt)
                                        }
                                        Err(e) => {
                                            if e.to_string().contains("invalid type: null") {
                                                TransactionReceiptResult::NotPresent
                                            } else {
                                                TransactionReceiptResult::Error(e.to_string())
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    TransactionReceiptResult::Error(e.to_string())
                                }
                            }
                        }).collect::<Vec<TransactionReceiptResult>>()
                    )
                }),
        )
    }
}

impl LowBlockchainIntWeb3 {
    pub fn new(transport: Http, contract_address: Address) -> Self {
        let web3= Web3::new(transport.clone());
        let web3_batch = Web3::new(Batch::new(transport));
        let contract = Contract::from_json(
            web3.eth(),
            contract_address,
            CONTRACT_ABI.as_bytes(),
        ).expect("Unable to initialize contract.");

        Self {
            web3,
            web3_batch,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use crate::blockchain::blockchain_interface::lower_level_interface::{LowBlockchainInt};
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::sub_lib::wallet::Wallet;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use ethabi::Address;
    use ethereum_types::{H256, U64};
    use futures::Future;
    use web3::transports::Http;
    use web3::types::{H2048, TransactionReceipt, U256};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TransactionReceiptResult;
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::test_utils::{make_blockchain_interface_web3, make_tx_hash};
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::{assert_string_contains, make_wallet};

    fn tmp_nested_get_transaction_fee_balance_future(subject: Box<dyn LowBlockchainInt>, address: Address) -> Box<dyn Future<Item = (), Error = String>> {
        Box::new(
            subject.get_transaction_fee_balance(address).map_err(|e| {
                format!("Error: 1 {:?}", e)
            }).and_then(move |balance_1| {
                subject.get_transaction_fee_balance(address).map_err(|e| {
                    format!("Error: 2 {:?}", e)
                }).and_then(move |balance_2| {
                    subject.get_transaction_fee_balance(address).map_err(|e| {
                        format!("Error: 3 {:?}", e)
                    }).and_then(move |balance_3| {
                        eprintln!("balance_1: {:?}", balance_1);
                        eprintln!("balance_2: {:?}", balance_2);
                        eprintln!("balance_3: {:?}", balance_3);
                        Ok(())
                    })
                })
            })
        )
    }

    #[test]
    fn tmp_nested_future_test() {
        let port = find_free_port();
        let blockchain_client_server = MBCSBuilder::new(port)
            .response("0xDEADBEEF".to_string(), 0)
            .response("0xDEADBEEE".to_string(), 0)
            .response("0xDEADBEED".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let wallet = make_wallet("test_wallet");
        let address = wallet.address();

        let result = tmp_nested_get_transaction_fee_balance_future(subject.lower_interface(), address);

        result.wait().expect("TODO: panic message");
    }

    #[test]
    fn get_transaction_fee_balance_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_fee_balance(wallet.address()).wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_gas_price_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response( "0x01".to_string(),1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_gas_price().wait().unwrap();

        assert_eq!(result, 1.into());
    }

    #[test]
    fn get_gas_price_returns_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(Some(port));

        let error = subject.lower_interface().get_gas_price().wait().unwrap_err();

        assert_eq!(error, QueryFailed("Transport error: Error(IncompleteMessage)".to_string()));
    }

    #[test]
    fn get_block_number_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_block_number().wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_block_number_returns_an_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("trash".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let error = subject.lower_interface().get_block_number().wait().unwrap_err();

        assert_eq!(
            error,
            QueryFailed("Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0)".to_string())
        );
    }

    #[test]
    fn get_transaction_id_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result = subject.lower_interface().get_transaction_id(wallet.address()).wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_id_returns_an_error_for_unintelligible_response() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_id(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
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
    fn get_transaction_fee_balance_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_transaction_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
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
    fn get_token_balance_can_retrieve_token_balance_of_a_wallet() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(Some(port));
        let contract = blockchain_interface_web3.get_contract();
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_service_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait()
            .unwrap();

        assert_eq!(result, U256::from(65_535));
    }

    #[test]
    fn get_token_balance_returns_error_for_unintelligible_response_to_token_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFQ".to_string(),
                0,
            )
            .start();
        let blockchain_interface_web3 = make_blockchain_interface_web3(Some(port));
        let contract = blockchain_interface_web3.get_contract();
        let expected_err_msg = "Invalid hex";
        let subject = make_blockchain_interface_web3(Some(port));

        let result = subject.lower_interface().get_service_fee_balance(
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                .unwrap()
                .address(),
        )
            .wait();

        let err_msg = match result {
            Err(BlockchainError::QueryFailed(msg)) => msg,
            x => panic!("Expected BlockchainError::QueryFailed, but got {:?}", x),
        };
        assert!(
            err_msg.contains(expected_err_msg),
            "Expected this fragment {} in this err msg: {}",
            expected_err_msg,
            err_msg
        )
    }

    #[test]
    fn transaction_receipt_works() {
        let port = find_free_port();
        let blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":{"transactionHash":"0xa128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e","blockHash":"0x6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18","blockNumber":"0xb0328d","contractAddress":null,"cumulativeGasUsed":"0x60ef","effectiveGasPrice":"0x22ecb25c00","from":"0x7424d05b59647119b01ff81e2d3987b6c358bf9c","gasUsed":"0x60ef","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000","status":"0x0","to":"0x384dec25e03f94931767ce4c3556168468ba24c3","transactionIndex":"0x0","type":"0x0"}}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let tx_hash =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();

        let result = subject.lower_interface().get_transaction_receipt(tx_hash).wait();

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
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
            .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceWeb3::new(transport, event_loop_handle, chain);
        let tx_hash = make_tx_hash(4564546);

        let actual_error = subject.lower_interface().get_transaction_receipt(tx_hash).wait().unwrap_err();
        let error_message = if let BlockchainError::QueryFailed(em) = actual_error {
            em
        } else {
            panic!("Expected BlockchainError::QueryFailed(msg)");
        };
        assert_string_contains(
            error_message.as_str(),
            "Transport error: Error(Connect, Os { code: ",
        );
        assert_string_contains(
            error_message.as_str(),
            ", kind: ConnectionRefused, message: ",
        );
    }

    #[test]
    fn transaction_receipt_batch_works() {
        let port = find_free_port();
        let blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":{"transactionHash":"0xa128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e","blockHash":"0x6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18","blockNumber":"0xb0328d","contractAddress":null,"cumulativeGasUsed":"0x60ef","effectiveGasPrice":"0x22ecb25c00","from":"0x7424d05b59647119b01ff81e2d3987b6c358bf9c","gasUsed":"0x60ef","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000","status":"0x0","to":"0x384dec25e03f94931767ce4c3556168468ba24c3","transactionIndex":"0x0","type":"0x0"}}"#.to_string())
            .response("trash".to_string(), 0)
            .end_batch()
            .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let tx_hash_1 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e").unwrap();
        let tx_hash_2 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f").unwrap();
        let tx_hash_3 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0a").unwrap();
        let tx_hash_4 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0b").unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2, tx_hash_3, tx_hash_4];

        let result = subject.lower_interface().get_transaction_receipt_batch(tx_hash_vec).wait().unwrap();

        assert_eq!(result[0], TransactionReceiptResult::Error("RPC error: Error { code: ServerError(429), message: \"The requests per second (RPS) of your requests are higher than your plan allows.\", data: None }".to_string()));
        assert_eq!(result[1], TransactionReceiptResult::NotPresent);
        assert_eq!(result[2], TransactionReceiptResult::Found(TransactionReceipt{
            transaction_hash: tx_hash_1,
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
        }));
        assert_eq!(result[3], TransactionReceiptResult::Error("invalid type: string \"trash\", expected struct Receipt".to_string()));
    }

    #[test]
    fn transaction_receipt_batch_fails_on_submit_batch() {
        let port = find_free_port();
        let blockchain_client_server = MBCSBuilder::new(port)
             .start();
        let subject = make_blockchain_interface_web3(Some(port));
        let tx_hash_1 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e").unwrap();
        let tx_hash_2 = H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f").unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2];

        let result = subject.lower_interface().get_transaction_receipt_batch(tx_hash_vec).wait().unwrap_err();

        assert_eq!(result, BlockchainError::QueryFailed("Transport error: Error(IncompleteMessage)".to_string()));
    }

}
