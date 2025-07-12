// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{FailedTx, FailureReason};
use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
use crate::accountant::db_access_objects::utils::TxHash;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::CONTRACT_ABI;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError;
use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::sub_lib::wallet::Wallet;
use ethereum_types::{H256, U256, U64};
use futures::Future;
use serde_json::Value;
use std::fmt::Display;
use std::str::FromStr;
use web3::contract::{Contract, Options};
use web3::transports::{Batch, Http};
use web3::types::{Address, BlockNumber, Filter, Log, TransactionReceipt};
use web3::{Error, Web3};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxReceiptResult {
    RpcResponse(TxWithStatus),
    RequestError(TxReceiptRequestError),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxWithStatus {
    pub sent_tx: SentTx,
    pub status: TxStatus,
}

impl TxWithStatus {
    pub fn new(sent_tx: SentTx, status: TxStatus) -> Self {
        Self { sent_tx, status }
    }
}

impl From<TransactionReceipt> for TxStatus {
    fn from(receipt: TransactionReceipt) -> Self {
        match (receipt.status, receipt.block_hash, receipt.block_number) {
            (Some(status), Some(block_hash), Some(block_number)) if status == U64::from(1) => {
                TxStatus::Succeeded(TransactionBlock {
                    block_hash,
                    block_number,
                })
            }
            (Some(status), _, _) if status == U64::from(0) => todo!(), //TxStatus::Failed(TxBlockchainFailure::Unknown),
            _ => TxStatus::Pending,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TxStatus {
    Failed(TxBlockchainFailure),
    Succeeded(TransactionBlock),
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxBlockchainFailure {
    Unknown,
}

impl Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxStatus::Failed(reason) => {
                todo!("make sure there is an assertion for this new syntax")
            } //write!(f, "Failed({:?})", reason),
            TxStatus::Succeeded(block) => {
                write!(
                    f,
                    "Succeeded({},{:?})",
                    block.block_number, block.block_hash
                )
            }
            TxStatus::Pending => write!(f, "Pending"),
        }
    }
}

// TODO figure out where this could be used????
// impl FromStr for TxStatus {
//     type Err = String;
//
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         match s {
//             "Pending" => Ok(TxStatus::Pending),
//             "Failed" => Ok(TxStatus::Failed), // TODO: GH-631: This should be removed
//             s if s.starts_with("Succeeded") => {
//                 // The format is "Succeeded(block_number, block_hash)"
//                 let parts: Vec<&str> = s[10..s.len() - 1].split(',').collect();
//                 if parts.len() != 2 {
//                     return Err("Invalid Succeeded format".to_string());
//                 }
//                 let block_number: u64 = parts[0]
//                     .parse()
//                     .map_err(|_| "Invalid block number".to_string())?;
//                 let block_hash =
//                     H256::from_str(&parts[1][2..]).map_err(|_| "Invalid block hash".to_string())?;
//                 Ok(TxStatus::Succeeded(TransactionBlock {
//                     block_hash,
//                     block_number: U64::from(block_number),
//                 }))
//             }
//             _ => Err(format!("Unknown status: {}", s)),
//         }
//     }
// }

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxReceiptRequestError {
    tx_hash: TxHash,
    err_msg: String,
}

impl TxReceiptRequestError {
    pub fn new(tx_hash: TxHash, err_msg: String) -> Self {
        todo!()
        // Self {
        //     tx_hash,
        //     err_msg
        // }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct TransactionBlock {
    pub block_hash: H256,
    pub block_number: U64,
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
            self.web3
                .eth()
                .gas_price()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_block_number(&self) -> Box<dyn Future<Item = U64, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .block_number()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_transaction_id(
        &self,
        address: Address,
    ) -> Box<dyn Future<Item = U256, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .transaction_count(address, Some(BlockNumber::Pending))
                .map_err(move |e| QueryFailed(format!("{} for wallet {}", e, address))),
        )
    }

    fn get_transaction_receipt_in_batch(
        &self,
        hash_vec: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<Result<Value, Error>>, Error = BlockchainError>> {
        hash_vec.into_iter().for_each(|hash| {
            self.web3_batch.eth().transaction_receipt(hash);
        });

        Box::new(
            self.web3_batch
                .transport()
                .submit_batch()
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_contract_address(&self) -> Address {
        self.contract.address()
    }

    fn get_transaction_logs(
        &self,
        filter: Filter,
    ) -> Box<dyn Future<Item = Vec<Log>, Error = BlockchainError>> {
        Box::new(
            self.web3
                .eth()
                .logs(filter)
                .map_err(|e| QueryFailed(e.to_string())),
        )
    }

    fn get_web3_batch(&self) -> Web3<Batch<Http>> {
        self.web3_batch.clone()
    }
}

impl LowBlockchainIntWeb3 {
    pub fn new(transport: Http, contract_address: Address) -> Self {
        let web3 = Web3::new(transport.clone());
        let web3_batch = Web3::new(Batch::new(transport));
        let contract = Contract::from_json(web3.eth(), contract_address, CONTRACT_ABI.as_bytes())
            .expect("Unable to initialize contract.");

        Self {
            web3,
            web3_batch,
            contract,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::TRANSACTION_LITERAL;
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface};
    use crate::blockchain::test_utils::{make_blockchain_interface_web3, make_tx_hash};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_wallet;
    use ethereum_types::{H256, U64};
    use futures::Future;
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;
    use std::str::FromStr;
    use web3::types::{BlockNumber, Bytes, FilterBuilder, Log, TransactionReceipt, U256};
    use crate::accountant::db_access_objects::sent_payable_dao::SentTx;
    use crate::accountant::test_utils::make_sent_tx;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TxWithStatus, TransactionBlock, TxBlockchainFailure, TxStatus};

    #[test]
    fn get_transaction_fee_balance_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x23".to_string(), 1)
            .start();
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_fee_balance(wallet.address())
            .wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_fee_balance_returns_an_error_for_unintelligible_response_to_requesting_eth_balance(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_fee_balance(
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
    fn get_gas_price_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x01".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject.lower_interface().get_gas_price().wait().unwrap();

        assert_eq!(result, 1.into());
    }

    #[test]
    fn get_gas_price_returns_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(port);

        let error = subject
            .lower_interface()
            .get_gas_price()
            .wait()
            .unwrap_err();

        assert_eq!(
            error,
            QueryFailed("Transport error: Error(IncompleteMessage)".to_string())
        );
    }

    #[test]
    fn get_block_number_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject.lower_interface().get_block_number().wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_block_number_returns_an_error() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("trash".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let error = subject
            .lower_interface()
            .get_block_number()
            .wait()
            .unwrap_err();

        assert_eq!(
            error,
            QueryFailed(
                "Decoder error: Error(\"0x prefix is missing\", line: 0, column: 0)".to_string()
            )
        );
    }

    #[test]
    fn get_transaction_id_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x23".to_string(), 1)
            .start();
        let subject = make_blockchain_interface_web3(port);
        let wallet = &Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();

        let result = subject
            .lower_interface()
            .get_transaction_id(wallet.address())
            .wait();

        assert_eq!(result, Ok(35.into()));
    }

    #[test]
    fn get_transaction_id_returns_an_error_for_unintelligible_response() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0xFFFQ".to_string(), 0)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_transaction_id(
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
            .ok_response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(),
                0,
            )
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_service_fee_balance(
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
            .ok_response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFQ".to_string(),
                0,
            )
            .start();
        let expected_err_msg = "Invalid hex";
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .lower_interface()
            .get_service_fee_balance(
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
    fn get_transaction_logs_works() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x0000000000000000000000000070617965655f31",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e3310720058c51f0de456e273c626cdd3",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                },
                {
                  "address": "0x06012c8cf97bead5deae237070f9587f8e7a266d",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e3310720058c51f0de456e273c626cdd3",
                  "logIndex": "0x57",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x788b1442414cb9c9a36dba2abe250763161a6f6395788a2e808f1b34e92beec1",
                  "transactionIndex": "0x54"
                }
              ]
            }"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);
        let contract_address = subject.chain.rec().contract;
        let start_block = BlockNumber::Number(U64::from(100));
        let response_block_number = BlockNumber::Number(U64::from(200));
        let recipient = make_wallet("test_wallet").address();
        let filter = FilterBuilder::default()
            .address(vec![contract_address])
            .from_block(start_block)
            .to_block(response_block_number)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.into()]),
                None,
            )
            .build();

        let result = subject
            .lower_interface()
            .get_transaction_logs(filter)
            .wait()
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            Log {
                address: make_wallet("payee_1").address(),
                topics: vec![H256::from_str(
                    "241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                )
                .unwrap()],
                data: Bytes(vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 51, 16, 114, 0, 88, 197, 31, 13, 228,
                    86, 226, 115, 198, 38, 205, 211
                ]),
                block_hash: Some(
                    H256::from_str(
                        "7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70"
                    )
                    .unwrap()
                ),
                block_number: Some(U64::from(6040059)),
                transaction_hash: Some(
                    H256::from_str(
                        "3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50"
                    )
                    .unwrap()
                ),
                transaction_index: Some(U64::from(29)),
                log_index: Some(U256::from(29)),
                transaction_log_index: None,
                log_type: None,
                removed: Some(false),
            }
        );
    }

    #[test]
    fn get_transaction_logs_fails() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .raw_response(r#"{
              "jsonrpc": "2.0",
              "id": 1,
              "result": [
                {
                  "address": "0x0000000000000000000000000070617965655f31",
                  "blockHash": "0x7c5a35e9cb3e8ae0e221ab470abae9d446c3a5626ce6689fc777dcffcab52c70",
                  "blockNumber": "0x5c29fb",
                  "data": "0x0000000000000000000000003e331",
                  "logIndex": "0x1d",
                  "removed": false,
                  "topics": [
                    "0x241ea03ca20251805084d27d4440371c34a0b85ff108f6bb5611248f73818b80"
                  ],
                  "transactionHash": "0x3dc91b98249fa9f2c5c37486a2427a3a7825be240c1c84961dfb3063d9c04d50",
                  "transactionIndex": "0x1d"
                }
              ]
            }"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);
        let contract_address = subject.chain.rec().contract;
        let start_block = BlockNumber::Number(U64::from(100));
        let response_block_number = BlockNumber::Number(U64::from(200));
        let recipient = make_wallet("test_wallet").address();
        let filter = FilterBuilder::default()
            .address(vec![contract_address])
            .from_block(start_block)
            .to_block(response_block_number)
            .topics(
                Some(vec![TRANSACTION_LITERAL]),
                None,
                Some(vec![recipient.into()]),
                None,
            )
            .build();

        let result = subject
            .lower_interface()
            .get_transaction_logs(filter)
            .wait()
            .unwrap_err();

        assert_eq!(
            result,
            QueryFailed(
                "Decoder error: Error(\"Invalid hex: Invalid input length\", line: 0, column: 0)"
                    .to_string()
            )
        );
    }

    #[test]
    fn transaction_receipt_can_be_converted_to_successful_transaction() {
        let tx_status = test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
            Some(U64::from(1)),
            Some(H256::from_low_u64_be(0x1234)),
            Some(U64::from(10)),
            H256::from_low_u64_be(0x5678),
        );

        match tx_status {
            TxStatus::Succeeded(ref block) => {
                assert_eq!(block.block_hash, H256::from_low_u64_be(0x1234));
                assert_eq!(block.block_number, U64::from(10));
            }
            _ => panic!("Expected status to be Succeeded"),
        }
    }

    #[test]
    fn transaction_receipt_can_be_converted_to_failed_transaction() {
        let tx_status = test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
            Some(U64::from(0)),
            None,
            None,
            H256::from_low_u64_be(0x5678),
        );

        assert_eq!(tx_status, TxStatus::Failed(TxBlockchainFailure::Unknown));
    }

    #[test]
    fn transaction_receipt_can_be_converted_to_pending_transaction_no_status() {
        let tx_status = test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
            None,
            None,
            None,
            H256::from_low_u64_be(0x5678),
        );

        assert_eq!(tx_status, TxStatus::Pending);
    }

    #[test]
    fn transaction_receipt_can_be_converted_to_pending_transaction_no_block_info() {
        let tx_status = test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
            Some(U64::from(1)),
            None,
            None,
            H256::from_low_u64_be(0x5678),
        );

        assert_eq!(tx_status, TxStatus::Pending);
    }

    #[test]
    fn transaction_receipt_can_be_converted_to_pending_transaction_no_status_and_block_info() {
        let tx_status = test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
            Some(U64::from(1)),
            Some(H256::from_low_u64_be(0x1234)),
            None,
            H256::from_low_u64_be(0x5678),
        );

        assert_eq!(tx_status, TxStatus::Pending);
    }

    #[test]
    fn tx_status_display_works() {
        // Test Failed
        assert_eq!(
            TxStatus::Failed(TxBlockchainFailure::Unknown).to_string(),
            "Failed"
        );

        // Test Pending
        assert_eq!(TxStatus::Pending.to_string(), "Pending");

        // Test Succeeded
        let block_number = U64::from(12345);
        let block_hash = H256::from_low_u64_be(0xabcdef);
        let succeeded = TxStatus::Succeeded(TransactionBlock {
            block_hash,
            block_number,
        });
        assert_eq!(
            succeeded.to_string(),
            format!("Succeeded({},0x{:x})", block_number, block_hash)
        );
    }
    //
    // #[test]
    // fn tx_status_from_str_works() {
    //     // Test Pending
    //     assert_eq!(TxStatus::from_str("Pending"), Ok(TxStatus::Pending));
    //
    //     // Test Failed
    //     assert_eq!(TxStatus::from_str("Failed"), Ok(TxStatus::Failed));
    //
    //     // Test Succeeded with valid input
    //     let block_number = 123456789;
    //     let block_hash = H256::from_low_u64_be(0xabcdef);
    //     let input = format!("Succeeded({},0x{:x})", block_number, block_hash);
    //     assert_eq!(
    //         TxStatus::from_str(&input),
    //         Ok(TxStatus::Succeeded(TransactionBlock {
    //             block_hash,
    //             block_number: U64::from(block_number),
    //         }))
    //     );
    //
    //     // Test Succeeded with invalid format
    //     assert_eq!(
    //         TxStatus::from_str("Succeeded(123)"),
    //         Err("Invalid Succeeded format".to_string())
    //     );
    //
    //     // Test Succeeded with invalid block number
    //     assert_eq!(
    //         TxStatus::from_str(
    //             "Succeeded(abc,0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef)"
    //         ),
    //         Err("Invalid block number".to_string())
    //     );
    //
    //     // Test Succeeded with invalid block hash
    //     assert_eq!(
    //         TxStatus::from_str("Succeeded(123,0xinvalidhash)"),
    //         Err("Invalid block hash".to_string())
    //     );
    //
    //     // Test unknown status
    //     assert_eq!(
    //         TxStatus::from_str("InProgress"),
    //         Err("Unknown status: InProgress".to_string())
    //     );
    // }

    fn test_deriving_tx_status_from_tx_receipt_and_adding_to_sent_tx(
        num_status_opt: Option<U64>,
        block_hash_opt: Option<H256>,
        block_number_opt: Option<U64>,
        transaction_hash: H256,
    ) -> TxStatus {
        let receipt = TransactionReceipt {
            status: num_status_opt,
            root: None,
            block_hash: block_hash_opt,
            block_number: block_number_opt,
            cumulative_gas_used: Default::default(),
            gas_used: None,
            contract_address: None,
            transaction_hash,
            transaction_index: Default::default(),
            logs: vec![],
            logs_bloom: Default::default(),
        };

        receipt.into()
    }
}
