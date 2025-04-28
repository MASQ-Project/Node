// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod lower_level_interface_web3;
mod utils;

use std::cmp::PartialEq;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_interface::data_structures::errors::{BlockchainError, PayableTransactionError};
use crate::blockchain::blockchain_interface::data_structures::{BlockchainTransaction, ProcessedPayableFallible};
use crate::blockchain::blockchain_interface::lower_level_interface::LowBlockchainInt;
use crate::blockchain::blockchain_interface::RetrievedBlockchainTransactions;
use crate::blockchain::blockchain_interface::{BlockchainAgentBuildError, BlockchainInterface};
use crate::sub_lib::wallet::Wallet;
use futures::{Future};
use indoc::indoc;
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use std::convert::{From, TryInto};
use std::fmt::Debug;
use actix::Recipient;
use ethereum_types::U64;
use web3::transports::{EventLoopHandle, Http};
use web3::types::{Address, Log, H256, U256, FilterBuilder, TransactionReceipt, BlockNumber};
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::{BlockMarker, BlockScanRange, PendingPayableFingerprintSeeds};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{LowBlockchainIntWeb3, TransactionReceiptResult, TxReceipt, TxStatus};
use crate::blockchain::blockchain_interface::blockchain_interface_web3::utils::{create_blockchain_agent_web3, send_payables_within_batch, BlockchainAgentFutureResult};

const CONTRACT_ABI: &str = indoc!(
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

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub const FRESH_START_BLOCK: u64 = 0;

pub const BLOCKCHAIN_SERVICE_URL_NOT_SPECIFIED: &str =
    "To avoid being delinquency-banned, you should \
restart the Node with a value for blockchain-service-url";

pub struct BlockchainInterfaceWeb3 {
    pub logger: Logger,
    chain: Chain,
    gas_limit_const_part: u128,
    // This must not be dropped for Web3 requests to be completed
    _event_loop_handle: EventLoopHandle,
    transport: Http,
}

pub const GWEI: U256 = U256([1_000_000_000u64, 0, 0, 0]);

pub fn to_wei(gwub: u64) -> U256 {
    let subgwei = U256::from(gwub);
    subgwei.full_mul(GWEI).try_into().expect("Internal Error")
}

impl BlockchainInterface for BlockchainInterfaceWeb3 {
    fn contract_address(&self) -> Address {
        self.chain.rec().contract
    }

    fn get_chain(&self) -> Chain {
        self.chain
    }

    fn lower_interface(&self) -> Box<dyn LowBlockchainInt> {
        Box::new(LowBlockchainIntWeb3::new(
            self.transport.clone(),
            self.contract_address(),
        ))
    }

    fn retrieve_transactions(
        &self,
        start_block_marker: BlockMarker,
        scan_range: BlockScanRange,
        recipient: Address,
    ) -> Box<dyn Future<Item = RetrievedBlockchainTransactions, Error = BlockchainError>> {
        let lower_level_interface = self.lower_interface();
        let logger = self.logger.clone();
        let contract_address = lower_level_interface.get_contract_address();
        let num_chain_id = self.chain.rec().num_chain_id;
        Box::new(
            lower_level_interface.get_block_number().then(move |rpc_block_number_result| {
                let start_block_number = match start_block_marker {
                    BlockMarker::Uninitialized => match rpc_block_number_result {
                        Ok(latest_block) => { BlockNumber::Number(latest_block) }
                        Err(_) => { BlockNumber::Latest }
                    },
                    BlockMarker::Value(number) => BlockNumber::Number(U64::from(number)),
                };
                let end_block_marker = Self::calculate_end_block_marker(start_block_marker, scan_range, rpc_block_number_result, &logger);
                let end_block_number = match end_block_marker {
                    BlockMarker::Uninitialized => { BlockNumber::Latest }
                    BlockMarker::Value(number) => { BlockNumber::Number(U64::from(number)) }
                };
                debug!(
                    logger,
                    "Retrieving transactions from start block: {:?} to end block: {:?} for: {} chain_id: {} contract: {:#x}",
                    start_block_number,
                    end_block_number,
                    recipient,
                    num_chain_id,
                    contract_address
                );
                let filter = FilterBuilder::default()
                    .address(vec![contract_address])
                    .from_block(start_block_number)
                    .to_block(end_block_number)
                    .topics(
                        Some(vec![TRANSACTION_LITERAL]),
                        None,
                        Some(vec![recipient.into()]),
                        None,
                    )
                    .build();
                lower_level_interface.get_transaction_logs(filter)
                    .then(move |logs_result| {
                        trace!(logger, "Transaction logs retrieval completed: {:?}", logs_result);
                        match Self::handle_transaction_logs(logs_result, &logger) {
                            Err(e) => Err(e),
                            Ok(transactions) => {
                                let new_start_block = Self::find_new_start_block(&transactions, start_block_marker, end_block_marker, &logger);
                                Ok(RetrievedBlockchainTransactions {
                                    new_start_block,
                                    transactions,
                                })
                            }
                        }
                    })
            },
            )
        )
    }

    fn build_blockchain_agent(
        &self,
        consuming_wallet: Wallet,
    ) -> Box<dyn Future<Item = Box<dyn BlockchainAgent>, Error = BlockchainAgentBuildError>> {
        let wallet_address = consuming_wallet.address();
        let gas_limit_const_part = self.gas_limit_const_part;
        // TODO: Would it be better to wrap these 3 calls into a single batch call?
        let get_gas_price = self.lower_interface().get_gas_price();
        let get_transaction_fee_balance = self
            .lower_interface()
            .get_transaction_fee_balance(wallet_address);
        let get_service_fee_balance = self
            .lower_interface()
            .get_service_fee_balance(wallet_address);
        let chain = self.chain;

        Box::new(
            get_gas_price
                .map_err(BlockchainAgentBuildError::GasPrice)
                .and_then(move |gas_price_wei| {
                    get_transaction_fee_balance
                        .map_err(move |e| {
                            BlockchainAgentBuildError::TransactionFeeBalance(wallet_address, e)
                        })
                        .and_then(move |transaction_fee_balance| {
                            get_service_fee_balance
                                .map_err(move |e| {
                                    BlockchainAgentBuildError::ServiceFeeBalance(wallet_address, e)
                                })
                                .and_then(move |masq_token_balance| {
                                    let blockchain_agent_future_result =
                                        BlockchainAgentFutureResult {
                                            gas_price_wei,
                                            transaction_fee_balance,
                                            masq_token_balance,
                                        };
                                    Ok(create_blockchain_agent_web3(
                                        gas_limit_const_part,
                                        blockchain_agent_future_result,
                                        consuming_wallet,
                                        chain,
                                    ))
                                })
                        })
                }),
        )
    }

    fn process_transaction_receipts(
        &self,
        transaction_hashes: Vec<H256>,
    ) -> Box<dyn Future<Item = Vec<TransactionReceiptResult>, Error = BlockchainError>> {
        Box::new(
            self.lower_interface()
                .get_transaction_receipt_in_batch(transaction_hashes.clone())
                .map_err(move |e| e)
                .and_then(move |batch_response| {
                    Ok(batch_response
                        .into_iter()
                        .zip(transaction_hashes)
                        .map(|(response, hash)| match response {
                            Ok(result) => {
                                match serde_json::from_value::<TransactionReceipt>(result) {
                                    Ok(receipt) => {
                                        TransactionReceiptResult::RpcResponse(receipt.into())
                                    }
                                    Err(e) => {
                                        if e.to_string().contains("invalid type: null") {
                                            TransactionReceiptResult::RpcResponse(TxReceipt {
                                                transaction_hash: hash,
                                                status: TxStatus::Pending,
                                            })
                                        } else {
                                            TransactionReceiptResult::LocalError(e.to_string())
                                        }
                                    }
                                }
                            }
                            Err(e) => TransactionReceiptResult::LocalError(e.to_string()),
                        })
                        .collect::<Vec<TransactionReceiptResult>>())
                }),
        )
    }

    fn submit_payables_in_batch(
        &self,
        logger: Logger,
        agent: Box<dyn BlockchainAgent>,
        fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
        affordable_accounts: Vec<PayableAccount>,
    ) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>>
    {
        let consuming_wallet = agent.consuming_wallet().clone();
        let web3_batch = self.lower_interface().get_web3_batch();
        let get_transaction_id = self
            .lower_interface()
            .get_transaction_id(consuming_wallet.address());
        let gas_price_wei = agent.agreed_fee_per_computation_unit();
        let chain = agent.get_chain();

        Box::new(
            get_transaction_id
                .map_err(PayableTransactionError::TransactionID)
                .and_then(move |pending_nonce| {
                    send_payables_within_batch(
                        &logger,
                        chain,
                        &web3_batch,
                        consuming_wallet,
                        gas_price_wei,
                        pending_nonce,
                        fingerprints_recipient,
                        affordable_accounts,
                    )
                }),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct HashAndAmount {
    pub hash: H256,
    pub amount: u128,
}

impl BlockchainInterfaceWeb3 {
    pub fn new(transport: Http, event_loop_handle: EventLoopHandle, chain: Chain) -> Self {
        let gas_limit_const_part = Self::web3_gas_limit_const_part(chain);

        Self {
            logger: Logger::new("BlockchainInterface"),
            chain,
            gas_limit_const_part,
            _event_loop_handle: event_loop_handle,
            transport,
        }
    }

    pub fn web3_gas_limit_const_part(chain: Chain) -> u128 {
        match chain {
            Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
            Chain::PolyMainnet | Chain::PolyAmoy | Chain::BaseMainnet | Chain::BaseSepolia => {
                70_000
            }
        }
    }

    fn extract_transactions_from_logs(logs: Vec<Log>) -> Vec<BlockchainTransaction> {
        logs.iter()
            .filter_map(|log: &Log| match log.block_number {
                None => None,
                Some(block_number) => {
                    let wei_amount = U256::from(log.data.0.as_slice()).as_u128();
                    Some(BlockchainTransaction {
                        block_number: block_number.as_u64(),
                        from: Wallet::from(log.topics[1]),
                        wei_amount,
                    })
                }
            })
            .collect()
    }

    fn find_highest_block_marker_from_txs(transactions: &[BlockchainTransaction]) -> BlockMarker {
        transactions
            .iter()
            .fold(BlockMarker::Uninitialized, |max, tx| match max {
                BlockMarker::Value(current_max) => {
                    BlockMarker::Value(current_max.max(tx.block_number))
                }
                BlockMarker::Uninitialized => BlockMarker::Value(tx.block_number),
            })
    }

    fn find_new_start_block(
        transactions: &[BlockchainTransaction],
        start_block_marker: BlockMarker,
        end_block_marker: BlockMarker,
        logger: &Logger,
    ) -> BlockMarker {
        match end_block_marker {
            BlockMarker::Value(end_block_number) => BlockMarker::Value(end_block_number + 1),
            BlockMarker::Uninitialized => {
                match Self::find_highest_block_marker_from_txs(transactions) {
                    BlockMarker::Value(block_number) => {
                        debug!(
                            logger,
                            "Discovered new start block number from transaction logs: {:?}",
                            block_number + 1
                        );

                        BlockMarker::Value(block_number + 1)
                    }
                    BlockMarker::Uninitialized => match start_block_marker {
                        BlockMarker::Value(start_block) => BlockMarker::Value(start_block + 1),
                        BlockMarker::Uninitialized => BlockMarker::Uninitialized,
                    },
                }
            }
        }
    }

    fn calculate_end_block_marker(
        start_block_marker: BlockMarker,
        scan_range: BlockScanRange,
        rpc_block_number_result: Result<U64, BlockchainError>,
        logger: &Logger,
    ) -> BlockMarker {
        let locally_determined_end_block_marker = match (start_block_marker, scan_range) {
            (BlockMarker::Value(start_block), BlockScanRange::Range(scan_range_number)) => {
                BlockMarker::Value(start_block + scan_range_number)
            }
            (_, _) => BlockMarker::Uninitialized,
        };
        match rpc_block_number_result {
            Ok(response_block) => {
                let response_block = response_block.as_u64();
                match locally_determined_end_block_marker {
                    BlockMarker::Uninitialized => BlockMarker::Value(response_block),
                    BlockMarker::Value(local_end_block_number) => {
                        BlockMarker::Value(local_end_block_number.min(response_block))
                    }
                }
            }
            Err(e) => {
                debug!(
                    logger,
                    "Using locally calculated end block number: '{:?}' due to error {:?}",
                    locally_determined_end_block_marker,
                    e
                );
                locally_determined_end_block_marker
            }
        }
    }

    fn handle_transaction_logs(
        logs_result: Result<Vec<Log>, BlockchainError>,
        logger: &Logger,
    ) -> Result<Vec<BlockchainTransaction>, BlockchainError> {
        let logs = logs_result?;
        let logs_len = logs.len();
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
            let transactions: Vec<BlockchainTransaction> =
                Self::extract_transactions_from_logs(logs);
            debug!(logger, "Retrieved transactions: {:?}", transactions);
            if transactions.is_empty() && logs_len != transactions.len() {
                warning!(
                    logger,
                    "Retrieving transactions: logs: {}, transactions: {}",
                    logs_len,
                    transactions.len()
                )
            }

            Ok(transactions)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, CONTRACT_ABI, REQUESTS_IN_PARALLEL, TRANSACTION_LITERAL,
        TRANSFER_METHOD_ID,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::BlockchainError::QueryFailed;
    use crate::blockchain::blockchain_interface::data_structures::BlockchainTransaction;
    use crate::blockchain::blockchain_interface::{
        BlockchainAgentBuildError, BlockchainError, BlockchainInterface,
        RetrievedBlockchainTransactions,
    };
    use crate::blockchain::test_utils::{
        all_chains, make_blockchain_interface_web3, ReceiptResponseBuilder,
    };
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use ethsign_crypto::Keccak256;
    use futures::Future;
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use web3::transports::Http;
    use web3::types::{H256, U256};
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::{TransactionBlock, TxReceipt, TxStatus, GAS_PRICE_INCREASE_PERCENTAGE};

    #[test]
    fn constants_are_correct() {
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
        assert_eq!(CONTRACT_ABI, contract_abi_expected);
        assert_eq!(TRANSACTION_LITERAL, transaction_literal_expected);
        assert_eq!(TRANSFER_METHOD_ID, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(REQUESTS_IN_PARALLEL, 1);
        assert_eq!(
            TRANSFER_METHOD_ID,
            "transfer(address,uint256)".keccak256()[0..4],
        );
        assert_eq!(FRESH_START_BLOCK, 0);
    }

    #[test]
    fn blockchain_interface_web3_can_return_contract() {
        all_chains().iter().for_each(|chain| {
            let mut subject = make_blockchain_interface_web3(find_free_port());
            subject.chain = *chain;

            assert_eq!(subject.contract_address(), chain.rec().contract)
        })
    }

    #[test]
    fn blockchain_interface_web3_retrieves_transactions_works() {
        let start_block_marker = BlockMarker::Value(42);
        let scan_range = BlockScanRange::Range(1000);
        let block_response = "0x7d0"; // 2_000
        let expected_new_start_block = BlockMarker::Value(42 + 1000 + 1);
        let expected_log = "from start block: Number(42) to end block: Number(1042)";
        assert_on_retrieves_transactions(
            start_block_marker,
            scan_range,
            block_response,
            expected_new_start_block,
            expected_log,
            "all_values_are_present",
        );

        let start_block_marker = BlockMarker::Uninitialized;
        let scan_range = BlockScanRange::Range(1000);
        let block_response = "0xe2f432"; // 14_873_650
        let expected_new_start_block = BlockMarker::Value(14_873_650 + 1);
        let expected_log = "from start block: Number(14873650) to end block: Number(14873650)";
        assert_on_retrieves_transactions(
            start_block_marker,
            scan_range,
            block_response,
            expected_new_start_block,
            expected_log,
            "start_block_is_missing",
        );

        let start_block_marker = BlockMarker::Uninitialized;
        let scan_range = BlockScanRange::Range(1000);
        let block_response = "trash";
        let expected_new_start_block = BlockMarker::Value(49);
        let expected_log = "from start block: Latest to end block: Latest";
        assert_on_retrieves_transactions(
            start_block_marker,
            scan_range,
            block_response,
            expected_new_start_block,
            expected_log,
            "start_block_is_missing",
        );

        let start_block_marker = BlockMarker::Value(42);
        let scan_range = BlockScanRange::NoLimit;
        let block_response = "0x7d0"; // 2_000
        let expected_new_start_block = BlockMarker::Value(2_000 + 1);
        let expected_log = "from start block: Number(42) to end block: Number(2000)";
        assert_on_retrieves_transactions(
            start_block_marker,
            scan_range,
            block_response,
            expected_new_start_block,
            expected_log,
            "scan_limit_is_missing",
        );

        let start_block_marker = BlockMarker::Value(42);
        let scan_range = BlockScanRange::NoLimit;
        let block_response = "trash";
        let expected_new_start_block = BlockMarker::Value(49); // 48 was the highest number present in the transactions
        let expected_log = "from start block: Number(42) to end block: Latest";
        assert_on_retrieves_transactions(
            start_block_marker,
            scan_range,
            block_response,
            expected_new_start_block,
            expected_log,
            "scan_limit_and_blockchain_response_is_unavailable",
        );
    }

    fn assert_on_retrieves_transactions(
        start_block_marker: BlockMarker,
        scan_range: BlockScanRange,
        block_response: &str,
        expected_new_start_block: BlockMarker,
        expected_log: &str,
        test_case: &str,
    ) {
        init_test_logging();
        let to = "0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc";
        let port = find_free_port();
        #[rustfmt::skip]
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response(block_response, 1)// 2000
            .raw_response(
                r#"{
                "jsonrpc":"2.0",
                "id":3,
                "result":[
                    {
                        "address":"0xcd6c588e005032dd882cd43bf53a32129be81302",
                        "blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a",
                        "blockNumber":"0x2e",
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
                        "blockNumber":"0x30",
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
            }"#.to_string()
            )
            .start();
        let mut subject = make_blockchain_interface_web3(port);
        subject.logger = Logger::new(test_case);

        let result = subject
            .retrieve_transactions(
                start_block_marker,
                scan_range,
                Wallet::from_str(&to).unwrap().address(),
            )
            .wait()
            .unwrap();

        assert_eq!(
            result,
            RetrievedBlockchainTransactions {
                new_start_block: expected_new_start_block,
                transactions: vec![
                    BlockchainTransaction {
                        block_number: 46,
                        from: Wallet::from_str("0x3ab28ecedea6cdb6feed398e93ae8c7b316b1182")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496u128,
                    },
                    BlockchainTransaction {
                        block_number: 48,
                        from: Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                            .unwrap(),
                        wei_amount: 4_503_599_627_370_496u128,
                    },
                ]
            }
        );
        TestLogHandler::new().exists_log_containing(&format!("DEBUG: {test_case}: Retrieving transactions {expected_log} for: 0x3f69…72fc chain_id: 137 contract: 0xee9a352f6aac4af1a5b9f467f6a93e0ffbe9dd35"));
    }

    #[test]
    fn blockchain_interface_web3_handles_no_retrieved_transactions() {
        let to_wallet = make_paying_wallet(b"test_wallet");
        let port = find_free_port();
        let empty_transactions_result: Vec<String> = vec![];
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x178def".to_string(), 2)
            .ok_response(empty_transactions_result, 2)
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .retrieve_transactions(
                BlockMarker::Value(42),
                BlockScanRange::NoLimit,
                to_wallet.address(),
            )
            .wait();

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: BlockMarker::Value(1543664),
                transactions: vec![]
            })
        );
    }

    #[test]
    #[should_panic(expected = "No address for an uninitialized wallet!")]
    fn retrieving_address_of_uninitialised_wallet_panics() {
        let subject = Wallet::new("0x3f69f9efd4f2592fd70beecd9dce71c472fc");

        subject.address();
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_returns_an_error_if_a_response_with_too_few_topics_is_returned(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x178def", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d63100000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .retrieve_transactions(
                BlockMarker::Value(42),
                BlockScanRange::NoLimit,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
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
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x178def", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":3,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","blockNumber":"0x4be663","data":"0x0000000000000000000000000000000000000000000000056bc75e2d6310000001","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .retrieve_transactions(
                BlockMarker::Uninitialized,
                BlockScanRange::NoLimit,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        assert_eq!(result, Err(BlockchainError::InvalidResponse));
    }

    #[test]
    fn blockchain_interface_web3_retrieve_transactions_ignores_transaction_logs_that_have_no_block_number(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x400", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        init_test_logging();
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();

        let end_block_nbr = BlockMarker::Value(1025u64);
        let subject =
            BlockchainInterfaceWeb3::new(transport, event_loop_handle, TEST_DEFAULT_CHAIN);

        let result = subject
            .retrieve_transactions(
                BlockMarker::Value(42),
                BlockScanRange::Range(1000),
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: end_block_nbr,
                transactions: vec![]
            })
        );
        let test_log_handler = TestLogHandler::new();
        test_log_handler.exists_log_containing(
            "WARN: BlockchainInterface: Retrieving transactions: logs: 1, transactions: 0",
        );
    }

    #[test]
    fn blockchain_interface_non_clandestine_retrieve_transactions_uses_block_number_latest_as_fallback_start_block_plus_one(
    ) {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("trash", 1)
            .raw_response(r#"{"jsonrpc":"2.0","id":2,"result":[{"address":"0xcd6c588e005032dd882cd43bf53a32129be81302","blockHash":"0x1a24b9169cbaec3f6effa1f600b70c7ab9e8e86db44062b49132a4415d26732a","data":"0x0000000000000000000000000000000000000000000000000010000000000000","logIndex":"0x0","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000003f69f9efd4f2592fd70be8c32ecd9dce71c472fc","0x000000000000000000000000adc1853c7859369639eb414b6342b36288fe6092"],"transactionHash":"0x955cec6ac4f832911ab894ce16aa22c3003f46deff3f7165b32700d2f5ff0681","transactionIndex":"0x0"}]}"#.to_string())
            .start();
        let subject = make_blockchain_interface_web3(port);
        let start_block = 42u64;
        let fallback_number = start_block;

        let result = subject
            .retrieve_transactions(
                BlockMarker::Value(42),
                BlockScanRange::NoLimit,
                Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc")
                    .unwrap()
                    .address(),
            )
            .wait();

        let expected_start_block = BlockMarker::Value(fallback_number + 1u64);
        assert_eq!(
            result,
            Ok(RetrievedBlockchainTransactions {
                new_start_block: expected_start_block,
                transactions: vec![]
            })
        );
    }

    #[test]
    fn blockchain_interface_web3_can_build_blockchain_agent() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            // gas_price
            .ok_response("0x3B9ACA00".to_string(), 0) // 1000000000
            // transaction_fee_balance
            .ok_response("0xFFF0".to_string(), 0) // 65520
            // masq_balance
            .ok_response(
                "0x000000000000000000000000000000000000000000000000000000000000FFFF".to_string(), // 65535
                0,
            )
            .start();
        let chain = Chain::PolyMainnet;
        let wallet = make_wallet("abc");
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .build_blockchain_agent(wallet.clone())
            .wait()
            .unwrap();

        let expected_transaction_fee_balance = U256::from(65_520);
        let expected_masq_balance = U256::from(65_535);
        let gas_price_from_rpc = 1_000_000_000;
        let gas_price_increase = (gas_price_from_rpc * GAS_PRICE_INCREASE_PERCENTAGE) / 100;
        let expected_gas_price_wei = gas_price_from_rpc + gas_price_increase;
        assert_eq!(result.consuming_wallet(), &wallet);
        assert_eq!(
            result.consuming_wallet_balances(),
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: expected_transaction_fee_balance,
                masq_token_balance_in_minor_units: expected_masq_balance
            }
        );
        assert_eq!(
            result.agreed_fee_per_computation_unit(),
            expected_gas_price_wei
        );
        let expected_fee_estimation = (3
            * (BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain)
                + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)
            * expected_gas_price_wei) as u128;
        assert_eq!(
            result.estimated_transaction_fee_total(3),
            expected_fee_estimation
        )
    }

    fn build_of_the_blockchain_agent_fails_on_blockchain_interface_error<F>(
        port: u16,
        expected_err_factory: F,
    ) where
        F: FnOnce(&Wallet) -> BlockchainAgentBuildError,
    {
        let wallet = make_wallet("bcd");
        let subject = make_blockchain_interface_web3(port);
        let result = subject.build_blockchain_agent(wallet.clone()).wait();
        let err = match result {
            Err(e) => e,
            _ => panic!("we expected Err() but got Ok()"),
        };
        let expected_err = expected_err_factory(&wallet);
        assert_eq!(err, expected_err)
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_fetching_gas_price() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let wallet = make_wallet("abc");
        let subject = make_blockchain_interface_web3(port);

        let err = subject.build_blockchain_agent(wallet).wait().err().unwrap();

        let expected_err = BlockchainAgentBuildError::GasPrice(QueryFailed(
            "Transport error: Error(IncompleteMessage)".to_string(),
        ));
        assert_eq!(err, expected_err)
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_transaction_fee_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .start();
        let expected_err_factory = |wallet: &Wallet| {
            BlockchainAgentBuildError::TransactionFeeBalance(
                wallet.address(),
                BlockchainError::QueryFailed(
                    "Transport error: Error(IncompleteMessage)".to_string(),
                ),
            )
        };

        build_of_the_blockchain_agent_fails_on_blockchain_interface_error(
            port,
            expected_err_factory,
        );
    }

    #[test]
    fn build_of_the_blockchain_agent_fails_on_masq_balance() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .ok_response("0x3B9ACA00".to_string(), 0)
            .ok_response("0xFFF0".to_string(), 0)
            .start();
        let expected_err_factory = |wallet: &Wallet| {
            BlockchainAgentBuildError::ServiceFeeBalance(
                wallet.address(),
                BlockchainError::QueryFailed(
                    "Api error: Transport error: Error(IncompleteMessage)".to_string(),
                ),
            )
        };

        build_of_the_blockchain_agent_fails_on_blockchain_interface_error(
            port,
            expected_err_factory,
        );
    }

    #[test]
    fn process_transaction_receipts_works() {
        let port = find_free_port();
        let tx_hash_1 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let tx_hash_2 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f")
                .unwrap();
        let tx_hash_3 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0a")
                .unwrap();
        let tx_hash_4 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0b")
                .unwrap();
        let tx_hash_5 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0c")
                .unwrap();
        let tx_hash_6 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0d")
                .unwrap();
        let tx_hash_vec = vec![
            tx_hash_1, tx_hash_2, tx_hash_3, tx_hash_4, tx_hash_5, tx_hash_6,
        ];
        let block_hash =
            H256::from_str("6d0abccae617442c26104c2bc63d1bc05e1e002e555aec4ab62a46e826b18f18")
                .unwrap();
        let block_number = U64::from_str("b0328d").unwrap();
        let cumulative_gas_used = U256::from_str("60ef").unwrap();
        let gas_used = U256::from_str("60ef").unwrap();
        let status = U64::from(1);
        let status_failed = U64::from(0);
        let tx_receipt_response_not_present = ReceiptResponseBuilder::default()
            .transaction_hash(tx_hash_4)
            .build();
        let tx_receipt_response_failed = ReceiptResponseBuilder::default()
            .transaction_hash(tx_hash_5)
            .status(status_failed)
            .build();
        let tx_receipt_response_success = ReceiptResponseBuilder::default()
            .transaction_hash(tx_hash_6)
            .block_hash(block_hash)
            .block_number(block_number)
            .cumulative_gas_used(cumulative_gas_used)
            .gas_used(gas_used)
            .status(status)
            .build();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .raw_response(r#"{ "jsonrpc": "2.0", "id": 1, "result": null }"#.to_string())
            .ok_response("trash".to_string(), 0)
            .raw_response(tx_receipt_response_not_present)
            .raw_response(tx_receipt_response_failed)
            .raw_response(tx_receipt_response_success)
            .end_batch()
            .start();
        let subject = make_blockchain_interface_web3(port);

        let result = subject
            .process_transaction_receipts(tx_hash_vec)
            .wait()
            .unwrap();

        assert_eq!(result[0], TransactionReceiptResult::LocalError("RPC error: Error { code: ServerError(429), message: \"The requests per second (RPS) of your requests are higher than your plan allows.\", data: None }".to_string()));
        assert_eq!(
            result[1],
            TransactionReceiptResult::RpcResponse(TxReceipt {
                transaction_hash: tx_hash_2,
                status: TxStatus::Pending
            })
        );
        assert_eq!(
            result[2],
            TransactionReceiptResult::LocalError(
                "invalid type: string \"trash\", expected struct Receipt".to_string()
            )
        );
        assert_eq!(
            result[3],
            TransactionReceiptResult::RpcResponse(TxReceipt {
                transaction_hash: tx_hash_4,
                status: TxStatus::Pending
            })
        );
        assert_eq!(
            result[4],
            TransactionReceiptResult::RpcResponse(TxReceipt {
                transaction_hash: tx_hash_5,
                status: TxStatus::Failed,
            })
        );
        assert_eq!(
            result[5],
            TransactionReceiptResult::RpcResponse(TxReceipt {
                transaction_hash: tx_hash_6,
                status: TxStatus::Succeeded(TransactionBlock {
                    block_hash,
                    block_number,
                }),
            })
        );
    }

    #[test]
    fn process_transaction_receipts_fails_on_submit_batch() {
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port).start();
        let subject = make_blockchain_interface_web3(port);
        let tx_hash_1 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0e")
                .unwrap();
        let tx_hash_2 =
            H256::from_str("a128f9ca1e705cc20a936a24a7fa1df73bad6e0aaf58e8e6ffcc154a7cff6e0f")
                .unwrap();
        let tx_hash_vec = vec![tx_hash_1, tx_hash_2];

        let error = subject
            .process_transaction_receipts(tx_hash_vec)
            .wait()
            .unwrap_err();

        assert_eq!(
            error,
            QueryFailed("Transport error: Error(IncompleteMessage)".to_string())
        );
    }

    #[test]
    fn web3_gas_limit_const_part_returns_reasonable_values() {
        type Subject = BlockchainInterfaceWeb3;
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::EthMainnet),
            55_000
        );
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::EthRopsten),
            55_000
        );
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::PolyMainnet),
            70_000
        );
        assert_eq!(Subject::web3_gas_limit_const_part(Chain::PolyAmoy), 70_000);
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::BaseSepolia),
            70_000
        );
        assert_eq!(Subject::web3_gas_limit_const_part(Chain::Dev), 55_000);
    }

    #[test]
    fn calculate_end_block_marker_works() {
        let logger = Logger::new("calculate_end_block_marker_works");

        type Subject = BlockchainInterfaceWeb3;

        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Uninitialized,
                BlockScanRange::NoLimit,
                Err(BlockchainError::InvalidResponse),
                &logger
            ),
            BlockMarker::Uninitialized
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Uninitialized,
                BlockScanRange::NoLimit,
                Ok(1000.into()),
                &logger
            ),
            BlockMarker::Value(1000)
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Uninitialized,
                BlockScanRange::Range(100),
                Err(BlockchainError::InvalidResponse),
                &logger
            ),
            BlockMarker::Uninitialized
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Uninitialized,
                BlockScanRange::Range(100),
                Ok(120.into()),
                &logger
            ),
            BlockMarker::Value(120)
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Value(50),
                BlockScanRange::NoLimit,
                Err(BlockchainError::InvalidResponse),
                &logger
            ),
            BlockMarker::Uninitialized
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Value(50),
                BlockScanRange::NoLimit,
                Ok(1000.into()),
                &logger
            ),
            BlockMarker::Value(1000)
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Value(50),
                BlockScanRange::Range(100),
                Err(BlockchainError::InvalidResponse),
                &logger
            ),
            BlockMarker::Value(150)
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Value(50),
                BlockScanRange::Range(100),
                Ok(120.into()),
                &logger
            ),
            BlockMarker::Value(120)
        );
        assert_eq!(
            Subject::calculate_end_block_marker(
                BlockMarker::Value(50),
                BlockScanRange::Range(10),
                Ok(120.into()),
                &logger
            ),
            BlockMarker::Value(50 + 10)
        );
    }

    #[test]
    fn find_new_start_block_works() {
        type Subject = BlockchainInterfaceWeb3;
        let logger = Logger::new("find_new_start_block_works");
        let transactions = vec![
            BlockchainTransaction {
                block_number: 10,
                from: make_wallet("wallet_1"),
                wei_amount: 1000,
            },
            BlockchainTransaction {
                block_number: 60,
                from: make_wallet("wallet_1"),
                wei_amount: 500,
            },
        ];

        // Case 1: end_block_marker is Value
        assert_eq!(
            Subject::find_new_start_block(
                &[],
                BlockMarker::Uninitialized,
                BlockMarker::Value(100),
                &logger
            ),
            BlockMarker::Value(101)
        );
        // Case 2: end_block_marker is Uninitialized, highest block found in transactions
        assert_eq!(
            Subject::find_new_start_block(
                &transactions,
                BlockMarker::Uninitialized,
                BlockMarker::Uninitialized,
                &logger
            ),
            BlockMarker::Value(61)
        );
        // Case 3: end_block_marker is Uninitialized, no transactions retrieved, start_block_marker is Value
        assert_eq!(
            Subject::find_new_start_block(
                &[],
                BlockMarker::Value(50),
                BlockMarker::Uninitialized,
                &logger
            ),
            BlockMarker::Value(51)
        );
        // Case 4: end_block_marker is Uninitialized, no transactions retrieved, start_block_marker is Uninitialized
        assert_eq!(
            Subject::find_new_start_block(
                &[],
                BlockMarker::Uninitialized,
                BlockMarker::Uninitialized,
                &logger
            ),
            BlockMarker::Uninitialized
        );
    }
}
