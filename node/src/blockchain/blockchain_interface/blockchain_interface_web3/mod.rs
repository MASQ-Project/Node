// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod blockchain_interface_helper_web3;

use std::fmt::Debug;
use std::iter::once;
use std::rc::Rc;
use actix::Recipient;
use futures::{Future, future};
use serde_json::Value;
use thousands::Separable;
use web3::{BatchTransport, Error, Web3};
use web3::contract::Contract;
use web3::transports::{Batch, EventLoopHandle};
use web3::types::{Address, BlockNumber, Bytes, FilterBuilder, H160, H256, Log, SignedTransaction, TransactionParameters, U256};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use crate::accountant::database_access_objects::payable_dao::{PayableAccount, PendingPayable};
use crate::accountant::gwei_to_wei;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::BlockchainAgentWeb3;
use crate::masq_lib::utils::ExpectValue;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
use crate::blockchain::batch_payable_tools::{BatchPayableTools, BatchPayableToolsReal};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{BlockchainError, BlockchainInterface, BlockchainTransaction, PayableTransactionError, ProcessedPayableFallible, ResultForReceipt, RetrievedBlockchainTransactions, RpcFailurePayables};
use crate::blockchain::blockchain_interface::blockchain_interface_helper::BlockchainInterfaceHelper;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::blockchain_interface_helper_web3::BlockchainInterfaceNonClandestineHelper;
use crate::db_config::persistent_configuration::PersistentConfiguration;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;

const CONTRACT_ABI: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;

const TRANSACTION_LITERAL: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

const TRANSFER_METHOD_ID: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

pub const REQUESTS_IN_PARALLEL: usize = 1;

pub struct BlockchainInterfaceNonClandestine<T>
where
    T: BatchTransport + Debug,
{
    logger: Logger,
    chain: Chain,
    gas_limit_const_part: u64,
    // This must not be dropped for Web3 requests to be completed
    _event_loop_handle: EventLoopHandle,
    web3: Rc<Web3<T>>,
    batch_web3: Rc<Web3<Batch<T>>>,
    helper: Box<dyn BlockchainInterfaceHelper>,
    batch_payable_tools: Box<dyn BatchPayableTools<T>>,
}

impl<T> BlockchainInterface for BlockchainInterfaceNonClandestine<T>
where
    T: BatchTransport + Debug + 'static,
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

    fn build_blockchain_agent(
        &self,
        consuming_wallet: &Wallet,
        persistent_config: &dyn PersistentConfiguration,
    ) -> Result<Box<dyn BlockchainAgent>, String> {
        macro_rules! err {
            ($($arg: tt)*) => {
                Err(format!("Blockchain agent build failed to fetch {}", format!($($arg)*)))
            };
        }

        let gas_price_gwei = match persistent_config.gas_price() {
            Ok(price) => price,
            Err(e) => return err!("gas price: {:?}", e),
        };

        let transaction_fee_balance =
            match self.helper.get_transaction_fee_balance(consuming_wallet) {
                Ok(balance) => balance,
                Err(e) => return err!("transaction fee balance for {}: {}", consuming_wallet, e),
            };

        let masq_token_balance = match self.helper.get_masq_balance(consuming_wallet) {
            Ok(balance) => balance,
            Err(e) => return err!("masq balance for {}: {}", consuming_wallet, e),
        };

        let pending_transaction_id = match self.helper.get_transaction_id(consuming_wallet) {
            Ok(id) => id,
            Err(e) => return err!("transaction id for {}: {}", consuming_wallet, e),
        };

        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: transaction_fee_balance,
            masq_token_balance_in_minor_units: masq_token_balance,
        };
        let consuming_wallet = consuming_wallet.clone();

        Ok(Box::new(BlockchainAgentWeb3::new(
            gas_price_gwei,
            self.gas_limit_const_part,
            consuming_wallet,
            consuming_wallet_balances,
            pending_transaction_id,
        )))
    }

    fn send_batch_of_payables(
        &self,
        agent: Box<dyn BlockchainAgent>,
        new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
        accounts: &[PayableAccount],
    ) -> Result<Vec<ProcessedPayableFallible>, PayableTransactionError> {
        let consuming_wallet = agent.consuming_wallet();
        let gas_price = agent.agreed_fee_per_computation_unit();
        let pending_nonce = agent.pending_transaction_id();

        debug!(
            self.logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
            consuming_wallet,
            self.chain.rec().contract,
            self.chain.rec().num_chain_id,
            gas_price
        );

        let hashes_and_paid_amounts = self.sign_and_append_multiple_payments(
            consuming_wallet,
            gas_price,
            pending_nonce,
            accounts,
        )?;
        let timestamp = self.batch_payable_tools.batch_wide_timestamp();
        self.batch_payable_tools
            .send_new_payable_fingerprints_seeds(
                timestamp,
                new_fingerprints_recipient,
                &hashes_and_paid_amounts,
            );

        info!(
            self.logger,
            "{}",
            self.transmission_log(accounts, gas_price)
        );

        match self.batch_payable_tools.submit_batch(&self.batch_web3) {
            Ok(responses) => Ok(Self::merged_output_data(
                responses,
                hashes_and_paid_amounts,
                accounts,
            )),
            Err(e) => Err(Self::error_with_hashes(e, hashes_and_paid_amounts)),
        }
    }

    fn get_transaction_receipt(&self, hash: H256) -> ResultForReceipt {
        self.web3
            .eth()
            .transaction_receipt(hash)
            .map_err(|e| BlockchainError::QueryFailed(e.to_string()))
            .wait()
    }

    fn helper(&self) -> &dyn BlockchainInterfaceHelper {
        &*self.helper
    }
}

impl<T> BlockchainInterfaceNonClandestine<T>
where
    T: BatchTransport + Debug + 'static,
{
    pub fn new(transport: T, event_loop_handle: EventLoopHandle, chain: Chain) -> Self {
        let web3 = Rc::new(Web3::new(transport.clone()));
        let batch_web3 = Rc::new(Web3::new(Batch::new(transport)));
        let batch_payable_tools = Box::new(BatchPayableToolsReal::<T>::default());
        let contract =
            Contract::from_json(web3.eth(), chain.rec().contract, CONTRACT_ABI.as_bytes())
                .expect("Unable to initialize contract.");
        let lower_level_blockchain_interface =
            Box::new(BlockchainInterfaceNonClandestineHelper::new(
                Rc::clone(&web3),
                Rc::clone(&batch_web3),
                contract,
            ));
        let gas_limit_const_part = Self::web3_gas_limit_const_part(chain);

        Self {
            logger: Logger::new("BlockchainInterface"),
            chain,
            gas_limit_const_part,
            _event_loop_handle: event_loop_handle,
            web3,
            batch_web3,
            helper: lower_level_blockchain_interface,
            batch_payable_tools,
        }
    }

    fn sign_and_append_multiple_payments(
        &self,
        consuming_wallet: &Wallet,
        gas_price: u64,
        pending_nonce: U256,
        accounts: &[PayableAccount],
    ) -> HashAndAmountResult {
        let init: (HashAndAmountResult, Option<U256>) =
            (Ok(Vec::with_capacity(accounts.len())), Some(pending_nonce));

        let (result, _) = accounts.iter().fold(
            init,
            |(processed_outputs_res, pending_nonce_opt), account| {
                if let Ok(hashes_and_amounts) = processed_outputs_res {
                    self.handle_payable_account(
                        pending_nonce_opt,
                        hashes_and_amounts,
                        consuming_wallet,
                        gas_price,
                        account,
                    )
                } else {
                    (processed_outputs_res, None)
                }
            },
        );
        result
    }

    fn handle_payable_account(
        &self,
        pending_nonce_opt: Option<U256>,
        hashes_and_amounts: Vec<(H256, u128)>,
        consuming_wallet: &Wallet,
        gas_price: u64,
        account: &PayableAccount,
    ) -> (HashAndAmountResult, Option<U256>) {
        let nonce = pending_nonce_opt.expectv("pending nonce");
        let updated_collected_attributes_of_processed_payments = self.sign_and_append_payment(
            hashes_and_amounts,
            consuming_wallet,
            nonce,
            gas_price,
            account,
        );
        let advanced_nonce = Self::advance_used_nonce(nonce);
        (
            updated_collected_attributes_of_processed_payments,
            Some(advanced_nonce),
        )
    }

    fn sign_and_append_payment(
        &self,
        mut hashes_and_amounts: Vec<(H256, u128)>,
        consuming_wallet: &Wallet,
        nonce: U256,
        gas_price: u64,
        account: &PayableAccount,
    ) -> HashAndAmountResult {
        debug!(
            self.logger,
            "Preparing payment of {} wei to {} with nonce {}",
            account.balance_wei.separate_with_commas(),
            account.wallet,
            nonce
        );

        match self.handle_new_transaction(
            &account.wallet,
            consuming_wallet,
            account.balance_wei,
            nonce,
            gas_price,
        ) {
            Ok(new_hash) => {
                hashes_and_amounts.push((new_hash, account.balance_wei));
                Ok(hashes_and_amounts)
            }
            Err(e) => Err(e),
        }
    }

    fn advance_used_nonce(current_nonce: U256) -> U256 {
        current_nonce
            .checked_add(U256::one())
            .expect("unexpected limits")
    }

    fn merged_output_data(
        responses: Vec<web3::transports::Result<Value>>,
        hashes_and_paid_amounts: Vec<(H256, u128)>,
        accounts: &[PayableAccount],
    ) -> Vec<ProcessedPayableFallible> {
        let iterator_with_all_data = responses
            .into_iter()
            .zip(hashes_and_paid_amounts.into_iter())
            .zip(accounts.iter());
        iterator_with_all_data
            .map(|((rpc_result, (hash, _)), account)| match rpc_result {
                Ok(_) => ProcessedPayableFallible::Correct(PendingPayable {
                    recipient_wallet: account.wallet.clone(),
                    hash,
                }),
                Err(rpc_error) => ProcessedPayableFallible::Failed(RpcFailurePayables {
                    rpc_error,
                    recipient_wallet: account.wallet.clone(),
                    hash,
                }),
            })
            .collect()
    }

    fn error_with_hashes(
        error: Error,
        hashes_and_paid_amounts: Vec<(H256, u128)>,
    ) -> PayableTransactionError {
        let hashes = hashes_and_paid_amounts
            .into_iter()
            .map(|(hash, _)| hash)
            .collect();
        PayableTransactionError::Sending {
            msg: error.to_string(),
            hashes,
        }
    }

    fn handle_new_transaction<'a>(
        &self,
        recipient: &'a Wallet,
        consuming_wallet: &'a Wallet,
        amount: u128,
        nonce: U256,
        gas_price: u64,
    ) -> Result<H256, PayableTransactionError> {
        let signed_tx =
            self.sign_transaction(recipient, consuming_wallet, amount, nonce, gas_price)?;
        self.batch_payable_tools
            .append_transaction_to_batch(signed_tx.raw_transaction, &self.batch_web3);
        Ok(signed_tx.transaction_hash)
    }

    fn sign_transaction<'a>(
        &self,
        recipient: &'a Wallet,
        consuming_wallet: &'a Wallet,
        amount: u128,
        nonce: U256,
        gas_price: u64,
    ) -> Result<SignedTransaction, PayableTransactionError> {
        let data = Self::transaction_data(recipient, amount);
        let gas_limit = self.compute_gas_limit(data.as_slice());
        let gas_price = gwei_to_wei::<U256, _>(gas_price);
        let transaction_parameters = TransactionParameters {
            nonce: Some(nonce),
            to: Some(H160(self.contract_address().0)),
            gas: gas_limit,
            gas_price: Some(gas_price),
            value: ethereum_types::U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(self.chain.rec().num_chain_id),
        };

        let key = match consuming_wallet.prepare_secp256k1_secret() {
            Ok(secret) => secret,
            Err(e) => return Err(PayableTransactionError::UnusableWallet(e.to_string())),
        };

        self.batch_payable_tools
            .sign_transaction(transaction_parameters, &self.batch_web3, &key)
            .map_err(|e| PayableTransactionError::Signing(e.to_string()))
    }

    fn transmission_log(&self, accounts: &[PayableAccount], gas_price: u64) -> String {
        let chain_name = self
            .chain
            .rec()
            .literal_identifier
            .chars()
            .skip_while(|char| char != &'-')
            .skip(1)
            .collect::<String>();
        let introduction = once(format!(
            "\
        Paying to creditors...\n\
        Transactions in the batch:\n\
        \n\
        gas price:                                   {} gwei\n\
        chain:                                       {}\n\
        \n\
        [wallet address]                             [payment in wei]\n",
            gas_price, chain_name
        ));
        let body = accounts.iter().map(|account| {
            format!(
                "{}   {}\n",
                account.wallet,
                account.balance_wei.separate_with_commas()
            )
        });
        introduction.chain(body).collect()
    }

    fn transaction_data(recipient: &Wallet, amount: u128) -> [u8; 68] {
        let mut data = [0u8; 4 + 32 + 32];
        data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
        data[16..36].copy_from_slice(&recipient.address().0[..]);
        U256::try_from(amount)
            .expect("shouldn't overflow")
            .to_big_endian(&mut data[36..68]);
        data
    }

    fn compute_gas_limit(&self, data: &[u8]) -> U256 {
        ethereum_types::U256::try_from(data.iter().fold(self.gas_limit_const_part, |acc, v| {
            acc + if v == &0u8 { 4 } else { 68 }
        }))
        .expect("Internal error")
    }

    fn web3_gas_limit_const_part(chain: Chain) -> u64 {
        match chain {
            Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
            Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
        }
    }

    #[cfg(test)]
    fn web3(&self) -> &Web3<T> {
        &self.web3
    }
}

type HashAndAmountResult = Result<Vec<(H256, u128)>, PayableTransactionError>;

#[cfg(test)]
mod tests {
    use crate::accountant::database_access_objects::payable_dao::{PayableAccount, PendingPayable};
    use crate::accountant::database_access_objects::utils::from_time_t;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::agent_web3::{
        BlockchainAgentWeb3, WEB3_MAXIMAL_GAS_LIMIT_MARGIN,
    };
    use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::blockchain_agent::BlockchainAgent;
    use crate::accountant::test_utils::{
        make_payable_account, make_payable_account_with_wallet_and_balance_and_timestamp_opt,
    };
    use crate::blockchain::bip32::Bip32ECKeyProvider;
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;

    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceNonClandestine, CONTRACT_ABI, REQUESTS_IN_PARALLEL, TRANSACTION_LITERAL,
        TRANSFER_METHOD_ID,
    };
    use crate::blockchain::blockchain_interface::test_utils::{
        test_blockchain_interface_is_connected_and_functioning, BlockchainInterfaceHelperMock,
    };
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failed};
    use crate::blockchain::blockchain_interface::{
        BlockchainError, BlockchainInterface, BlockchainTransaction, PayableTransactionError,
        RetrievedBlockchainTransactions, RpcFailurePayables,
    };
    use crate::blockchain::test_utils::{
        all_chains, make_default_signed_transaction, make_fake_event_loop_handle, make_tx_hash,
        BatchPayableToolsMock, TestTransport,
    };
    use crate::db_config::persistent_configuration::PersistentConfigError;
    use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::http_test_server::TestServer;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::decode_hex;
    use crate::test_utils::{make_paying_wallet, make_wallet, TestRawTransaction};
    use actix::{Actor, System};
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use futures::Future;
    use jsonrpc_core::Version::V2;
    use jsonrpc_core::{Call, Error as RPCError, ErrorCode, Id, MethodCall, Params};
    use masq_lib::blockchains::chains::Chain;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::find_free_port;
    use serde_derive::Deserialize;
    use serde_json::{json, Value};
    use std::net::Ipv4Addr;

    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use web3::transports::{Batch, Http};
    use web3::types::{
        Address, Bytes, TransactionParameters, TransactionReceipt, H2048, H256, U256,
    };
    use web3::Error as Web3Error;
    use web3::Web3;

    #[test]
    fn constants_are_correct() {
        let contract_abi_expected: &str = r#"[{"constant":true,"inputs":[{"name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]"#;
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
    }

    #[test]
    fn blockchain_interface_non_clandestine_returns_contract() {
        all_chains().iter().for_each(|chain| {
            let subject = BlockchainInterfaceNonClandestine::new(
                TestTransport::default(),
                make_fake_event_loop_handle(),
                *chain,
            );

            assert_eq!(subject.contract_address(), chain.rec().contract)
        })
    }

    #[test]
    fn blockchain_interface_non_clandestine_provides_correct_helper() {
        //TODO you can rewrite this code to be less shared between tests
        let subject_factory = |port: u16, _chain: Chain| {
            let chain = Chain::PolyMainnet;
            let (event_loop_handle, transport) = Http::with_max_parallel(
                &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
                REQUESTS_IN_PARALLEL,
            )
            .unwrap();
            Box::new(BlockchainInterfaceNonClandestine::new(
                transport,
                event_loop_handle,
                chain,
            )) as Box<dyn BlockchainInterface>
        };

        test_blockchain_interface_is_connected_and_functioning(subject_factory)
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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
            bodies[0]["params"][0]["topics"][2].to_string(),
            format!("\"0x000000000000000000000000{}\"", &to[2..]),
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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
        let port = find_free_port();
        let (event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);

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
    fn blockchain_interface_can_build_blockchain_agent() {
        let get_transaction_fee_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let get_masq_balance_params_arc = Arc::new(Mutex::new(vec![]));
        let get_transactions_id_params_arc = Arc::new(Mutex::new(vec![]));
        let chain = Chain::PolyMainnet;
        let wallet = make_wallet("abc");
        let persistent_config = PersistentConfigurationMock::new().gas_price_result(Ok(50));
        let mut subject = BlockchainInterfaceNonClandestine::new(
            TestTransport::default(),
            make_fake_event_loop_handle(),
            chain,
        );
        let transaction_fee_balance = U256::from(123_456_789);
        let masq_balance = U256::from(444_444_444);
        let transaction_id = U256::from(23);
        let blockchain_interface_helper = BlockchainInterfaceHelperMock::default()
            .get_transaction_fee_balance_params(&get_transaction_fee_balance_params_arc)
            .get_transaction_fee_balance_result(Ok(transaction_fee_balance))
            .get_masq_balance_params(&get_masq_balance_params_arc)
            .get_masq_balance_result(Ok(masq_balance))
            .get_transaction_id_params(&get_transactions_id_params_arc)
            .get_transaction_id_result(Ok(transaction_id));
        subject.helper = Box::new(blockchain_interface_helper);

        let result = subject
            .build_blockchain_agent(&wallet, &persistent_config)
            .unwrap();

        let get_transaction_fee_balance_params =
            get_transaction_fee_balance_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_fee_balance_params, vec![wallet.clone()]);
        let get_masq_balance_params = get_masq_balance_params_arc.lock().unwrap();
        assert_eq!(*get_masq_balance_params, vec![wallet.clone()]);
        let get_transaction_id_params = get_transactions_id_params_arc.lock().unwrap();
        assert_eq!(*get_transaction_id_params, vec![wallet.clone()]);
        assert_eq!(result.consuming_wallet(), &wallet);
        assert_eq!(result.pending_transaction_id(), transaction_id);
        assert_eq!(
            result.consuming_wallet_balances(),
            ConsumingWalletBalances {
                transaction_fee_balance_in_minor_units: transaction_fee_balance,
                masq_token_balance_in_minor_units: masq_balance
            }
        );
        assert_eq!(result.agreed_fee_per_computation_unit(), 50);
        let expected_fee_estimation = (3
            * (BlockchainInterfaceNonClandestine::<Http>::web3_gas_limit_const_part(chain)
                + WEB3_MAXIMAL_GAS_LIMIT_MARGIN)
            * 50) as u128;
        assert_eq!(
            result.estimated_transaction_fee_total(3),
            expected_fee_estimation
        )
    }

    #[test]
    fn build_of_blockchain_agent_fails_on_gas_price() {
        let chain = Chain::PolyMumbai;
        let wallet = make_wallet("abc");
        let persistent_config = PersistentConfigurationMock::new().gas_price_result(Err(
            PersistentConfigError::UninterpretableValue("booga".to_string()),
        ));
        let subject = BlockchainInterfaceNonClandestine::new(
            TestTransport::default(),
            make_fake_event_loop_handle(),
            chain,
        );

        let result = subject.build_blockchain_agent(&wallet, &persistent_config);

        let err = match result {
            Err(e) => e,
            _ => panic!("we expected Err() but got Ok()"),
        };
        let expected_err_msg = "Blockchain agent build failed to fetch gas price: \
        UninterpretableValue(\"booga\")";
        assert_eq!(err, expected_err_msg)
    }

    fn build_of_blockchain_agent_fails_on_blockchain_interface_error(
        blockchain_interface_helper: BlockchainInterfaceHelperMock,
        expected_err_msg: &str,
    ) {
        let chain = Chain::EthMainnet;
        let wallet = make_wallet("bcd");
        let persistent_config = PersistentConfigurationMock::new().gas_price_result(Ok(30));
        let mut subject = BlockchainInterfaceNonClandestine::new(
            TestTransport::default(),
            make_fake_event_loop_handle(),
            chain,
        );
        subject.helper = Box::new(blockchain_interface_helper);

        let result = subject.build_blockchain_agent(&wallet, &persistent_config);

        let err = match result {
            Err(e) => e,
            _ => panic!("we expected Err() but got Ok()"),
        };
        assert_eq!(err, expected_err_msg)
    }

    #[test]
    fn build_of_blockchain_agent_fails_on_transaction_fee_balance() {
        let blockchain_interface_helper = BlockchainInterfaceHelperMock::default()
            .get_transaction_fee_balance_result(Err(BlockchainError::InvalidAddress));
        let expected_err_msg =
            "Blockchain agent build failed to fetch transaction fee balance for \
        0x0000000000000000000000000000000000626364: Blockchain error: Invalid address";

        build_of_blockchain_agent_fails_on_blockchain_interface_error(
            blockchain_interface_helper,
            expected_err_msg,
        )
    }

    #[test]
    fn build_of_blockchain_agent_fails_on_masq_balance() {
        let transaction_fee_balance = U256::from(123_456_789);
        let blockchain_interface_helper = BlockchainInterfaceHelperMock::default()
            .get_transaction_fee_balance_result(Ok(transaction_fee_balance))
            .get_masq_balance_result(Err(BlockchainError::InvalidAddress));
        let expected_err_msg = "Blockchain agent build failed to fetch masq balance for \
        0x0000000000000000000000000000000000626364: Blockchain error: Invalid address";

        build_of_blockchain_agent_fails_on_blockchain_interface_error(
            blockchain_interface_helper,
            expected_err_msg,
        )
    }

    #[test]
    fn build_of_blockchain_agent_fails_on_transaction_id() {
        let transaction_fee_balance = U256::from(123_456_789);
        let masq_balance = U256::from(500_000_000);
        let blockchain_interface_helper = BlockchainInterfaceHelperMock::default()
            .get_transaction_fee_balance_result(Ok(transaction_fee_balance))
            .get_masq_balance_result(Ok(masq_balance))
            .get_transaction_id_result(Err(BlockchainError::InvalidResponse));
        let expected_err_msg = "Blockchain agent build failed to fetch transaction id for \
        0x0000000000000000000000000000000000626364: Blockchain error: Invalid response";

        build_of_blockchain_agent_fails_on_blockchain_interface_error(
            blockchain_interface_helper,
            expected_err_msg,
        )
    }

    #[test]
    fn blockchain_interface_non_clandestine_can_transfer_tokens_in_batch() {
        //exercising also the layer of web3 functions, but the transport layer is mocked
        init_test_logging();
        let send_batch_params_arc = Arc::new(Mutex::new(vec![]));
        //we compute the hashes ourselves during the batch preparation and so we don't care about
        //the same ones coming back with the response; we use the returned OKs as indicators of success only.
        //Any eventual rpc errors brought back are processed as well...
        let expected_batch_responses = vec![
            Ok(json!("...unnecessarily important hash...")),
            Err(web3::Error::Rpc(RPCError {
                code: ErrorCode::ServerError(114),
                message: "server being busy".to_string(),
                data: None,
            })),
            Ok(json!("...unnecessarily important hash...")),
        ];
        let transport = TestTransport::default()
            .send_batch_params(&send_batch_params_arc)
            .send_batch_result(expected_batch_responses);
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let actor_addr = accountant.start();
        let fingerprint_recipient = recipient!(actor_addr, PendingPayableFingerprintSeeds);
        let logger = Logger::new("sending_batch_payments");
        let chain = TEST_DEFAULT_CHAIN;
        let mut subject = BlockchainInterfaceNonClandestine::new(
            transport.clone(),
            make_fake_event_loop_handle(),
            chain,
        );
        subject.logger = logger;
        let amount_1 = gwei_to_wei(900_000_000_u64);
        let account_1 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w123"),
            amount_1,
            None,
        );
        let amount_2 = 123_456_789;
        let account_2 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w555"),
            amount_2,
            None,
        );
        let amount_3 = gwei_to_wei(33_355_666_u64);
        let account_3 = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("w987"),
            amount_3,
            None,
        );
        let accounts_to_process = vec![account_1, account_2, account_3];
        let consuming_wallet = make_paying_wallet(b"gdasgsa");
        let agent = make_initialized_agent(120, consuming_wallet, U256::from(6), chain);
        let test_timestamp_before = SystemTime::now();

        let result = subject
            .send_batch_of_payables(agent, &fingerprint_recipient, &accounts_to_process)
            .unwrap();

        let test_timestamp_after = SystemTime::now();
        let system = System::new("can transfer tokens test");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let send_batch_params = send_batch_params_arc.lock().unwrap();
        assert_eq!(
            *send_batch_params,
            vec![vec![
                (
                    1,
                    Call::MethodCall(MethodCall {
                        jsonrpc: Some(V2),
                        method: "eth_sendRawTransaction".to_string(),
                        params: Params::Array(vec![Value::String("0xf8a906851bf08eb00082db6894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb000\
        00000000000000000000000000000000000000000000000000000773132330000000000000000000000000000000000000000000000000c7d713b49da00002aa060b9f375c06f56\
        41951606643d76ef999d32ae02f6b6cd62c9275ebdaa36a390a0199c3d8644c428efd5e0e0698c031172ac6873037d90dcca36a1fbf2e67960ff".to_string())]),
                        id: Id::Num(1)
                    })
                ),
                (
                    2,
                    Call::MethodCall(MethodCall {
                        jsonrpc: Some(V2),
                        method: "eth_sendRawTransaction".to_string(),
                        params: Params::Array(vec![Value::String("0xf8a907851bf08eb00082dae894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb000\
        000000000000000000000000000000000000000000000000000007735353500000000000000000000000000000000000000000000000000000000075bcd1529a00e61352bb2ac9b\
        32b411206250f219b35cdc85db679f3e2416daac4f730a12f1a02c2ad62759d86942f3af2b8915ecfbaa58268010e00d32c18a49a9fc3b9bd20a".to_string())]),
                        id: Id::Num(1)
                    })
                ),
                (
                    3,
                    Call::MethodCall(MethodCall {
                        jsonrpc: Some(V2),
                        method: "eth_sendRawTransaction".to_string(),
                        params: Params::Array(vec![Value::String("0xf8a908851bf08eb00082db6894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb000\
        0000000000000000000000000000000000000000000000000000077393837000000000000000000000000000000000000000000000000007680cd2f2d34002aa02d300cc8ba7b63\
        b0147727c824a54a7db9ec083273be52a32bdca72657a3e310a042a17224b35e7036d84976a23fbe8b1a488b2bcabed1e4a2b0b03f0c9bbc38e9".to_string())]),
                        id: Id::Num(1)
                    })
                )
            ]]
        );
        let check_expected_successful_request = |expected_hash: H256, idx: usize| {
            let pending_payable = match &result[idx]{
                Correct(pp) => pp,
                Failed(RpcFailurePayables{ rpc_error, recipient_wallet: recipient, hash }) => panic!(
                    "we expected correct pending payable but got one with rpc_error: {:?} and hash: {} for recipient: {}",
                    rpc_error, hash, recipient
                ),
            };
            let hash = pending_payable.hash;
            assert_eq!(hash, expected_hash)
        };
        //first successful request
        let expected_hash_1 =
            H256::from_str("26e5e0cec02023e40faff67e88e3cf48a98574b5f9fdafc03ef42cad96dae1c1")
                .unwrap();
        check_expected_successful_request(expected_hash_1, 0);
        //failing request
        let pending_payable_fallible_2 = &result[1];
        let (rpc_error, recipient_2, hash_2) = match pending_payable_fallible_2 {
            Correct(pp) => panic!(
                "we expected failing pending payable but got a good one: {:?}",
                pp
            ),
            Failed(RpcFailurePayables {
                rpc_error,
                recipient_wallet: recipient,
                hash,
            }) => (rpc_error, recipient, hash),
        };
        assert_eq!(
            rpc_error,
            &web3::Error::Rpc(RPCError {
                code: ErrorCode::ServerError(114),
                message: "server being busy".to_string(),
                data: None
            })
        );
        let expected_hash_2 =
            H256::from_str("57e7c9a5f6af1ab3363e323d59c2c9d1144bbb1a7c2065eeb6696d4e302e67f2")
                .unwrap();
        assert_eq!(hash_2, &expected_hash_2);
        assert_eq!(recipient_2, &make_wallet("w555"));
        //second_succeeding_request
        let expected_hash_3 =
            H256::from_str("a472e3b81bc167140a217447d9701e9ed2b65252f1428f7779acc3710a9ede44")
                .unwrap();
        check_expected_successful_request(expected_hash_3, 2);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1);
        let initiate_fingerprints_msg =
            accountant_recording.get_record::<PendingPayableFingerprintSeeds>(0);
        let actual_common_timestamp = initiate_fingerprints_msg.batch_wide_timestamp;
        assert!(
            test_timestamp_before <= actual_common_timestamp
                && actual_common_timestamp <= test_timestamp_after
        );
        assert_eq!(
            initiate_fingerprints_msg,
            &PendingPayableFingerprintSeeds {
                batch_wide_timestamp: actual_common_timestamp,
                hashes_and_balances: vec![
                    (expected_hash_1, gwei_to_wei(900_000_000_u64)),
                    (expected_hash_2, 123_456_789),
                    (expected_hash_3, gwei_to_wei(33_355_666_u64))
                ]
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: sending_batch_payments: \
        Common attributes of payables to be transacted: sender wallet: 0x5c361ba8d82fcf0e5538b2a823e9d457a2296725, contract: \
          0x384dec25e03f94931767ce4c3556168468ba24c3, chain_id: 3, gas_price: 120");
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payment of 900,000,000,000,000,000 wei \
        to 0x0000000000000000000000000000000077313233 with nonce 6",
        );
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payment of 123,456,789 wei \
        to 0x0000000000000000000000000000000077353535 with nonce 7",
        );
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payment of 33,355,666,000,000,000 wei \
        to 0x0000000000000000000000000000000077393837 with nonce 8",
        );
        log_handler.exists_log_containing(
            "INFO: sending_batch_payments: Paying to creditors...\n\
        Transactions in the batch:\n\
        \n\
        gas price:                                   120 gwei\n\
        chain:                                       ropsten\n\
        \n\
        [wallet address]                             [payment in wei]\n\
        0x0000000000000000000000000000000077313233   900,000,000,000,000,000\n\
        0x0000000000000000000000000000000077353535   123,456,789\n\
        0x0000000000000000000000000000000077393837   33,355,666,000,000,000\n",
        );
    }

    #[test]
    fn non_clandestine_interface_send_batch_of_payables_components_work_together_as_expected() {
        let sign_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let append_transaction_to_batch_params_arc = Arc::new(Mutex::new(vec![]));
        let new_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        let submit_batch_params_arc: Arc<Mutex<Vec<Web3<Batch<TestTransport>>>>> =
            Arc::new(Mutex::new(vec![]));
        let reference_counter_arc = Arc::new(());
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let initiate_fingerprints_recipient = accountant.start().recipient();
        let consuming_wallet_secret = b"consuming_wallet_0123456789abcde";
        let secret_key =
            (&Bip32ECKeyProvider::from_raw_secret(consuming_wallet_secret).unwrap()).into();
        let batch_wide_timestamp_expected = SystemTime::now();
        let transport = TestTransport::default().initiate_reference_counter(&reference_counter_arc);
        let chain = Chain::EthMainnet;
        let mut subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let first_transaction_params_expected = TransactionParameters {
            nonce: Some(U256::from(4)),
            to: Some(subject.contract_address()),
            gas: U256::from(56_552),
            gas_price: Some(U256::from(123000000000_u64)),
            value: U256::from(0),
            data: Bytes(vec![
                169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                99, 114, 101, 100, 105, 116, 111, 114, 51, 50, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 149, 149, 231, 24,
            ]),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let first_signed_transaction = subject
            .web3
            .accounts()
            .sign_transaction(first_transaction_params_expected.clone(), &secret_key)
            .wait()
            .unwrap();
        let second_transaction_params_expected = TransactionParameters {
            nonce: Some(U256::from(5)),
            to: Some(subject.contract_address()),
            gas: U256::from(56_552),
            gas_price: Some(U256::from(123000000000_u64)),
            value: U256::from(0),
            data: Bytes(vec![
                169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                99, 114, 101, 100, 105, 116, 111, 114, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 156, 231, 56, 4,
            ]),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let second_signed_transaction = subject
            .web3
            .accounts()
            .sign_transaction(second_transaction_params_expected.clone(), &secret_key)
            .wait()
            .unwrap();
        let first_hash = first_signed_transaction.transaction_hash;
        let second_hash = second_signed_transaction.transaction_hash;
        //technically, the JSON values in the correct responses don't matter, we only check for errors if any came back
        let rpc_responses = vec![
            Ok(Value::String((&first_hash.to_string()[2..]).to_string())),
            Ok(Value::String((&second_hash.to_string()[2..]).to_string())),
        ];
        let batch_payables_tools = BatchPayableToolsMock::default()
            .sign_transaction_params(&sign_transaction_params_arc)
            .sign_transaction_result(Ok(first_signed_transaction.clone()))
            .sign_transaction_result(Ok(second_signed_transaction.clone()))
            .batch_wide_timestamp_result(batch_wide_timestamp_expected)
            .send_new_payable_fingerprint_credentials_params(&new_payable_fingerprint_params_arc)
            .append_transaction_to_batch_params(&append_transaction_to_batch_params_arc)
            .submit_batch_params(&submit_batch_params_arc)
            .submit_batch_result(Ok(rpc_responses));
        subject.batch_payable_tools = Box::new(batch_payables_tools);
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret);
        let first_payment_amount = 333_222_111_000;
        let first_creditor_wallet = make_wallet("creditor321");
        let first_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            first_creditor_wallet.clone(),
            first_payment_amount,
            None,
        );
        let second_payment_amount = 11_222_333_444;
        let second_creditor_wallet = make_wallet("creditor123");
        let second_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            second_creditor_wallet.clone(),
            second_payment_amount,
            None,
        );
        let agent = make_initialized_agent(123, consuming_wallet, U256::from(4), chain);

        let result = subject.send_batch_of_payables(
            agent,
            &initiate_fingerprints_recipient,
            &vec![first_account, second_account],
        );

        let first_resulting_pending_payable = PendingPayable {
            recipient_wallet: first_creditor_wallet.clone(),
            hash: first_hash,
        };
        let second_resulting_pending_payable = PendingPayable {
            recipient_wallet: second_creditor_wallet.clone(),
            hash: second_hash,
        };
        assert_eq!(
            result,
            Ok(vec![
                Correct(first_resulting_pending_payable),
                Correct(second_resulting_pending_payable)
            ])
        );
        let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        let (first_transaction_params_actual, web3, secret) = sign_transaction_params.remove(0);
        assert_eq!(
            first_transaction_params_actual,
            first_transaction_params_expected
        );
        let check_web3_origin = |web3: &Web3<Batch<TestTransport>>| {
            let ref_count_before_clone = Arc::strong_count(&reference_counter_arc);
            let _new_ref = web3.clone();
            let ref_count_after_clone = Arc::strong_count(&reference_counter_arc);
            assert_eq!(ref_count_after_clone, ref_count_before_clone + 1);
        };
        check_web3_origin(&web3);
        assert_eq!(
            secret,
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret.keccak256()).unwrap())
                .into()
        );
        let (second_transaction_params_actual, web3_from_st_call, secret) =
            sign_transaction_params.remove(0);
        assert_eq!(
            second_transaction_params_actual,
            second_transaction_params_expected
        );
        check_web3_origin(&web3_from_st_call);
        assert_eq!(
            secret,
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret.keccak256()).unwrap())
                .into()
        );
        assert!(sign_transaction_params.is_empty());
        let new_payable_fingerprint_params = new_payable_fingerprint_params_arc.lock().unwrap();
        let (batch_wide_timestamp, recipient, actual_pending_payables) =
            &new_payable_fingerprint_params[0];
        assert_eq!(batch_wide_timestamp, &batch_wide_timestamp_expected);
        assert_eq!(
            actual_pending_payables,
            &vec![
                (first_hash, first_payment_amount),
                (second_hash, second_payment_amount)
            ]
        );
        let mut append_transaction_to_batch_params =
            append_transaction_to_batch_params_arc.lock().unwrap();
        let (bytes_first_payment, web3_from_ertb_call_1) =
            append_transaction_to_batch_params.remove(0);
        check_web3_origin(&web3_from_ertb_call_1);
        assert_eq!(
            bytes_first_payment,
            first_signed_transaction.raw_transaction
        );
        let (bytes_second_payment, web3_from_ertb_call_2) =
            append_transaction_to_batch_params.remove(0);
        check_web3_origin(&web3_from_ertb_call_2);
        assert_eq!(
            bytes_second_payment,
            second_signed_transaction.raw_transaction
        );
        assert_eq!(append_transaction_to_batch_params.len(), 0);
        let submit_batch_params = submit_batch_params_arc.lock().unwrap();
        let web3_from_sb_call = &submit_batch_params[0];
        assert_eq!(submit_batch_params.len(), 1);
        check_web3_origin(&web3_from_sb_call);
        assert!(accountant_recording_arc.lock().unwrap().is_empty());
        let system = System::new("non_clandestine_interface_send_payables_in_batch_components_are_used_together_properly");
        let probe_message = PendingPayableFingerprintSeeds {
            batch_wide_timestamp: SystemTime::now(),
            hashes_and_balances: vec![],
        };
        recipient.try_send(probe_message).unwrap();
        System::current().stop();
        system.run();
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 1)
    }

    #[test]
    fn web3_gas_limit_const_part_returns_reasonable_values() {
        type Subject = BlockchainInterfaceNonClandestine<Http>;
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
        assert_eq!(
            Subject::web3_gas_limit_const_part(Chain::PolyMumbai),
            70_000
        );
        assert_eq!(Subject::web3_gas_limit_const_part(Chain::Dev), 55_000);
    }

    #[test]
    fn non_clandestine_gas_limit_for_polygon_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::PolyMainnet);
    }

    #[test]
    fn non_clandestine_gas_limit_for_eth_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::EthMainnet)
    }

    fn test_gas_limit_is_between_limits(chain: Chain) {
        let sign_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        let transport = TestTransport::default();
        let mut subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let not_under_this_value =
            BlockchainInterfaceNonClandestine::<Http>::web3_gas_limit_const_part(chain);
        let not_above_this_value = not_under_this_value + WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
        let consuming_wallet_secret_raw_bytes = b"my-wallet";
        let batch_payable_tools = BatchPayableToolsMock::<TestTransport>::default()
            .sign_transaction_params(&sign_transaction_params_arc)
            .sign_transaction_result(Ok(make_default_signed_transaction()));
        subject.batch_payable_tools = Box::new(batch_payable_tools);
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(5);

        let _ = subject.sign_transaction(
            &make_wallet("wallet1"),
            &consuming_wallet,
            1_000_000_000,
            nonce,
            gas_price,
        );

        let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        let (transaction_params, _, secret) = sign_transaction_params.remove(0);
        assert!(sign_transaction_params.is_empty());
        assert!(
            transaction_params.gas >= U256::from(not_under_this_value),
            "actual gas limit {} isn't above {}",
            transaction_params.gas,
            not_under_this_value
        );
        assert!(
            transaction_params.gas <= U256::from(not_above_this_value),
            "actual gas limit {} isn't below {}",
            transaction_params.gas,
            not_above_this_value
        );
        assert_eq!(
            secret,
            (&Bip32ECKeyProvider::from_raw_secret(&consuming_wallet_secret_raw_bytes.keccak256())
                .unwrap())
                .into()
        );
    }

    #[test]
    fn signing_error_ends_iteration_over_accounts_after_detecting_first_error_which_is_then_propagated_all_way_up_and_out(
    ) {
        let transport = TestTransport::default();
        let chain = Chain::PolyMumbai;
        let batch_payable_tools = BatchPayableToolsMock::<TestTransport>::default()
            .sign_transaction_result(Err(Web3Error::Signing(
                secp256k1secrets::Error::InvalidSecretKey,
            )))
            //we return after meeting the first result
            .sign_transaction_result(Err(Web3Error::Internal));
        let mut subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        subject.batch_payable_tools = Box::new(batch_payable_tools);
        let recipient = Recorder::new().start().recipient();
        let consuming_wallet = make_paying_wallet(&b"consume, you greedy fool!"[..]);
        let accounts = vec![make_payable_account(5555), make_payable_account(6666)];
        let agent = make_initialized_agent(123, consuming_wallet, U256::from(4), chain);
        let result = subject.send_batch_of_payables(agent, &recipient, &accounts);

        assert_eq!(
            result,
            Err(PayableTransactionError::Signing(
                "Signing error: secp: malformed or out-of-range \
            secret key"
                    .to_string()
            ))
        )
    }

    #[test]
    fn send_batch_of_payables_fails_on_badly_prepared_consuming_wallet_without_secret() {
        let transport = TestTransport::default();
        let incomplete_consuming_wallet =
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let chain = TEST_DEFAULT_CHAIN;
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let system = System::new("test");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let agent = make_initialized_agent(123, incomplete_consuming_wallet, U256::from(1), chain);

        let result = subject.send_batch_of_payables(agent, &recipient, &vec![account]);

        System::current().stop();
        system.run();
        assert_eq!(result,
                   Err(PayableTransactionError::UnusableWallet("Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()))
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0)
    }

    #[test]
    fn send_batch_of_payables_fails_on_sending() {
        let transport = TestTransport::default();
        let hash = make_tx_hash(123);
        let mut signed_transaction = make_default_signed_transaction();
        signed_transaction.transaction_hash = hash;
        let batch_payable_tools = BatchPayableToolsMock::<TestTransport>::default()
            .sign_transaction_result(Ok(signed_transaction))
            .batch_wide_timestamp_result(SystemTime::now())
            .submit_batch_result(Err(Web3Error::Transport("Transaction crashed".to_string())));
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let chain = Chain::PolyMumbai;
        let mut subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        subject.batch_payable_tools = Box::new(batch_payable_tools);
        let unimportant_recipient = Recorder::new().start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            5000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let agent = make_initialized_agent(120, consuming_wallet, U256::from(6), chain);

        let result = subject.send_batch_of_payables(agent, &unimportant_recipient, &vec![account]);

        assert_eq!(
            result,
            Err(PayableTransactionError::Sending {
                msg: "Transport error: Transaction crashed".to_string(),
                hashes: vec![hash]
            })
        );
    }

    #[test]
    fn sign_transaction_fails_on_signing_itself() {
        let transport = TestTransport::default();
        let batch_payable_tools = BatchPayableToolsMock::<TestTransport>::default()
            .sign_transaction_result(Err(Web3Error::Signing(
                secp256k1secrets::Error::InvalidSecretKey,
            )));
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let chain = Chain::PolyMumbai;
        let mut subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        subject.batch_payable_tools = Box::new(batch_payable_tools);
        let recipient = make_wallet("unlucky man");
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(1);

        let result =
            subject.sign_transaction(&recipient, &consuming_wallet, 444444, nonce, gas_price);

        assert_eq!(
            result,
            Err(PayableTransactionError::Signing(
                "Signing error: secp: malformed or out-of-range secret key".to_string()
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
        let transport = TestTransport::default();
        let subject =
            BlockchainInterfaceNonClandestine::new(transport, make_fake_event_loop_handle(), chain);
        let consuming_wallet = test_consuming_wallet_with_secret();
        let recipient_wallet = test_recipient_wallet();
        let nonce_correct_type = U256::from(nonce);
        let gas_price = match chain {
            Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => TEST_GAS_PRICE_ETH,
            Chain::PolyMainnet | Chain::PolyMumbai => TEST_GAS_PRICE_POLYGON,
        };
        let payable_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet,
            TEST_PAYMENT_AMOUNT,
            None,
        );

        let signed_transaction = subject
            .sign_transaction(
                &payable_account.wallet,
                &consuming_wallet,
                payable_account.balance_wei,
                nonce_correct_type,
                gas_price,
            )
            .unwrap();

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(byte_set_to_compare.as_slice(), template)
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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
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
        let chain = TEST_DEFAULT_CHAIN;
        let subject = BlockchainInterfaceNonClandestine::new(transport, event_loop_handle, chain);
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
    fn advance_used_nonce() {
        let initial_nonce = U256::from(55);

        let result =
            BlockchainInterfaceNonClandestine::<TestTransport>::advance_used_nonce(initial_nonce);

        assert_eq!(result, U256::from(56))
    }

    #[test]
    fn output_by_joining_sources_works() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("4567"),
                balance_wei: 2_345_678,
                last_paid_timestamp: from_time_t(4500000),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("5656"),
                balance_wei: 6_543_210,
                last_paid_timestamp: from_time_t(333000),
                pending_payable_opt: None,
            },
        ];
        let fingerprint_inputs = vec![
            (make_tx_hash(444), 2_345_678),
            (make_tx_hash(333), 6_543_210),
        ];
        let responses = vec![
            Ok(Value::String(String::from("blah"))),
            Err(web3::Error::Rpc(RPCError {
                code: ErrorCode::ParseError,
                message: "I guess we've got a problem".to_string(),
                data: None,
            })),
        ];

        let result = BlockchainInterfaceNonClandestine::<TestTransport>::merged_output_data(
            responses,
            fingerprint_inputs,
            &accounts,
        );

        assert_eq!(
            result,
            vec![
                Correct(PendingPayable {
                    recipient_wallet: make_wallet("4567"),
                    hash: make_tx_hash(444)
                }),
                Failed(RpcFailurePayables {
                    rpc_error: web3::Error::Rpc(RPCError {
                        code: ErrorCode::ParseError,
                        message: "I guess we've got a problem".to_string(),
                        data: None,
                    }),
                    recipient_wallet: make_wallet("5656"),
                    hash: make_tx_hash(333)
                })
            ]
        )
    }

    fn make_initialized_agent(
        gas_price_gwei: u64,
        consuming_wallet: Wallet,
        nonce: U256,
        chain: Chain,
    ) -> Box<dyn BlockchainAgent> {
        let gas_limit_const_part =
            BlockchainInterfaceNonClandestine::<Http>::web3_gas_limit_const_part(chain);
        let consuming_wallet_balances = ConsumingWalletBalances {
            transaction_fee_balance_in_minor_units: Default::default(),
            masq_token_balance_in_minor_units: Default::default(),
        };
        Box::new(BlockchainAgentWeb3::new(
            gas_price_gwei,
            gas_limit_const_part,
            consuming_wallet,
            consuming_wallet_balances,
            nonce,
        ))
    }

    #[test]
    fn hash_the_smartcontract_transfer_function_signature() {
        assert_eq!(
            TRANSFER_METHOD_ID,
            "transfer(address,uint256)".keccak256()[0..4]
        );
    }
}
