// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::sent_payable_dao::{SentTx, TxStatus};
use crate::accountant::db_access_objects::utils::{to_unix_timestamp, TxHash};
use crate::accountant::scanners::payable_scanner_extension::msgs::PricedQualifiedPayables;
use crate::accountant::PendingPayable;
use crate::blockchain::blockchain_agent::agent_web3::BlockchainAgentWeb3;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::RegisterNewPendingPayables;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, TRANSFER_METHOD_ID,
};
use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError;
use crate::blockchain::blockchain_interface::data_structures::BatchResults;
use crate::blockchain::errors::validation_status::ValidationStatus;
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use ethabi::Address;
use futures::Future;
use itertools::Either;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use masq_lib::logger::Logger;
use secp256k1secrets::SecretKey;
use serde_json::Value;
use std::collections::HashSet;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::{Batch, Http};
use web3::types::{Bytes, SignedTransaction, TransactionParameters, U256};
use web3::Web3;

#[derive(Debug)]
pub struct BlockchainAgentFutureResult {
    pub gas_price_minor: U256,
    pub transaction_fee_balance: U256,
    pub masq_token_balance: U256,
}

fn return_sending_error(sent_txs: &[Tx], error: &Web3Error) -> LocalPayableError {
    LocalPayableError::Sending(
        sent_txs
            .iter()
            .map(|sent_tx| FailedTx::from((sent_tx, error)))
            .collect(),
    )
}

pub fn return_batch_results(
    txs: Vec<Tx>,
    responses: Vec<web3::transports::Result<Value>>,
) -> BatchResults {
    txs.into_iter().zip(responses).fold(
        BatchResults::default(),
        |mut batch_results, (sent_tx, response)| {
            match response {
                Ok(_) => batch_results.sent_txs.push(sent_tx), // TODO: GH-547: Validate the JSON output
                Err(rpc_error) => batch_results
                    .failed_txs
                    .push(FailedTx::from((&sent_tx, &rpc_error))),
            }
            batch_results
        },
    )
}

fn calculate_payments_column_width(signable_tx_templates: &SignableTxTemplates) -> usize {
    let label_length = "[payment wei]".len();
    let largest_amount_length = signable_tx_templates
        .largest_amount()
        .separate_with_commas()
        .len();

    label_length.max(largest_amount_length)
}

pub fn transmission_log(chain: Chain, signable_tx_templates: &SignableTxTemplates) -> String {
    let chain_name = chain.rec().literal_identifier;
    let (first_nonce, last_nonce) = signable_tx_templates.nonce_range();
    let payment_column_width = calculate_payments_column_width(signable_tx_templates);

    let introduction = once(format!(
        "\n\
        Paying creditors\n\
        Transactions:\n\
        \n\
        {:first_column_width$}   {}\n\
        {:first_column_width$}   {}...{}\n\
        \n\
        {:first_column_width$}   {:<payment_column_width$}   {}\n",
        "chain:",
        chain_name,
        "nonces:",
        first_nonce.separate_with_commas(),
        last_nonce.separate_with_commas(),
        "[wallet address]",
        "[payment wei]",
        "[gas price wei]",
        first_column_width = WALLET_ADDRESS_LENGTH,
        payment_column_width = payment_column_width,
    ));

    let body = signable_tx_templates.iter().map(|signable_tx_template| {
        format!(
            "{:wallet_address_length$}   {:<payment_column_width$}   {}\n",
            format!("{:?}", signable_tx_template.receiver_address),
            signable_tx_template.amount_in_wei.separate_with_commas(),
            signable_tx_template.gas_price_wei.separate_with_commas(),
            wallet_address_length = WALLET_ADDRESS_LENGTH,
            payment_column_width = payment_column_width,
        )
    });
    introduction.chain(body).collect()
}

pub fn sign_transaction_data(amount_minor: u128, receiver_address: Address) -> [u8; 68] {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&receiver_address.0[..]);
    U256::from(amount_minor).to_big_endian(&mut data[36..68]);
    data
}

pub fn gas_limit(data: [u8; 68], chain: Chain) -> U256 {
    let base_gas_limit = BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain);
    ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
        acc + if v == &0u8 { 4 } else { 68 }
    }))
    .expect("Internal error")
}

pub fn sign_transaction(
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    signable_tx_template: &SignableTxTemplate,
    consuming_wallet: &Wallet,
) -> SignedTransaction {
    let &SignableTxTemplate {
        receiver_address,
        amount_in_wei,
        gas_price_wei,
        nonce,
    } = signable_tx_template;

    let data = sign_transaction_data(amount_in_wei, receiver_address);
    let gas_limit = gas_limit(data, chain);
    // Warning: If you set gas_price or nonce to None in transaction_parameters, sign_transaction
    // will start making RPC calls which we don't want (Do it at your own risk).
    let transaction_parameters = TransactionParameters {
        nonce: Some(U256::from(nonce)),
        to: Some(chain.rec().contract),
        gas: gas_limit,
        gas_price: Some(U256::from(gas_price_wei)),
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };

    let key = consuming_wallet
        .prepare_secp256k1_secret()
        .expect("Consuming wallet doesn't contain a secret key");

    sign_transaction_locally(web3_batch, transaction_parameters, &key)
}

pub fn sign_transaction_locally(
    web3_batch: &Web3<Batch<Http>>,
    transaction_parameters: TransactionParameters,
    key: &SecretKey,
) -> SignedTransaction {
    if transaction_parameters.nonce.is_none()
        || transaction_parameters.chain_id.is_none()
        || transaction_parameters.gas_price.is_none()
    {
        panic!("We don't want to fetch any values while signing");
    }

    // This wait call doesn't actually make any RPC call as long as nonce, chain_id & gas_price are set.
    web3_batch
        .accounts()
        .sign_transaction(transaction_parameters, key)
        .wait()
        .expect("Web call wasn't allowed")
}

pub fn sign_and_append_payment(
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    signable_tx_template: &SignableTxTemplate,
    consuming_wallet: &Wallet,
    logger: &Logger,
) -> Tx {
    let &SignableTxTemplate {
        receiver_address,
        amount_in_wei,
        gas_price_wei,
        nonce,
    } = signable_tx_template;

    let signed_tx = sign_transaction(chain, web3_batch, signable_tx_template, consuming_wallet);

    append_signed_transaction_to_batch(web3_batch, signed_tx.raw_transaction);

    let hash = signed_tx.transaction_hash;
    debug!(
        logger,
        "Appending transaction with hash {:?}, amount: {} wei, to {:?}, nonce: {}, gas price: {} wei",
        hash,
        amount_in_wei.separate_with_commas(),
        receiver_address,
        nonce,
        gas_price_wei.separate_with_commas()
    );

    Tx {
        hash,
        receiver_address,
        amount: amount_in_wei,
        timestamp: to_unix_timestamp(SystemTime::now()),
        gas_price_wei,
        nonce,
        status: TxStatus::Pending(ValidationStatus::Waiting),
    }
}

pub fn append_signed_transaction_to_batch(web3_batch: &Web3<Batch<Http>>, raw_transaction: Bytes) {
    // This function only prepares a raw transaction for a batch call and doesn't actually send it right here.
    web3_batch.eth().send_raw_transaction(raw_transaction);
}

pub fn sign_and_append_multiple_payments(
    now: SystemTime,
    logger: &Logger,
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    signable_tx_templates: &SignableTxTemplates,
    consuming_wallet: Wallet,
) -> Vec<Tx> {
    signable_tx_templates
        .iter()
        .map(|signable_tx_template| {
            sign_and_append_payment(
                chain,
                web3_batch,
                signable_tx_template,
                &consuming_wallet,
                logger,
            )
        })
        .collect()
}

pub fn send_payables_within_batch(
    logger: &Logger,
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    signable_tx_templates: SignableTxTemplates,
    consuming_wallet: Wallet,
) -> Box<dyn Future<Item = BatchResults, Error = LocalPayableError> + 'static> {
    debug!(
            logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}",
            consuming_wallet,
            chain.rec().contract,
            chain.rec().num_chain_id,
        );

    let sent_txs = sign_and_append_multiple_payments(
        logger,
        chain,
        web3_batch,
        &signable_tx_templates,
        consuming_wallet,
    );
    let sent_txs_for_err = sent_txs.clone();
    // TODO: GH-701: We were sending a message here to register txs at an initial stage (refer commit - 2fd4bcc72)

    info!(
        logger,
        "{}",
        transmission_log(chain, &signable_tx_templates)
    );

    Box::new(
        web3_batch
            .transport()
            .submit_batch()
            .map_err(move |e| return_sending_error(&sent_txs_for_err, &e))
            .and_then(move |batch_responses| Ok(return_batch_results(sent_txs, batch_responses))),
    )
}

pub fn create_blockchain_agent_web3(
    blockchain_agent_future_result: BlockchainAgentFutureResult,
    gas_limit_const_part: u128,
    wallet: Wallet,
    chain: Chain,
) -> Box<dyn BlockchainAgent> {
    let transaction_fee_balance_in_minor_units =
        blockchain_agent_future_result.transaction_fee_balance;
    let masq_token_balance_in_minor_units = blockchain_agent_future_result.masq_token_balance;
    let cons_wallet_balances = ConsumingWalletBalances::new(
        transaction_fee_balance_in_minor_units,
        masq_token_balance_in_minor_units,
    );
    Box::new(BlockchainAgentWeb3::new(
        blockchain_agent_future_result.gas_price_minor.as_u128(),
        gas_limit_const_part,
        wallet,
        cons_wallet_balances,
        chain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::test_utils::{
        assert_on_failed_txs, assert_on_sent_txs, FailedTxBuilder, TxBuilder,
    };
    use crate::accountant::gwei_to_wei;
    use crate::accountant::scanners::payable_scanner::tx_templates::priced::new::{
        PricedNewTxTemplate, PricedNewTxTemplates,
    };
    use crate::accountant::scanners::payable_scanner::tx_templates::test_utils::make_signable_tx_template;
    use crate::accountant::scanners::payable_scanner::tx_templates::BaseTxTemplate;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_agent::agent_web3::WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::LocalPayableError::Sending;
    use crate::blockchain::errors::rpc_errors::AppRpcError;
    use crate::blockchain::errors::rpc_errors::LocalError::Transport;
    use crate::blockchain::errors::rpc_errors::RemoteError::Web3RpcError;
    use crate::blockchain::test_utils::{
        make_address, make_blockchain_interface_web3, make_tx_hash, transport_error_code,
        transport_error_message,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::make_recorder;
    use crate::test_utils::unshared_test_utils::decode_hex;
    use actix::{Actor, System};
    use ethabi::Address;
    use ethereum_types::H256;
    use jsonrpc_core::ErrorCode::ServerError;
    use jsonrpc_core::{Error, ErrorCode};
    use masq_lib::constants::{DEFAULT_CHAIN, DEFAULT_GAS_PRICE};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::mock_blockchain_client_server::MBCSBuilder;
    use masq_lib::utils::find_free_port;
    use serde_json::Value;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::SystemTime;
    use web3::api::Namespace;

    #[test]
    fn sign_and_append_payment_works() {
        init_test_logging();
        let test_name = "sign_and_append_payment_works";
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .ok_response(
                "0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2".to_string(),
                7,
            )
            .end_batch()
            .start();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = DEFAULT_CHAIN;
        let gas_price_in_gwei = DEFAULT_GAS_PRICE;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let web3_batch = Web3::new(Batch::new(transport));
        let signable_tx_template = SignableTxTemplate {
            receiver_address: make_wallet("wallet1").address(),
            amount_in_wei: 1_000_000_000,
            gas_price_wei: gwei_to_wei(gas_price_in_gwei),
            nonce: 1,
        };

        let result = sign_and_append_payment(
            chain,
            &web3_batch,
            &signable_tx_template,
            &consuming_wallet,
            &Logger::new(test_name),
        );

        let mut batch_result = web3_batch.eth().transport().submit_batch().wait().unwrap();
        let hash =
            H256::from_str("94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2")
                .unwrap();
        let expected_tx = TxBuilder::default()
            .hash(hash)
            .template(signable_tx_template)
            .timestamp(to_unix_timestamp(SystemTime::now()))
            .status(TxStatus::Pending(ValidationStatus::Waiting))
            .build();
        assert_on_sent_txs(vec![result], vec![expected_tx]);
        assert_eq!(
            batch_result.pop().unwrap().unwrap(),
            Value::String(
                "0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2".to_string()
            )
        );
        TestLogHandler::new().exists_log_containing(&format!(
            "DEBUG: {test_name}: Appending transaction with hash \
            0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2, \
            amount: 1,000,000,000 wei, \
            to 0x0000000000000000000000000077616c6c657431, \
            nonce: 1, \
            gas price: 1,000,000,000 wei"
        ));
    }

    #[test]
    fn sign_and_append_multiple_payments_works() {
        let now = SystemTime::now();
        let port = find_free_port();
        let logger = Logger::new("sign_and_append_multiple_payments_works");
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let signable_tx_templates = SignableTxTemplates(vec![
            make_signable_tx_template(1),
            make_signable_tx_template(2),
            make_signable_tx_template(3),
            make_signable_tx_template(4),
            make_signable_tx_template(5),
        ]);

        let mut result = sign_and_append_multiple_payments(
            now,
            &logger,
            DEFAULT_CHAIN,
            &web3_batch,
            &signable_tx_templates,
            make_paying_wallet(b"paying_wallet"),
        );

        result
            .iter()
            .zip(signable_tx_templates.iter())
            .enumerate()
            .for_each(|(index, (sent_tx, template))| {
                assert_eq!(
                    sent_tx.receiver_address, template.receiver_address,
                    "Transaction {} receiver_address mismatch",
                    index
                );
                assert_eq!(
                    sent_tx.amount, template.amount_in_wei,
                    "Transaction {} amount mismatch",
                    index
                );
                assert_eq!(
                    sent_tx.gas_price_wei, template.gas_price_wei,
                    "Transaction {} gas_price_wei mismatch",
                    index
                );
                assert_eq!(
                    sent_tx.nonce, template.nonce,
                    "Transaction {} nonce mismatch",
                    index
                );
                assert_eq!(
                    sent_tx.status,
                    TxStatus::Pending(ValidationStatus::Waiting),
                    "Transaction {} status mismatch",
                    index
                )
            });
        let first_actual_sent_tx = result.remove(0);
        let second_actual_sent_tx = result.remove(0);
        assert_prepared_sent_tx_record(
            first_actual_sent_tx,
            now,
            account_1,
            "0x6b85347ff8edf8b126dffb85e7517ac7af1b23eace4ed5ad099d783fd039b1ee",
            1,
            111_234_111,
        );
        assert_prepared_sent_tx_record(
            second_actual_sent_tx,
            now,
            account_2,
            "0x3dac025697b994920c9cd72ab0d2df82a7caaa24d44e78b7c04e223299819d54",
            2,
            222_432_222,
        );
    }

    fn assert_prepared_sent_tx_record(
        actual_sent_tx: SentTx,
        now: SystemTime,
        account_1: PayableAccount,
        expected_tx_hash_including_prefix: &str,
        expected_nonce: u64,
        expected_gas_price_minor: u128,
    ) {
        assert_eq!(actual_sent_tx.receiver_address, account_1.wallet.address());
        assert_eq!(
            actual_sent_tx.hash,
            H256::from_str(&expected_tx_hash_including_prefix[2..]).unwrap()
        );
        assert_eq!(actual_sent_tx.amount_minor, account_1.balance_wei);
        assert_eq!(actual_sent_tx.gas_price_minor, expected_gas_price_minor);
        assert_eq!(actual_sent_tx.nonce, expected_nonce);
        assert_eq!(
            actual_sent_tx.status,
            TxStatus::Pending(ValidationStatus::Waiting)
        );
        assert_eq!(actual_sent_tx.timestamp, to_unix_timestamp(now));
    }

    #[test]
    fn transmission_log_is_well_formatted() {
        // This test only focuses on the formatting, but there are other tests asserting printing
        // this in the logs

        // Case 1
        let payments = [
            gwei_to_wei(900_000_000_u64),
            123_456_789_u128,
            gwei_to_wei(33_355_666_u64),
        ];
        let latest_nonce = 123456789;
        let expected_format = "\n\
        Paying creditors\n\
        Transactions:\n\
        \n\
        chain:                                       base-sepolia\n\
        nonces:                                      123,456,789...123,456,791\n\
        \n\
        [wallet address]                             [payment wei]             [gas price wei]\n\
        0x0000000000000000000000000077616c6c657430   900,000,000,000,000,000   246,913,578\n\
        0x0000000000000000000000000077616c6c657431   123,456,789               493,827,156\n\
        0x0000000000000000000000000077616c6c657432   33,355,666,000,000,000    740,740,734\n";

        test_transmission_log(
            1,
            payments,
            Chain::BaseSepolia,
            latest_nonce,
            expected_format,
        );

        // Case 2
        let payments = [
            gwei_to_wei(5_400_u64),
            gwei_to_wei(10_000_u64),
            44_444_555_u128,
        ];
        let latest_nonce = 100;
        let expected_format = "\n\
        Paying creditors\n\
        Transactions:\n\
        \n\
        chain:                                       eth-mainnet\n\
        nonces:                                      100...102\n\
        \n\
        [wallet address]                             [payment wei]        [gas price wei]\n\
        0x0000000000000000000000000077616c6c657430   5,400,000,000,000    246,913,578\n\
        0x0000000000000000000000000077616c6c657431   10,000,000,000,000   493,827,156\n\
        0x0000000000000000000000000077616c6c657432   44,444,555           740,740,734\n";

        test_transmission_log(
            2,
            payments,
            Chain::EthMainnet,
            latest_nonce,
            expected_format,
        );

        // Case 3
        let payments = [45_000_888, 1_999_999, 444_444_555];
        let latest_nonce = 1;
        let expected_format = "\n\
        Paying creditors\n\
        Transactions:\n\
        \n\
        chain:                                       polygon-mainnet\n\
        nonces:                                      1...3\n\
        \n\
        [wallet address]                             [payment wei]   [gas price wei]\n\
        0x0000000000000000000000000077616c6c657430   45,000,888      246,913,578\n\
        0x0000000000000000000000000077616c6c657431   1,999,999       493,827,156\n\
        0x0000000000000000000000000077616c6c657432   444,444,555     740,740,734\n";

        test_transmission_log(
            3,
            payments,
            Chain::PolyMainnet,
            latest_nonce,
            expected_format,
        );
    }

    fn test_transmission_log(
        case: usize,
        payments: [u128; 3],
        chain: Chain,
        latest_nonce: u64,
        expected_result: &str,
    ) {
        let priced_new_tx_templates = payments
            .iter()
            .enumerate()
            .map(|(i, amount_in_wei)| {
                let wallet = make_wallet(&format!("wallet{}", i));
                let computed_gas_price_wei = (i as u128 + 1) * 2 * 123_456_789;
                PricedNewTxTemplate {
                    base: BaseTxTemplate {
                        receiver_address: wallet.address(),
                        amount_in_wei: *amount_in_wei,
                    },
                    computed_gas_price_wei,
                }
            })
            .collect::<PricedNewTxTemplates>();
        let signable_tx_templates =
            SignableTxTemplates::new(Either::Left(priced_new_tx_templates), latest_nonce);

        let result = transmission_log(chain, &signable_tx_templates);

        assert_eq!(
            result, expected_result,
            "Test case {}: we expected this format: \"{}\", but it was: \"{}\"",
            case, expected_result, result
        );
    }

    fn test_send_payables_within_batch(
        test_name: &str,
        signable_tx_templates: SignableTxTemplates,
        expected_result: Result<BatchResults, LocalPayableError>,
        port: u16,
    ) {
        // TODO: GH-701: Add assertions for the new_fingerprints_message here, since it existed earlier
        init_test_logging();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let logger = Logger::new(test_name);
        let chain = DEFAULT_CHAIN;
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let system = System::new(test_name);
        let expected_transmission_log = transmission_log(chain, &signable_tx_templates);

        let result = send_payables_within_batch(
            &logger,
            chain,
            &web3_batch,
            signable_tx_templates,
            consuming_wallet.clone(),
        )
        .wait();

        System::current().stop();
        system.run();
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            &format!("DEBUG: {test_name}: Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}",
                     consuming_wallet,
                     chain.rec().contract,
                     chain.rec().num_chain_id,
            )
        );
        tlh.exists_log_containing(&format!("INFO: {test_name}: {expected_transmission_log}"));
        match result {
            Ok(resulted_batch) => {
                let expected_batch = expected_result.unwrap();
                assert_on_failed_txs(resulted_batch.failed_txs, expected_batch.failed_txs);
                assert_on_sent_txs(resulted_batch.sent_txs, expected_batch.sent_txs);
            }
            Err(resulted_err) => match resulted_err {
                LocalPayableError::Sending(resulted_failed_txs) => {
                    if let Err(LocalPayableError::Sending(expected_failed_txs)) = expected_result {
                        assert_on_failed_txs(resulted_failed_txs, expected_failed_txs);
                    } else {
                        panic!(
                            "Expected different error but received  {}",
                            expected_result.unwrap_err(),
                        )
                    }
                }
                other_err => {
                    panic!("Only LocalPayableError::Sending is returned by send_payables_within_batch but received something else: {} ", other_err)
                }
            },
        }
    }

    #[test]
    fn send_payables_within_batch_works() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let template_1 = SignableTxTemplate {
            receiver_address: make_address(1),
            amount_in_wei: 111_222,
            gas_price_wei: 123,
            nonce: 1,
        };
        let template_2 = SignableTxTemplate {
            receiver_address: make_address(2),
            amount_in_wei: 222_333,
            gas_price_wei: 234,
            nonce: 2,
        };
        let signable_tx_templates =
            SignableTxTemplates(vec![template_1.clone(), template_2.clone()]);
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            // TODO: GH-547: This rpc_result should be validated in production code.
            .ok_response("irrelevant_ok_rpc_response".to_string(), 7)
            .ok_response("irrelevant_ok_rpc_response_2".to_string(), 8)
            .end_batch()
            .start();
        let batch_results = {
            let signed_tx_1 =
                sign_transaction(DEFAULT_CHAIN, &web3_batch, &template_1, &consuming_wallet);
            let sent_tx_1 = TxBuilder::default()
                .hash(signed_tx_1.transaction_hash)
                .template(template_1)
                .status(TxStatus::Pending(ValidationStatus::Waiting))
                .build();
            let signed_tx_2 =
                sign_transaction(DEFAULT_CHAIN, &web3_batch, &template_2, &consuming_wallet);
            let sent_tx_2 = TxBuilder::default()
                .hash(signed_tx_2.transaction_hash)
                .template(template_2)
                .status(TxStatus::Pending(ValidationStatus::Waiting))
                .build();

            BatchResults {
                sent_txs: vec![sent_tx_1, sent_tx_2],
                failed_txs: vec![],
            }
        };

        test_send_payables_within_batch(
            "send_payables_within_batch_works",
            signable_tx_templates,
            Ok(batch_results),
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_fails_on_submit_batch_call() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let signable_tx_templates = SignableTxTemplates(vec![
            SignableTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 12345,
                gas_price_wei: 99,
                nonce: 5,
            },
            SignableTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 22345,
                gas_price_wei: 100,
                nonce: 6,
            },
        ]);
        let os_specific_code = transport_error_code();
        let os_specific_msg = transport_error_message();
        let err_msg = format!(
            "Error(Connect, Os {{ code: {}, kind: ConnectionRefused, message: {:?} }})",
            os_specific_code, os_specific_msg
        );
        let failed_txs = signable_tx_templates
            .iter()
            .map(|template| {
                let signed_tx =
                    sign_transaction(DEFAULT_CHAIN, &web3_batch, template, &consuming_wallet);
                FailedTxBuilder::default()
                    .hash(signed_tx.transaction_hash)
                    .receiver_address(template.receiver_address)
                    .amount(template.amount_in_wei)
                    .timestamp(to_unix_timestamp(SystemTime::now()) - 5)
                    .gas_price_wei(template.gas_price_wei)
                    .nonce(template.nonce)
                    .reason(FailureReason::Submission(AppRpcError::Local(Transport(
                        err_msg.clone(),
                    ))))
                    .status(FailureStatus::RetryRequired)
                    .build()
            })
            .collect();
        let expected_result = Err(Sending(failed_txs));

        test_send_payables_within_batch(
            "send_payables_within_batch_fails_on_submit_batch_call",
            signable_tx_templates,
            expected_result,
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_all_payments_fail() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let signable_tx_templates = SignableTxTemplates(vec![
            SignableTxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 111_222,
                gas_price_wei: 123,
                nonce: 1,
            },
            SignableTxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 222_333,
                gas_price_wei: 234,
                nonce: 2,
            },
        ]);
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                8,
            )
            .end_batch()
            .start();
        let failed_txs = signable_tx_templates
            .iter()
            .map(|template| {
                let signed_tx =
                    sign_transaction(DEFAULT_CHAIN, &web3_batch, template, &consuming_wallet);
                FailedTxBuilder::default()
                    .hash(signed_tx.transaction_hash)
                    .receiver_address(template.receiver_address)
                    .amount(template.amount_in_wei)
                    .timestamp(to_unix_timestamp(SystemTime::now()) - 5)
                    .gas_price_wei(template.gas_price_wei)
                    .nonce(template.nonce)
                    .reason(FailureReason::Submission(AppRpcError::Remote(Web3RpcError { code: 429, message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string() })))
                    .status(FailureStatus::RetryRequired)
                    .build()
            })
            .collect();

        test_send_payables_within_batch(
            "send_payables_within_batch_all_payments_fail",
            signable_tx_templates,
            Ok(BatchResults {
                sent_txs: vec![],
                failed_txs,
            }),
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_one_payment_works_the_other_fails() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let template_1 = SignableTxTemplate {
            receiver_address: make_address(1),
            amount_in_wei: 111_222,
            gas_price_wei: 123,
            nonce: 1,
        };
        let template_2 = SignableTxTemplate {
            receiver_address: make_address(2),
            amount_in_wei: 222_333,
            gas_price_wei: 234,
            nonce: 2,
        };
        let signable_tx_templates =
            SignableTxTemplates(vec![template_1.clone(), template_2.clone()]);
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            .ok_response("rpc_result".to_string(), 7)
            .err_response(
                429,
                "The requests per second (RPS) of your requests are higher than your plan allows."
                    .to_string(),
                7,
            )
            .end_batch()
            .start();
        let batch_results = {
            let signed_tx_1 =
                sign_transaction(DEFAULT_CHAIN, &web3_batch, &template_1, &consuming_wallet);
            let sent_tx = TxBuilder::default()
                .hash(signed_tx_1.transaction_hash)
                .template(template_1)
                .timestamp(to_unix_timestamp(SystemTime::now()))
                .status(TxStatus::Pending(ValidationStatus::Waiting))
                .build();
            let signed_tx_2 =
                sign_transaction(DEFAULT_CHAIN, &web3_batch, &template_2, &consuming_wallet);
            let failed_tx = FailedTxBuilder::default()
                .hash(signed_tx_2.transaction_hash)
                .template(template_2)
                .timestamp(to_unix_timestamp(SystemTime::now()))
                .reason(FailureReason::Submission(AppRpcError::Remote(Web3RpcError {
                    code: 429,
                    message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                })))
                .status(FailureStatus::RetryRequired)
                .build();

            BatchResults {
                sent_txs: vec![sent_tx],
                failed_txs: vec![failed_tx],
            }
        };

        test_send_payables_within_batch(
            "send_payables_within_batch_one_payment_works_the_other_fails",
            signable_tx_templates,
            Ok(batch_results),
            port,
        );
    }

    #[test]
    #[should_panic(
        expected = "Consuming wallet doesn't contain a secret key: Signature(\"Cannot sign with non-keypair wallet: Address(0x000000000000000000006261645f77616c6c6574).\")"
    )]
    fn sign_transaction_panics_due_to_lack_of_secret_key() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let consuming_wallet = make_wallet("bad_wallet");
        let gas_price = 123_000_000_000;
        let signable_tx_template = SignableTxTemplate {
            receiver_address: make_address(1),
            amount_in_wei: 1223,
            gas_price_wei: gas_price,
            nonce: 1,
        };

        sign_transaction(
            Chain::PolyAmoy,
            &Web3::new(Batch::new(transport)),
            &signable_tx_template,
            &consuming_wallet,
        );
    }

    #[test]
    fn sign_transaction_just_works() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3 = Web3::new(transport.clone());
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_price_in_wei = 123 * 10_u128.pow(9);
        let nonce = 5;
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let consuming_wallet_secret_key = consuming_wallet.prepare_secp256k1_secret().unwrap();
        let data = sign_transaction_data(amount, recipient_wallet.address());
        let tx_parameters = TransactionParameters {
            nonce: Some(U256::from(nonce)),
            to: Some(chain.rec().contract),
            gas: gas_limit(data, chain),
            gas_price: Some(U256::from(gas_price_in_wei)),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let signable_tx_template = SignableTxTemplate {
            receiver_address: recipient_wallet.address(),
            amount_in_wei: amount,
            gas_price_wei: gas_price_in_wei,
            nonce,
        };
        let result = sign_transaction(
            chain,
            &Web3::new(Batch::new(transport)),
            &signable_tx_template,
            &consuming_wallet,
        );

        let expected_tx_result = web3
            .accounts()
            .sign_transaction(tx_parameters, &consuming_wallet_secret_key)
            .wait()
            .unwrap();

        assert_eq!(result, expected_tx_result);
    }

    #[test]
    #[should_panic(expected = "We don't want to fetch any values while signing")]
    fn sign_transaction_locally_panics_on_signed_transaction() {
        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_limit = U256::from(5);
        let gas_price = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let data = sign_transaction_data(amount, recipient_wallet.address());
        // sign_transaction makes a blockchain call because nonce is set to None
        let transaction_parameters = TransactionParameters {
            nonce: None,
            to: Some(chain.rec().contract),
            gas: gas_limit,
            gas_price: Some(gas_price),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let key = consuming_wallet
            .prepare_secp256k1_secret()
            .expect("Consuming wallet doesn't contain a secret key");

        let _result = sign_transaction_locally(
            &Web3::new(Batch::new(transport)),
            transaction_parameters,
            &key,
        );
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_polygon_amoy() {
        let chain = Chain::PolyAmoy;
        let nonce = 4;
        let signed_transaction_data = "f8ad04850ba43b74008301198094d98c3ebd6b7f9b7cda2449ecac00d1e5f47a819380b844a9\
        059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b0000000000000000000000000000000000000000000\
        00000000000e8d4a5100083027127a0ef0873170be31c30f532edf3c97fe8a1d577859fd4045b060007cf9e75bda875a01e4a3f7e06d12b22\
        68d9889e279643ad8e1d291bca8f9f741bd6ec1aca2c0766";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_eth_ropsten() {
        let chain = Chain::EthRopsten;
        let nonce = 1; //must stay like this!
        let signed_transaction_data = "f8a90185199c82cc0082dee894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cb\
        b0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000\
        000e8d4a510002aa0635fbb3652e1c3063afac6ffdf47220e0431825015aef7daff9251694e449bfca00b2ed6d556bd030ac75291bf58817da15\
        a891cd027a4c261bb80b51f33b78adf";
        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //not confirmed on the real network
    #[test]
    fn web3_interface_signing_a_transaction_for_polygon_mainnet() {
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
    fn web3_interface_signing_a_transaction_for_eth_mainnet() {
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

    #[test]
    fn gas_limit_for_polygon_mumbai_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::PolyAmoy);
    }

    #[test]
    fn gas_limit_for_polygon_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::PolyMainnet);
    }

    #[test]
    fn gas_limit_for_eth_mainnet_lies_within_limits_for_raw_transaction() {
        test_gas_limit_is_between_limits(Chain::EthMainnet)
    }

    fn assert_that_signed_transactions_agrees_with_template(
        chain: Chain,
        nonce: u64,
        template: &[u8],
    ) {
        const TEST_PAYMENT_AMOUNT: u128 = 1_000_000_000_000;
        const TEST_GAS_PRICE_ETH: u64 = 110;
        const TEST_GAS_PRICE_POLYGON: u64 = 50;

        let port = find_free_port();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST.to_string(), port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let consuming_wallet = {
            let key_pair = Bip32EncryptionKeyProvider::from_raw_secret(
                &decode_hex("97923d8fd8de4a00f912bfb77ef483141dec551bd73ea59343ef5c4aac965d04")
                    .unwrap(),
            )
            .unwrap();
            Wallet::from(key_pair)
        };
        let recipient_wallet = {
            let hex_part = &"0x7788df76BBd9a0C7c3e5bf0f77bb28C60a167a7b"[2..];
            let recipient_address_bytes = decode_hex(hex_part).unwrap();
            let address = Address::from_slice(&recipient_address_bytes);
            Wallet::from(address)
        };
        let gas_price_in_gwei = match chain {
            Chain::EthMainnet => TEST_GAS_PRICE_ETH,
            Chain::EthRopsten => TEST_GAS_PRICE_ETH,
            Chain::PolyMainnet => TEST_GAS_PRICE_POLYGON,
            Chain::PolyAmoy => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };
        let signable_tx_template = SignableTxTemplate {
            receiver_address: recipient_wallet.address(),
            amount_in_wei: TEST_PAYMENT_AMOUNT,
            gas_price_wei: gwei_to_wei(gas_price_in_gwei),
            nonce,
        };

        let signed_transaction = sign_transaction(
            chain,
            &Web3::new(Batch::new(transport)),
            &signable_tx_template,
            &consuming_wallet,
        );

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(byte_set_to_compare.as_slice(), template)
    }

    fn test_gas_limit_is_between_limits(chain: Chain) {
        let not_under_this_value = BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain);
        let not_above_this_value = not_under_this_value + WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
        let data = sign_transaction_data(1_000_000_000, make_wallet("wallet1").address());

        let gas_limit = gas_limit(data, chain);

        assert!(
            gas_limit >= U256::from(not_under_this_value),
            "actual gas limit {} isn't above or equal {}",
            gas_limit,
            not_under_this_value
        );
        assert!(
            gas_limit <= U256::from(not_above_this_value),
            "actual gas limit {} isn't below or equal {}",
            gas_limit,
            not_above_this_value
        );
    }
}
