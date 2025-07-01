// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::scanners::payable_scanner_extension::msgs::PricedQualifiedPayables;
use crate::blockchain::blockchain_agent::agent_web3::BlockchainAgentWeb3;
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    BlockchainInterfaceWeb3, HashAndAmount, TRANSFER_METHOD_ID,
};
use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError;
use crate::blockchain::blockchain_interface::data_structures::{
    ProcessedPayableFallible, RpcPayableFailure,
};
use crate::sub_lib::blockchain_bridge::ConsumingWalletBalances;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::Future;
use masq_lib::blockchains::chains::Chain;
use masq_lib::constants::WALLET_ADDRESS_LENGTH;
use masq_lib::logger::Logger;
use secp256k1secrets::SecretKey;
use serde_json::Value;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::{Batch, Http};
use web3::types::{Bytes, SignedTransaction, TransactionParameters, U256};
use web3::Error as Web3Error;
use web3::Web3;

#[derive(Debug)]
pub struct BlockchainAgentFutureResult {
    pub gas_price_wei: U256,
    pub transaction_fee_balance: U256,
    pub masq_token_balance: U256,
}
pub fn advance_used_nonce(current_nonce: U256) -> U256 {
    current_nonce
        .checked_add(U256::one())
        .expect("unexpected limits")
}

fn error_with_hashes(
    error: Web3Error,
    hashes_and_paid_amounts: Vec<HashAndAmount>,
) -> PayableTransactionError {
    let hashes = hashes_and_paid_amounts
        .into_iter()
        .map(|hash_and_amount| hash_and_amount.hash)
        .collect();
    PayableTransactionError::Sending {
        msg: error.to_string(),
        hashes,
    }
}

pub fn merged_output_data(
    responses: Vec<web3::transports::Result<Value>>,
    hashes_and_paid_amounts: Vec<HashAndAmount>,
    accounts: Vec<PayableAccount>,
) -> Vec<ProcessedPayableFallible> {
    let iterator_with_all_data = responses
        .into_iter()
        .zip(hashes_and_paid_amounts.into_iter())
        .zip(accounts.iter());
    iterator_with_all_data
        .map(
            |((rpc_result, hash_and_amount), account)| match rpc_result {
                Ok(_rpc_result) => {
                    // TODO: GH-547: This rpc_result should be validated
                    ProcessedPayableFallible::Correct(PendingPayable {
                        recipient_wallet: account.wallet.clone(),
                        hash: hash_and_amount.hash,
                    })
                }
                Err(rpc_error) => ProcessedPayableFallible::Failed(RpcPayableFailure {
                    rpc_error,
                    recipient_wallet: account.wallet.clone(),
                    hash: hash_and_amount.hash,
                }),
            },
        )
        .collect()
}

pub fn transmission_log(
    chain: Chain,
    qualified_payables: &PricedQualifiedPayables,
    lowest_nonce_used: U256,
) -> String {
    let chain_name = chain.rec().literal_identifier;
    let account_count = qualified_payables.payables.len();
    let last_nonce_used = lowest_nonce_used + U256::from(account_count - 1);
    let biggest_payable = qualified_payables
        .payables
        .iter()
        .map(|payable_with_gas_price| payable_with_gas_price.payable.balance_wei)
        .max()
        .unwrap();
    let max_length_as_str = biggest_payable.separate_with_commas().len();
    let payment_wei_label = "[payment wei]";
    let payment_column_width = payment_wei_label.len().max(max_length_as_str);

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
        lowest_nonce_used.separate_with_commas(),
        last_nonce_used.separate_with_commas(),
        "[wallet address]",
        "[payment wei]",
        "[gas price wei]",
        first_column_width = WALLET_ADDRESS_LENGTH,
        payment_column_width = payment_column_width,
    ));

    let body = qualified_payables
        .payables
        .iter()
        .map(|payable_with_gas_price| {
            let payable = &payable_with_gas_price.payable;
            format!(
                "{:wallet_address_length$}   {:<payment_column_width$}   {}\n",
                payable.wallet,
                payable.balance_wei.separate_with_commas(),
                payable_with_gas_price
                    .gas_price_minor
                    .separate_with_commas(),
                wallet_address_length = WALLET_ADDRESS_LENGTH,
                payment_column_width = payment_column_width,
            )
        });
    introduction.chain(body).collect()
}

pub fn sign_transaction_data(amount: u128, recipient_wallet: Wallet) -> [u8; 68] {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&recipient_wallet.address().0[..]);
    U256::from(amount).to_big_endian(&mut data[36..68]);
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
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price_in_wei: u128,
) -> SignedTransaction {
    let data = sign_transaction_data(amount, recipient_wallet);
    let gas_limit = gas_limit(data, chain);
    // Warning: If you set gas_price or nonce to None in transaction_parameters, sign_transaction
    // will start making RPC calls which we don't want (Do it at your own risk).
    let transaction_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(chain.rec().contract),
        gas: gas_limit,
        gas_price: Some(U256::from(gas_price_in_wei)),
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
    recipient: &PayableAccount,
    consuming_wallet: Wallet,
    nonce: U256,
    gas_price_in_wei: u128,
) -> HashAndAmount {
    let signed_tx = sign_transaction(
        chain,
        web3_batch,
        recipient.wallet.clone(),
        consuming_wallet,
        recipient.balance_wei,
        nonce,
        gas_price_in_wei,
    );
    append_signed_transaction_to_batch(web3_batch, signed_tx.raw_transaction);

    HashAndAmount {
        hash: signed_tx.transaction_hash,
        amount: recipient.balance_wei,
    }
}

pub fn append_signed_transaction_to_batch(web3_batch: &Web3<Batch<Http>>, raw_transaction: Bytes) {
    // This function only prepares a raw transaction for a batch call and doesn't actually send it right here.
    web3_batch.eth().send_raw_transaction(raw_transaction);
}

pub fn sign_and_append_multiple_payments(
    logger: &Logger,
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    consuming_wallet: Wallet,
    mut pending_nonce: U256,
    accounts: &PricedQualifiedPayables,
) -> Vec<HashAndAmount> {
    let mut hash_and_amount_list = vec![];
    accounts.payables.iter().for_each(|payable_pack| {
        let payable = &payable_pack.payable;
        debug!(
            logger,
            "Preparing payable future of {} wei to {} with nonce {}",
            payable.balance_wei.separate_with_commas(),
            payable.wallet,
            pending_nonce
        );

        let hash_and_amount = sign_and_append_payment(
            chain,
            web3_batch,
            payable,
            consuming_wallet.clone(),
            pending_nonce,
            payable_pack.gas_price_minor,
        );

        pending_nonce = advance_used_nonce(pending_nonce);
        hash_and_amount_list.push(hash_and_amount);
    });
    hash_and_amount_list
}

#[allow(clippy::too_many_arguments)]
pub fn send_payables_within_batch(
    logger: &Logger,
    chain: Chain,
    web3_batch: &Web3<Batch<Http>>,
    consuming_wallet: Wallet,
    pending_nonce: U256,
    new_fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
    accounts: PricedQualifiedPayables,
) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError> + 'static>
{
    debug!(
            logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}",
            consuming_wallet,
            chain.rec().contract,
            chain.rec().num_chain_id,
        );

    let hashes_and_paid_amounts = sign_and_append_multiple_payments(
        logger,
        chain,
        web3_batch,
        consuming_wallet,
        pending_nonce,
        &accounts,
    );

    let timestamp = SystemTime::now();
    let hashes_and_paid_amounts_error = hashes_and_paid_amounts.clone();
    let hashes_and_paid_amounts_ok = hashes_and_paid_amounts.clone();

    new_fingerprints_recipient
        .try_send(PendingPayableFingerprintSeeds {
            batch_wide_timestamp: timestamp,
            hashes_and_balances: hashes_and_paid_amounts,
        })
        .expect("Accountant is dead");

    info!(
        logger,
        "{}",
        transmission_log(chain, &accounts, pending_nonce)
    );

    Box::new(
        web3_batch
            .transport()
            .submit_batch()
            .map_err(|e| error_with_hashes(e, hashes_and_paid_amounts_error))
            .and_then(move |batch_response| {
                Ok(merged_output_data(
                    batch_response,
                    hashes_and_paid_amounts_ok,
                    accounts.into(),
                ))
            }),
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
        blockchain_agent_future_result.gas_price_wei.as_u128(),
        gas_limit_const_part,
        wallet,
        cons_wallet_balances,
        chain,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::utils::from_unix_timestamp;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::{
        make_payable_account, make_payable_account_with_wallet_and_balance_and_timestamp_opt,
        make_priced_qualified_payables,
    };
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_agent::agent_web3::WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
        BlockchainInterfaceWeb3, REQUESTS_IN_PARALLEL,
    };
    use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError::Sending;
    use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible::{
        Correct, Failed,
    };
    use crate::blockchain::test_utils::{
        make_tx_hash, transport_error_code, transport_error_message,
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
    use web3::Error::Rpc;

    #[test]
    fn sign_and_append_payment_works() {
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
        let pending_nonce = 1;
        let chain = DEFAULT_CHAIN;
        let gas_price_in_gwei = DEFAULT_GAS_PRICE;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account = make_payable_account(1);
        let web3_batch = Web3::new(Batch::new(transport));

        let result = sign_and_append_payment(
            chain,
            &web3_batch,
            &account,
            consuming_wallet,
            pending_nonce.into(),
            gwei_to_wei(gas_price_in_gwei),
        );

        let mut batch_result = web3_batch.eth().transport().submit_batch().wait().unwrap();
        assert_eq!(
            result,
            HashAndAmount {
                hash: H256::from_str(
                    "94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2"
                )
                .unwrap(),
                amount: account.balance_wei
            }
        );
        assert_eq!(
            batch_result.pop().unwrap().unwrap(),
            Value::String(
                "0x94881436a9c89f48b01651ff491c69e97089daf71ab8cfb240243d7ecf9b38b2".to_string()
            )
        );
    }

    #[test]
    fn send_and_append_multiple_payments_works() {
        let port = find_free_port();
        let logger = Logger::new("send_and_append_multiple_payments_works");
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let web3_batch = Web3::new(Batch::new(transport));
        let chain = DEFAULT_CHAIN;
        let pending_nonce = 1;
        let consuming_wallet = make_paying_wallet(b"paying_wallet");
        let account_1 = make_payable_account(1);
        let account_2 = make_payable_account(2);
        let accounts = make_priced_qualified_payables(vec![
            (account_1, 111_111_111),
            (account_2, 222_222_222),
        ]);

        let result = sign_and_append_multiple_payments(
            &logger,
            chain,
            &web3_batch,
            consuming_wallet,
            pending_nonce.into(),
            &accounts,
        );

        assert_eq!(
            result,
            vec![
                HashAndAmount {
                    hash: H256::from_str(
                        "374b7d023f4ac7d99e612d82beda494b0747116e9b9dc975b33b865f331ee934"
                    )
                    .unwrap(),
                    amount: 1000000000
                },
                HashAndAmount {
                    hash: H256::from_str(
                        "5708afd876bc2573f9db984ec6d0e7f8ef222dd9f115643c9b9056d8bef8bbd9"
                    )
                    .unwrap(),
                    amount: 2000000000
                }
            ]
        );
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
        let pending_nonce = 123456789.into();
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
            pending_nonce,
            expected_format,
        );

        // Case 2
        let payments = [
            gwei_to_wei(5_400_u64),
            gwei_to_wei(10_000_u64),
            44_444_555_u128,
        ];
        let pending_nonce = 100.into();
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
            pending_nonce,
            expected_format,
        );

        // Case 3
        let payments = [45_000_888, 1_999_999, 444_444_555];
        let pending_nonce = 1.into();
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
            pending_nonce,
            expected_format,
        );
    }

    fn test_transmission_log(
        case: usize,
        payments: [u128; 3],
        chain: Chain,
        pending_nonce: U256,
        expected_result: &str,
    ) {
        let accounts_to_process_seeds = payments
            .iter()
            .enumerate()
            .map(|(i, payment)| {
                let wallet = make_wallet(&format!("wallet{}", i));
                let gas_price = (i as u128 + 1) * 2 * 123_456_789;
                let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
                    wallet, *payment, None,
                );
                (account, gas_price)
            })
            .collect();
        let accounts_to_process = make_priced_qualified_payables(accounts_to_process_seeds);

        let result = transmission_log(chain, &accounts_to_process, pending_nonce);

        assert_eq!(
            result, expected_result,
            "Test case {}: we expected this format: \"{}\", but it was: \"{}\"",
            case, expected_result, result
        );
    }

    #[test]
    fn output_by_joining_sources_works() {
        let accounts = vec![
            PayableAccount {
                wallet: make_wallet("4567"),
                balance_wei: 2_345_678,
                last_paid_timestamp: from_unix_timestamp(4500000),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("5656"),
                balance_wei: 6_543_210,
                last_paid_timestamp: from_unix_timestamp(333000),
                pending_payable_opt: None,
            },
        ];
        let fingerprint_inputs = vec![
            HashAndAmount {
                hash: make_tx_hash(444),
                amount: 2_345_678,
            },
            HashAndAmount {
                hash: make_tx_hash(333),
                amount: 6_543_210,
            },
        ];
        let responses = vec![
            Ok(Value::String(String::from("blah"))),
            Err(web3::Error::Rpc(Error {
                code: ErrorCode::ParseError,
                message: "I guess we've got a problem".to_string(),
                data: None,
            })),
        ];

        let result = merged_output_data(responses, fingerprint_inputs, accounts.to_vec());

        assert_eq!(
            result,
            vec![
                Correct(PendingPayable {
                    recipient_wallet: make_wallet("4567"),
                    hash: make_tx_hash(444)
                }),
                Failed(RpcPayableFailure {
                    rpc_error: web3::Error::Rpc(Error {
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

    fn test_send_payables_within_batch(
        test_name: &str,
        accounts: PricedQualifiedPayables,
        expected_result: Result<Vec<ProcessedPayableFallible>, PayableTransactionError>,
        port: u16,
    ) {
        init_test_logging();
        let (_event_loop_handle, transport) = Http::with_max_parallel(
            &format!("http://{}:{}", &Ipv4Addr::LOCALHOST, port),
            REQUESTS_IN_PARALLEL,
        )
        .unwrap();
        let pending_nonce: U256 = 1.into();
        let web3_batch = Web3::new(Batch::new(transport));
        let (accountant, _, accountant_recording) = make_recorder();
        let logger = Logger::new(test_name);
        let chain = DEFAULT_CHAIN;
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let new_fingerprints_recipient = accountant.start().recipient();
        let system = System::new(test_name);
        let timestamp_before = SystemTime::now();

        let result = send_payables_within_batch(
            &logger,
            chain,
            &web3_batch,
            consuming_wallet.clone(),
            pending_nonce,
            new_fingerprints_recipient,
            accounts.clone(),
        )
        .wait();

        System::current().stop();
        system.run();
        let timestamp_after = SystemTime::now();
        let accountant_recording_result = accountant_recording.lock().unwrap();
        let ppfs_message =
            accountant_recording_result.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(accountant_recording_result.len(), 1);
        assert!(timestamp_before <= ppfs_message.batch_wide_timestamp);
        assert!(timestamp_after >= ppfs_message.batch_wide_timestamp);
        let tlh = TestLogHandler::new();
        tlh.exists_log_containing(
            &format!("DEBUG: {test_name}: Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}",
                     consuming_wallet,
                     chain.rec().contract,
                     chain.rec().num_chain_id,
            )
        );
        tlh.exists_log_containing(&format!(
            "INFO: {test_name}: {}",
            transmission_log(chain, &accounts, pending_nonce)
        ));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn send_payables_within_batch_works() {
        let account_1 = make_payable_account(1);
        let account_2 = make_payable_account(2);
        let port = find_free_port();
        let _blockchain_client_server = MBCSBuilder::new(port)
            .begin_batch()
            // TODO: GH-547: This rpc_result should be validated in production code.
            .ok_response("irrelevant_ok_rpc_response".to_string(), 7)
            .ok_response("irrelevant_ok_rpc_response_2".to_string(), 8)
            .end_batch()
            .start();
        let expected_result = Ok(vec![
            Correct(PendingPayable {
                recipient_wallet: account_1.wallet.clone(),
                hash: H256::from_str(
                    "6e7fa351eef640186f76c629cb74106b3082c8f8a1a9df75ff02fe5bfd4dd1a2",
                )
                .unwrap(),
            }),
            Correct(PendingPayable {
                recipient_wallet: account_2.wallet.clone(),
                hash: H256::from_str(
                    "b67a61b29c0c48d8b63a64fda73b3247e8e2af68082c710325675d4911e113d4",
                )
                .unwrap(),
            }),
        ]);

        test_send_payables_within_batch(
            "send_payables_within_batch_works",
            make_priced_qualified_payables(vec![
                (account_1, 111_111_111),
                (account_2, 222_222_222),
            ]),
            expected_result,
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_fails_on_submit_batch_call() {
        let accounts = make_priced_qualified_payables(vec![
            (make_payable_account(1), 111_222_333),
            (make_payable_account(2), 222_333_444),
        ]);
        let os_code = transport_error_code();
        let os_msg = transport_error_message();
        let port = find_free_port();
        let expected_result = Err(Sending {
            msg: format!("Transport error: Error(Connect, Os {{ code: {}, kind: ConnectionRefused, message: {:?} }})", os_code, os_msg).to_string(),
            hashes: vec![
                H256::from_str("ec7ac48060b75889f949f5e8d301b386198218e60e2635c95cb6b0934a0887ea").unwrap(),
                H256::from_str("c2d5059db0ec2fbf15f83d9157eeb0d793d6242de5e73a607935fb5660e7e925").unwrap()
            ],
        });

        test_send_payables_within_batch(
            "send_payables_within_batch_fails_on_submit_batch_call",
            accounts,
            expected_result,
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_all_payments_fail() {
        let account_1 = make_payable_account(1);
        let account_2 = make_payable_account(2);
        let port = find_free_port();
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
        let expected_result = Ok(vec![
            Failed(RpcPayableFailure {
                rpc_error: Rpc(Error {
                    code: ServerError(429),
                    message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                    data: None,
                }),
                recipient_wallet: account_1.wallet.clone(),
                hash: H256::from_str("6e7fa351eef640186f76c629cb74106b3082c8f8a1a9df75ff02fe5bfd4dd1a2").unwrap(),
            }),
            Failed(RpcPayableFailure {
                rpc_error: Rpc(Error {
                    code: ServerError(429),
                    message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                    data: None,
                }),
                recipient_wallet: account_2.wallet.clone(),
                hash: H256::from_str("ca6ad0a60daeaf31cbca7ce6e499c0f4ff5870564c5e845de11834f1fc05bd4e").unwrap(),
            }),
        ]);

        test_send_payables_within_batch(
            "send_payables_within_batch_all_payments_fail",
            make_priced_qualified_payables(vec![
                (account_1, 111_111_111),
                (account_2, 111_111_111),
            ]),
            expected_result,
            port,
        );
    }

    #[test]
    fn send_payables_within_batch_one_payment_works_the_other_fails() {
        let account_1 = make_payable_account(1);
        let account_2 = make_payable_account(2);
        let port = find_free_port();
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
        let expected_result = Ok(vec![
            Correct(PendingPayable {
                recipient_wallet: account_1.wallet.clone(),
                hash: H256::from_str("6e7fa351eef640186f76c629cb74106b3082c8f8a1a9df75ff02fe5bfd4dd1a2").unwrap(),
            }),
            Failed(RpcPayableFailure {
                rpc_error: Rpc(Error {
                    code: ServerError(429),
                    message: "The requests per second (RPS) of your requests are higher than your plan allows.".to_string(),
                    data: None,
                }),
                recipient_wallet: account_2.wallet.clone(),
                hash: H256::from_str("ca6ad0a60daeaf31cbca7ce6e499c0f4ff5870564c5e845de11834f1fc05bd4e").unwrap(),
            }),
        ]);

        test_send_payables_within_batch(
            "send_payables_within_batch_one_payment_works_the_other_fails",
            make_priced_qualified_payables(vec![
                (account_1, 111_111_111),
                (account_2, 111_111_111),
            ]),
            expected_result,
            port,
        );
    }

    #[test]
    fn advance_used_nonce_works() {
        let initial_nonce = U256::from(55);

        let result = advance_used_nonce(initial_nonce);

        assert_eq!(result, U256::from(56))
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
        let recipient_wallet = make_wallet("unlucky man");
        let consuming_wallet = make_wallet("bad_wallet");
        let gas_price = 123_000_000_000;
        let nonce = U256::from(1);

        sign_transaction(
            Chain::PolyAmoy,
            &Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            444444,
            nonce,
            gas_price,
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
        let gas_price_in_wei = 123 * 10_u128.pow(18);
        let nonce = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let consuming_wallet_secret_key = consuming_wallet.prepare_secp256k1_secret().unwrap();
        let data = sign_transaction_data(amount, recipient_wallet.clone());
        let tx_parameters = TransactionParameters {
            nonce: Some(nonce),
            to: Some(chain.rec().contract),
            gas: gas_limit(data, chain),
            gas_price: Some(U256::from(gas_price_in_wei)),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };
        let result = sign_transaction(
            chain,
            &Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            amount,
            nonce,
            gas_price_in_wei,
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
        let data = sign_transaction_data(amount, recipient_wallet);
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
        let nonce_correct_type = U256::from(nonce);
        let gas_price_in_gwei = match chain {
            Chain::EthMainnet => TEST_GAS_PRICE_ETH,
            Chain::EthRopsten => TEST_GAS_PRICE_ETH,
            Chain::PolyMainnet => TEST_GAS_PRICE_POLYGON,
            Chain::PolyAmoy => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };
        let payable_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet,
            TEST_PAYMENT_AMOUNT,
            None,
        );

        let signed_transaction = sign_transaction(
            chain,
            &Web3::new(Batch::new(transport)),
            payable_account.wallet,
            consuming_wallet,
            payable_account.balance_wei,
            nonce_correct_type,
            gwei_to_wei(gas_price_in_gwei),
        );

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(byte_set_to_compare.as_slice(), template)
    }

    fn test_gas_limit_is_between_limits(chain: Chain) {
        let not_under_this_value = BlockchainInterfaceWeb3::web3_gas_limit_const_part(chain);
        let not_above_this_value = not_under_this_value + WEB3_MAXIMAL_GAS_LIMIT_MARGIN;
        let data = sign_transaction_data(1_000_000_000, make_wallet("wallet1"));

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
