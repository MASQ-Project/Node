use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PendingPayable};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{
    to_wei, HashAndAmountResult, PayableTransactionError, ProcessedPayableFallible,
    RpcPayableFailure, TRANSFER_METHOD_ID,
};
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::future::err;
use futures::Future;
use masq_lib::blockchains::chains::{Chain, ChainFamily};
use masq_lib::logger::Logger;
use serde_json::Value;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::Batch;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, H160, H256, U256};
use web3::Error as Web3Error;
use web3::{BatchTransport, Web3};

fn base_gas_limit(chain: Chain) -> u64 {
    match chain.rec().chain_family {
        ChainFamily::Polygon => 70_000,
        ChainFamily::Eth => 55_000,
        ChainFamily::Dev => 55_000,
    }
}

pub fn advance_used_nonce(current_nonce: U256) -> U256 {
    current_nonce
        .checked_add(U256::one())
        .expect("unexpected limits")
}

fn error_with_hashes(
    error: Web3Error,
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

pub fn merged_output_data(
    responses: Vec<web3::transports::Result<Value>>,
    hashes_and_paid_amounts: Vec<(H256, u128)>,
    accounts: Vec<PayableAccount>,
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
            Err(rpc_error) => ProcessedPayableFallible::Failed(RpcPayableFailure {
                rpc_error,
                recipient_wallet: account.wallet.clone(),
                hash,
            }),
        })
        .collect()
}

pub fn transmission_log(chain: Chain, accounts: &[PayableAccount], gas_price: u64) -> String {
    let chain_name = chain
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

pub fn sign_transaction_data(amount: u128, recipient_wallet: Wallet) -> [u8; 68] {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&recipient_wallet.address().0[..]);
    U256::from(amount).to_big_endian(&mut data[36..68]);
    return data;
}
pub fn gas_limit(data: [u8; 68], chain: Chain) -> U256 {
    let base_gas_limit = base_gas_limit(chain);
    let gas_limit = ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
        acc + if v == &0u8 { 4 } else { 68 }
    }))
    .expect("Internal error");
    return gas_limit;
}
pub fn sign_transaction<T: BatchTransport>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> Result<SignedTransaction, PayableTransactionError> {
    let data = sign_transaction_data(amount, recipient_wallet);
    let gas_limit = gas_limit(data, chain);

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
        to: Some(H160(chain.rec().contract.0)),
        gas: gas_limit,
        gas_price: Some(gas_price),
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };

    let key = match consuming_wallet.prepare_secp256k1_secret() {
        Ok(secret) => secret,
        Err(e) => return Err(PayableTransactionError::UnusableWallet(e.to_string())),
    };

    batch_web3
        .accounts()
        .sign_transaction(transaction_parameters, &key)
        .wait() // TODO: GH-744 Remove this wait.
        .map_err(|e| PayableTransactionError::Signing(e.to_string()))
}

pub fn handle_new_transaction<T: BatchTransport>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> Result<H256, PayableTransactionError> {
    let signed_tx = sign_transaction(
        chain,
        batch_web3.clone(),
        recipient_wallet.clone(),
        consuming_wallet.clone(),
        amount,
        nonce,
        gas_price,
    )?;

    // self.batch_payable_tools
    //     .append_transaction_to_batch(signed_tx.raw_transaction, &self.batch_web3);
    batch_web3
        .eth()
        .send_raw_transaction(signed_tx.raw_transaction);
    Ok(signed_tx.transaction_hash)
}

pub fn sign_and_append_payment<T: BatchTransport>(
    logger: &Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    mut hashes_and_amounts: Vec<(H256, u128)>,
    consuming_wallet: Wallet,
    nonce: U256,
    gas_price: u64,
    account: &PayableAccount,
) -> HashAndAmountResult {
    debug!(
        logger,
        "Preparing payment of {} wei to {} with nonce {}",
        account.balance_wei.separate_with_commas(),
        account.wallet,
        nonce
    );

    match handle_new_transaction(
        chain,
        batch_web3,
        account.wallet.clone(),
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

pub fn handle_payable_account<T: BatchTransport>(
    logger: &Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    pending_nonce_opt: Option<U256>,
    hashes_and_amounts: Vec<(H256, u128)>,
    consuming_wallet: &Wallet,
    gas_price: u64,
    account: &PayableAccount,
) -> (HashAndAmountResult, Option<U256>) {
    let nonce = pending_nonce_opt.expectv("pending nonce");
    let updated_collected_attributes_of_processed_payments = sign_and_append_payment(
        logger,
        chain,
        batch_web3,
        hashes_and_amounts,
        consuming_wallet.clone(),
        nonce,
        gas_price,
        account,
    );
    let advanced_nonce = advance_used_nonce(nonce);
    (
        updated_collected_attributes_of_processed_payments,
        Some(advanced_nonce),
    )
}

pub fn sign_and_append_multiple_payments<T: BatchTransport>(
    logger: &Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
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
                handle_payable_account(
                    logger,
                    chain,
                    batch_web3.clone(),
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

// pub fn send_payables_within_batch<T: BatchTransport + 'static>(
pub fn send_payables_within_batch<T: BatchTransport + 'static>(
    logger: &Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    consuming_wallet: Wallet,
    gas_price: u64,
    pending_nonce: U256,
    new_fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
    accounts: Vec<PayableAccount>,
) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError>> {
    debug!(
            logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
            consuming_wallet,
            chain.rec().contract,
            chain.rec().num_chain_id,
            gas_price
        );

    let hashes_and_paid_amounts = match sign_and_append_multiple_payments(
        logger,
        chain,
        batch_web3.clone(),
        &consuming_wallet,
        gas_price,
        pending_nonce,
        &accounts,
    ) {
        Ok(hashes_and_paid_amounts) => hashes_and_paid_amounts,
        Err(e) => {
            return Box::new(err(e));
        }
    };

    let timestamp = SystemTime::now();

    let hashes_and_paid_amounts_error = hashes_and_paid_amounts.clone();
    let hashes_and_paid_amounts_ok = hashes_and_paid_amounts.clone();

    new_fingerprints_recipient
        .try_send(PendingPayableFingerprintSeeds {
            batch_wide_timestamp: timestamp,
            hashes_and_balances: hashes_and_paid_amounts,
        })
        .expect("Accountant is dead");

    info!(logger, "{}", transmission_log(chain, &accounts, gas_price));

    return Box::new(
        batch_web3
            .transport()
            .submit_batch()
            .map_err(|e| {
                todo!("We are hitting the correct place");
                error_with_hashes(e, hashes_and_paid_amounts_error)
            })
            .and_then(move |batch_response| {
                // todo!("We are hitting the wrong place");
                Ok(merged_output_data(
                    batch_response,
                    hashes_and_paid_amounts_ok,
                    accounts,
                ))
            }),
    );

    // return Box::new(err(PayableTransactionError::GasPriceQueryFailed(
    //     "test Error".to_string(),
    // )));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accountant::db_access_objects::dao_utils::from_time_t;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::{
        make_payable_account, make_payable_account_with_wallet_and_balance_and_timestamp_opt,
    };
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::blockchain_interface::ProcessedPayableFallible::{Correct, Failed};
    use crate::blockchain::test_utils::{
        make_default_signed_transaction, make_fake_event_loop_handle, make_tx_hash, TestTransport,
    };
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::decode_hex;
    use crate::test_utils::{make_wallet, TestRawTransaction};
    use actix::{Actor, System};
    use crossbeam_channel::{unbounded, Receiver};
    use ethereum_types::U64;
    use ethsign_crypto::Keccak256;
    use jsonrpc_core::Version::V2;
    use jsonrpc_core::{Call, Error, ErrorCode, Id, MethodCall, Params};
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use masq_lib::utils::{find_free_port, slice_of_strs_to_vec_of_strings};
    use serde_derive::Deserialize;
    use serde_json::json;
    use serde_json::Value;
    use simple_server::{Request, Server};
    use std::fmt::Debug;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::ops::Add;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};
    use web3::transports::Http;
    use web3::types::H2048;
    use web3::Error as Web3Error;

    #[test]
    fn blockchain_interface_web3_can_transfer_tokens_in_batch() {
        //exercising also the layer of web3 functions, but the transport layer is mocked
        init_test_logging();
        let send_batch_params_arc = Arc::new(Mutex::new(vec![]));
        //we compute the hashes ourselves during the batch preparation and so we don't care about
        //the same ones coming back with the response; we use the returned OKs as indicators of success only.
        //Any eventual rpc errors brought back are processed as well...
        let expected_batch_responses = vec![
            Ok(json!("...unnecessarily important hash...")),
            Err(web3::Error::Rpc(Error {
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
        let gas_price = 120;
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
        let pending_nonce = U256::from(6);
        let accounts_to_process = vec![account_1, account_2, account_3];
        let consuming_wallet = make_paying_wallet(b"gdasgsa");
        let test_timestamp_before = SystemTime::now();

        let result = send_payables_within_batch(
            &logger,
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            gas_price,
            pending_nonce,
            fingerprint_recipient,
            accounts_to_process.to_vec(),
        )
        .wait()
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
            Failed(RpcPayableFailure{ rpc_error, recipient_wallet: recipient, hash }) => panic!(
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
            Failed(RpcPayableFailure {
                rpc_error,
                recipient_wallet: recipient,
                hash,
            }) => (rpc_error, recipient, hash),
        };
        assert_eq!(
            rpc_error,
            &web3::Error::Rpc(Error {
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

    #[test]
    fn send_payables_within_batch_fails_on_badly_prepared_consuming_wallet_without_secret() {
        let transport = TestTransport::default();
        let incomplete_consuming_wallet =
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let system = System::new("test");
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = send_payables_within_batch(
            &Logger::new("test"),
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            incomplete_consuming_wallet,
            gas_price,
            nonce,
            recipient,
            vec![account],
        )
        .wait();

        System::current().stop();
        system.run();
        assert_eq!(result,
                   Err(PayableTransactionError::UnusableWallet("Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()))
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0)
    }

    #[test]
    fn send_payables_within_batch_fails_on_sending() {
        let hash = make_tx_hash(123);
        let transport =
            TestTransport::default().send_batch_result(vec![Err(Web3Error::Unreachable)]);

        let mut signed_transaction = make_default_signed_transaction();
        signed_transaction.transaction_hash = hash;
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        // let mut subject = BlockchainInterfaceWeb3::new(
        //     transport,
        //     make_fake_event_loop_handle(),
        //     Chain::PolyMumbai,
        // );
        let unimportant_recipient = Recorder::new().start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            5000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = send_payables_within_batch(
            &Logger::new("test"),
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            gas_price,
            nonce,
            unimportant_recipient,
            vec![account],
        )
        .wait();

        assert_eq!(
            result,
            Err(PayableTransactionError::Sending {
                msg: "Transport error: Transaction crashed".to_string(),
                hashes: vec![hash]
            })
        );
    }

    #[test]
    fn advance_used_nonce_works() {
        let initial_nonce = U256::from(55);

        let result = advance_used_nonce(initial_nonce);

        assert_eq!(result, U256::from(56))
    }

    #[test]
    fn sign_transaction_fails_on_signing_itself() {
        let transport = TestTransport::default();
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        // let mut subject = BlockchainInterfaceWeb3::new(
        //     transport,
        //     make_fake_event_loop_handle(),
        //     Chain::PolyMumbai,
        // );
        let recipient_wallet = make_wallet("unlucky man");
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = sign_transaction(
            Chain::PolyMumbai,
            Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            444444,
            nonce,
            gas_price,
        );

        assert_eq!(
            result,
            Err(PayableTransactionError::Signing(
                "Signing error: secp: malformed or out-of-range secret key".to_string()
            ))
        );
    }

    #[test]
    fn signing_error_ends_iteration_over_accounts_after_detecting_first_error_which_is_then_propagated_all_way_up_and_out(
    ) {
        let transport = TestTransport::default();
        // let mut subject = BlockchainInterfaceWeb3::new(
        //     transport,
        //     make_fake_event_loop_handle(),
        //     Chain::PolyMumbai,
        // );
        let recipient = Recorder::new().start().recipient();
        let consuming_wallet = make_paying_wallet(&b"consume, you greedy fool!"[..]);
        let nonce = U256::from(123);
        let accounts = vec![make_payable_account(5555), make_payable_account(6666)];

        let result = send_payables_within_batch(
            &Logger::new("test"),
            Chain::PolyMumbai,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            111,
            nonce,
            recipient,
            accounts.to_vec(),
        )
        .wait();

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
    fn web3_interface_send_payables_within_batch_components_are_used_together_properly() {
        todo!("Fix this later");
        // let sign_transaction_params_arc = Arc::new(Mutex::new(vec![]));
        // let append_transaction_to_batch_params_arc = Arc::new(Mutex::new(vec![]));
        // let new_payable_fingerprint_params_arc = Arc::new(Mutex::new(vec![]));
        //
        // let submit_batch_params_arc: Arc<Mutex<Vec<Web3<Batch<TestTransport>>>>> =
        //     Arc::new(Mutex::new(vec![]));
        // let reference_counter_arc = Arc::new(());
        // let (accountant, _, accountant_recording_arc) = make_recorder();
        // let initiate_fingerprints_recipient = accountant.start().recipient();
        // let consuming_wallet_secret = b"consuming_wallet_0123456789abcde";
        // let secret_key =
        //     (&Bip32EncryptionKeyProvider::from_raw_secret(consuming_wallet_secret).unwrap()).into();
        // let batch_wide_timestamp_expected = SystemTime::now();
        // let transport = TestTransport::default().initiate_reference_counter(&reference_counter_arc);
        // let chain = Chain::EthMainnet;
        // let contract_address = chain.rec().contract;
        // let web3 = Web3::new(transport.clone());
        //
        // // let mut subject =
        // //     BlockchainInterfaceWeb3::new(transport, make_fake_event_loop_handle(), chain);
        // let first_tx_parameters = TransactionParameters {
        //     nonce: Some(U256::from(4)),
        //     to: Some(contract_address),
        //     gas: U256::from(56_552),
        //     gas_price: Some(U256::from(123000000000_u64)),
        //     value: U256::from(0),
        //     data: Bytes(vec![
        //         169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //         99, 114, 101, 100, 105, 116, 111, 114, 51, 50, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 149, 149, 231, 24,
        //     ]),
        //     chain_id: Some(chain.rec().num_chain_id),
        // };
        // let first_signed_transaction = web3
        //     .accounts()
        //     .sign_transaction(first_tx_parameters.clone(), &secret_key)
        //     .wait()
        //     .unwrap();
        //
        // let second_tx_parameters = TransactionParameters {
        //     nonce: Some(U256::from(5)),
        //     to: Some(contract_address),
        //     gas: U256::from(56_552),
        //     gas_price: Some(U256::from(123000000000_u64)),
        //     value: U256::from(0),
        //     data: Bytes(vec![
        //         169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //         99, 114, 101, 100, 105, 116, 111, 114, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        //         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 156, 231, 56, 4,
        //     ]),
        //     chain_id: Some(chain.rec().num_chain_id),
        // };
        // let second_signed_transaction = web3
        //     .accounts()
        //     .sign_transaction(second_tx_parameters.clone(), &secret_key)
        //     .wait()
        //     .unwrap();
        // let first_hash = first_signed_transaction.transaction_hash;
        // let second_hash = second_signed_transaction.transaction_hash;
        // let pending_nonce = U256::from(4);
        // // technically, the JSON values in the correct responses don't matter, we only check for errors if any came back
        // let rpc_responses = vec![
        //     Ok(Value::String((&first_hash.to_string()[2..]).to_string())),
        //     Ok(Value::String((&second_hash.to_string()[2..]).to_string())),
        // ];
        // let consuming_wallet = make_paying_wallet(consuming_wallet_secret);
        // let gas_price = 123;
        // let first_payment_amount = 333_222_111_000;
        // let first_creditor_wallet = make_wallet("creditor321");
        // let first_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
        //     first_creditor_wallet.clone(),
        //     first_payment_amount,
        //     None,
        // );
        // let second_payment_amount = 11_222_333_444;
        // let second_creditor_wallet = make_wallet("creditor123");
        // let second_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
        //     second_creditor_wallet.clone(),
        //     second_payment_amount,
        //     None,
        // );
        //
        // let result = send_payables_within_batch(
        //     &Logger::new("test"),
        //     chain,
        //     Web3::new(Batch::new(transport)),
        //     consuming_wallet,
        //     gas_price,
        //     pending_nonce,
        //     initiate_fingerprints_recipient,
        //     vec![first_account, second_account],
        // )
        // .wait();
        //
        // let first_resulting_pending_payable = PendingPayable {
        //     recipient_wallet: first_creditor_wallet.clone(),
        //     hash: first_hash,
        // };
        // let second_resulting_pending_payable = PendingPayable {
        //     recipient_wallet: second_creditor_wallet.clone(),
        //     hash: second_hash,
        // };
        // assert_eq!(
        //     result,
        //     Ok(vec![
        //         Correct(first_resulting_pending_payable),
        //         Correct(second_resulting_pending_payable)
        //     ])
        // );
        // let mut sign_transaction_params = sign_transaction_params_arc.lock().unwrap();
        // let (first_transaction_params, web3, secret) = sign_transaction_params.remove(0);
        // assert_eq!(first_transaction_params, first_tx_parameters);
        // let check_web3_origin = |web3: &Web3<Batch<TestTransport>>| {
        //     let ref_count_before_clone = Arc::strong_count(&reference_counter_arc);
        //     let _new_ref = web3.clone();
        //     let ref_count_after_clone = Arc::strong_count(&reference_counter_arc);
        //     assert_eq!(ref_count_after_clone, ref_count_before_clone + 1);
        // };
        // check_web3_origin(&web3);
        // assert_eq!(
        //     secret,
        //     (&Bip32EncryptionKeyProvider::from_raw_secret(&consuming_wallet_secret.keccak256())
        //         .unwrap())
        //         .into()
        // );
        // let (second_transaction_params, web3_from_st_call, secret) =
        //     sign_transaction_params.remove(0);
        // assert_eq!(second_transaction_params, second_tx_parameters);
        // check_web3_origin(&web3_from_st_call);
        // assert_eq!(
        //     secret,
        //     (&Bip32EncryptionKeyProvider::from_raw_secret(&consuming_wallet_secret.keccak256())
        //         .unwrap())
        //         .into()
        // );
        // assert!(sign_transaction_params.is_empty());
        // let new_payable_fingerprint_params = new_payable_fingerprint_params_arc.lock().unwrap();
        // let (batch_wide_timestamp, recipient, actual_pending_payables) =
        //     &new_payable_fingerprint_params[0];
        // assert_eq!(batch_wide_timestamp, &batch_wide_timestamp_expected);
        // assert_eq!(
        //     actual_pending_payables,
        //     &vec![
        //         (first_hash, first_payment_amount),
        //         (second_hash, second_payment_amount)
        //     ]
        // );
        // let mut append_transaction_to_batch_params =
        //     append_transaction_to_batch_params_arc.lock().unwrap();
        // let (bytes_first_payment, web3_from_ertb_call_1) =
        //     append_transaction_to_batch_params.remove(0);
        // check_web3_origin(&web3_from_ertb_call_1);
        // assert_eq!(
        //     bytes_first_payment,
        //     first_signed_transaction.raw_transaction
        // );
        // let (bytes_second_payment, web3_from_ertb_call_2) =
        //     append_transaction_to_batch_params.remove(0);
        // check_web3_origin(&web3_from_ertb_call_2);
        // assert_eq!(
        //     bytes_second_payment,
        //     second_signed_transaction.raw_transaction
        // );
        // assert_eq!(append_transaction_to_batch_params.len(), 0);
        // let submit_batch_params = submit_batch_params_arc.lock().unwrap();
        // let web3_from_sb_call = &submit_batch_params[0];
        // assert_eq!(submit_batch_params.len(), 1);
        // check_web3_origin(&web3_from_sb_call);
        // assert!(accountant_recording_arc.lock().unwrap().is_empty());
        // let system = System::new(
        //     "web3_interface_send_payables_in_batch_components_are_used_together_properly",
        // );
        // let probe_message = PendingPayableFingerprintSeeds {
        //     batch_wide_timestamp: SystemTime::now(),
        //     hashes_and_balances: vec![],
        // };
        // // recipient.try_send(probe_message).unwrap();
        // System::current().stop();
        // system.run();
        // let accountant_recording = accountant_recording_arc.lock().unwrap();
        // assert_eq!(accountant_recording.len(), 1)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_polygon_mumbai() {
        let chain = Chain::PolyMumbai;
        let nonce = 5;
        // signed_transaction_data changed after we changed the contract address of polygon matic
        let signed_transaction_data = "f8ad05850ba43b740083011980949b27034acabd44223fb23d628ba4849867ce1db280b844a9059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000000e8d4a5100083027126a09fdbbd7064d3b7240f5422b2164aaa13d62f0946a683d82ee26f97f242570d90a077b49dbb408c20d73e0666ba0a77ac888bf7a9cb14824a5f35c97217b9bc0a5a";

        let in_bytes = decode_hex(signed_transaction_data).unwrap();

        assert_that_signed_transactions_agrees_with_template(chain, nonce, &in_bytes)
    }

    //with a real confirmation through a transaction sent with this data to the network
    #[test]
    fn web3_interface_signing_a_transaction_works_for_eth_ropsten() {
        let chain = Chain::EthRopsten;
        let nonce = 1; //must stay like this!
        let signed_transaction_data = "f8a90185199c82cc0082dee894384dec25e03f94931767ce4c3556168468ba24c380b844a9059cbb0000000000000000000000007788df76bbd9a0c7c3e5bf0f77bb28c60a167a7b000000000000000000000000000000000000000000000000000000e8d4a510002aa0635fbb3652e1c3063afac6ffdf47220e0431825015aef7daff9251694e449bfca00b2ed6d556bd030ac75291bf58817da15a891cd027a4c261bb80b51f33b78adf";
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

        let transport = TestTransport::default();
        // let subject = BlockchainInterfaceWeb3::new(transport, make_fake_event_loop_handle(), chain);

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
        let gas_price = match chain.rec().chain_family {
            ChainFamily::Eth => TEST_GAS_PRICE_ETH,
            ChainFamily::Polygon => TEST_GAS_PRICE_POLYGON,
            _ => panic!("isn't our interest in this test"),
        };
        let payable_account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet,
            TEST_PAYMENT_AMOUNT,
            None,
        );

        let signed_transaction = sign_transaction(
            chain,
            Web3::new(Batch::new(transport)),
            payable_account.wallet,
            consuming_wallet,
            payable_account.balance_wei,
            nonce_correct_type,
            gas_price,
        )
        .unwrap();

        let byte_set_to_compare = signed_transaction.raw_transaction.0;
        assert_eq!(byte_set_to_compare.as_slice(), template)
    }

    fn test_gas_limit_is_between_limits(chain: Chain) {
        let not_under_this_value = match chain {
            // TODO: GH-744 this could be use by web3_gas_limit_const_part - once Merged with Master
            Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
            Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
        };
        let not_above_this_value = not_under_this_value + 3328; // TODO: GH-744: this number can be replace by const WEB3_MAXIMAL_GAS_LIMIT_MARGIN. - once Merged with Master
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
