use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::{
    to_wei, HashAndAmount, ProcessedPayableFallible, RpcPayableFailure, TRANSFER_METHOD_ID,
};

use crate::blockchain::blockchain_interface::data_structures::errors::PayableTransactionError;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::future::err;
use futures::stream::FuturesOrdered;
use futures::{Future, Stream};
use masq_lib::blockchains::chains::Chain;
use masq_lib::logger::Logger;
use serde_json::Value;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::Batch;
use web3::types::{Address, Bytes, SignedTransaction, TransactionParameters, H256, U256};
use web3::Error as Web3Error;
use web3::{BatchTransport, Web3};

fn base_gas_limit(chain: Chain) -> u64 {
    //TODO: GH-744: There is a duplicated function web3_gas_limit_const_part
    match chain {
        Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
        Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
    }
}

// fn web3_gas_limit_const_part(chain: Chain) -> u64 {
//     match chain {
//         Chain::EthMainnet | Chain::EthRopsten | Chain::Dev => 55_000,
//         Chain::PolyMainnet | Chain::PolyMumbai => 70_000,
//     }
// }

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
    // TODO: GH-744 Hashes and paid amounts are now out of sync with accounts. Need to look into this.
    let iterator_with_all_data = responses
        .into_iter()
        .zip(hashes_and_paid_amounts.into_iter())
        .zip(accounts.iter());
    iterator_with_all_data
        .map(
            |((rpc_result, hash_and_amount), account)| match rpc_result {
                Ok(_) => ProcessedPayableFallible::Correct(PendingPayable {
                    recipient_wallet: account.wallet.clone(),
                    hash: hash_and_amount.hash,
                }),
                Err(rpc_error) => ProcessedPayableFallible::Failed(RpcPayableFailure {
                    rpc_error,
                    recipient_wallet: account.wallet.clone(),
                    hash: hash_and_amount.hash,
                }),
            },
        )
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
// Result<SignedTransaction, PayableTransactionError>
pub fn sign_transaction<T: BatchTransport + 'static>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price_in_gwei: u64,
) -> Box<dyn Future<Item = SignedTransaction, Error = PayableTransactionError>> {
    let data = sign_transaction_data(amount, recipient_wallet);
    let gas_limit = gas_limit(data, chain);
    let gas_price_in_wei = to_wei(gas_price_in_gwei);

    let transaction_parameters = TransactionParameters {
        nonce: Some(nonce), // TODO: GH-744 Change this to None and let the BlockChain figure out the correct Nonce instead.
        to: Some(chain.rec().contract),
        gas: gas_limit,
        gas_price: Some(gas_price_in_wei), // TODO: GH-744 Talk about this.
        value: ethereum_types::U256::zero(),
        data: Bytes(data.to_vec()),
        chain_id: Some(chain.rec().num_chain_id),
    };

    let key = match consuming_wallet.prepare_secp256k1_secret() {
        Ok(secret) => secret,
        Err(e) => return Box::new(err(PayableTransactionError::UnusableWallet(e.to_string()))),
    };

    Box::new(
        batch_web3
            .accounts()
            .sign_transaction(transaction_parameters, &key)
            .map_err(|e| PayableTransactionError::Signing(e.to_string())),
    )
}

// Result<H256, PayableTransactionError>
pub fn handle_new_transaction<T: BatchTransport + 'static>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    recipient_wallet: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> Box<dyn Future<Item = H256, Error = PayableTransactionError>> {
    Box::new(
        sign_transaction(
            chain,
            batch_web3.clone(),
            recipient_wallet.clone(),
            consuming_wallet.clone(),
            amount,
            nonce,
            gas_price,
        )
        .map_err(|e| e)
        .and_then(move |signed_tx| {
            batch_web3
                .eth()
                .send_raw_transaction(signed_tx.raw_transaction);
            Ok(signed_tx.transaction_hash)
        }),
    )
}

// TODO: GH-744 Rename and refactor this function after merging with Master
pub fn sign_and_append_payment<T: BatchTransport + 'static>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    consuming_wallet: Wallet,
    nonce: U256,
    gas_price: u64,
    account: PayableAccount,
) -> Box<dyn Future<Item = HashAndAmount, Error = PayableTransactionError> + 'static> {
    Box::new(
        handle_new_transaction(
            chain,
            batch_web3,
            account.wallet.clone(),
            consuming_wallet,
            account.balance_wei,
            nonce,
            gas_price,
        )
        .map_err(|e| {
            return e;
        })
        .and_then(move |new_hash| {
            Ok(HashAndAmount {
                hash: new_hash,
                amount: account.balance_wei,
            })
        }),
    )
}

// HashAndAmountResult
pub fn sign_and_append_multiple_payments<T: BatchTransport + 'static>(
    logger: Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    consuming_wallet: Wallet,
    gas_price: u64,
    mut pending_nonce: U256,
    accounts: Vec<PayableAccount>,
) -> FuturesOrdered<Box<dyn Future<Item = HashAndAmount, Error = PayableTransactionError> + 'static>>
{
    // todo!("Stop for FuturesOrdered");
    let mut payable_que = FuturesOrdered::new();
    accounts.into_iter().for_each(|payable| {
        debug!(
            logger,
            "Preparing payable future of {} wei to {} with nonce {}",
            payable.balance_wei.separate_with_commas(),
            payable.wallet,
            pending_nonce
        );

        let payable_future = sign_and_append_payment(
            chain,
            batch_web3.clone(),
            consuming_wallet.clone(),
            pending_nonce,
            gas_price,
            payable,
        );
        pending_nonce = advance_used_nonce(pending_nonce);
        payable_que.push(payable_future)
    });

    payable_que
}
pub fn send_payables_within_batch<T: BatchTransport + 'static>(
    logger: Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    consuming_wallet: Wallet,
    gas_price: u64,
    pending_nonce: U256,
    new_fingerprints_recipient: Recipient<PendingPayableFingerprintSeeds>,
    accounts: Vec<PayableAccount>,
) -> Box<dyn Future<Item = Vec<ProcessedPayableFallible>, Error = PayableTransactionError> + 'static>
{
    debug!(
            logger,
            "Common attributes of payables to be transacted: sender wallet: {}, contract: {:?}, chain_id: {}, gas_price: {}",
            consuming_wallet,
            chain.rec().contract,
            chain.rec().num_chain_id,
            gas_price
        );

    // let hashes_and_paid_amounts = match sign_and_append_multiple_payments(
    //     logger,
    //     chain,
    //     batch_web3.clone(),
    //     &consuming_wallet,
    //     gas_price,
    //     pending_nonce,
    //     &accounts,
    // ) {
    //     Ok(hashes_and_paid_amounts) => hashes_and_paid_amounts,
    //     Err(e) => {
    //         return Box::new(err(e));
    //     }
    // };

    // let timestamp = SystemTime::now();
    //
    // let hashes_and_paid_amounts_error = hashes_and_paid_amounts.clone();
    // let hashes_and_paid_amounts_ok = hashes_and_paid_amounts.clone();
    //
    // new_fingerprints_recipient
    //     .try_send(PendingPayableFingerprintSeeds {
    //         batch_wide_timestamp: timestamp,
    //         hashes_and_balances: hashes_and_paid_amounts,
    //     })
    //     .expect("Accountant is dead");
    //
    // info!(logger, "{}", transmission_log(chain, &accounts, gas_price));

    return Box::new(
        sign_and_append_multiple_payments(
            logger.clone(),
            chain,
            batch_web3.clone(),
            consuming_wallet,
            gas_price,
            pending_nonce,
            accounts.clone(),
        )
        .collect()
        // .map_err(|e| {
        //     // todo!("sign_and_append_multiple_payments -- map_err");
        //     return err(e);
        // })
        // TODO: GH-744: Need to fix errors -- The current version of futures, doesnt give us enough util to catch errors here.
        // The thinking is we could return here to fix this after falling behind is completed.
        .and_then(move |hashes_and_paid_amounts| {
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

            batch_web3
                .transport()
                .submit_batch()
                .map_err(|e| {
                    // todo!("We are hitting the correct place");
                    error_with_hashes(e, hashes_and_paid_amounts_error)
                })
                .and_then(move |batch_response| {
                    // todo!("We are hitting the wrong place");
                    Ok(merged_output_data(
                        batch_response,
                        hashes_and_paid_amounts_ok,
                        accounts,
                    ))
                })
        }),
    );

    // return Box::new(err(PayableTransactionError::GasPriceQueryFailed(
    //     "test Error".to_string(),
    // )));
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::accountant::db_access_objects::dao_utils::from_time_t;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::make_payable_account_with_wallet_and_balance_and_timestamp_opt;
    use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
    use crate::blockchain::test_utils::{make_tx_hash, TestTransport};
    use crate::sub_lib::wallet::Wallet;
    use crate::test_utils::make_paying_wallet;
    use crate::test_utils::make_wallet;
    use crate::test_utils::recorder::{make_recorder, Recorder};
    use crate::test_utils::unshared_test_utils::decode_hex;
    use actix::{Actor, System};
    use jsonrpc_core::Version::V2;
    use jsonrpc_core::{Call, Error, ErrorCode, Id, MethodCall, Params};
    use masq_lib::constants::DEFAULT_CHAIN;
    use masq_lib::test_utils::logging::{init_test_logging, TestLogHandler};
    use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
    use serde_json::json;
    use serde_json::Value;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use web3::Error as Web3Error;
    use web3::Error::Unreachable;
    use crate::accountant::db_access_objects::utils::from_time_t;
    use crate::blockchain::blockchain_interface::blockchain_interface_web3::ProcessedPayableFallible::{Correct, Failed};

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
        let amount_2 = 123_456_789_u128;
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
            logger,
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
        let hash_and_amount_1 = HashAndAmount {
            hash: expected_hash_1,
            amount: gwei_to_wei(900_000_000_u64),
        };
        let hash_and_amount_2 = HashAndAmount {
            hash: expected_hash_2,
            amount: 123_456_789_u128,
        };
        let hash_and_amount_3 = HashAndAmount {
            hash: expected_hash_3,
            amount: gwei_to_wei(33_355_666_u64),
        };
        assert_eq!(
            initiate_fingerprints_msg,
            &PendingPayableFingerprintSeeds {
                batch_wide_timestamp: actual_common_timestamp,
                hashes_and_balances: vec![hash_and_amount_1, hash_and_amount_2, hash_and_amount_3]
            }
        );
        let log_handler = TestLogHandler::new();
        log_handler.exists_log_containing("DEBUG: sending_batch_payments: \
        Common attributes of payables to be transacted: sender wallet: 0x5c361ba8d82fcf0e5538b2a823e9d457a2296725, contract: \
          0x384dec25e03f94931767ce4c3556168468ba24c3, chain_id: 3, gas_price: 120");
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payable future of 900,000,000,000,000,000 wei \
        to 0x0000000000000000000000000000000077313233 with nonce 6",
        );
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payable future of 123,456,789 wei \
        to 0x0000000000000000000000000000000077353535 with nonce 7",
        );
        log_handler.exists_log_containing(
            "DEBUG: sending_batch_payments: Preparing payable future of 33,355,666,000,000,000 wei \
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

    #[test]
    fn send_payables_within_batch_fails_on_badly_prepared_consuming_wallet_without_secret() {
        // TODO: GH-744 After we merge in master rename this test to: send_payables_within_batch_does_not_send_a_message_to_accountant_if_consuming_wallet_is_badly_prepared
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
            Logger::new("test"),
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
        assert_eq!(
            result,
            Err(PayableTransactionError::UnusableWallet("Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()))
        );
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        assert_eq!(accountant_recording.len(), 0)
    }

    #[test]
    fn send_payables_within_batch_fails_on_sending() {
        let transport =
            TestTransport::default().send_batch_result(vec![Err(Web3Error::Unreachable)]);
        let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        let recipient_wallet = make_wallet("blah123");
        let unimportant_recipient = Recorder::new().start().recipient();
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            recipient_wallet.clone(),
            5000,
            None,
        );
        let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = send_payables_within_batch(
            Logger::new("test"),
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
            Ok(vec![Failed(RpcPayableFailure {
                rpc_error: Unreachable,
                recipient_wallet,
                hash: H256::from_str(
                    "424c0231591a9879d82f25e0d81e09f39499b2bfd56b3aba708491995e35b4ac"
                )
                .unwrap()
            })])
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
        // TODO: GH-744: Signing will only fail if we make an RPC call.
        // DO this after we remove gas_price & nonce (This will be done last, just before we merged master in)
        // let transport = TestTransport::default();
        // let consuming_wallet_secret_raw_bytes = b"okay-wallet";
        // // let mut subject = BlockchainInterfaceWeb3::new(
        // //     transport,
        // //     make_fake_event_loop_handle(),
        // //     Chain::PolyMumbai,
        // // );
        // let recipient_wallet = make_wallet("unlucky man");
        // let consuming_wallet = make_paying_wallet(consuming_wallet_secret_raw_bytes);
        // let gas_price = 123;
        // let nonce = U256::from(1);
        //
        // let result = sign_transaction(
        //     Chain::PolyMumbai,
        //     Web3::new(Batch::new(transport)),
        //     recipient_wallet,
        //     consuming_wallet,
        //     444444,
        //     nonce,
        //     gas_price,
        // )
        // .wait();

        // assert_eq!(
        //     result,
        //     Err(PayableTransactionError::Signing(
        //         "Signing error: secp: malformed or out-of-range secret key".to_string()
        //     ))
        // );
    }

    #[test]
    fn signing_error_ends_iteration_over_accounts_after_detecting_first_error_which_is_then_propagated_all_way_up_and_out(
    ) {
        // TODO: GH-744: This test can be remove once we fix FuturesOrdered - Allowing other payments to continue.
        // DO this after we remove gas_price & nonce (This will be done last, just before we merged master in)
        // send_payables_within_batch has changed a lot!
        // let transport = TestTransport::default();
        // let mut subject = BlockchainInterfaceWeb3::new(
        //     transport,
        //     make_fake_event_loop_handle(),
        //     Chain::PolyMumbai,
        // );
        // let recipient = Recorder::new().start().recipient();
        // let consuming_wallet = make_paying_wallet(&b"consume, you greedy fool!"[..]);
        // let nonce = U256::from(123);
        // let accounts = vec![make_payable_account(5555), make_payable_account(6666)];

        // let result = send_payables_within_batch(
        //     Logger::new("test"),
        //     Chain::PolyMumbai,
        //     Web3::new(Batch::new(transport)),
        //     consuming_wallet,
        //     111,
        //     nonce,
        //     recipient,
        //     accounts.to_vec(),
        // )
        // .wait();
        //
        // assert_eq!(
        //     result,
        //     Err(PayableTransactionError::Signing(
        //         "Signing error: secp: malformed or out-of-range \
        //     secret key"
        //             .to_string()
        //     ))
        // )
    }

    #[test]
    fn sign_transaction_just_works() {
        let transport = TestTransport::default();
        let web3 = Web3::new(transport.clone());
        let chain = DEFAULT_CHAIN;
        let amount = 11_222_333_444;
        let gas_price_in_gwei = 123000000000_u64;
        let nonce = U256::from(5);
        let recipient_wallet = make_wallet("recipient_wallet");
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let consuming_wallet_secret_key = consuming_wallet.prepare_secp256k1_secret().unwrap();
        let data = sign_transaction_data(amount, recipient_wallet.clone());

        let tx_parameters = TransactionParameters {
            nonce: Some(nonce),
            to: Some(chain.rec().contract),
            gas: gas_limit(data, chain),
            gas_price: Some(to_wei(gas_price_in_gwei)),
            value: U256::zero(),
            data: Bytes(data.to_vec()),
            chain_id: Some(chain.rec().num_chain_id),
        };

        let result = sign_transaction(
            chain,
            Web3::new(Batch::new(transport)),
            recipient_wallet,
            consuming_wallet,
            amount,
            nonce,
            gas_price_in_gwei,
        )
        .wait();

        let signed_transaction = web3
            .accounts()
            .sign_transaction(tx_parameters, &consuming_wallet_secret_key)
            .wait()
            .unwrap();

        assert_eq!(result, Ok(signed_transaction));
    }

    #[test]
    fn sign_and_append_payment_fails_on_badly_prepared_consuming_wallet_without_secret() {
        let transport = TestTransport::default();
        let incomplete_consuming_wallet =
            Wallet::from_str("0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc").unwrap();
        let system = System::new("test");
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = sign_and_append_payment(
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            incomplete_consuming_wallet,
            nonce,
            gas_price,
            account,
        )
        .wait();

        System::current().stop();
        system.run();
        assert_eq!(
            result,
            Err(PayableTransactionError::UnusableWallet("Cannot sign with non-keypair wallet: Address(0x3f69f9efd4f2592fd70be8c32ecd9dce71c472fc).".to_string()))
        );
    }

    #[test]
    fn sign_and_append_payment_just_works() {
        let transport = TestTransport::default();
        let consuming_wallet = make_paying_wallet(b"consuming_wallet");
        let system = System::new("test");
        let account = make_payable_account_with_wallet_and_balance_and_timestamp_opt(
            make_wallet("blah123"),
            9000,
            None,
        );
        let gas_price = 123;
        let nonce = U256::from(1);

        let result = sign_and_append_payment(
            TEST_DEFAULT_CHAIN,
            Web3::new(Batch::new(transport)),
            consuming_wallet,
            nonce,
            gas_price,
            account,
        )
        .wait()
        .unwrap();

        System::current().stop();
        system.run();
        let expected_hash =
            H256::from_str("8d278f82f42ee4f3b9eef2e099cccc91ff117e80c28d6369fec38ec50f5bd2c2")
                .unwrap();
        assert_eq!(result.hash, expected_hash);
        assert_eq!(result.amount, 9000);
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
        let gas_price = match chain {
            Chain::EthMainnet => TEST_GAS_PRICE_ETH,
            Chain::PolyMainnet => TEST_GAS_PRICE_POLYGON,
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
        .wait()
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
