use crate::accountant::db_access_objects::payable_dao::{PayableAccount, PendingPayable};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_interface::{
    to_wei, HashAndAmountResult, PayableTransactionError, ProcessedPayableFallible,
    RpcPayableFailure, TRANSFER_METHOD_ID,
};
use crate::masq_lib::utils::ExpectValue;
use crate::sub_lib::wallet::Wallet;
use actix::Recipient;
use futures::Future;
use masq_lib::blockchains::chains::{Chain, ChainFamily};
use masq_lib::logger::Logger;
use serde_json::Value;
use std::iter::once;
use std::time::SystemTime;
use thousands::Separable;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters, H160, H256, U256};
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

pub fn sign_transaction<T: BatchTransport>(
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    recipient: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> Result<SignedTransaction, PayableTransactionError> {
    let mut data = [0u8; 4 + 32 + 32];
    data[0..4].copy_from_slice(&TRANSFER_METHOD_ID);
    data[16..36].copy_from_slice(&recipient.address().0[..]);
    U256::try_from(amount)
        .expect("shouldn't overflow")
        .to_big_endian(&mut data[36..68]);
    let base_gas_limit = base_gas_limit(chain);
    let gas_limit = ethereum_types::U256::try_from(data.iter().fold(base_gas_limit, |acc, v| {
        acc + if v == &0u8 { 4 } else { 68 }
    }))
    .expect("Internal error");
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
    recipient: Wallet,
    consuming_wallet: Wallet,
    amount: u128,
    nonce: U256,
    gas_price: u64,
) -> Result<H256, PayableTransactionError> {
    let signed_tx = sign_transaction(
        chain,
        batch_web3.clone(),
        recipient.clone(),
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

pub fn send_payables_within_batch<T: BatchTransport + 'static>(
    logger: &Logger,
    chain: Chain,
    batch_web3: Web3<Batch<T>>,
    consuming_wallet: &Wallet,
    gas_price: u64,
    pending_nonce: U256,
    new_fingerprints_recipient: &Recipient<PendingPayableFingerprintSeeds>,
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
        consuming_wallet,
        gas_price,
        pending_nonce,
        &accounts,
    ) {
        Ok(hashes_and_paid_amounts) => hashes_and_paid_amounts,
        Err(e) => {
            todo!("TODO: GH-744 sign_and_append_multiple_payments Error");
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
            .map_err(|e| error_with_hashes(e, hashes_and_paid_amounts_error))
            .and_then(move |batch_response| {
                Ok(merged_output_data(
                    batch_response,
                    hashes_and_paid_amounts_ok,
                    accounts,
                ))
            }),
    );
}
