// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethereum_types::H256;
use std::fmt::Debug;
use web3::futures::Future;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Transport;
use web3::{Error as Web3Error, Web3};

pub trait SendTransactionToolsWrapper {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error>;
}

pub struct SendTransactionToolsWrapperReal<'a, T: Transport + Debug> {
    web3: &'a Web3<T>,
}

impl<'a, T: Transport + Debug> SendTransactionToolsWrapperReal<'a, T> {
    pub fn new(web3: &'a Web3<T>) -> Self {
        Self { web3 }
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolsWrapper
    for SendTransactionToolsWrapperReal<'a, T>
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        self.web3
            .accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
        self.web3.eth().send_raw_transaction(rlp).wait()
    }
}

pub struct SendTransactionToolsWrapperNull;

impl SendTransactionToolsWrapper for SendTransactionToolsWrapperNull {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sing_transaction() for a null object - should never be called")
    }

    fn send_raw_transaction(&self, _rlp: Bytes) -> Result<H256, Web3Error> {
        panic!("send_raw_transaction() for a null object - should never be called")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::tool_wrappers::{
        SendTransactionToolsWrapper, SendTransactionToolsWrapperNull,
    };
    use web3::types::{Bytes, TransactionParameters};

    #[test]
    #[should_panic(expected = "sing_transaction() for a null object - should never be called")]
    fn null_sign_transaction_stops_the_run() {
        let transaction_parameters = TransactionParameters {
            nonce: None,
            to: None,
            gas: Default::default(),
            gas_price: None,
            value: Default::default(),
            data: Default::default(),
            chain_id: None,
        };
        let secret_key =
            secp256k1secrets::key::SecretKey::from_slice(b"000000000000000000000000000000aa")
                .unwrap();

        let _ =
            SendTransactionToolsWrapperNull.sign_transaction(transaction_parameters, &secret_key);
    }

    #[test]
    #[should_panic(expected = "send_raw_transaction() for a null object - should never be called")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolsWrapperNull.send_raw_transaction(rlp);
    }
}
