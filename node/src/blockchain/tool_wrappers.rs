// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ethereum_types::H256;
use std::any::Any;
use std::fmt::Debug;
use web3::futures::Future;
use web3::types::{Bytes, SignedTransaction, Transaction, TransactionParameters};
use web3::Error as Web3Error;
use web3::{Transport, Web3};

pub trait ToolFactories {
    fn make_send_transaction_tools<'a>(
        &'a self,
        tool_factory: &'a (dyn SendTransactionToolWrapperFactory + 'a),
    ) -> Box<dyn SendTransactionToolWrapper + 'a>;
}

pub trait SendTransactionToolWrapperFactory {
    fn make<'a>(
        &'a self,
        real_factory_assembly_line: Box<
            dyn FnOnce() -> Box<dyn SendTransactionToolWrapper + 'a> + 'a,
        >,
    ) -> Box<dyn SendTransactionToolWrapper + 'a>;
    as_any_dcl!();
}

#[derive(Debug, PartialEq)]
pub struct SendTransactionToolWrapperFactoryReal;

impl SendTransactionToolWrapperFactory for SendTransactionToolWrapperFactoryReal {
    fn make<'a>(
        &'a self,
        real_assembly_line: Box<dyn FnOnce() -> Box<dyn SendTransactionToolWrapper + 'a> + 'a>,
    ) -> Box<dyn SendTransactionToolWrapper + 'a> {
        real_assembly_line()
    }
    as_any_impl!();
}

pub trait SendTransactionToolWrapper {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error>;
}

pub struct SendTransactionToolWrapperReal<'a, T: Transport + Debug> {
    web3: &'a Web3<T>,
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapperReal<'a, T> {
    pub fn new(web3: &'a Web3<T>) -> Self {
        Self { web3 }
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapper
    for SendTransactionToolWrapperReal<'a, T>
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

pub struct SendTransactionToolWrapperNull;

impl SendTransactionToolWrapper for SendTransactionToolWrapperNull {
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

//TODO the following lines are just a sketch...be careful
pub trait CheckOutPendingTransactionToolWrapperFactory {
    fn make<'a>(
        &'a self,
        real_assembly_line: Box<
            dyn FnOnce() -> Box<dyn CheckOutPendingTransactionToolWrapper + 'a> + 'a,
        >,
    ) -> Box<dyn CheckOutPendingTransactionToolWrapper + 'a>;
    as_any_dcl!();
}

#[derive(Debug, PartialEq)]
pub struct CheckOutPendingTransactionToolWrapperFactoryReal;

impl CheckOutPendingTransactionToolWrapperFactory
    for CheckOutPendingTransactionToolWrapperFactoryReal
{
    fn make<'a>(
        &'a self,
        real_assembly_line: Box<
            dyn FnOnce() -> Box<dyn CheckOutPendingTransactionToolWrapper + 'a> + 'a,
        >,
    ) -> Box<dyn CheckOutPendingTransactionToolWrapper + 'a> {
        todo!()
    }
    as_any_impl!();
}

pub trait CheckOutPendingTransactionToolWrapper {
    fn transaction_info(&self, transaction_hash: H256) -> Result<Transaction, Web3Error>;
}

#[cfg(test)]
mod tests {
    use crate::blockchain::tool_wrappers::{
        SendTransactionToolWrapper, SendTransactionToolWrapperNull,
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
            SendTransactionToolWrapperNull.sign_transaction(transaction_parameters, &secret_key);
    }

    #[test]
    #[should_panic(expected = "send_raw_transaction() for a null object - should never be called")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolWrapperNull.send_raw_transaction(rlp);
    }
}
