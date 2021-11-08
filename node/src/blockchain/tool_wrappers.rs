// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use web3::Web3;
use web3::Transport;
use std::fmt::Debug;
use web3::types::{SignedTransaction, TransactionParameters, Bytes};
use ethereum_types::H256;
use secp256k1::key::SecretKey;
use web3::futures::Future;
use std::pin::Pin;

//I'm going to clone Web3 and paste it in this struct for the time of sending a transaction. But reference if possible...
pub enum TransactionToolsError{

}

pub trait SendTransactionToolsFactory {
    fn make(&self)->Box<dyn SendTransactionTools>;
}

pub struct SendTransactionToolsFactoryReal;

impl SendTransactionToolsFactory for SendTransactionToolsFactoryReal {
    fn make(&self) -> Box<dyn SendTransactionTools> {
        todo!()
    }
}

pub trait SendTransactionTools {
  fn sign_transaction(&self,transaction_params: TransactionParameters,key: &SecretKey)-> Result<SignedTransaction,TransactionToolsError>;
  fn send_raw_transaction(&self, rlp: Bytes)->Result<H256,TransactionToolsError>;
}

pub struct SendTransactionToolsWrapperReal<'a, T: Transport + Debug>{
    web3:&'a Web3<T>
}

impl <'a,T: Transport + Debug> SendTransactionToolsWrapperReal<'a,T>{
    pub fn new(web3: &'a Web3<T>) -> Self{
        Self{ web3 }
    }
}

impl <'a,T:Transport + Debug> SendTransactionTools for SendTransactionToolsWrapperReal<'a,T>{
    fn sign_transaction(&self,transaction_params: TransactionParameters,key: &SecretKey) -> Result<SignedTransaction, TransactionToolsError> {
        match self.web3.accounts().sign_transaction(transaction_params,key).wait(){
            Ok(tx) => Ok(tx),
            Err(e) => unimplemented!()
        }

    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, TransactionToolsError> {
        match self.web3.eth().send_raw_transaction(rlp).wait(){
            Ok(hash) => Ok(hash),
            Err(e) => unimplemented!()
        }
    }
}

pub struct SendTransactionToolsNull;

impl SendTransactionTools for SendTransactionToolsNull {
    fn sign_transaction(&self, _transaction_params: TransactionParameters, key: &SecretKey) -> Result<SignedTransaction, TransactionToolsError> {
        panic!("sing_transaction() for a null object - should never be called")
    }

    fn send_raw_transaction(&self, _rlp: Bytes) -> Result<H256, TransactionToolsError> {
        panic!("send_raw_transaction() for a null object - should never be called")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::tool_wrappers::{SendTransactionToolsNull, SendTransactionTools};
    use web3::types::{TransactionParameters, Bytes};
    use secp256k1::key::SecretKey;

    #[test]
    #[should_panic(expected="sing_transaction() for a null object - should never be called")]
    fn null_sign_transaction_stops_the_run(){
        let transaction_parameters = TransactionParameters{
            nonce: None,
            to: None,
            gas: Default::default(),
            gas_price: None,
            value: Default::default(),
            data: Default::default(),
            chain_id: None
        };
        let secret_key = SecretKey::from_slice(b"000000000000000000000000000000aa").unwrap();

        let _ = SendTransactionToolsNull.sign_transaction(transaction_parameters, &secret_key);
    }

    #[test]
    #[should_panic(expected="send_raw_transaction() for a null object - should never be called")]
    fn null_send_raw_transaction_stops_the_run(){
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolsNull.send_raw_transaction(rlp);
    }
}