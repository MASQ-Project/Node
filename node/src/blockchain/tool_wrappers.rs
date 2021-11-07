// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use web3::Web3;
use web3::Transport;
use std::fmt::Debug;
use web3::types::{SignedTransaction, TransactionParameters, Bytes};
use ethereum_types::H256;
use secp256k1::key::SecretKey;
use web3::futures::Future;

//I'm going to clone Web3 and paste it in this struct for the time of sending a transaction. But reference if possible...
pub enum TransactionToolsError{

}

pub trait SendTransactionToolsWrapper {
  fn sign_transaction(&self,transaction_params: TransactionParameters,key: &SecretKey)-> Result<SignedTransaction,TransactionToolsError>;
  fn send_raw_transaction(&self, rlp: Bytes)->Result<H256,TransactionToolsError>;
}

pub struct SendTransactionToolsWrapperReal<'a, T: Transport + Debug>{
    web3:&'a Web3<T>
}

impl <'a,T:Transport + Debug> SendTransactionToolsWrapper for SendTransactionToolsWrapperReal<'a,T>{
    fn sign_transaction(&self,transaction_params: TransactionParameters,key: &SecretKey) -> Result<SignedTransaction, TransactionToolsError> {
        match self.web3.accounts().sign_transaction(transaction_params,key).wait(){
            Ok(tx) => unimplemented!(),
            Err(e) => unimplemented!()
        }

    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, TransactionToolsError> {
        match self.web3.eth().send_raw_transaction(signed_transaction.raw_transaction).wait(){
            Ok(hash) => unimplemented!(), //Ok(hash),
            Err(e) => unimplemented!()
        }
    }
}

pub struct SendTransactionToolsWrapperNull;

impl SendTransactionToolsWrapper for SendTransactionToolsWrapperNull{
    fn sign_transaction(&self, transaction_params: TransactionParameters, key: &SecretKey) -> Result<SignedTransaction, TransactionToolsError> {
        todo!()
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, TransactionToolsError> {
        todo!()
    }
}