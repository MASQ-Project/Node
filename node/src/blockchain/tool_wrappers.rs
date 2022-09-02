// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
use actix::Recipient;
use ethereum_types::H256;
use std::fmt::{Debug, Formatter};
use std::time::SystemTime;
use web3::futures::Future;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Error as Web3Error;
use web3::{Transport, Web3};

pub trait SendTransactionToolsWrapper: Debug {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn request_new_payable_fingerprint(&self, transaction_hash: H256, amount: u64) -> SystemTime;
    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error>;
}

pub struct SendTransactionToolWrapperReal<'a, T: Transport + Debug> {
    web3: &'a Web3<T>,
    pending_payable_fingerprint_sub: &'a Recipient<PendingPayableFingerprint>,
}

impl<'a, T: Transport + Debug> Debug for SendTransactionToolWrapperReal<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SendTransactionToolWrapperReal {{ web3: {:?}, pending_payable_fingerprint_sub: _OMITTED_ }}",self.web3)
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolWrapperReal<'a, T> {
    pub fn new(
        web3: &'a Web3<T>,
        pending_payable_fingerprint_sub: &'a Recipient<PendingPayableFingerprint>,
    ) -> Self {
        Self {
            web3,
            pending_payable_fingerprint_sub,
        }
    }
}

impl<'a, T: Transport + Debug> SendTransactionToolsWrapper
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

    fn request_new_payable_fingerprint(&self, hash: H256, amount: u64) -> SystemTime {
        let now = SystemTime::now();
        self.pending_payable_fingerprint_sub
            .try_send(PendingPayableFingerprint {
                amount,
                rowid_opt: None,
                timestamp: now,
                hash,
                attempt_opt: None,
                process_error: None,
            })
            .expect("Accountant is dead");
        now
    }

    fn send_raw_transaction(&self, rlp: Bytes) -> Result<H256, Web3Error> {
        self.web3.eth().send_raw_transaction(rlp).wait()
    }
}

#[derive(Debug)]
pub struct SendTransactionToolsWrapperNull;

impl SendTransactionToolsWrapper for SendTransactionToolsWrapperNull {
    fn sign_transaction(
        &self,
        _transaction_params: TransactionParameters,
        _key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        panic!("sign_transaction() should never be called on the null object")
    }

    fn request_new_payable_fingerprint(&self, _transaction_hash: H256, _amount: u64) -> SystemTime {
        panic!(
            "request_new_pending_payable_fingerprint() should never be called on the null object"
        )
    }

    fn send_raw_transaction(&self, _rlp: Bytes) -> Result<H256, Web3Error> {
        panic!("send_raw_transaction() should never be called on the null object")
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprint;
    use crate::blockchain::test_utils::TestTransport;
    use crate::blockchain::tool_wrappers::{
        SendTransactionToolWrapperReal, SendTransactionToolsWrapper,
        SendTransactionToolsWrapperNull,
    };
    use crate::test_utils::recorder::make_recorder;
    use actix::{Actor, Recipient};
    use web3::types::{Bytes, TransactionParameters};
    use web3::Web3;

    #[test]
    #[should_panic(expected = "sign_transaction() should never be called on the null object")]
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
    #[should_panic(expected = "send_raw_transaction() should never be called on the null object")]
    fn null_send_raw_transaction_stops_the_run() {
        let rlp = Bytes(b"data".to_vec());

        let _ = SendTransactionToolsWrapperNull.send_raw_transaction(rlp);
    }

    #[test]
    #[should_panic(
        expected = "request_new_pending_payable_fingerprint() should never be called on the null object"
    )]
    fn null_request_new_pending_payable_fingerprint_stops_the_run() {
        let _ =
            SendTransactionToolsWrapperNull.request_new_payable_fingerprint(Default::default(), 5);
    }

    #[test]
    fn custom_debug_for_send_transaction_tool_wrapper_real() {
        let transport = TestTransport::default();
        let web3 = Web3::new(transport);
        let (random_actor, _, _) = make_recorder();
        let recipient: Recipient<PendingPayableFingerprint> = random_actor.start().recipient();

        let result = format!(
            "{:?}",
            SendTransactionToolWrapperReal::new(&web3, &recipient)
        );

        assert_eq!(result,"SendTransactionToolWrapperReal { web3: Web3 { transport: TestTransport { asserted: 0, \
         requests: RefCell { value: [] }, responses: RefCell { value: [] } } }, pending_payable_fingerprint_sub: _OMITTED_ }")
    }
}
