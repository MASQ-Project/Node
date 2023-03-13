// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::{RequestTransactionReceipts, ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use ethereum_types::H256;
use masq_lib::blockchains::chains::Chain;
use masq_lib::ui_gateway::NodeFromUiMessage;
use serde_json::Value;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::time::SystemTime;
use web3::futures::Future;
use web3::transports::Batch;
use web3::types::{Bytes, SignedTransaction, TransactionParameters};
use web3::Web3;
use web3::{BatchTransport, Error as Web3Error};

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url_opt: Option<String>,
    pub chain: Chain,
    pub gas_price: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub report_accounts_payable: Recipient<ReportAccountsPayable>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub ui_sub: Recipient<NodeFromUiMessage>,
    pub request_transaction_receipts: Recipient<RequestTransactionReceipts>,
}

impl Debug for BlockchainBridgeSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockchainBridgeSubs")
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct ReportAccountsPayable {
    pub accounts: Vec<PayableAccount>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl SkeletonOptHolder for ReportAccountsPayable {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct SetDbPasswordMsg {
    pub client_id: u64,
    pub password: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Message)]
pub struct SetGasPriceMsg {
    pub client_id: u64,
    pub gas_price: String,
}

//TODO maybe this isn't a suitable place for logic, just plain structures seem to love here
pub trait BatchPayableTools<T>
where
    T: BatchTransport,
{
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error>;
    fn enter_raw_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>);
    fn batch_wide_timestamp(&self) -> SystemTime;
    fn send_new_payable_fingerprints_credentials(
        &self,
        batch_wide_timestamp: SystemTime,
        new_pp_fingerprints_sub: &Recipient<PendingPayableFingerprintSeeds>,
        hashes_and_balances: &[(H256, u128)],
    );
    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<Value>>, Web3Error>;
}

#[derive(Debug)]
pub struct BatchPayableToolsReal<T> {
    phantom: PhantomData<T>,
}

impl<T: BatchTransport> Default for BatchPayableToolsReal<T> {
    fn default() -> Self {
        Self {
            phantom: Default::default(),
        }
    }
}

impl<T: BatchTransport + Debug> BatchPayableTools<T> for BatchPayableToolsReal<T> {
    fn sign_transaction(
        &self,
        transaction_params: TransactionParameters,
        web3: &Web3<Batch<T>>,
        key: &secp256k1secrets::key::SecretKey,
    ) -> Result<SignedTransaction, Web3Error> {
        web3.accounts()
            .sign_transaction(transaction_params, key)
            .wait()
    }

    fn enter_raw_transaction_to_batch(&self, signed_transaction: Bytes, web3: &Web3<Batch<T>>) {
        let _ = web3.eth().send_raw_transaction(signed_transaction);
    }

    fn batch_wide_timestamp(&self) -> SystemTime {
        SystemTime::now()
    }

    fn send_new_payable_fingerprints_credentials(
        &self,
        batch_wide_timestamp: SystemTime,
        pp_fingerprint_sub: &Recipient<PendingPayableFingerprintSeeds>,
        hashes_and_balances: &[(H256, u128)],
    ) {
        pp_fingerprint_sub
            .try_send(PendingPayableFingerprintSeeds {
                batch_wide_timestamp,
                hashes_and_balances: hashes_and_balances.to_vec(),
            })
            .expect("Accountant is dead");
    }

    fn submit_batch(
        &self,
        web3: &Web3<Batch<T>>,
    ) -> Result<Vec<web3::transports::Result<Value>>, Web3Error> {
        web3.transport().submit_batch().wait()
    }
}

#[cfg(test)]
mod tests {
    use crate::blockchain::blockchain_bridge::PendingPayableFingerprintSeeds;
    use crate::blockchain::test_utils::{make_tx_hash, TestTransport};
    use crate::sub_lib::blockchain_bridge::{BatchPayableTools, BatchPayableToolsReal};
    use crate::test_utils::recorder::{make_blockchain_bridge_subs_from, make_recorder, Recorder};
    use actix::{Actor, System};
    use std::time::SystemTime;

    #[test]
    fn request_new_payable_fingerprints_works() {
        let (accountant, _, accountant_recording_arc) = make_recorder();
        let recipient = accountant.start().recipient();
        let timestamp = SystemTime::now();
        let hashes_and_balances = vec![(make_tx_hash(123), 5), (make_tx_hash(45466), 444444)];

        let _ = BatchPayableToolsReal::<TestTransport>::default()
            .send_new_payable_fingerprints_credentials(timestamp, &recipient, &hashes_and_balances);

        let system = System::new("new fingerprints");
        System::current().stop();
        assert_eq!(system.run(), 0);
        let accountant_recording = accountant_recording_arc.lock().unwrap();
        let message = accountant_recording.get_record::<PendingPayableFingerprintSeeds>(0);
        assert_eq!(
            message,
            &PendingPayableFingerprintSeeds {
                batch_wide_timestamp: timestamp,
                hashes_and_balances
            }
        )
    }

    #[test]
    fn batch_wide_timestamp_returns_current_now() {
        let subject = BatchPayableToolsReal::<TestTransport>::default();
        let before = SystemTime::now();

        let result = subject.batch_wide_timestamp();

        let after = SystemTime::now();
        assert!(
            before <= result && result <= after,
            "Actual timestamp {:?} didn't fit between before {:?} and after {:?}",
            result,
            before,
            after
        )
    }

    #[test]
    fn blockchain_bridge_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = make_blockchain_bridge_subs_from(&recorder);

        assert_eq!(format!("{:?}", subject), "BlockchainBridgeSubs");
    }
}
