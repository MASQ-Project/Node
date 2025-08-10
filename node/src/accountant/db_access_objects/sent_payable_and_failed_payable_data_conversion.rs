// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::{
    FailedTx, FailureReason, FailureStatus,
};
use crate::accountant::db_access_objects::sent_payable_dao::{Detection, SentTx, TxStatus};
use crate::blockchain::blockchain_interface::data_structures::TxBlock;

impl From<(FailedTx, TxBlock)> for SentTx {
    fn from((failed_tx, confirmation_block): (FailedTx, TxBlock)) -> Self {
        SentTx {
            hash: failed_tx.hash,
            receiver_address: failed_tx.receiver_address,
            amount_minor: failed_tx.amount_minor,
            timestamp: failed_tx.timestamp,
            gas_price_minor: failed_tx.gas_price_minor,
            nonce: failed_tx.nonce,
            status: TxStatus::Confirmed {
                block_hash: format!("{:?}", confirmation_block.block_hash),
                block_number: confirmation_block.block_number.as_u64(),
                detection: Detection::Reclaim,
            },
        }
    }
}

impl From<(SentTx, FailureReason)> for FailedTx {
    fn from((sent_tx, failure_reason): (SentTx, FailureReason)) -> Self {
        FailedTx {
            hash: sent_tx.hash,
            receiver_address: sent_tx.receiver_address,
            amount_minor: sent_tx.amount_minor,
            timestamp: sent_tx.timestamp,
            gas_price_minor: sent_tx.gas_price_minor,
            nonce: sent_tx.nonce,
            reason: failure_reason,
            status: FailureStatus::RetryRequired,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus, ValidationStatus,
    };
    use crate::accountant::db_access_objects::sent_payable_dao::{Detection, SentTx, TxStatus};
    use crate::accountant::db_access_objects::utils::to_unix_timestamp;
    use crate::accountant::gwei_to_wei;
    use crate::accountant::test_utils::make_transaction_block;
    use crate::blockchain::errors::{AppRpcError, LocalError};
    use crate::blockchain::test_utils::make_tx_hash;
    use crate::test_utils::make_wallet;
    use std::time::{Duration, SystemTime};

    #[test]
    fn sent_tx_record_can_be_converted_from_failed_tx_record() {
        let failed_tx = FailedTx {
            hash: make_tx_hash(456),
            receiver_address: make_wallet("abc").address(),
            amount_minor: 456789012,
            timestamp: 345678974,
            gas_price_minor: 123456789,
            nonce: 11,
            reason: FailureReason::PendingTooLong,
            status: FailureStatus::RetryRequired,
        };
        let tx_block = make_transaction_block(789);

        let result = SentTx::from((failed_tx.clone(), tx_block));

        assert_eq!(
            result,
            SentTx {
                hash: make_tx_hash(456),
                receiver_address: make_wallet("abc").address(),
                amount_minor: 456789012,
                timestamp: 345678974,
                gas_price_minor: 123456789,
                nonce: 11,
                status: TxStatus::Confirmed {
                    block_hash:
                        "0x000000000000000000000000000000000000000000000000000000003b9acd15"
                            .to_string(),
                    block_number: 491169069,
                    detection: Detection::Reclaim,
                },
            }
        );
    }

    #[test]
    fn conversion_from_sent_tx_and_failure_reason_to_failed_tx_works() {
        let sent_tx = SentTx {
            hash: make_tx_hash(789),
            receiver_address: make_wallet("receiver").address(),
            amount_minor: 123_456_789,
            timestamp: to_unix_timestamp(
                SystemTime::now()
                    .checked_sub(Duration::from_secs(10_000))
                    .unwrap(),
            ),
            gas_price_minor: gwei_to_wei(424_u64),
            nonce: 456_u64.into(),
            status: TxStatus::Pending(ValidationStatus::Waiting),
        };

        let result_1 = FailedTx::from((sent_tx.clone(), FailureReason::Reverted));
        let result_2 = FailedTx::from((
            sent_tx.clone(),
            FailureReason::Submission(AppRpcError::Local(LocalError::Internal)),
        ));

        assert_conversion_into_failed_tx(result_1, sent_tx.clone(), FailureReason::Reverted);
        assert_conversion_into_failed_tx(
            result_2,
            sent_tx,
            FailureReason::Submission(AppRpcError::Local(LocalError::Internal)),
        );
    }

    fn assert_conversion_into_failed_tx(
        result: FailedTx,
        original_sent_tx: SentTx,
        expected_failure_reason: FailureReason,
    ) {
        assert_eq!(result.hash, original_sent_tx.hash);
        assert_eq!(result.receiver_address, original_sent_tx.receiver_address);
        assert_eq!(result.amount_minor, original_sent_tx.amount_minor);
        assert_eq!(result.timestamp, original_sent_tx.timestamp);
        assert_eq!(result.gas_price_minor, original_sent_tx.gas_price_minor);
        assert_eq!(result.nonce, original_sent_tx.nonce);
        assert_eq!(result.status, FailureStatus::RetryRequired);
        assert_eq!(result.reason, expected_failure_reason);
    }
}
