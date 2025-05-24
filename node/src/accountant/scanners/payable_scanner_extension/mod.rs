// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod agent_null;
pub mod agent_web3;
pub mod blockchain_agent;
pub mod msgs;
pub mod test_utils;

use crate::accountant::payment_adjuster::Adjustment;
use crate::accountant::scanners::payable_scanner_extension::msgs::{
    BlockchainAgentWithContextMessage, QualifiedPayablesMessage,
};
use crate::accountant::scanners::scanners_utils::payable_scanner_utils::PayableScanResult;
use crate::accountant::scanners::{Scanner, StartableScanner};
use crate::accountant::{ScanForNewPayables, ScanForRetryPayables, SentPayables};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use itertools::Either;
use masq_lib::logger::Logger;

pub(in crate::accountant::scanners) trait MultistageDualPayableScanner:
    StartableScanner<ScanForNewPayables, QualifiedPayablesMessage>
    + StartableScanner<ScanForRetryPayables, QualifiedPayablesMessage>
    + SolvencySensitivePaymentInstructor
    + Scanner<SentPayables, PayableScanResult>
{
}

pub(in crate::accountant::scanners) trait SolvencySensitivePaymentInstructor {
    fn try_skipping_payment_adjustment(
        &self,
        msg: BlockchainAgentWithContextMessage,
        logger: &Logger,
    ) -> Result<Either<OutboundPaymentsInstructions, PreparedAdjustment>, String>;

    fn perform_payment_adjustment(
        &self,
        setup: PreparedAdjustment,
        logger: &Logger,
    ) -> OutboundPaymentsInstructions;
}

pub struct PreparedAdjustment {
    pub original_setup_msg: BlockchainAgentWithContextMessage,
    pub adjustment: Adjustment,
}

impl PreparedAdjustment {
    pub fn new(
        original_setup_msg: BlockchainAgentWithContextMessage,
        adjustment: Adjustment,
    ) -> Self {
        Self {
            original_setup_msg,
            adjustment,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::scanners::payable_scanner_extension::PreparedAdjustment;

    impl Clone for PreparedAdjustment {
        fn clone(&self) -> Self {
            Self {
                original_setup_msg: self.original_setup_msg.clone(),
                adjustment: self.adjustment.clone(),
            }
        }
    }
}
