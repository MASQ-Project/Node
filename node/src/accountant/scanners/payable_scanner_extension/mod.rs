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
use crate::accountant::scanners::{
    PrivateScannerWithAccessToken, PrivateStartableScannerWithAccessToken, Scanner,
};
use crate::accountant::{ScanForNewPayables, ScanForRetryPayables, SentPayables};
use crate::sub_lib::blockchain_bridge::OutboundPaymentsInstructions;
use actix::Message;
use itertools::Either;
use masq_lib::logger::Logger;

pub trait MultistageDualPayableScanner:
    PrivateStartableScannerWithAccessToken<ScanForNewPayables, QualifiedPayablesMessage>
    + PrivateStartableScannerWithAccessToken<ScanForRetryPayables, QualifiedPayablesMessage>
    + PrivateScannerWithAccessToken<SentPayables>
    + SolvencySensitivePaymentInstructor
{
}

pub trait SolvencySensitivePaymentInstructor {
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
