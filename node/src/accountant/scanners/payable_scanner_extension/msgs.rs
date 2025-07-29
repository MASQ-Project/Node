// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::failed_payable_dao::FailedTx;
use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::{ResponseSkeleton, SkeletonOptHolder};
use crate::blockchain::blockchain_agent::BlockchainAgent;
use crate::blockchain::test_utils::make_address;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::make_wallet;
use actix::Message;
use itertools::Either;
use std::fmt::Debug;
use std::ops::Deref;
use web3::types::Address;

#[derive(Debug, Message, PartialEq, Eq, Clone)]
pub struct QualifiedPayablesMessage {
    pub tx_templates: Either<Vec<NewTxTemplate>, Vec<RetryTxTemplate>>,
    pub consuming_wallet: Wallet,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxTemplates(pub Vec<TxTemplate>);

impl Deref for TxTemplates {
    type Target = Vec<TxTemplate>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TxTemplates {
    pub fn has_retry_template(&self) -> bool {
        self.iter()
            .any(|template| template.prev_tx_values_opt.is_some())
    }
}

// TODO: GH-605: It can be a reference instead
impl From<Vec<PayableAccount>> for TxTemplates {
    fn from(payable_accounts: Vec<PayableAccount>) -> Self {
        Self(
            payable_accounts
                .iter()
                .map(|payable| TxTemplate::from(payable))
                .collect(),
        )
    }
}

// I'd suggest don't do it like this yet
// #[derive(Debug, Clone, PartialEq, Eq)]
// enum PrevTxValues {
//     EVM { gas_price_wei: u128, nonce: u64 },
// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevTxValues {
    pub gas_price_wei: u128,
    pub nonce: u64,
}

// Values used to form PricedPayable: gas_price and receiver address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
    pub prev_tx_values_opt: Option<PrevTxValues>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseTxTemplate {
    pub receiver_address: Address,
    pub amount_in_wei: u128,
}

impl From<&PayableAccount> for BaseTxTemplate {
    fn from(payable_account: &PayableAccount) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTxTemplate {
    pub base: BaseTxTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasPriceOnlyTxTemplate {
    pub base: BaseTxTemplate,
    pub gas_price_wei: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTxTemplate {
    pub base: BaseTxTemplate,
    pub prev_gas_price_wei: u128,
    pub prev_nonce: u64,
}

impl From<&FailedTx> for RetryTxTemplate {
    fn from(_: &FailedTx) -> Self {
        todo!()
    }
}

impl From<&PayableAccount> for TxTemplate {
    fn from(payable: &PayableAccount) -> Self {
        Self {
            receiver_address: payable.wallet.address(),
            amount_in_wei: payable.balance_wei,
            prev_tx_values_opt: None,
        }
    }
}

impl From<&FailedTx> for TxTemplate {
    fn from(failed_tx: &FailedTx) -> Self {
        Self {
            receiver_address: failed_tx.receiver_address,
            amount_in_wei: failed_tx.amount,
            prev_tx_values_opt: Some(PrevTxValues {
                gas_price_wei: failed_tx.gas_price_wei,
                nonce: failed_tx.nonce,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PricedQualifiedPayables {
    pub payables: Vec<QualifiedPayableWithGasPrice>,
}

impl Into<Vec<PayableAccount>> for PricedQualifiedPayables {
    fn into(self) -> Vec<PayableAccount> {
        self.payables
            .into_iter()
            .map(|qualified_payable| qualified_payable.payable)
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct QualifiedPayableWithGasPrice {
    pub payable: PayableAccount,
    pub gas_price_minor: u128,
}

impl QualifiedPayableWithGasPrice {
    pub fn new(payable: PayableAccount, gas_price_minor: u128) -> Self {
        Self {
            payable,
            gas_price_minor,
        }
    }
}

//
// impl QualifiedPayablesMessage {
//     pub(in crate::accountant) fn new(
//         tx_templates: TxTemplates,
//         consuming_wallet: Wallet,
//         response_skeleton_opt: Option<ResponseSkeleton>,
//     ) -> Self {
//         Self {
//             tx_templates,
//             consuming_wallet,
//             response_skeleton_opt,
//         }
//     }
// }

impl SkeletonOptHolder for QualifiedPayablesMessage {
    fn skeleton_opt(&self) -> Option<ResponseSkeleton> {
        self.response_skeleton_opt
    }
}

#[derive(Message)]
pub struct BlockchainAgentWithContextMessage {
    pub qualified_payables: PricedQualifiedPayables,
    pub agent: Box<dyn BlockchainAgent>,
    pub response_skeleton_opt: Option<ResponseSkeleton>,
}

impl BlockchainAgentWithContextMessage {
    pub fn new(
        qualified_payables: PricedQualifiedPayables,
        agent: Box<dyn BlockchainAgent>,
        response_skeleton_opt: Option<ResponseSkeleton>,
    ) -> Self {
        Self {
            qualified_payables,
            agent,
            response_skeleton_opt,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::failed_payable_dao::{
        FailedTx, FailureReason, FailureStatus,
    };
    use crate::accountant::db_access_objects::payable_dao::PayableAccount;
    use crate::accountant::scanners::payable_scanner_extension::msgs::{
        BlockchainAgentWithContextMessage, PrevTxValues, TxTemplate, TxTemplates,
    };
    use crate::accountant::scanners::payable_scanner_extension::test_utils::BlockchainAgentMock;
    use crate::blockchain::test_utils::{make_address, make_tx_hash};
    use crate::test_utils::make_wallet;
    use std::time::SystemTime;

    impl Clone for BlockchainAgentWithContextMessage {
        fn clone(&self) -> Self {
            let original_agent_id = self.agent.arbitrary_id_stamp();
            let cloned_agent =
                BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
            Self {
                qualified_payables: self.qualified_payables.clone(),
                agent: Box::new(cloned_agent),
                response_skeleton_opt: self.response_skeleton_opt,
            }
        }
    }

    #[test]
    fn tx_template_can_be_created_from_payable_account() {
        assert_eq!(
            TxTemplate::from(&PayableAccount {
                wallet: make_wallet("some wallet"),
                balance_wei: 1234,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }),
            TxTemplate {
                receiver_address: make_wallet("some wallet").address(),
                amount_in_wei: 1234,
                prev_tx_values_opt: None,
            }
        );

        assert_eq!(
            TxTemplate::from(&PayableAccount {
                wallet: make_wallet("another wallet"),
                balance_wei: 4321,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            }),
            TxTemplate {
                receiver_address: make_wallet("another wallet").address(),
                amount_in_wei: 4321,
                prev_tx_values_opt: None,
            }
        );
    }

    #[test]
    fn tx_template_can_be_created_from_failed_tx() {
        assert_eq!(
            TxTemplate::from(&FailedTx {
                hash: make_tx_hash(1),
                receiver_address: make_address(1),
                amount: 12345,
                timestamp: 341431,
                gas_price_wei: 901,
                nonce: 1,
                reason: FailureReason::Reverted,
                status: FailureStatus::RetryRequired,
            }),
            TxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 12345,
                prev_tx_values_opt: Some(PrevTxValues {
                    gas_price_wei: 901,
                    nonce: 1,
                }),
            }
        );

        assert_eq!(
            TxTemplate::from(&FailedTx {
                hash: make_tx_hash(1),
                receiver_address: make_address(2),
                amount: 123456,
                timestamp: 341431,
                gas_price_wei: 9012,
                nonce: 2,
                reason: FailureReason::Reverted,
                status: FailureStatus::RetryRequired,
            }),
            TxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 123456,
                prev_tx_values_opt: Some(PrevTxValues {
                    gas_price_wei: 9012,
                    nonce: 2,
                }),
            }
        );
    }

    #[test]
    fn tx_templates_deref_provides_access_to_inner_vector() {
        let template1 = TxTemplate {
            receiver_address: make_address(1),
            amount_in_wei: 1000,
            prev_tx_values_opt: None,
        };
        let template2 = TxTemplate {
            receiver_address: make_address(2),
            amount_in_wei: 2000,
            prev_tx_values_opt: None,
        };

        let templates = TxTemplates(vec![template1.clone(), template2.clone()]);

        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0], template1);
        assert_eq!(templates[1], template2);
        assert!(!templates.is_empty());
        assert!(templates.contains(&template1));
        assert_eq!(
            templates
                .iter()
                .map(|template| template.amount_in_wei)
                .sum::<u128>(),
            3000
        );
    }

    #[test]
    fn tx_templates_is_retry_works() {
        // Case 1: No templates are retries
        let templates1 = TxTemplates(vec![
            TxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
                prev_tx_values_opt: None,
            },
            TxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
                prev_tx_values_opt: None,
            },
        ]);
        assert_eq!(templates1.has_retry_template(), false);

        // Case 2: One template is a retry
        let templates2 = TxTemplates(vec![
            TxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
                prev_tx_values_opt: None,
            },
            TxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
                prev_tx_values_opt: Some(PrevTxValues {
                    gas_price_wei: 5000,
                    nonce: 3,
                }),
            },
        ]);
        assert_eq!(templates2.has_retry_template(), true);

        // Case 3: All templates are retries
        let templates3 = TxTemplates(vec![
            TxTemplate {
                receiver_address: make_address(1),
                amount_in_wei: 1000,
                prev_tx_values_opt: Some(PrevTxValues {
                    gas_price_wei: 4000,
                    nonce: 2,
                }),
            },
            TxTemplate {
                receiver_address: make_address(2),
                amount_in_wei: 2000,
                prev_tx_values_opt: Some(PrevTxValues {
                    gas_price_wei: 5000,
                    nonce: 3,
                }),
            },
        ]);
        assert_eq!(templates3.has_retry_template(), true);

        // Case 4: Empty templates
        let templates4 = TxTemplates(vec![]);
        assert_eq!(templates4.has_retry_template(), false);
    }
}
