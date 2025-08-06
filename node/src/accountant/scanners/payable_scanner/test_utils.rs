use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayable;
use crate::accountant::scanners::payable_scanner::data_structures::retry_tx_template::RetryTxTemplate;
use crate::accountant::scanners::payable_scanner::data_structures::BaseTxTemplate;
use crate::accountant::scanners::payable_scanner::payable_scanner_extension::msgs::BlockchainAgentWithContextMessage;
use crate::accountant::scanners::payable_scanner::{PayableScanner, PreparedAdjustment};
use crate::accountant::test_utils::{
    FailedPayableDaoMock, PayableDaoMock, PaymentAdjusterMock, SentPayableDaoMock,
};
use crate::blockchain::blockchain_agent::test_utils::BlockchainAgentMock;
use crate::blockchain::blockchain_interface::data_structures::RpcPayableFailure;
use crate::blockchain::test_utils::{make_address, make_tx_hash};
use crate::sub_lib::accountant::PaymentThresholds;
use crate::test_utils::make_wallet;
use std::rc::Rc;
use web3::types::Address;

pub struct PayableScannerBuilder {
    payable_dao: PayableDaoMock,
    sent_payable_dao: SentPayableDaoMock,
    failed_payable_dao: FailedPayableDaoMock,
    payment_thresholds: PaymentThresholds,
    payment_adjuster: PaymentAdjusterMock,
}

impl PayableScannerBuilder {
    pub fn new() -> Self {
        Self {
            payable_dao: PayableDaoMock::new(),
            sent_payable_dao: SentPayableDaoMock::new(),
            failed_payable_dao: FailedPayableDaoMock::new(),
            payment_thresholds: PaymentThresholds::default(),
            payment_adjuster: PaymentAdjusterMock::default(),
        }
    }

    pub fn payable_dao(mut self, payable_dao: PayableDaoMock) -> PayableScannerBuilder {
        self.payable_dao = payable_dao;
        self
    }

    pub fn sent_payable_dao(
        mut self,
        sent_payable_dao: SentPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.sent_payable_dao = sent_payable_dao;
        self
    }

    pub fn failed_payable_dao(
        mut self,
        failed_payable_dao: FailedPayableDaoMock,
    ) -> PayableScannerBuilder {
        self.failed_payable_dao = failed_payable_dao;
        self
    }

    pub fn payment_adjuster(
        mut self,
        payment_adjuster: PaymentAdjusterMock,
    ) -> PayableScannerBuilder {
        self.payment_adjuster = payment_adjuster;
        self
    }

    pub fn payment_thresholds(mut self, payment_thresholds: PaymentThresholds) -> Self {
        self.payment_thresholds = payment_thresholds;
        self
    }

    pub fn build(self) -> PayableScanner {
        PayableScanner::new(
            Box::new(self.payable_dao),
            Box::new(self.sent_payable_dao),
            Box::new(self.failed_payable_dao),
            Rc::new(self.payment_thresholds),
            Box::new(self.payment_adjuster),
        )
    }
}

#[derive(Clone)]
pub struct RetryTxTemplateBuilder {
    receiver_address: Option<Address>,
    amount_in_wei: Option<u128>,
    prev_gas_price_wei: Option<u128>,
    prev_nonce: Option<u64>,
    computed_gas_price_wei_opt: Option<u128>,
}

impl Default for RetryTxTemplateBuilder {
    fn default() -> Self {
        RetryTxTemplateBuilder::new()
    }
}

impl RetryTxTemplateBuilder {
    pub fn new() -> Self {
        Self {
            receiver_address: None,
            amount_in_wei: None,
            prev_gas_price_wei: None,
            prev_nonce: None,
            computed_gas_price_wei_opt: None,
        }
    }

    pub fn receiver_address(mut self, address: Address) -> Self {
        self.receiver_address = Some(address);
        self
    }

    pub fn amount_in_wei(mut self, amount: u128) -> Self {
        self.amount_in_wei = Some(amount);
        self
    }

    pub fn prev_gas_price_wei(mut self, gas_price: u128) -> Self {
        self.prev_gas_price_wei = Some(gas_price);
        self
    }

    pub fn prev_nonce(mut self, nonce: u64) -> Self {
        self.prev_nonce = Some(nonce);
        self
    }

    pub fn computed_gas_price_wei(mut self, gas_price: u128) -> Self {
        self.computed_gas_price_wei_opt = Some(gas_price);
        self
    }

    pub fn payable_account(mut self, payable_account: &PayableAccount) -> Self {
        self.receiver_address = Some(payable_account.wallet.address());
        self.amount_in_wei = Some(payable_account.balance_wei);
        self
    }

    pub fn build(self) -> RetryTxTemplate {
        RetryTxTemplate {
            base: BaseTxTemplate {
                receiver_address: self.receiver_address.unwrap_or_else(|| make_address(0)),
                amount_in_wei: self.amount_in_wei.unwrap_or(0),
            },
            prev_gas_price_wei: self.prev_gas_price_wei.unwrap_or(0),
            prev_nonce: self.prev_nonce.unwrap_or(0),
            computed_gas_price_wei: self.computed_gas_price_wei_opt,
        }
    }
}

impl Clone for BlockchainAgentWithContextMessage {
    fn clone(&self) -> Self {
        let original_agent_id = self.agent.arbitrary_id_stamp();
        let cloned_agent = BlockchainAgentMock::default().set_arbitrary_id_stamp(original_agent_id);
        Self {
            priced_templates: self.priced_templates.clone(),
            agent: Box::new(cloned_agent),
            response_skeleton_opt: self.response_skeleton_opt,
        }
    }
}

impl Clone for PreparedAdjustment {
    fn clone(&self) -> Self {
        Self {
            original_setup_msg: self.original_setup_msg.clone(),
            adjustment: self.adjustment.clone(),
        }
    }
}

pub fn make_retry_tx_template(n: u32) -> RetryTxTemplate {
    RetryTxTemplateBuilder::new()
        .receiver_address(make_address(n))
        .amount_in_wei(n as u128 * 1000)
        .prev_gas_price_wei(n as u128 * 100)
        .prev_nonce(n as u64)
        .build()
}

// TODO: GH-605: Remove other declaration in file agent_web3.rs
pub fn make_retry_tx_template_with_prev_gas_price(
    payable: &PayableAccount,
    gas_price_wei: u128,
) -> RetryTxTemplate {
    let base = BaseTxTemplate::from(payable);
    RetryTxTemplate {
        base,
        prev_gas_price_wei: gas_price_wei,
        prev_nonce: 0,
        computed_gas_price_wei: None,
    }
}

pub fn make_pending_payable(n: u32) -> PendingPayable {
    PendingPayable {
        recipient_wallet: make_wallet(&format!("pending_payable_recipient_{n}")),
        hash: make_tx_hash(n * 4724927),
    }
}

pub fn make_rpc_payable_failure(n: u32) -> RpcPayableFailure {
    RpcPayableFailure {
        recipient_wallet: make_wallet(&format!("rpc_payable_failure_recipient_{n}")),
        hash: make_tx_hash(n * 234819),
        rpc_error: web3::Error::Rpc(jsonrpc_core::Error::internal_error()),
    }
}
