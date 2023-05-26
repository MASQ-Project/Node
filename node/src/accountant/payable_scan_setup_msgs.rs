// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//TODO remove this mod frame around
pub mod inter_actor_communication_for_payable_scanner {
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::ResponseSkeleton;
    use actix::Message;
    use crate::sub_lib::blockchain_bridge::{ConsumingWalletBalances, RequestBalancesToPayPayables};

    #[derive(Debug, Message, PartialEq, Eq, Clone)]
    pub struct PayableScannerPaymentSetupMessage<T: Clone>{
        //this field should stay private for anybody outside Accountant
        pub (in crate::accountant) qualified_payables: Vec<PayableAccount>,
        pub current_stage_data: T,
        pub response_skeleton_opt: Option<ResponseSkeleton>
    }

    impl <T: Clone> PayableScannerPaymentSetupMessage<T>{
        pub fn qualified_payables(&self)->&[PayableAccount]{
            todo!()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ConsumingWalletBalancesAndGasPrice {
        pub consuming_wallet_balances: ConsumingWalletBalances,
        pub gas_price: u64
    }

    impl From<PayableScannerPaymentSetupMessage<ConsumingWalletBalancesAndGasPrice>> for Vec<PayableAccount>{
        fn from(_: PayableScannerPaymentSetupMessage<ConsumingWalletBalancesAndGasPrice>) -> Self {
            todo!()
        }
    }

    impl From<(RequestBalancesToPayPayables, ConsumingWalletBalancesAndGasPrice)> for PayableScannerPaymentSetupMessage<ConsumingWalletBalancesAndGasPrice>{
        fn from((previous_msg, current_stage_data):(RequestBalancesToPayPayables, ConsumingWalletBalancesAndGasPrice)) -> Self {
            PayableScannerPaymentSetupMessage{
                qualified_payables: previous_msg.accounts,
                current_stage_data,
                response_skeleton_opt: previous_msg.response_skeleton_opt,
            }
        }
    }
}

