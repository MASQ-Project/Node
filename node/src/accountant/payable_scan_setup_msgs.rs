// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

//TODO remove this mod frame around
pub mod inter_actor_communication_for_payable_scanner {
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::ResponseSkeleton;
    use crate::sub_lib::blockchain_bridge::{
        ConsumingWalletBalances, RequestBalancesToPayPayables,
    };
    use actix::Message;

    #[derive(Debug, Message, PartialEq, Eq, Clone)]
    pub struct PayablePaymentSetup<T: Clone> {
        //this field should stay private for anybody outside Accountant
        pub(in crate::accountant) qualified_payables: Vec<PayableAccount>,
        pub this_stage_data: T,
        pub response_skeleton_opt: Option<ResponseSkeleton>,
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ConsumingWalletBalancesAndGasPrice {
        pub consuming_wallet_balances: ConsumingWalletBalances,
        pub preferred_gas_price: u64,
    }

    impl
        From<(
            RequestBalancesToPayPayables,
            ConsumingWalletBalancesAndGasPrice,
        )> for PayablePaymentSetup<ConsumingWalletBalancesAndGasPrice>
    {
        fn from(
            (previous_msg, current_stage_data): (
                RequestBalancesToPayPayables,
                ConsumingWalletBalancesAndGasPrice,
            ),
        ) -> Self {
            PayablePaymentSetup {
                qualified_payables: previous_msg.accounts,
                this_stage_data: current_stage_data,
                response_skeleton_opt: previous_msg.response_skeleton_opt,
            }
        }
    }
}
