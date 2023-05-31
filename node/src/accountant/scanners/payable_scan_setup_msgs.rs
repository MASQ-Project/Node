// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.


    use crate::accountant::database_access_objects::payable_dao::PayableAccount;
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
    pub struct ConsumingWalletBalancesAndGasParams {
        pub consuming_wallet_balances: ConsumingWalletBalances,
        pub estimated_gas_limit_per_transaction: u64,
        pub desired_gas_price_gwei: u64,
    }

    impl
        From<(
            RequestBalancesToPayPayables,
            ConsumingWalletBalancesAndGasParams,
        )> for PayablePaymentSetup<ConsumingWalletBalancesAndGasParams>
    {
        fn from(
            (previous_msg, current_stage_data): (
                RequestBalancesToPayPayables,
                ConsumingWalletBalancesAndGasParams,
            ),
        ) -> Self {
            PayablePaymentSetup {
                qualified_payables: previous_msg.accounts,
                this_stage_data: current_stage_data,
                response_skeleton_opt: previous_msg.response_skeleton_opt,
            }
        }
    }
