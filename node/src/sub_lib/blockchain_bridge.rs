// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::{PayableAccount, Payment};
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::blockchain::blockchain_interface::BlockchainResult;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url: Option<String>,
    pub chain_id: u8,
}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub report_accounts_payable: Recipient<ReportAccountsPayable>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
    pub set_consuming_wallet_password_sub: Recipient<SetWalletPasswordMsg>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ReportAccountsPayable {
    pub accounts: Vec<PayableAccount>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct SetWalletPasswordMsg {
    pub client_id: u64,
    pub password: String,
}

impl Message for ReportAccountsPayable {
    type Result = Result<Vec<BlockchainResult<Payment>>, String>;
}
