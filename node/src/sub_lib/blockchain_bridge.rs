// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use web3::types::H160;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url: Option<String>,
    pub contract_address: H160,
    pub consuming_private_key: Option<String>,
}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub report_accounts_payable: Recipient<ReportAccountsPayable>,
    pub retrieve_transactions: Recipient<RetrieveTransactions>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportAccountsPayable {
    pub accounts: Vec<PayableAccount>,
}
