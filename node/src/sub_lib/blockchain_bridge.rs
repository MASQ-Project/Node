// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::blockchain::blockchain_bridge::RetrieveTransactions;
use crate::sub_lib::peer_actors::BindMessage;
use crate::sub_lib::wallet::Wallet;
use actix::Message;
use actix::Recipient;
use web3::types::Address;

#[derive(Clone, PartialEq, Debug, Default)]
pub struct BlockchainBridgeConfig {
    pub blockchain_service_url: Option<String>,
    pub contract_address: Address,
    pub consuming_wallet: Option<Wallet>,
    pub mnemonic_seed: Option<String>,
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
