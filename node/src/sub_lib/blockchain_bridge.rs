// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::PayableAccount;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;

#[derive(Clone, PartialEq, Debug)]
pub struct BlockchainBridgeConfig {
    pub consuming_private_key: Option<String>,
}

#[derive(Clone)]
pub struct BlockchainBridgeSubs {
    pub bind: Recipient<BindMessage>,
    pub report_accounts_payable: Recipient<ReportAccountsPayable>,
}

#[derive(Clone, PartialEq, Debug, Message)]
pub struct ReportAccountsPayable {
    pub accounts: Vec<PayableAccount>,
}
