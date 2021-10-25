// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::wallet::Wallet;
use actix::Message;

#[derive(Clone, PartialEq, Debug, Message)]
pub struct SetConsumingWalletMessage {
    pub wallet: Wallet,
}
