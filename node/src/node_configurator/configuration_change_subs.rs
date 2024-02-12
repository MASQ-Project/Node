// Copyright (c) 2019-2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::neighborhood::ConfigurationChangeMessage;
use actix::Recipient;

pub struct UpdateWalletsSubs {
    pub accountant: Recipient<ConfigurationChangeMessage>,
    pub blockchain_bridge: Recipient<ConfigurationChangeMessage>,
    pub neighborhood: Recipient<ConfigurationChangeMessage>,
}

impl UpdateWalletsSubs {
    pub fn recipients(&self) -> [&Recipient<ConfigurationChangeMessage>; 3] {
        [
            &self.accountant,
            &self.blockchain_bridge,
            &self.neighborhood,
        ]
    }
}
