// Copyright (c) 2019-2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::neighborhood::ConfigChangeMsg;
use actix::Recipient;

pub trait ConfigChangeSubs {
    fn recipients(&self) -> Vec<&Recipient<ConfigChangeMsg>>;

    fn send_msg_to_subs(&self, msg: ConfigChangeMsg) {
        self.recipients().iter().for_each(|recipient| {
            recipient
                .try_send(msg.clone())
                .expect("ConfigChangeMsg recipient is dead")
        })
    }
}

pub struct UpdateMinHopsSubs {
    pub neighborhood: Recipient<ConfigChangeMsg>,
}

impl ConfigChangeSubs for UpdateMinHopsSubs {
    fn recipients(&self) -> Vec<&Recipient<ConfigChangeMsg>> {
        vec![&self.neighborhood]
    }
}

pub struct UpdatePasswordSubs {
    pub neighborhood: Recipient<ConfigChangeMsg>,
}

impl ConfigChangeSubs for UpdatePasswordSubs {
    fn recipients(&self) -> Vec<&Recipient<ConfigChangeMsg>> {
        vec![&self.neighborhood]
    }
}

pub struct UpdateWalletsSubs {
    pub accountant: Recipient<ConfigChangeMsg>,
    pub blockchain_bridge: Recipient<ConfigChangeMsg>,
    pub neighborhood: Recipient<ConfigChangeMsg>,
}

impl ConfigChangeSubs for UpdateWalletsSubs {
    fn recipients(&self) -> Vec<&Recipient<ConfigChangeMsg>> {
        vec![
            &self.accountant,
            &self.blockchain_bridge,
            &self.neighborhood,
        ]
    }
}
