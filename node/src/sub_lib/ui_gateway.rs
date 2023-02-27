// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::peer_actors::BindMessage;
use actix::Recipient;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use std::fmt::{Debug, Formatter};

#[derive(Clone, Debug)]
pub struct UiGatewayConfig {
    pub ui_port: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct UiGatewaySubs {
    pub bind: Recipient<BindMessage>,
    pub node_from_ui_message_sub: Recipient<NodeFromUiMessage>,
    pub node_to_ui_message_sub: Recipient<NodeToUiMessage>,
}

impl Debug for UiGatewaySubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "UiGatewaySubs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::sub_lib::ui_gateway::UiGatewaySubs;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn ui_gateway_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = UiGatewaySubs {
            bind: recipient!(recorder, BindMessage),
            node_from_ui_message_sub: recipient!(recorder, NodeFromUiMessage),
            node_to_ui_message_sub: recipient!(recorder, NodeToUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "UiGatewaySubs");
    }
}
