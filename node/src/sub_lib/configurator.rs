// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::peer_actors::BindMessage;
use actix::Recipient;
use masq_lib::ui_gateway::NodeFromUiMessage;
use std::fmt;
use std::fmt::{Debug, Formatter};

#[derive(Clone, PartialEq, Eq)]
pub struct ConfiguratorSubs {
    pub bind: Recipient<BindMessage>,
    pub node_from_ui_sub: Recipient<NodeFromUiMessage>,
}

impl Debug for ConfiguratorSubs {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ConfiguratorSubs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn configurator_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = ConfiguratorSubs {
            bind: recipient!(recorder, BindMessage),
            node_from_ui_sub: recipient!(recorder, NodeFromUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "ConfiguratorSubs");
    }
}
