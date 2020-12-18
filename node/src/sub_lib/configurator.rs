// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::peer_actors::BindMessage;
use actix::Recipient;
use masq_lib::ui_gateway::NodeToUiMessage;
use std::fmt;
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct ConfiguratorSubs {
    pub bind: Recipient<BindMessage>,
    pub node_to_ui_sub: Recipient<NodeToUiMessage>,
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
            node_to_ui_sub: recipient!(recorder, NodeToUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "ConfiguratorSubs");
    }
}
