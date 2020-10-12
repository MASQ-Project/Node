// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::sub_lib::accountant::FinancialStatisticsMessage;
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;
use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
use serde_derive::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

#[derive(Message, PartialEq, Debug)]
pub struct FromUiMessage {
    pub client_id: u64,
    pub json: String,
}

#[derive(Clone, Debug)]
pub struct UiGatewayConfig {
    pub ui_port: u16,
    pub node_descriptor: String, // TODO: This really shouldn't be here; it exists only to answer
                                 // the GetNodeDescriptor message, which A) is part of MASQNode-UI,
                                 // and B) shouldn't be answered by the UiGateway anyway.
}

#[derive(Clone)]
pub struct UiGatewaySubs {
    pub bind: Recipient<BindMessage>,
    pub ui_message_sub: Recipient<UiCarrierMessage>,
    pub from_ui_message_sub: Recipient<FromUiMessage>,
    pub node_from_ui_message_sub: Recipient<NodeFromUiMessage>,
    pub node_to_ui_message_sub: Recipient<NodeToUiMessage>,
}

impl Debug for UiGatewaySubs {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "UiGatewaySubs")
    }
}

#[derive(Message, Debug, Serialize, Deserialize, PartialEq)]
pub struct UiCarrierMessage {
    pub client_id: u64,
    pub data: UiMessage,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum UiMessage {
    GetFinancialStatisticsMessage,
    FinancialStatisticsResponse(FinancialStatisticsMessage),
    SetGasPrice(String),
    SetGasPriceResponse(bool),
    SetDbPassword(String),
    SetDbPasswordResponse(bool),
    GetNodeDescriptor,
    NodeDescriptor(String),
    NeighborhoodDotGraphRequest,
    NeighborhoodDotGraphResponse(String),
    ShutdownMessage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::peer_actors::BindMessage;
    use crate::sub_lib::ui_gateway::{FromUiMessage, UiCarrierMessage, UiGatewaySubs};
    use crate::test_utils::recorder::Recorder;
    use actix::Actor;

    #[test]
    fn ui_gateway_subs_debug() {
        let recorder = Recorder::new().start();

        let subject = UiGatewaySubs {
            bind: recipient!(recorder, BindMessage),
            ui_message_sub: recipient!(recorder, UiCarrierMessage),
            from_ui_message_sub: recipient!(recorder, FromUiMessage),
            node_from_ui_message_sub: recipient!(recorder, NodeFromUiMessage),
            node_to_ui_message_sub: recipient!(recorder, NodeToUiMessage),
        };

        assert_eq!(format!("{:?}", subject), "UiGatewaySubs");
    }
}
