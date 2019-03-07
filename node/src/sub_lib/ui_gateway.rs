// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::sub_lib::peer_actors::BindMessage;
use actix::Message;
use actix::Recipient;

pub const DEFAULT_UI_PORT: u16 = 5333;

#[derive(Clone)]
pub struct UiGatewayConfig {
    pub ui_port: u16,
}

#[derive(Clone)]
pub struct UiGatewaySubs {
    pub bind: Recipient<BindMessage>,
    pub ui_message_sub: Recipient<UiMessage>,
    pub from_ui_message_sub: Recipient<FromUiMessage>,
}

// TODO: Needs client_id
#[derive(Message, PartialEq, Debug)]
pub enum UiMessage {
    ShutdownMessage,
}

// TODO: Needs client_id
#[derive(Message, PartialEq, Debug)]
pub struct FromUiMessage {
    pub json: String,
}

// Keep these for now, getting the types right was tricky
//#[derive(Message)]
//pub struct UiMessageWrapper {
//    pub msg: Box<UiMessage>,
//}
//
//pub trait UiMessage: Send + Debug {
//    fn msg_type(&self) -> &str;
//}

//impl UiMessage for ShutdownMessage {
//    fn msg_type(&self) -> &str {
//        "shutdown"
//    }
//}
//// TODO: This can move into ui_gateway because it's never used anywhere but there
//#[derive(Debug, PartialEq)]
//pub struct ShutdownMessage;
