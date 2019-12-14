// Copyright (c) 2019, MASQ (https://masq.ai). All rights reserved.

use actix::{Actor, Context, Handler, Message};
use actix::Recipient;
use crate::sub_lib::ui_gateway::{NewFromUiMessage, NewToUiMessage};

#[derive(Message, PartialEq, Clone)]
pub struct DaemonBindMessage {
    pub to_ui_message_recipient: Recipient<NewToUiMessage>, // for everybody to send UI-bound messages to
    pub from_ui_message_recipient: Recipient<NewFromUiMessage>, // for the WebsocketSupervisor to send inbound UI messages to the UiGateway
    pub from_ui_message_recipients: Vec<Recipient<NewFromUiMessage>>, // for the UiGateway to relay inbound UI messages to everybody
}

pub struct Daemon {

}

impl Actor for Daemon {
    type Context = Context<Daemon>;
}

impl Handler<DaemonBindMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, _msg: DaemonBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        unimplemented!()
    }
}

impl Handler<NewFromUiMessage> for Daemon {
    type Result = ();

    fn handle(&mut self, _msg: NewFromUiMessage, _ctx: &mut Self::Context) -> Self::Result {
        unimplemented!()
    }
}

impl Daemon {
    pub fn new() -> Daemon {
        Daemon {
        }
    }
}