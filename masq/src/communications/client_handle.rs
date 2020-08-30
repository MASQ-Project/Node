// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::communications::node_connection::ClientError;
use crate::communications::node_connection::ClientError::{
    ConnectionDropped, Deserialization, NoServer, PacketType,
};
use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::ui_gateway::MessageBody;
use masq_lib::ui_traffic_converter::UiTrafficConverter;
use masq_lib::utils::localhost;
use std::net::TcpStream;
use websocket::result::WebSocketResult;
use websocket::sync::Client;
use websocket::WebSocketError;
use websocket::{ClientBuilder, OwnedMessage};

pub struct ClientHandle {
    daemon_ui_port: u16,
    active_ui_port: u16,
    client: Client<TcpStream>,
}

impl ClientHandle {
    pub fn try_new(daemon_ui_port: u16, active_ui_port: u16) -> Result<Self, ClientError> {
        let client = match Self::make_client(active_ui_port) {
            Err(e) => return Err(NoServer(active_ui_port, format!("{:?}", e))),
            Ok(c) => c,
        };
        Ok(ClientHandle {
            daemon_ui_port,
            active_ui_port,
            client,
        })
    }

    pub fn daemon_ui_port(&self) -> u16 {
        self.daemon_ui_port
    }

    pub fn send(&mut self, outgoing_msg: MessageBody) -> Result<(), ClientError> {
        let outgoing_msg_json = UiTrafficConverter::new_marshal(outgoing_msg);
        let result = {
            self.client
                .send_message(&OwnedMessage::Text(outgoing_msg_json))
        };
        if let Err(e) = result {
            match self.fall_back(&e) {
                Ok(_) => Err(ConnectionDropped(format!("{:?}", e))),
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }

    pub fn receive(&mut self) -> Result<MessageBody, ClientError> {
        let incoming_msg = { self.client.recv_message() };
        let incoming_msg_json = match incoming_msg {
            Ok(OwnedMessage::Text(json)) => json,
            Ok(x) => return Err(PacketType(format!("{:?}", x))),
            Err(e) => {
                return match self.fall_back(&e) {
                    Ok(_) => Err(ClientError::ConnectionDropped(format!("{:?}", e))),
                    Err(e) => Err(e),
                }
            }
        };
        match UiTrafficConverter::new_unmarshal(&incoming_msg_json) {
            Ok(m) => Ok(m),
            Err(e) => Err(Deserialization(e)),
        }
    }

    pub fn close(&mut self) {
        let _ = self.client.send_message(&OwnedMessage::Close(None));
    }

    fn make_client(port: u16) -> WebSocketResult<Client<TcpStream>> {
        let builder =
            ClientBuilder::new(format!("ws://{}:{}", localhost(), port).as_str()).expect("Bad URL");
        builder.add_protocol(NODE_UI_PROTOCOL).connect_insecure()
    }

    fn fall_back(&mut self, e: &WebSocketError) -> Result<(), ClientError> {
        if self.daemon_ui_port == self.active_ui_port {
            return Err(ClientError::FallbackFailed(format!(
                "Daemon has terminated: {:?}",
                e
            )));
        }
        match Self::make_client(self.daemon_ui_port) {
            Ok(client) => {
                self.client = client;
                self.active_ui_port = self.daemon_ui_port
            }
            Err(e) => {
                return Err(ClientError::FallbackFailed(format!(
                    "Both Node and Daemon have terminated: {:?}",
                    e
                )))
            }
        }
        Ok(())
    }
}
