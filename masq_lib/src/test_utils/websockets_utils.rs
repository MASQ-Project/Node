// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use std::net::SocketAddr;
use futures_util::io::{BufReader, BufWriter};
use soketto::handshake;
// use crate::messages::NODE_UI_PROTOCOL;
// use async_channel::{Receiver, Sender};
// use futures_util::TryFutureExt;
// use std::sync::{Arc, Mutex};
// use std::time::Duration;
// use tokio::sync::mpsc::unbounded_channel;
// use workflow_websocket::client::{Ack, Message, WebSocket};
// use workflow_websocket::client::{ConnectOptions, Handshake, WebSocketConfig};
use soketto::handshake::{Client, ServerResponse};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncReadCompatExt;
use crate::utils::localhost;
use crate::websockets_handshake::{WSReceiver, WSSender};

pub async fn establish_ws_conn_with_protocols(
    port: u16,
    protocols: Vec<String>,
) -> Result<(WSSender, WSReceiver), String> {
    let socket_addr = SocketAddr::new(localhost(), port);
    let stream = TcpStream::connect(socket_addr)
        .await
        .map_err(|e| format!("Connecting a TCP stream to the websocket server failed: {}", e))?;
    let host = socket_addr.to_string();
    let mut client = handshake::Client::new(
        BufReader::new(BufWriter::new(stream.compat())),
        host.as_str(),
        "/"
    );
    protocols.iter().for_each (|protocol| {client.add_protocol(protocol.as_str());});
    let handshake_response = client
        .handshake()
        .await
        .map_err(|e| format!("Handshake with the websocket server failed: {}", e))?;
    match handshake_response {
        ServerResponse::Accepted { protocol: protocol_opt } => {
            // TODO: Record protocol_opt somehow so that it can be asserted
        }
        _ => {
            return Err(format!("Websocket server did not accept any of these subprotocols: {:?}: {:?}",
                protocols, handshake_response));
        }
    }
    let (sender, receiver) = client.into_builder().finish();
    Ok((sender, receiver))
}
