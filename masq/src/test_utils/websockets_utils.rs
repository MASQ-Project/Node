//Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use futures::io::{BufReader, BufWriter};
use masq_lib::messages::NODE_UI_PROTOCOL;
use masq_lib::utils::localhost;
use masq_lib::websockets_types::{WSReceiver, WSSender};
use soketto::handshake::server::Response;
use soketto::handshake::{Client, Server, ServerResponse};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::AsyncWrite;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use crate::communications::websockets_client::ConnectError;

pub async fn simulate_server_ws_handshake(port: u16) -> (WSSender, WSReceiver) {
    let listener = TcpListener::bind(SocketAddr::new(localhost(), port))
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let mut server = Server::new(BufReader::new(BufWriter::new(stream.compat())));
    server.add_protocol(NODE_UI_PROTOCOL);
    let req = server.receive_request().await.unwrap();
    let key = req.key();
    server
        .send_response(&Response::Accept {
            key,
            protocol: Some(NODE_UI_PROTOCOL),
        })
        .await
        .unwrap();
    server.into_builder().finish()
}