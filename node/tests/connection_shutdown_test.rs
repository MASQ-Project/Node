// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod utils;

use crossbeam_channel::{unbounded, Sender};
use masq_lib::utils::find_free_port;
use node_lib::test_utils::read_until_timeout;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::net::{Shutdown, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{io, thread};

// 'node' below must not be named '_' alone or disappear, or the MASQNode will be immediately reclaimed.
#[test]
fn proxy_client_stream_reader_dies_when_client_stream_is_killed_integration() {
    let _node = utils::MASQNode::start_standard(
        "proxy_client_stream_reader_dies_when_client_stream_is_killed_integration",
        None,
        true,
        true,
        false,
        true,
    );
    let (write_error_tx, write_error_rx) = unbounded();
    let server_port = find_free_port();
    thread::spawn(move || {
        endless_write_server(server_port, write_error_tx);
    });
    let mut stream = TcpStream::connect(SocketAddr::from_str("127.0.0.1:80").unwrap()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\n\r\n");

    stream.write(request.as_bytes()).unwrap();
    let mut buf = [0u8; 16384];
    // We want to make sure the Server is sending before we shutdown the stream
    stream.read(&mut buf).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let write_error = write_error_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(write_error.kind(), io::ErrorKind::ConnectionAborted);
}

fn endless_write_server(port: u16, write_error_tx: Sender<io::Error>) {
    let listener = TcpListener::bind(SocketAddr::new(
        IpAddr::from_str("127.0.0.1").unwrap(),
        port,
    ))
    .unwrap();
    let mut buf = [0u8; 16_384];
    let (mut stream, _) = listener.accept().unwrap();
    let _ = stream.read(&mut buf).unwrap();
    stream
        .write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_bytes())
        .unwrap();
    let msg = "Chancellor on brink of second bailout for banks";
    let msg_len = msg.len();
    let chunk_body = format!("{msg_len}\r\n{msg}\r\n");
    loop {
        if let Err(e) = stream.write(chunk_body.as_bytes()) {
            write_error_tx.send(e).unwrap();
            break;
        }

        thread::sleep(Duration::from_millis(250));
    }
}
