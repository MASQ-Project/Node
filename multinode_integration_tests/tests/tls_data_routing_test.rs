use multinode_integration_tests_lib::substratum_node::SubstratumNode;
use multinode_integration_tests_lib::substratum_node_cluster::SubstratumNodeCluster;
use multinode_integration_tests_lib::substratum_real_node::{
    NodeStartupConfigBuilder, SubstratumRealNode,
};
use native_tls::HandshakeError;
use native_tls::TlsConnector;
use native_tls::TlsStream;
use node_lib::test_utils::test_utils::*;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[test]
fn tls_end_to_end_routing_test() {
    let mut cluster = SubstratumNodeCluster::start().unwrap();
    let first_node = cluster.start_real_node(NodeStartupConfigBuilder::standard().build());

    let nodes = (0..7)
        .map(|_| {
            cluster.start_real_node(
                NodeStartupConfigBuilder::standard()
                    .neighbor(first_node.node_reference())
                    .build(),
            )
        })
        .collect::<Vec<SubstratumRealNode>>();

    thread::sleep(Duration::from_millis(500 * (nodes.len() as u64)));

    let mut tls_stream = {
        let mut tls_stream: Option<TlsStream<TcpStream>> = None;
        let stream = TcpStream::connect(
            SocketAddr::from_str(&format!(
                "{}:{}",
                &nodes[5].node_addr().ip_addr().to_string(),
                "8443"
            ))
            .unwrap(),
        )
        .expect(&format!(
            "Could not connect to {}:8443",
            &nodes[5].node_addr().ip_addr().to_string()
        ));
        stream
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .expect("Could not set read timeout to 1000ms");
        let connector = TlsConnector::new().expect("Could not build TlsConnector");
        match connector.connect(
            "example.com",
            stream.try_clone().expect("Couldn't clone TcpStream"),
        ) {
            Ok(s) => {
                tls_stream = Some(s);
            }
            Err(HandshakeError::WouldBlock(interrupted_stream)) => {
                thread::sleep(Duration::from_millis(100));
                match interrupted_stream.handshake() {
                    Ok(stream) => tls_stream = Some(stream),
                    Err(e) => {
                        println!("connection error after interruption retry: {:?}", e);
                        handle_connection_error(stream);
                    }
                }
            }
            Err(e) => {
                println!("connection error: {:?}", e);
                handle_connection_error(stream);
            }
        }

        tls_stream.expect("Couldn't handshake")
    };
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes();
    tls_stream
        .write(request.clone())
        .expect("Could not write request to TLS stream");
    let buf = read_until_timeout(&mut tls_stream);
    let _ = tls_stream.shutdown().is_ok(); // Can't do anything about an error here

    let response = String::from_utf8(Vec::from(&buf[..])).expect("Response is not UTF-8");
    assert_eq!(&response[9..15], &"200 OK"[..]);
    assert_eq!(
        response.contains(
            "This domain is established to be used for illustrative examples in documents."
        ),
        true,
        "{}",
        response
    );
    assert_eq!(response.contains("You may use this\n    domain in examples without prior coordination or asking for permission."), true, "{}", response);
}
