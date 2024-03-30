// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::db_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::test_utils::BlockchainAgentMock;
use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::BlockchainInterfaceWeb3;
use crate::blockchain::blockchain_interface::data_structures::ProcessedPayableFallible;
use crate::blockchain::blockchain_interface::BlockchainInterface;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::recorder::Recorder;
use crate::test_utils::unshared_test_utils::decode_hex;
use actix::{Actor, System};
use ethereum_types::{U256, U64};
use masq_lib::blockchains::chains::Chain;
use masq_lib::utils::{find_free_port, localhost};
use native_tls::TlsConnector;
use regex::Regex;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::ops::Add;
use std::str::FromStr;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};
use crossbeam_channel::{Receiver, Sender, unbounded};
use web3::transports::Http;
use websocket::client::Url;

enum TestingMode<F> where F: Fn(&str) -> Box<dyn BlockchainInterface>,{
    BlockchainInterfaceImplemented{
        proxy_port: u16,
        blockchain_interface_factory: F,
        real_blockchain_endpoint_url:String,
        consuming_wallet_secret_key: Vec<u8>,
        pending_transaction_nonce: U256,
        transaction_fee_per_unit_major: u64,
        example_payables: ExamplePayables,
    },
    TestingOnlySigning
}

fn examine_request_and_get_txs_verified_on_chain<F>(
    proxy_port: u16,
    blockchain_interface_factory: F,
    real_blockchain_endpoint_url: &str,
    consuming_wallet_secret_key: &[u8],
    pending_transaction_nonce: U256,
    transaction_fee_per_unit_major: u64,
    example_payables: ExamplePayables,
) where
    F: Fn(&str) -> Box<dyn BlockchainInterface>,
{
    let (results_tx, results_rx) = unbounded();
    let _join_handle = start_up_proxy_server(proxy_port, real_blockchain_endpoint_url.to_string(), results_tx);
    let key_provider =
        Bip32EncryptionKeyProvider::from_raw_secret(consuming_wallet_secret_key).unwrap();
    let consuming_wallet = Wallet::from(key_provider);
    let blockchain_agent = BlockchainAgentMock::default()
        .agreed_fee_per_computation_unit_result(transaction_fee_per_unit_major)
        .pending_transaction_id_result(pending_transaction_nonce)
        .consuming_wallet_result(consuming_wallet);
    let _system = System::new("test");
    let recipient = Recorder::new().start().recipient();
    let payables = Vec::<PayableAccount>::from(example_payables);
    let proxy_address = format!("http://{}:{}", localhost(), proxy_port);
    let blockchain_interface = blockchain_interface_factory(&proxy_address);

    let result = blockchain_interface.send_batch_of_payables(
        Box::new(blockchain_agent),
        &recipient,
        &payables,
    );

    // Transaction request
    display_intercepted_comm(results_rx.clone());

    verify_transactions(
        blockchain_interface_factory,
        results_rx,
        real_blockchain_endpoint_url,
        result.unwrap(),
    )
}

fn display_intercepted_comm(results_rx: Receiver<InterceptedCommunication>) {
    let payment_comm = results_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        eprintln!(
            "\
    Request: \n\n{}\n\n\
    Response: \n\n{}\n\n",
            payment_comm.request,
            payment_comm.response
        );
}

fn verify_transactions<F>(
    blockchain_interface_factory: F,
    results_rx: Receiver<InterceptedCommunication>,
    real_blockchain_endpoint_url: &str,
    payment_results: Vec<ProcessedPayableFallible>,
) where
    F: Fn(&str) -> Box<dyn BlockchainInterface>,
{
    let transaction_hashes = match &payment_results[..] {
        [Ok(pending_payable_a), Ok(pending_payable_b)] => {
            vec![pending_payable_a.hash, pending_payable_b.hash]
        }
        _ => panic!(
            "Expected two successful transactions but got: {:?}",
            payment_results
        ),
    };

    let blockchain_interface = blockchain_interface_factory(real_blockchain_endpoint_url);
    let expected_confirmation_format = vec![Some(U64::from(1)), Some(U64::from(1))];

    let start = SystemTime::now();
    loop {
        let checked = transaction_hashes
            .iter()
            .map(|hash| {
                blockchain_interface
                    .get_transaction_receipt(*hash)
                    .unwrap()
                    .unwrap()
                    .status
            })
            .collect::<Vec<_>>();
        if checked == expected_confirmation_format {
            break;
        } else if SystemTime::now().duration_since(start).unwrap() > Duration::from_secs(10) {
            panic!("Something went wrong. Txs were never confirmed");
        } else {
            thread::sleep(Duration::from_secs(1))
        }
    }
}

struct InterceptedCommunication{
    request: String,
    response: String
}

struct ProxyServer {
    listener: TcpListener,
    blockchain_service_url: String,
    results_sender: Sender<InterceptedCommunication>,
    task_pool: Vec<JoinHandle<Option<InterceptedCommunication>>>,
}

impl ProxyServer {
    fn new(port: u16, blockchain_service_url: String, results_sender: Sender<InterceptedCommunication>) -> Self {
        let socket = SocketAddr::new(localhost(), port);
        let listener = TcpListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            listener,
            blockchain_service_url,
            results_sender,
            task_pool: Vec::new()
        }
    }
    fn check_finished_task(&mut self) -> Vec<InterceptedCommunication> {
        let mut unfinished_tasks = Vec::new();
        let mut finished_tasks= Vec::new();
        for i in 0..self.task_pool.len(){
            let task = self.task_pool.remove(0);
            if !task.is_finished() {
                unfinished_tasks.push(task)
            } else {
                match task.join().unwrap(){
                    Some(int_comm) => finished_tasks.push(int_comm),
                    None => ()
                }
            }
        }
        self.task_pool = unfinished_tasks;
        finished_tasks
    }
    fn start_task_if_asked(&self) -> Option<TaskDoer> {
        match self.listener.accept(){
            Err(e) if e.kind() == ErrorKind::WouldBlock && e.kind() == ErrorKind::TimedOut => {
                None
            }
            Err(e) => {eprintln!("Listener panicked: {:?}", e); None},
            Ok((inner_conn, peer_adr) ) => {
                assert_eq!(peer_adr.ip(), localhost());
                Some(
                    TaskDoer {
                        stream: inner_conn,
                        blockchain_endpoint_url: self.blockchain_service_url.clone(),
                    }
                )
            }
        }
    }

    fn server_loop(&mut self){
        loop {
            self.check_finished_task().into_iter().for_each(|int_comm|self.results_sender.send(int_comm).unwrap());
            if let Some(mut task_doer) = self.start_task_if_asked(){
                let task_thread_handle = thread::spawn(move || {
                    let mut inner_conn_buffer = [0; 1256];
                    loop {
                        match task_doer.stream.read(&mut inner_conn_buffer) {
                            Ok(0) => break None,
                            Ok(_) => break task_doer.capture_and_forward_communication(&inner_conn_buffer),
                            Err(e) => panic!("Reading request failed: {}", e),
                        };
                    }
                });
                self
                    .task_pool
                    .push(task_thread_handle);
            } else {
                thread::sleep(Duration::from_millis(100))
            }
        }
    }
}

struct TaskDoer {
    stream: TcpStream,
    blockchain_endpoint_url: String,
}

impl TaskDoer {
    fn capture_and_forward_communication(&mut self, request: &[u8]) -> Option<InterceptedCommunication> {
        let mut outer_conn_buffer = [0; 1256];
        let url = Url::from_str(&self.blockchain_endpoint_url).unwrap();
        let (corrected_request, human_readable_request, domain) =
            Self::correct_http_header(request, &url);
        let tls_connector = TlsConnector::new().unwrap();
        let outer_conn = TcpStream::connect(&url).unwrap();
        let mut tls_stream = tls_connector.connect(&domain, outer_conn).unwrap();
        let bytes = tls_stream.write(&corrected_request).unwrap();
        assert_eq!(bytes, corrected_request.len());

        let start = SystemTime::now();
        loop {
            if SystemTime::now().duration_since(start).unwrap() > Duration::from_millis(1000) {
                panic!("Waiting for response too long")
            }

            match tls_stream.read(&mut outer_conn_buffer) {
                Ok(0) => (),
                Ok(_) => break,
                Err(e) => {
                    panic!("Waiting for blockchain service response failed: {}", e)
                }
            }

            thread::sleep(Duration::from_millis(100))
        }

        let response_len = outer_conn_buffer.len();
        let human_readable_response =  String::from_utf8_lossy(&outer_conn_buffer).to_string();
        let bytes = self.stream.write(&outer_conn_buffer).unwrap();
        assert_eq!(bytes, response_len);
        let results = InterceptedCommunication{
            request: human_readable_request,
            response: human_readable_response
        };
        Some(results)
    }

    fn correct_http_header(
        request: &[u8],
        blockchain_endpoint_url: &Url,
    ) -> (Vec<u8>, String, String) {
        let request = String::from_utf8_lossy(request).to_string();
        if blockchain_endpoint_url.query_pairs().count() > 0 {
            panic!("Cannot handle url with queries")
        };
        let regex = Regex::new(r#"^https://(.*\.com)(.*)"#).unwrap();
        let captures = regex
            .captures(blockchain_endpoint_url.as_str())
            .expect("No sources specified");
        let host = captures.get(1).unwrap().as_str();
        let path = captures.get(2).unwrap().as_str();
        let request = Regex::new("POST / HTTP/1.1")
            .unwrap()
            .replace(&request, &format!("POST {} HTTP/1.1", path))
            .to_string();
        let request = Regex::new(r#"host:\s*.*"#)
            .unwrap()
            .replace(&request, &format!("host: {}", host))
            .to_string();
        (request.as_bytes().to_vec(), request, host.to_string())
    }
}

fn start_up_proxy_server(proxy_port: u16, blockchain_endpoint_url: String, results_sender: Sender<InterceptedCommunication>) -> JoinHandle<()> {
    let server_thread_join_handle = thread::spawn(move || {
        let mut server = ProxyServer::new(proxy_port, blockchain_endpoint_url, results_sender);
        server.server_loop()}
        );
    let deadline = Instant::now().add(Duration::from_secs(5));
    loop {
        thread::sleep(Duration::from_millis(10));
        match TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), proxy_port)) {
            Ok(_) => break,
            Err(e) => eprintln!("No: {:?}", e),
        }
        if Instant::now().gt(&deadline) {
            panic!("TestServer still not started after 5sec");
        }
    }
    server_thread_join_handle
}

struct ExamplePayables {
    a: ExamplePayable,
    b: ExamplePayable,
}

struct ExamplePayable {
    wallet: Wallet,
    balance: u128,
}

impl ExamplePayables {
    fn new(a: ExamplePayable, b: ExamplePayable) -> Self {
        Self { a, b }
    }
}

impl From<ExamplePayables> for Vec<PayableAccount> {
    fn from(exp: ExamplePayables) -> Self {
        vec![exp.a, exp.b]
            .into_iter()
            .map(|inputs| PayableAccount {
                wallet: inputs.wallet,
                balance_wei: inputs.balance,
                last_paid_timestamp: SystemTime::now(),
                pending_payable_opt: None,
            })
            .collect()
    }
}

#[test]
fn fetch_test_assertion_data() {
    let proxy_port = find_free_port();
    let blockchain_interface_factory = |url: &str| -> Box<dyn BlockchainInterface> {
        let (event_loop, http) = Http::new(url).unwrap();
        Box::new(BlockchainInterfaceWeb3::new(
            http,
            event_loop,
            Chain::PolyAmoy,
        ))
    };
    let extended_cw_private_key =
        decode_hex("97923d8fd8de4a00f912bfb77ef483141dec551bd73ea59343ef5c4aac965d04").unwrap();
    let pending_transaction_nonce = U256::from(23);
    let transaction_fee_per_unit = 50;
    let example_payables = ExamplePayables::new(
        ExamplePayable {
            wallet: Wallet::from_str("0x7788df76BBd9a0C7c3e5bf0f77bb28C60a167a7b").unwrap(),
            balance: 11111,
        },
        ExamplePayable {
            wallet: Wallet::from_str("0xFBD6939f34307033368EAA6018022EF5f29B8A59").unwrap(),
            balance: 22222,
        },
    );
    let blockchain_service_endpoint =
        "https://polygon-mumbai.g.alchemy.com/v2/wFOdk2UWjB8SqeZvzsiwmYX3iBEOq3UC"; //TODO replace with new endpoint from Kauri

    examine_request_and_get_txs_verified_on_chain(
        proxy_port,
        blockchain_interface_factory,
        blockchain_service_endpoint,
        &extended_cw_private_key,
        pending_transaction_nonce,
        transaction_fee_per_unit,
        example_payables,
    );
}
