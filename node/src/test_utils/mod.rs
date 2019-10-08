// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

#[macro_use]
pub mod channel_wrapper_mocks;
pub mod config_dao_mock;
pub mod data_hunk;
pub mod data_hunk_framer;
pub mod environment_guard;
pub mod little_tcp_server;
pub mod logging;
pub mod persistent_configuration_mock;
pub mod recorder;
pub mod stream_connector_mock;
pub mod tcp_wrapper_mocks;
pub mod tokio_wrapper_mocks;

use crate::blockchain::bip32::Bip32ECKeyPair;
use crate::blockchain::blockchain_interface::contract_address;
use crate::blockchain::payer::Payer;
use crate::persistent_configuration::HTTP_PORT;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::hopper::MessageType;
use crate::sub_lib::main_tools::StdStreams;
use crate::sub_lib::neighborhood::ExpectedService;
use crate::sub_lib::neighborhood::ExpectedServices;
use crate::sub_lib::neighborhood::RatePack;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::proxy_client::{ClientResponsePayload, DnsResolveFailure};
use crate::sub_lib::proxy_server::{ClientRequestPayload, ProxyProtocol};
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::utils::localhost;
use crate::sub_lib::wallet::Wallet;
use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
use ethsign_crypto::Keccak256;
use lazy_static::lazy_static;
use regex::Regex;
use rustc_hex::ToHex;
use std::cmp::min;
use std::collections::btree_set::BTreeSet;
use std::collections::HashSet;
use std::convert::From;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::Read;
use std::io::Write;
use std::io::{Error, ErrorKind};
use std::iter::repeat;
use std::net::{Shutdown, TcpStream};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::str::from_utf8;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::{fs, io};

pub const DEFAULT_CHAIN_ID: u8 = 3u8; //For testing only

lazy_static! {
    static ref CRYPT_DE_NULL: CryptDENull = CryptDENull::new(DEFAULT_CHAIN_ID);
}

pub fn cryptde() -> &'static CryptDENull {
    &CRYPT_DE_NULL
}

#[derive(Default)]
pub struct ByteArrayWriter {
    pub byte_array: Vec<u8>,
    pub next_error: Option<Error>,
}

impl ByteArrayWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_bytes(&self) -> &[u8] {
        self.byte_array.as_slice()
    }
    pub fn get_string(&self) -> String {
        String::from(from_utf8(self.byte_array.as_slice()).unwrap())
    }

    pub fn reject_next_write(&mut self, error: Error) {
        self.next_error = Some(error);
    }
}

impl Write for ByteArrayWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next_error_opt = self.next_error.take();
        match next_error_opt {
            None => {
                for byte in buf {
                    self.byte_array.push(*byte)
                }
                Ok(buf.len())
            }
            Some(next_error) => Err(next_error),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct ByteArrayReader {
    byte_array: Vec<u8>,
    position: usize,
}

impl ByteArrayReader {
    pub fn new(byte_array: &[u8]) -> ByteArrayReader {
        ByteArrayReader {
            byte_array: byte_array.to_vec(),
            position: 0,
        }
    }
}

impl Read for ByteArrayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let to_copy = min(buf.len(), self.byte_array.len() - self.position);
        for idx in 0..to_copy {
            buf[idx] = self.byte_array[self.position + idx]
        }
        self.position += to_copy;
        Ok(to_copy)
    }
}

pub struct FakeStreamHolder {
    pub stdin: ByteArrayReader,
    pub stdout: ByteArrayWriter,
    pub stderr: ByteArrayWriter,
}

impl Default for FakeStreamHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeStreamHolder {
    pub fn new() -> FakeStreamHolder {
        FakeStreamHolder {
            stdin: ByteArrayReader::new(&[0; 0]),
            stdout: ByteArrayWriter::new(),
            stderr: ByteArrayWriter::new(),
        }
    }

    pub fn streams(&mut self) -> StdStreams<'_> {
        StdStreams {
            stdin: &mut self.stdin,
            stdout: &mut self.stdout,
            stderr: &mut self.stderr,
        }
    }
}

pub struct ArgsBuilder {
    args: Vec<String>,
}

impl Into<Vec<String>> for ArgsBuilder {
    fn into(self) -> Vec<String> {
        self.args
    }
}

impl Default for ArgsBuilder {
    fn default() -> Self {
        ArgsBuilder::new()
    }
}

impl ArgsBuilder {
    pub fn new() -> ArgsBuilder {
        ArgsBuilder {
            args: vec!["command".to_string()],
        }
    }

    pub fn opt(mut self, option: &str) -> ArgsBuilder {
        self.args.push(option.to_string());
        self
    }

    pub fn param(self, option: &str, value: &str) -> ArgsBuilder {
        self.opt(option).opt(value)
    }
}

pub fn assert_ends_with(string: &str, suffix: &str) {
    assert_eq!(
        string.ends_with(suffix),
        true,
        "'{}' did not end with '{}'",
        string,
        suffix
    );
}

pub fn assert_matches(string: &str, regex: &str) {
    let validator = Regex::new(regex).unwrap();
    assert_eq!(
        validator.is_match(string),
        true,
        "'{}' was not matched by '{}'",
        string,
        regex
    );
}

pub fn to_millis(dur: &Duration) -> u64 {
    (dur.as_secs() * 1000) + (u64::from(dur.subsec_nanos()) / 1_000_000)
}

pub fn signal() -> (Signaler, Waiter) {
    let (tx, rx) = mpsc::channel();
    (Signaler { tx }, Waiter { rx })
}

pub struct Signaler {
    tx: Sender<()>,
}

impl Signaler {
    pub fn signal(&self) {
        self.tx.send(()).unwrap();
    }
}

pub struct Waiter {
    rx: Receiver<()>,
}

impl Waiter {
    pub fn wait(&self) {
        let _ = self.rx.recv();
    }
}

pub fn make_meaningless_stream_key() -> StreamKey {
    StreamKey::new(
        PublicKey::new(&[]),
        SocketAddr::from_str("4.3.2.1:8765").unwrap(),
    )
}

pub fn make_meaningless_message_type() -> MessageType {
    DnsResolveFailure::new(make_meaningless_stream_key()).into()
}

pub fn make_meaningless_route() -> Route {
    Route::one_way(
        RouteSegment::new(
            vec![
                &PublicKey::new(&b"ooga"[..]),
                &PublicKey::new(&b"booga"[..]),
            ],
            Component::ProxyClient,
        ),
        cryptde(),
        Some(make_paying_wallet(b"irrelevant")),
        Some(contract_address(DEFAULT_CHAIN_ID)),
    )
    .unwrap()
}

pub fn make_meaningless_public_key() -> PublicKey {
    PublicKey::new(&make_garbage_data(8))
}

pub fn make_meaningless_wallet_private_key() -> PlainData {
    PlainData::from(
        repeat(vec![0xABu8, 0xCDu8])
            .take(16)
            .flat_map(|x| x)
            .collect::<Vec<u8>>(),
    )
}

pub fn make_default_persistent_configuration() -> PersistentConfigurationMock {
    PersistentConfigurationMock::new()
        .earning_wallet_from_address_result(None)
        .consuming_wallet_derivation_path_result(None)
        .consuming_wallet_public_key_result(None)
        .encrypted_mnemonic_seed_result(None)
}

pub fn route_to_proxy_client(key: &PublicKey, cryptde: &dyn CryptDE) -> Route {
    shift_one_hop(zero_hop_route_response(key, cryptde).route, cryptde)
}

pub fn route_from_proxy_client(key: &PublicKey, cryptde: &dyn CryptDE) -> Route {
    // Happens to be the same
    route_to_proxy_client(key, cryptde)
}

pub fn route_to_proxy_server(key: &PublicKey, cryptde: &dyn CryptDE) -> Route {
    shift_one_hop(route_from_proxy_client(key, cryptde), cryptde)
}

pub fn zero_hop_route_response(
    public_key: &PublicKey,
    cryptde: &dyn CryptDE,
) -> RouteQueryResponse {
    RouteQueryResponse {
        route: Route::round_trip(
            RouteSegment::new(vec![public_key, public_key], Component::ProxyClient),
            RouteSegment::new(vec![public_key, public_key], Component::ProxyServer),
            cryptde,
            None,
            0,
            None,
        )
        .unwrap(),
        expected_services: ExpectedServices::RoundTrip(
            vec![ExpectedService::Nothing, ExpectedService::Nothing],
            vec![ExpectedService::Nothing, ExpectedService::Nothing],
            0,
        ),
    }
}

fn shift_one_hop(mut route: Route, cryptde: &dyn CryptDE) -> Route {
    route.shift(cryptde).unwrap();
    route
}

pub fn encrypt_return_route_id(return_route_id: u32, cryptde: &dyn CryptDE) -> CryptData {
    let return_route_id_ser = serde_cbor::ser::to_vec(&return_route_id).unwrap();
    cryptde
        .encode(&cryptde.public_key(), &PlainData::from(return_route_id_ser))
        .unwrap()
}

pub fn make_garbage_data(bytes: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        data.push(0);
    }
    data
}

pub fn make_request_payload(bytes: usize, cryptde: &dyn CryptDE) -> ClientRequestPayload {
    ClientRequestPayload {
        version: ClientRequestPayload::version(),
        stream_key: StreamKey::new(
            cryptde.public_key().clone(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket::new(make_garbage_data(bytes), 0, true),
        target_hostname: Some("example.com".to_string()),
        target_port: HTTP_PORT,
        protocol: ProxyProtocol::HTTP,
        originator_public_key: cryptde.public_key().clone(),
    }
}

pub fn make_response_payload(bytes: usize, cryptde: &dyn CryptDE) -> ClientResponsePayload {
    ClientResponsePayload {
        version: ClientResponsePayload::version(),
        stream_key: StreamKey::new(
            cryptde.public_key().clone(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket {
            data: make_garbage_data(bytes),
            sequence_number: 0,
            last_data: false,
        },
    }
}

pub fn rate_pack_routing_byte(base_rate: u64) -> u64 {
    base_rate + 1
}
pub fn rate_pack_routing(base_rate: u64) -> u64 {
    base_rate + 2
}
pub fn rate_pack_exit_byte(base_rate: u64) -> u64 {
    base_rate + 3
}
pub fn rate_pack_exit(base_rate: u64) -> u64 {
    base_rate + 4
}

pub fn rate_pack(base_rate: u64) -> RatePack {
    RatePack {
        routing_byte_rate: rate_pack_routing_byte(base_rate),
        routing_service_rate: rate_pack_routing(base_rate),
        exit_byte_rate: rate_pack_exit_byte(base_rate),
        exit_service_rate: rate_pack_exit(base_rate),
    }
}

const FIND_FREE_PORT_LOWEST: u16 = 32768;
const FIND_FREE_PORT_HIGHEST: u16 = 65535;

lazy_static! {
    static ref FIND_FREE_PORT_NEXT: Arc<Mutex<u16>> = Arc::new(Mutex::new(FIND_FREE_PORT_LOWEST));
}

fn next_port(port: u16) -> u16 {
    match port {
        p if p < FIND_FREE_PORT_HIGHEST => p + 1,
        _ => FIND_FREE_PORT_LOWEST,
    }
}

pub fn find_free_port() -> u16 {
    let mut candidate = FIND_FREE_PORT_NEXT.lock().unwrap();
    loop {
        match TcpListener::bind(SocketAddr::new(localhost(), *candidate)) {
            Err(ref e) if e.kind() == ErrorKind::AddrInUse => *candidate = next_port(*candidate),
            Err(e) => panic!("Couldn't find free port: {:?}", e),
            Ok(_listener) => {
                let result = *candidate;
                *candidate = next_port(*candidate);
                return result;
            }
        }
    }
}

pub fn await_messages<T>(expected_message_count: usize, messages_arc_mutex: &Arc<Mutex<Vec<T>>>) {
    let local_arc_mutex = messages_arc_mutex.clone();
    let limit = 1000u64;
    let mut prev_len: usize = 0;
    let begin = Instant::now();
    loop {
        let cur_len = {
            local_arc_mutex
                .lock()
                .expect("await_messages helper function is poisoned")
                .len()
        };
        if cur_len != prev_len {
            println!("message collector has received {} messages", cur_len)
        }
        let latency_so_far = to_millis(&Instant::now().duration_since(begin));
        if latency_so_far > limit {
            panic!(
                "After {}ms, message collector has received only {} messages, not {}",
                limit, cur_len, expected_message_count
            );
        }
        prev_len = cur_len;
        if cur_len >= expected_message_count {
            return;
        }
        thread::sleep(Duration::from_millis(50))
    }
}

pub fn wait_for<F>(interval_ms: Option<u64>, limit_ms: Option<u64>, mut f: F)
where
    F: FnMut() -> bool,
{
    let real_interval_ms = interval_ms.unwrap_or(250);
    let real_limit_ms = limit_ms.unwrap_or(1000);
    let time_limit = Instant::now() + Duration::from_millis(real_limit_ms);
    while !f() {
        assert_eq!(
            Instant::now() < time_limit,
            true,
            "Timeout: waited for more than {}ms",
            real_limit_ms
        );
        thread::sleep(Duration::from_millis(real_interval_ms));
    }
}

pub fn assert_contains<T>(haystack: &Vec<T>, needle: &T)
where
    T: Debug + PartialEq,
{
    assert_eq!(
        haystack.contains(needle),
        true,
        "\n{:?}\ndoes not contain\n{:?}",
        haystack,
        needle
    );
}

pub fn assert_string_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "\n\"{}\"\ndoes not contain\n{}",
        haystack,
        needle
    );
}

pub fn vec_to_set<T>(vec: Vec<T>) -> HashSet<T>
where
    T: Eq + Hash,
{
    let set: HashSet<T> = vec.into_iter().collect();
    set
}

pub fn vec_to_btset<T>(vec: Vec<T>) -> BTreeSet<T>
where
    T: Eq + Hash + Ord,
{
    let set: BTreeSet<T> = vec.into_iter().collect();
    set
}

pub const BASE_TEST_DIR: &str = "generated/test";

pub fn node_home_directory(module: &str, name: &str) -> PathBuf {
    let home_dir_string = format!("{}/{}/{}/home", BASE_TEST_DIR, module, name);
    PathBuf::from(home_dir_string.as_str())
}

pub fn ensure_node_home_directory_does_not_exist(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    home_dir
}

pub fn ensure_node_home_directory_exists(module: &str, name: &str) -> PathBuf {
    let home_dir = node_home_directory(module, name);
    let _ = fs::remove_dir_all(&home_dir);
    let _ = fs::create_dir_all(&home_dir);
    home_dir
}

pub fn read_until_timeout(stream: &mut dyn Read) -> Vec<u8> {
    let mut response: Vec<u8> = vec![];
    let mut buf = [0u8; 16384];
    let mut last_data_at = Instant::now();
    loop {
        match stream.read(&mut buf) {
            Err(ref e)
                if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
            {
                thread::sleep(Duration::from_millis(1000));
            }
            Err(ref e) if (e.kind() == ErrorKind::ConnectionReset) && !response.is_empty() => break,
            Err(e) => panic!("Read error: {}", e),
            Ok(len) => {
                response.extend(&buf[..len]);
                last_data_at = Instant::now()
            }
        }
        let now = Instant::now();
        if now.duration_since(last_data_at).subsec_millis() > 500 {
            break;
        }
    }
    response
}

pub fn handle_connection_error(stream: TcpStream) {
    let _ = stream.shutdown(Shutdown::Both).is_ok();
    thread::sleep(Duration::from_millis(5000));
}

pub fn dummy_address_to_hex(dummy_address: &str) -> String {
    let s = if dummy_address.len() > 20 {
        &dummy_address[..20]
    } else {
        dummy_address
    };

    let fragment = String::from(s).as_bytes().to_hex::<String>();

    format!("0x{}{}", "0".repeat(40 - fragment.len()), fragment)
}

pub fn make_payer(secret: &[u8], public_key: &PublicKey) -> Payer {
    let wallet = make_paying_wallet(secret);
    wallet.as_payer(public_key, &contract_address(DEFAULT_CHAIN_ID))
}

pub fn make_paying_wallet(secret: &[u8]) -> Wallet {
    let digest = secret.keccak256();
    Wallet::from(
        Bip32ECKeyPair::from_raw_secret(&digest).expect("Invalid Secret for Bip32ECKeyPair"),
    )
}

pub fn make_wallet(address: &str) -> Wallet {
    Wallet::from_str(&dummy_address_to_hex(address)).unwrap()
}

pub fn assert_eq_debug<T: Debug>(a: T, b: T) {
    let a_str = format!("{:?}", a);
    let b_str = format!("{:?}", b);
    assert_eq!(a_str, b_str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::CryptData;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::neighborhood::ExpectedService;
    use std::borrow::BorrowMut;
    use std::iter;
    use std::ops::Deref;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn characterize_zero_hop_route() {
        let cryptde = cryptde();
        let key = cryptde.public_key();

        let subject = zero_hop_route_response(&key, cryptde);

        assert_eq!(
            subject.route.hops,
            vec!(
                LiveHop::new(&key, None, Component::Hopper)
                    .encode(&key, cryptde)
                    .unwrap(),
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, cryptde),
            )
        );
        assert_eq!(
            subject.expected_services,
            ExpectedServices::RoundTrip(
                vec![ExpectedService::Nothing, ExpectedService::Nothing,],
                vec![ExpectedService::Nothing, ExpectedService::Nothing,],
                0
            )
        );
    }

    #[test]
    fn characterize_route_to_proxy_client() {
        let cryptde = cryptde();
        let key = cryptde.public_key();

        let subject = route_to_proxy_client(&key, cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(96).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, cryptde),
                CryptData::new(&garbage_can[..])
            )
        );
    }

    #[test]
    fn characterize_route_from_proxy_client() {
        let cryptde = cryptde();
        let key = cryptde.public_key();

        let subject = route_from_proxy_client(&key, cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(96).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, cryptde),
                CryptData::new(&garbage_can[..])
            )
        );
    }

    #[test]
    fn characterize_route_to_proxy_server() {
        let cryptde = cryptde();
        let key = cryptde.public_key();

        let subject = route_to_proxy_server(&key, cryptde);

        let mut first_garbage_can: Vec<u8> = iter::repeat(0u8).take(96).collect();
        let mut second_garbage_can: Vec<u8> = iter::repeat(0u8).take(96).collect();
        cryptde.random(&mut first_garbage_can[..]);
        cryptde.random(&mut second_garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, cryptde),
                CryptData::new(&first_garbage_can[..]),
                CryptData::new(&second_garbage_can[..]),
            )
        );
    }

    #[test]
    fn signal_imposes_order() {
        for _ in 0..10 {
            let (signaler, waiter) = signal();
            let mut signaler_log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
            let mut waiter_log = signaler_log.clone();
            let check_log = waiter_log.clone();
            let handle = {
                let handle = thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    signaler_log.borrow_mut().lock().unwrap().push("signaler");
                    signaler.signal();
                });
                waiter.wait();
                waiter_log.borrow_mut().lock().unwrap().push("waiter");
                handle
            };
            handle.join().unwrap();
            let mutex_guard = check_log.as_ref().lock().unwrap();
            let log: &Vec<&str> = mutex_guard.deref();
            assert_eq!(log, &vec!("signaler", "waiter"));
        }
    }

    #[test]
    fn if_signaler_disappears_before_wait_then_wait_becomes_noop() {
        let waiter = {
            let (_, waiter) = signal();
            waiter
        };

        waiter.wait();

        // no panic; test passes
    }
}
