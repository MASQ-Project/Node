// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
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
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use regex::Regex;
use std::cmp::min;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::io;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
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

lazy_static! {
    static ref CRYPT_DE_NULL: CryptDENull = CryptDENull::new();
}

pub fn cryptde() -> &'static CryptDENull {
    &CRYPT_DE_NULL
}

pub fn sha1_hash(data: &[u8]) -> String {
    let mut hash = sha1::Sha1::new();
    hash.update(data);
    hash.digest().to_string()
}

pub struct ByteArrayWriter {
    pub byte_array: Vec<u8>,
    pub next_error: Option<Error>,
}

impl ByteArrayWriter {
    pub fn new() -> ByteArrayWriter {
        let vec = Vec::new();
        ByteArrayWriter {
            byte_array: vec,
            next_error: None,
        }
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
        if next_error_opt.is_none() {
            for byte in buf {
                self.byte_array.push(*byte)
            }
            Ok(buf.len())
        } else {
            Err(next_error_opt.unwrap())
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
    (dur.as_secs() * 1000) + (dur.subsec_nanos() as u64 / 1000000)
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
        match self.rx.recv() {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

pub fn make_meaningless_stream_key() -> StreamKey {
    StreamKey::new(
        PublicKey::new(&[]),
        SocketAddr::from_str("4.3.2.1:8765").unwrap(),
    )
}

pub fn make_meaningless_message_type() -> MessageType {
    DnsResolveFailure {
        stream_key: make_meaningless_stream_key(),
    }
    .into()
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
        &CryptDENull::new(),
        Some(Wallet::new("irrelevant")),
    )
    .unwrap()
}

pub fn make_meaningless_public_key() -> PublicKey {
    PublicKey::new(&make_garbage_data(8))
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

pub fn encrypt_return_route_id(return_route_id: u32, cryptde: &CryptDE) -> CryptData {
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

pub fn make_request_payload(bytes: usize, cryptde: &CryptDE) -> ClientRequestPayload {
    ClientRequestPayload {
        stream_key: StreamKey::new(
            cryptde.public_key(),
            SocketAddr::from_str("1.2.3.4:5678").unwrap(),
        ),
        sequenced_packet: SequencedPacket::new(make_garbage_data(bytes), 0, true),
        target_hostname: Some("example.com".to_string()),
        target_port: 80,
        protocol: ProxyProtocol::HTTP,
        originator_public_key: cryptde.public_key(),
    }
}

pub fn make_response_payload(bytes: usize, cryptde: &CryptDE) -> ClientResponsePayload {
    ClientResponsePayload {
        stream_key: StreamKey::new(
            cryptde.public_key(),
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

pub fn find_free_port() -> u16 {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .expect("Not enough free ports");
    socket.local_addr().expect("Bind failed").port()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::CryptData;
    use crate::sub_lib::cryptde_null::CryptDENull;
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
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = zero_hop_route_response(&key, &cryptde);

        assert_eq!(
            subject.route.hops,
            vec!(
                LiveHop::new(&key, None, Component::Hopper)
                    .encode(&key, &cryptde)
                    .unwrap(),
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, &cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, &cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, &cryptde),
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
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_to_proxy_client(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(68).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, &cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, &cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, &cryptde),
                CryptData::new(&garbage_can[..])
            )
        );
    }

    #[test]
    fn characterize_route_from_proxy_client() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_from_proxy_client(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(68).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&key, None, Component::ProxyClient)
                    .encode(&key, &cryptde)
                    .unwrap(),
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, &cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, &cryptde),
                CryptData::new(&garbage_can[..])
            )
        );
    }

    #[test]
    fn characterize_route_to_proxy_server() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_to_proxy_server(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat(0u8).take(68).collect();
        cryptde.random(&mut garbage_can[..]);
        assert_eq!(
            subject.hops,
            vec!(
                LiveHop::new(&PublicKey::new(b""), None, Component::ProxyServer)
                    .encode(&key, &cryptde)
                    .unwrap(),
                encrypt_return_route_id(0, &cryptde),
                CryptData::new(&garbage_can[..]),
                CryptData::new(&garbage_can[..]),
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
