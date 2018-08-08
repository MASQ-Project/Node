// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::cell::RefCell;
use std::cmp::min;
use std::io;
use std::io::Error;
use std::io::Read;
use std::io::Write;
use std::str::from_utf8;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use regex::Regex;
use log::Log;
use log::Metadata;
use log::Record;
use log::set_logger;
use sub_lib::cryptde::CryptDE;
use sub_lib::cryptde::Key;
use sub_lib::cryptde_null::CryptDENull;
use sub_lib::dispatcher::Component;
use sub_lib::main_tools::StdStreams;
use sub_lib::route::Route;
use sub_lib::route::RouteSegment;
use std::net::UdpSocket;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;

lazy_static! {
    static ref CRYPT_DE_NULL: CryptDENull = CryptDENull::new ();
}

pub fn cryptde () -> &'static CryptDENull {
    &CRYPT_DE_NULL
}

pub struct ByteArrayWriter {
    pub byte_array: Vec<u8>,
    pub next_error: Option<Error>
}

impl ByteArrayWriter {
    pub fn new () -> ByteArrayWriter {
        let vec = Vec::new ();
        ByteArrayWriter {byte_array: vec, next_error: None}
    }

    pub fn get_bytes (&self) -> &[u8] {
        self.byte_array.as_slice ()
    }
    pub fn get_string (&self) -> String {
        String::from (from_utf8(self.byte_array.as_slice()).unwrap ())
    }

    pub fn reject_next_write (&mut self, error: Error) {
        self.next_error = Some(error);
    }
}

impl Write for ByteArrayWriter {
    fn write (&mut self, buf: &[u8]) -> io::Result<usize> {
        let next_error_opt = self.next_error.take ();
        if next_error_opt.is_none () {
            for byte in buf {
                self.byte_array.push (*byte)
            };
            Ok (buf.len ())
        }
        else {
            Err(next_error_opt.unwrap ())
        }
    }

    fn flush (&mut self) -> io::Result<()> {
        Ok (())
    }
}

pub struct ByteArrayReader {
    byte_array: Vec<u8>,
    position: usize
}

impl ByteArrayReader {
    pub fn new (byte_array: &[u8]) -> ByteArrayReader {
        ByteArrayReader {byte_array: byte_array.to_vec (), position: 0}
    }
}

impl Read for ByteArrayReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let to_copy = min (buf.len (), self.byte_array.len () - self.position);
        for idx in 0..to_copy {
            buf[idx] = self.byte_array[self.position + idx]
        }
        self.position += to_copy;
        Ok (to_copy)
    }
}

pub struct FakeStreamHolder {
    pub stdin: ByteArrayReader,
    pub stdout: ByteArrayWriter,
    pub stderr: ByteArrayWriter
}

impl FakeStreamHolder {
    pub fn new () -> FakeStreamHolder {
        FakeStreamHolder {
            stdin: ByteArrayReader::new (&[0; 0]),
            stdout: ByteArrayWriter::new (),
            stderr: ByteArrayWriter::new ()
        }
    }

    pub fn streams (&mut self) -> StdStreams {
        StdStreams {
            stdin: &mut self.stdin,
            stdout: &mut self.stdout,
            stderr: &mut self.stderr
        }
    }
}

pub fn assert_ends_with (string: &str, suffix: &str) {
    assert_eq! (string.ends_with (suffix), true, "'{}' did not end with '{}'", string, suffix);
}

pub fn assert_matches (string: &str, regex: &str) {
    let validator = Regex::new (regex).unwrap ();
    assert_eq! (validator.is_match (string), true, "'{}' was not matched by '{}'", string, regex);
}

pub fn to_millis (dur: &Duration) -> u64 {
    (dur.as_secs () * 1000) + (dur.subsec_nanos() as u64 / 1000000)
}

pub struct TestLog {
    ref_log: RefCell<Vec<String>>
}

unsafe impl Sync for TestLog {}
unsafe impl Send for TestLog {}

impl TestLog {
    pub fn new () -> TestLog {
        TestLog {ref_log: RefCell::new (vec! ())}
    }

    pub fn log (&self, log: String) {
        self.ref_log.borrow_mut ().push (log);
    }

    pub fn dump (&self) -> Vec<String> {
        self.ref_log.borrow ().clone ()
    }
}

pub fn signal () -> (Signaler, Waiter) {
    let (tx, rx) = mpsc::channel ();
    (Signaler {tx}, Waiter {rx})
}

pub struct Signaler {
    tx: Sender<()>
}

impl Signaler {
    pub fn signal (&self) {
        self.tx.send (()).unwrap ();
    }
}

pub struct Waiter {
    rx: Receiver<()>
}

impl Waiter {
    pub fn wait (&self) {
        match self.rx.recv () {
            Ok (_) => (),
            Err (_) => ()
        }
    }
}

static mut TEST_LOGS_ARC: Option<Arc<Mutex<Vec<String>>>> = None;

pub struct TestLogHandler {}

impl TestLogHandler {
    pub fn new () -> TestLogHandler {
        TestLogHandler {}
    }

    pub fn add_log(&self, log: String) {
        unsafe { TEST_LOGS_ARC.as_ref().unwrap().lock().expect("TestLogHandler is poisoned in add_log").push(log) }
    }

    pub fn exists_log_matching(&self, pattern: &str) -> usize {
        match self.find_first_log_matching (pattern) {
            Some(index) => index,
            None => panic!("No existing logs match '{}':\n{}", pattern, self.list_logs ())
        }
    }

    pub fn await_log_matching (&self, pattern: &str, millis: u64) -> usize {
        let began_at = Instant::now ();
        while to_millis (&began_at.elapsed ()) < millis {
            match self.find_first_log_matching (pattern) {
                Some (index) => return index,
                None => thread::sleep (Duration::from_millis(50))
            }
        }
        panic! ("Waited {}ms for log matching '{}':\n{}", millis, pattern, self.list_logs ());
    }

    pub fn exists_no_log_matching(&self, pattern: &str) {
        match self.logs_match (pattern) {
            Some(index) => panic! ("Log at index {} matches '{}':\n{}", index, pattern, self.get_log_at (index)),
            None => ()
        }
    }

    pub fn exists_log_containing(&self, fragment: &str) -> usize {
        match self.find_first_log_containing (fragment) {
            Some(index) => index,
            None => panic!("No existing logs contain '{}':\n{}", fragment, self.list_logs ())
        }
    }

    pub fn exists_no_log_containing(&self, fragment: &str) {
        match self.logs_contain (fragment) {
            Some(index) => panic! ("Log at index {} contains '{}':\n{}", index, fragment, self.get_log_at (index)),
            None => ()
        }
    }

    pub fn await_log_containing (&self, fragment: &str, millis: u64) -> usize {
        let began_at = Instant::now ();
        while to_millis (&began_at.elapsed ()) < millis {
            match self.find_first_log_containing (fragment) {
                Some (index) => return index,
                None => thread::sleep (Duration::from_millis (50))
            }
        }
        panic! ("Waited {}ms for log containing '{}':\n{}", millis, fragment, self.list_logs ());
    }

    pub fn assert_logs_match_in_order(&self, patterns: Vec<&str>) {
        let indexes: Vec<usize> = patterns.iter ().map (|pattern| {
            self.exists_log_matching(*pattern)
        }).collect ();
        if self.in_order (&indexes) {return}
        self.complain_about_order (&indexes, &patterns)
    }

    pub fn assert_logs_contain_in_order(&self, fragments: Vec<&str>) {
        let indexes: Vec<usize> = fragments.iter ().map (|fragment| {
            self.exists_log_containing(*fragment)
        }).collect ();
        if self.in_order (&indexes) {return}
        self.complain_about_order (&indexes, &fragments)
    }

    pub fn get_log_at (&self, index: usize) -> String {
        self.get_logs ()[index].clone ()
    }

    pub fn logs_initialized(&self) -> bool {
        unsafe { TEST_LOGS_ARC.is_some() }
    }

    pub fn initialize_logs(&self) {
        unsafe { TEST_LOGS_ARC = Some(Arc::new(Mutex::new(vec!()))) }
    }

    fn get_logs(&self) -> MutexGuard<Vec<String>> {
        unsafe { TEST_LOGS_ARC.as_ref().unwrap().lock().expect("TestLogHandler is poisoned in get_logs") }
    }

    fn list_logs(&self) -> String {
        self.get_logs ().join ("\n")
    }

    fn find_first_log_matching (&self, pattern: &str) -> Option<usize> {
        let logs = self.get_logs ();
        let regex = Regex::new (pattern).unwrap ();
        for index in 0..logs.len () {
            if regex.is_match (&logs[index][..]) {return Some (index)}
        }
        None
    }

    fn find_first_log_containing (&self, fragment: &str) -> Option<usize> {
        let logs = self.get_logs ();
        for index in 0..logs.len () {
            if logs[index].contains (fragment) {return Some (index)}
        }
        None
    }

    fn in_order(&self, indexes: &Vec<usize>) -> bool {
        let mut prev_index: usize = 0;
        for index in indexes.clone () {
            if index < prev_index {return false}
            prev_index = index;
        }
        true
    }

    fn complain_about_order (&self, indexes: &Vec<usize>, matchers: &Vec<&str>) {
        let mut msg = String::from ("Logs were found, but not in specified order:\n");
        for index in 0..indexes.len () {
            msg.push_str (&format! ("  {}: '{}'\n", indexes[index], matchers[index])[..])
        }
        panic! ("{}\nGot:\n{}", msg, self.list_logs());
    }

    fn logs_match (&self, pattern: &str) -> Option<usize> {
        let logs = self.get_logs ();
        let regex = Regex::new (pattern).unwrap ();
        for index in 0..logs.len () {
            if regex.is_match (&logs[index][..]) {return Some (index)}
        }
        None
    }

    fn logs_contain (&self, fragment: &str) -> Option<usize> {
        let logs = self.get_logs ();
        for index in 0..logs.len () {
            if logs[index].contains (fragment) {return Some (index)}
        }
        None
    }
}

static TEST_LOGGER: TestLogger = TestLogger {};

pub fn init_test_logging() -> bool {
    let tlh = TestLogHandler::new ();
    let result = if tlh.logs_initialized () {
        true
    }
        else {
            tlh.initialize_logs();
            match set_logger (&TEST_LOGGER) {
                Ok (_) => true,
                Err (_) => false
            }
        };
    result
}

#[derive (Clone)]
pub struct TestLogger {}

impl Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let string = format! ("{}",
                              record.args ()
        );
        TestLogHandler::new ().add_log (string);
    }

    fn flush(&self) {
    }
}

impl TestLogger {
    pub fn new () -> TestLogger {
        TestLogger {}
    }
}

#[derive (Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadMock {
    pub data: Vec<u8>
}

impl PayloadMock {
    pub fn new () -> PayloadMock {
        PayloadMock {
            data: Vec::from ("payload".as_bytes ())
        }
    }
}

pub fn make_meaningless_route () -> Route {
    Route::new (
        vec! (RouteSegment::new (vec! (&Key::new (&b"ooga"[..]), &Key::new (&b"booga"[..])),
                                 Component::ProxyClient)),
        &CryptDENull::new ()
    ).unwrap ()
}

pub fn route_to_proxy_client (key: &Key, cryptde: &CryptDE) -> Route {
    shift_one_hop(zero_hop_route(key, cryptde), cryptde)
}

pub fn route_from_proxy_client (key: &Key, cryptde: &CryptDE) -> Route {
    // Happens to be the same
    route_to_proxy_client (key, cryptde)
}

pub fn route_to_proxy_server (key: &Key, cryptde: &CryptDE) -> Route {
    shift_one_hop(route_from_proxy_client(key, cryptde), cryptde)
}

pub fn zero_hop_route(public_key: &Key, cryptde: &CryptDE) -> Route {
    Route::new(vec! (
        RouteSegment::new(vec! (public_key, public_key), Component::ProxyClient),
        RouteSegment::new(vec! (public_key, public_key), Component::ProxyServer)
    ), cryptde).unwrap()
}

fn shift_one_hop(mut route: Route, cryptde: &CryptDE) -> Route {
    route.shift(&cryptde.private_key (), cryptde);
    route
}

pub fn find_free_port () -> u16 {
    let socket = UdpSocket::bind (SocketAddr::new (IpAddr::V4 (Ipv4Addr::new (127, 0, 0, 1)), 0)).expect ("Not enough free ports");
    socket.local_addr ().expect ("Bind failed").port ()
}

pub fn await_messages<T>(expected_message_count: usize, messages_arc_mutex: &Arc<Mutex<Vec<T>>>) {
    let local_arc_mutex = messages_arc_mutex.clone();
    let limit = 1000u64;
    let mut prev_len: usize = 0;
    let begin = Instant::now ();
    loop {
        let cur_len = {
            local_arc_mutex.lock ().expect ("await_messages helper function is poisoned").len ()
        };
        if cur_len != prev_len {
            println! ("message collector has received {} messages", cur_len)
        }
        let latency_so_far = to_millis (&Instant::now ().duration_since(begin));
        if latency_so_far > limit {
            panic! ("After {}ms, message collector has received only {} messages, not {}",
                    limit, cur_len, expected_message_count);
        }
        prev_len = cur_len;
        if cur_len >= expected_message_count {return}
        thread::sleep (Duration::from_millis (50))
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::borrow::BorrowMut;
    use std::iter;
    use std::ops::Deref;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use sub_lib::cryptde::CryptData;
    use sub_lib::cryptde_null::CryptDENull;
    use sub_lib::hop::Hop;

    #[test]
    fn characterize_zero_hop_route() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = zero_hop_route(&key, &cryptde);

        assert_eq! (subject.hops, vec! (
            Hop::new (&key, Component::Hopper).encode (&key, &cryptde).unwrap (),
            Hop::new (&key, Component::ProxyClient).encode (&key, &cryptde).unwrap (),
            Hop::new (&Key::new(b""), Component::ProxyServer).encode (&key, &cryptde).unwrap (),
        ));
    }

    #[test]
    fn characterize_route_to_proxy_client() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_to_proxy_client(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat (0u8).take (50).collect ();
        cryptde.random (&mut garbage_can[..]);
        assert_eq! (subject.hops, vec! (
            Hop::new (&key, Component::ProxyClient).encode (&key, &cryptde).unwrap (),
            Hop::new (&Key::new(b""), Component::ProxyServer).encode (&key, &cryptde).unwrap (),
            CryptData::new(&garbage_can[..])
        ));
    }

    #[test]
    fn characterize_route_from_proxy_client() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_from_proxy_client(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat (0u8).take (50).collect ();
        cryptde.random (&mut garbage_can[..]);
        assert_eq! (subject.hops, vec! (
            Hop::new (&key, Component::ProxyClient).encode (&key, &cryptde).unwrap (),
            Hop::new (&Key::new(b""), Component::ProxyServer).encode (&key, &cryptde).unwrap (),
            CryptData::new(&garbage_can[..])
        ));
    }

    #[test]
    fn characterize_route_to_proxy_server() {
        let cryptde = CryptDENull::new();
        let key = cryptde.public_key();

        let subject = route_to_proxy_server(&key, &cryptde);

        let mut garbage_can: Vec<u8> = iter::repeat (0u8).take (50).collect ();
        cryptde.random (&mut garbage_can[..]);
        assert_eq! (subject.hops, vec! (
            Hop::new(&Key::new(b""), Component::ProxyServer).encode(&key, &cryptde).unwrap(),
            CryptData::new (&garbage_can[..]),
            CryptData::new (&garbage_can[..]),
        ));
    }

    #[test]
    fn signal_imposes_order () {
        for _ in 0..10 {
            let (signaler, waiter) = signal ();
            let mut signaler_log: Arc<Mutex<Vec<&str>>> = Arc::new (Mutex::new (vec! ()));
            let mut waiter_log = signaler_log.clone ();
            let check_log = waiter_log.clone ();
            let handle = {
                let handle = thread::spawn(move || {
                    thread::sleep(Duration::from_millis (10));
                    signaler_log.borrow_mut().lock().unwrap().push("signaler");
                    signaler.signal();
                });
                waiter.wait ();
                waiter_log.borrow_mut ().lock ().unwrap ().push ("waiter");
                handle
            };
            handle.join ().unwrap ();
            let mutex_guard = check_log.as_ref ().lock ().unwrap ();
            let log: &Vec<&str> = mutex_guard.deref ();
            assert_eq! (log, &vec! ("signaler", "waiter"));
        }
    }

    #[test]
    fn if_signaler_disappears_before_wait_then_wait_becomes_noop () {
        let waiter = {
            let (_, waiter) = signal ();
            waiter
        };

        waiter.wait ();

        // no panic; test passes
    }
}
