// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::any::Any;
use std::io::Read;
use std::io::Write;
use std::io;
use std::io::Error;
use std::cell::RefCell;
use std::cmp::min;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Instant;
use std::time::Duration;
use std::thread;
use log::set_logger;
use log::Log;
use log::Record;
use log::Metadata;
use regex::Regex;
use main_tools::StdStreams;
use logger::LoggerInitializerWrapper;
use dispatcher::DispatcherClient;
use dispatcher::DispatcherError;
use dispatcher::TransmitterHandle;
use dispatcher::PeerClients;
use dispatcher::Endpoint;
use dispatcher::Component;
use node_addr::NodeAddr;
use route::Route;
use neighborhood::Neighborhood;
use neighborhood::NeighborhoodError;
use cryptde::Key;
use cryptde::PlainData;
use utils;
use actix::SyncAddress;
use actix::Actor;
use actix::Context;
use actix::Handler;
use proxy_server::ProxyServerSubs;
use hopper::HopperSubs;
use dispatcher::DispatcherFacadeSubs;
use proxy_client::ProxyClientSubs;
use dispatcher::InboundClientData;
use stream_handler_pool::StreamHandlerPoolSubs;
use stream_handler_pool::AddStreamMsg;
use stream_handler_pool::RemoveStreamMsg;
use stream_handler_pool::TransmitDataMsg;
use actor_messages::PeerActors;
use actor_messages::ExpiredCoresPackageMessage;
use actor_messages::IncipientCoresPackageMessage;
use actor_messages::ResponseMessage;
use actor_messages::BindMessage;
use actor_messages::RequestMessage;
use actor_messages::TemporaryBindMessage;

#[allow(dead_code)]
pub struct ByteArrayWriter {
    pub byte_array: Vec<u8>,
    pub next_error: Option<Error>
}

#[allow(dead_code)]
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

#[allow(dead_code)]
pub struct ByteArrayReader {
    byte_array: Vec<u8>,
    position: usize
}

#[allow(dead_code)]
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
        unsafe { TEST_LOGS_ARC.as_ref().unwrap().lock().unwrap().push(log) }
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
        unsafe { TEST_LOGS_ARC.as_ref().unwrap().lock().unwrap() }
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
        panic! ("{}", msg);
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

#[derive (Clone)]
pub struct LoggerInitializerWrapperMock {}

impl LoggerInitializerWrapper for LoggerInitializerWrapperMock {
    fn init(&mut self) -> bool {
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
}

impl LoggerInitializerWrapperMock {
    pub fn new () -> LoggerInitializerWrapperMock {
        LoggerInitializerWrapperMock {}
    }
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

#[allow (dead_code)]
pub struct DispatcherClientMock {

}

impl DispatcherClient for DispatcherClientMock {
    fn bind(&mut self, _transmitter_handle: Box<TransmitterHandle>, _clients: &PeerClients) {
        unimplemented!()
    }

    fn receive(&mut self, _source: Endpoint, _data: PlainData) {
        unimplemented!()
    }
}

pub struct NeighborhoodMock {
}

impl NeighborhoodMock {
    pub fn new () -> NeighborhoodMock {
        NeighborhoodMock {}
    }
}

impl Neighborhood for NeighborhoodMock {
    fn route_one_way(&mut self, _destination: &Key, _remote_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn route_round_trip(&mut self, _destination: &Key, _remote_recipient: Component, _local_recipient: Component) -> Result<Route, NeighborhoodError> {
        unimplemented!()
    }

    fn public_key_from_ip_address(&self, _ip_addr: &IpAddr) -> Option<Key> {
        unimplemented!()
    }

    fn node_addr_from_public_key(&self, _public_key: &[u8]) -> Option<NodeAddr> {
        unimplemented!()
    }

    fn node_addr_from_ip_address(&self, _ip_addr: &IpAddr) -> Option<NodeAddr> {
        unimplemented!()
    }
}

impl DispatcherClient for NeighborhoodMock {
    fn bind(&mut self, _transmitter_handle: Box<TransmitterHandle>, _clients: &PeerClients) {
        unimplemented!()
    }

    fn receive(&mut self, _source: Endpoint, _data: PlainData) {
        unimplemented!()
    }
}

unsafe impl Send for NeighborhoodMock {}
unsafe impl Sync for NeighborhoodMock {}

pub fn make_peer_clients_with_mocks () -> PeerClients {
    PeerClients {
        neighborhood: Arc::new (Mutex::new (NeighborhoodMock::new ())),
    }
}


pub struct TransmitterHandleMock {
    pub log: Arc<TestLog>,
    pub transmit_to_ip_result: Result<(), DispatcherError>,
    pub transmit_to_socket_addr_result: Result<(), DispatcherError>
}

impl TransmitterHandle for TransmitterHandleMock {
    fn transmit(&self, _to_public_key: &Key, _data: PlainData) -> Result<(), DispatcherError> {
        unimplemented!()
    }

    fn transmit_to_ip(&self, to_ip_addr: IpAddr, data: PlainData) -> Result<(), DispatcherError> {
        self.log.log(format!("transmit_to_ip ({}, {:?})", to_ip_addr, data));
        self.transmit_to_ip_result.clone ()
    }

    fn transmit_to_socket_addr(&self, to_socket_addr: SocketAddr, data: PlainData) -> Result<(), DispatcherError> {
        self.log.log(format!("transmit_to_socket_addr: to_socket_addr: {:?}, data: {:?}",
                                  to_socket_addr, utils::to_string(&data.data)));
        self.transmit_to_socket_addr_result.clone()
    }
}

impl TransmitterHandleMock {
    pub fn new() -> Self {
        TransmitterHandleMock {
            log: Arc::new(TestLog::new()),
            transmit_to_ip_result: Ok (()),
            transmit_to_socket_addr_result: Ok(())
        }
    }
}

pub fn make_proxy_server_subs_from(addr: &SyncAddress<Recorder>) -> ProxyServerSubs {
    ProxyServerSubs {
        bind: addr.subscriber::<BindMessage>(),
        from_dispatcher: addr.subscriber::<RequestMessage>(),
        from_hopper: addr.subscriber::<ExpiredCoresPackageMessage>(),
    }
}

pub fn make_dispatcher_subs_from(addr: &SyncAddress<Recorder>) -> DispatcherFacadeSubs {
    DispatcherFacadeSubs{
        ibcd_sub: addr.subscriber::<InboundClientData>(),
        bind: addr.subscriber::<BindMessage>(),
        from_proxy_server: addr.subscriber::<ResponseMessage>(),
        transmitter_bind: addr.subscriber::<TemporaryBindMessage>(),
    }
}

pub fn make_hopper_subs_from(addr: &SyncAddress<Recorder>) -> HopperSubs {
    HopperSubs {
        bind: addr.subscriber::<BindMessage>(),
        from_hopper_client: addr.subscriber::<IncipientCoresPackageMessage>(),
    }
}

pub fn make_stream_handler_pool_subs_from(addr: &SyncAddress<Recorder>) -> StreamHandlerPoolSubs {
    StreamHandlerPoolSubs {
        add_sub: addr.subscriber::<AddStreamMsg>(),
        transmit_sub: addr.subscriber::<TransmitDataMsg>(),
        remove_sub: addr.subscriber::<RemoveStreamMsg>(),
        bind: addr.subscriber::<BindMessage>(),
    }
}

pub fn make_proxy_client_subs_from(addr: &SyncAddress<Recorder>) -> ProxyClientSubs {
    ProxyClientSubs {
        bind: addr.subscriber::<BindMessage>(),
        from_hopper: addr.subscriber::<ExpiredCoresPackageMessage>(),
    }
}

// This must be called after System.new and before System.run
pub fn make_peer_actors_from(proxy_server: Option<Recorder>, dispatcher: Option<Recorder>, hopper: Option<Recorder>, stream_handler_pool: Option<Recorder>, proxy_client: Option<Recorder>) -> PeerActors {
    let proxy_server = match proxy_server {
        Some(proxy_server) => proxy_server,
        None => Recorder::new()
    };

    let dispatcher = match dispatcher {
        Some(dispatcher) => dispatcher,
        None => Recorder::new()
    };

    let hopper = match hopper {
        Some(hopper) => hopper,
        None => Recorder::new()
    };

    let stream_handler_pool = match stream_handler_pool {
        Some(stream_handler_pool) => stream_handler_pool,
        None => Recorder::new()
    };

    let proxy_client = match proxy_client {
        Some(proxy_client) => proxy_client,
        None => Recorder::new()
    };

    make_peer_actors_from_recorders(proxy_server, dispatcher, hopper, stream_handler_pool, proxy_client)
}

// This must be called after System.new and before System.run
pub fn make_peer_actors() -> PeerActors {
    make_peer_actors_from_recorders(Recorder::new(), Recorder::new(), Recorder::new(), Recorder::new(), Recorder::new())
}

fn make_peer_actors_from_recorders(proxy_server: Recorder, dispatcher: Recorder, hopper: Recorder, stream_handler_pool: Recorder, proxy_client: Recorder) -> PeerActors {
    let proxy_server_addr = proxy_server.start();
    let dispatcher_addr = dispatcher.start();
    let hopper_addr = hopper.start();
    let stream_handler_pool_addr = stream_handler_pool.start();
    let proxy_client_addr = proxy_client.start();

    PeerActors {
        proxy_server: make_proxy_server_subs_from(&proxy_server_addr),
        dispatcher: make_dispatcher_subs_from(&dispatcher_addr),
        hopper: make_hopper_subs_from(&hopper_addr),
        proxy_client: make_proxy_client_subs_from(&proxy_client_addr),
        stream_handler_pool: make_stream_handler_pool_subs_from(&stream_handler_pool_addr),
    }
}

pub struct Recorder {
    recording: Arc<Mutex<Recording>>,
}

pub struct Recording {
    messages: Vec<Box<Any + Send>>
}

pub struct RecordAwaiter {
    recording: Arc<Mutex<Recording>>
}

impl Actor for Recorder {
    type Context = Context<Self>;
}

impl Handler<RemoveStreamMsg> for Recorder {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: RemoveStreamMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        Ok (())
    }
}

impl Handler<TransmitDataMsg> for Recorder {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: TransmitDataMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        Ok (())
    }
}

impl Handler<BindMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: BindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        ()
    }
}

impl Handler<ResponseMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: ResponseMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        ()
    }
}

impl Handler<RequestMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: RequestMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        ()
    }
}

impl Handler<IncipientCoresPackageMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: IncipientCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        ()
    }
}

impl Handler<TemporaryBindMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: TemporaryBindMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record(msg);
        ()
    }
}

impl Handler<ExpiredCoresPackageMessage> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: ExpiredCoresPackageMessage, _ctx: &mut Self::Context) -> Self::Result {
        self.record(msg);
        ()
    }
}

impl Handler<AddStreamMsg> for Recorder {
    type Result = io::Result<()>;

    fn handle(&mut self, msg: AddStreamMsg, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg);
        Ok (())
    }
}

impl Handler<InboundClientData> for Recorder {
    type Result = ();

    fn handle(&mut self, msg: InboundClientData, _ctx: &mut Self::Context) -> Self::Result {
        self.record (msg)
    }
}

impl Recorder {
    pub fn new () -> Recorder {
        Recorder {
            recording: Arc::new (Mutex::new (Recording {messages: vec! ()})),
        }
    }

    pub fn record<T> (&mut self, item: T) where T: Any + Send {
        let mut recording = self.recording.lock ().unwrap ();
        let messages: &mut Vec<Box<Any + Send>> = &mut recording.messages;
        let item_box = Box::new (item);
        messages.push (item_box);
    }

    pub fn get_recording (&self) -> Arc<Mutex<Recording>> {
        self.recording.clone ()
    }

    pub fn get_awaiter (&self) -> RecordAwaiter {
        RecordAwaiter {
            recording: self.recording.clone ()
        }
    }
}

impl Recording {
    pub fn len(&self) -> usize {
        return self.messages.len ()
    }

    pub fn get_record<T> (&self, index: usize) -> &T where T: Any + Send {
        let item_box = match self.messages.get (index) {
            Some (item_box) => item_box,
            None => panic! ("Only {} messages recorded: no message #{} in the recording", self.messages.len (), index)
        };
        let item_opt = item_box.downcast_ref::<T> ();
        let item_success_ref = item_opt.unwrap ();
        item_success_ref
    }
}

impl RecordAwaiter {
    pub fn await_message_count (&self, count: usize) {
        let limit = 1000u64;
        let mut prev_len: usize = 0;
        let begin = Instant::now ();
        loop {
            let cur_len = {
                self.recording.lock ().unwrap ().len ()
            };
            if cur_len != prev_len {
                println! ("Recorder has received {} messages", cur_len)
            }
            let latency_so_far = to_millis (&Instant::now ().duration_since(begin));
            if latency_so_far > limit {
                panic! ("After {}ms, recorder has received only {} messages, not {}",
                    limit, cur_len, count);
            }
            prev_len = cur_len;
            if cur_len >= count {return}
            thread::sleep (Duration::from_millis (10))
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::thread;
    use std::ops::Deref;
    use std::borrow::BorrowMut;
    use actix::System;
    use actix::Address;
    use actix::Arbiter;
    use actix::msgs;
    use actix::ResponseType;

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

    #[derive (Debug, PartialEq)]
    struct FirstMessageType {
        string: String
    }

    impl ResponseType for FirstMessageType {
        type Item = ();
        type Error = ();
    }

    impl Handler<FirstMessageType> for Recorder {
        type Result = ();

        fn handle(&mut self, msg: FirstMessageType, _ctx: &mut Context<Self>) -> () {
            self.record (msg)
        }
    }

    #[derive (Debug, PartialEq)]
    struct SecondMessageType {
        size: usize,
        flag: bool
    }

    impl ResponseType for SecondMessageType {
        type Item = ();
        type Error = ();
    }

    impl Handler<SecondMessageType> for Recorder {
        type Result = ();

        fn handle(&mut self, msg: SecondMessageType, _ctx: &mut Context<Self>) -> () {
            self.record (msg)
        }
    }

    #[test]
    fn recorder_records_different_messages () {
        let system = System::new ("test");
        let recorder = Recorder::new ();
        let recording_arc = recorder.get_recording ();

        let rec_addr: Address<_> = recorder.start ();

        rec_addr.send (FirstMessageType {string: String::from ("String")});
        rec_addr.send (SecondMessageType {size: 42, flag: false});
        Arbiter::system ().send (msgs::SystemExit(0));

        system.run ();

        let recording = recording_arc.lock ().unwrap ();
        assert_eq! (recording.get_record::<FirstMessageType> (0), &FirstMessageType {string: String::from ("String")});
        assert_eq! (recording.get_record::<SecondMessageType> (1), &SecondMessageType {size: 42, flag: false});
        assert_eq! (recording.len(), 2);
    }
}
