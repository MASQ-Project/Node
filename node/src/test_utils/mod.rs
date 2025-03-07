// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#[macro_use]
pub mod channel_wrapper_mocks;
pub mod automap_mocks;
pub mod data_hunk;
pub mod data_hunk_framer;
pub mod database_utils;
pub mod little_tcp_server;
pub mod logfile_name_guard;
pub mod neighborhood_test_utils;
pub mod persistent_configuration_mock;
pub mod recorder;
pub mod recorder_stop_conditions;
pub mod stream_connector_mock;
pub mod tcp_wrapper_mocks;
pub mod tokio_wrapper_mocks;
use crate::blockchain::bip32::Bip32EncryptionKeyProvider;
use crate::blockchain::payer::Payer;
use crate::bootstrapper::CryptDEPair;
use crate::sub_lib::cryptde::CryptDE;
use crate::sub_lib::cryptde::CryptData;
use crate::sub_lib::cryptde::PlainData;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::cryptde_null::CryptDENull;
use crate::sub_lib::dispatcher::Component;
use crate::sub_lib::hopper::MessageType;
use crate::sub_lib::neighborhood::ExpectedServices;
use crate::sub_lib::neighborhood::RouteQueryResponse;
use crate::sub_lib::neighborhood::{ExpectedService, RatePack};
use crate::sub_lib::proxy_client::{ClientResponsePayload_0v1, DnsResolveFailure_0v1};
use crate::sub_lib::proxy_server::{ClientRequestPayload_0v1, ProxyProtocol};
use crate::sub_lib::route::Route;
use crate::sub_lib::route::RouteSegment;
use crate::sub_lib::sequence_buffer::SequencedPacket;
use crate::sub_lib::stream_key::StreamKey;
use crate::sub_lib::wallet::Wallet;
use crossbeam_channel::{unbounded, Receiver, Sender};
use ethsign_crypto::Keccak256;
use lazy_static::lazy_static;
use masq_lib::constants::HTTP_PORT;
use masq_lib::test_utils::utils::TEST_DEFAULT_CHAIN;
use rand::RngCore;
use regex::Regex;
use rustc_hex::ToHex;
use serde_derive::{Deserialize, Serialize};
use std::collections::btree_set::BTreeSet;
use std::collections::HashSet;
use std::convert::From;
use std::fmt::Debug;
use std::hash::Hash;
use std::io::ErrorKind;
use std::io::Read;
use std::iter::repeat;
use std::net::SocketAddr;
use std::net::{Shutdown, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::unbounded_channel;
use web3::types::{Address, U256};
use futures_util::FutureExt;

lazy_static! {
    static ref MAIN_CRYPTDE_NULL: Box<dyn CryptDE + 'static> =
        Box::new(CryptDENull::new(TEST_DEFAULT_CHAIN));
    static ref ALIAS_CRYPTDE_NULL: Box<dyn CryptDE + 'static> =
        Box::new(CryptDENull::new(TEST_DEFAULT_CHAIN));
}

pub fn main_cryptde() -> &'static dyn CryptDE {
    MAIN_CRYPTDE_NULL.as_ref()
}

pub fn alias_cryptde() -> &'static dyn CryptDE {
    ALIAS_CRYPTDE_NULL.as_ref()
}

pub fn make_cryptde_pair() -> CryptDEPair {
    CryptDEPair {
        main: main_cryptde(),
        alias: alias_cryptde(),
    }
}

pub struct ArgsBuilder {
    args: Vec<String>,
}

impl From<ArgsBuilder> for Vec<String> {
    fn from(builder: ArgsBuilder) -> Self {
        builder.args
    }
}

impl From<&[String]> for ArgsBuilder {
    fn from(args: &[String]) -> Self {
        Self {
            args: args.to_vec(),
        }
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
    assert!(
        string.ends_with(suffix),
        "'{}' did not end with '{}'",
        string,
        suffix
    );
}

pub fn assert_matches(string: &str, regex: &str) {
    let validator = Regex::new(regex).unwrap();
    assert!(
        validator.is_match(string),
        "'{}' was not matched by '{}'",
        string,
        regex
    );
}

pub fn to_millis(dur: &Duration) -> u64 {
    dur.as_millis() as u64
}

pub fn signal() -> (Signaler, Waiter) {
    let (tx, rx) = unbounded();
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
    DnsResolveFailure_0v1::new(make_meaningless_stream_key()).into()
}

pub fn make_one_way_route_to_proxy_client(public_keys: Vec<&PublicKey>) -> Route {
    Route::one_way(
        RouteSegment::new(public_keys, Component::ProxyClient),
        main_cryptde(),
        Some(make_paying_wallet(b"irrelevant")),
        Some(TEST_DEFAULT_CHAIN.rec().contract),
    )
    .unwrap()
}

pub fn make_meaningless_route() -> Route {
    Route::one_way(
        RouteSegment::new(
            vec![
                &make_meaningless_public_key(),
                &make_meaningless_public_key(),
            ],
            Component::ProxyClient,
        ),
        main_cryptde(),
        Some(make_paying_wallet(b"irrelevant")),
        Some(TEST_DEFAULT_CHAIN.rec().contract),
    )
    .unwrap()
}

pub fn make_meaningless_public_key() -> PublicKey {
    PublicKey::new(&make_garbage_data(main_cryptde().public_key().len()))
}

pub fn make_meaningless_wallet_private_key() -> PlainData {
    PlainData::from(
        repeat(vec![0xABu8, 0xCDu8])
            .take(16)
            .flatten()
            .collect::<Vec<u8>>(),
    )
}

// TODO: The three functions below should use only one argument, cryptde
pub fn route_to_proxy_client(main_key: &PublicKey, main_cryptde: &dyn CryptDE) -> Route {
    shift_one_hop(
        zero_hop_route_response(main_key, main_cryptde).route,
        main_cryptde,
    )
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
        .encode(cryptde.public_key(), &PlainData::from(return_route_id_ser))
        .unwrap()
}

pub fn make_garbage_data(bytes: usize) -> Vec<u8> {
    let mut data = vec![0; bytes];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

pub fn make_request_payload(bytes: usize, cryptde: &dyn CryptDE) -> ClientRequestPayload_0v1 {
    ClientRequestPayload_0v1 {
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

pub fn make_response_payload(bytes: usize, cryptde: &dyn CryptDE) -> ClientResponsePayload_0v1 {
    ClientResponsePayload_0v1 {
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

pub fn make_send_error() -> SendError<SequencedPacket> {
    let (tx, rx) = unbounded_channel();
    drop(rx);
    tx.send(SequencedPacket {
        data: vec![],
        sequence_number: 0,
        last_data: false,
    })
    .unwrap_err()
}

pub fn rate_pack_routing_byte(base_rate: u64) -> u64 {
    base_rate + 1
}
pub fn rate_pack_routing(base_rate: u64) -> u64 {
    base_rate + 200
}
pub fn rate_pack_exit_byte(base_rate: u64) -> u64 {
    base_rate + 3
}
pub fn rate_pack_exit(base_rate: u64) -> u64 {
    base_rate + 400
}

pub fn rate_pack(base_rate: u64) -> RatePack {
    RatePack {
        routing_byte_rate: rate_pack_routing_byte(base_rate),
        routing_service_rate: rate_pack_routing(base_rate),
        exit_byte_rate: rate_pack_exit_byte(base_rate),
        exit_service_rate: rate_pack_exit(base_rate),
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
    let _ = await_value(Some((real_interval_ms, real_limit_ms)), || {
        if f() {
            Ok(true)
        } else {
            Err("false".to_string())
        }
    })
    .unwrap();
}

//must stay without cfg(test) -- used in another crate
pub fn await_value<F, T, E>(
    interval_and_limit_ms: Option<(u64, u64)>,
    mut f: F,
) -> Result<T, String>
where
    E: Debug,
    F: FnMut() -> Result<T, E>,
{
    let (interval_ms, limit_ms) = interval_and_limit_ms.unwrap_or((250, 1000));
    let interval_dur = Duration::from_millis(interval_ms);
    let deadline = Instant::now() + Duration::from_millis(limit_ms);
    let mut delay = 0;
    let mut log = "".to_string();
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "\n{}\nTimeout: waited for more than {}ms",
                log, limit_ms
            ));
        }
        match f() {
            Ok(t) => return Ok(t),
            Err(e) => {
                log.extend(format!("  +{}: {:?}\n", delay, e).chars());
                delay += interval_ms;
                thread::sleep(interval_dur);
            }
        }
    }
}

pub fn assert_contains<T>(haystack: &[T], needle: &T)
where
    T: Debug + PartialEq,
{
    assert!(
        haystack.contains(needle),
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

//must stay without cfg(test) -- used in another crate
pub fn read_until_timeout(stream: &mut dyn Read) -> Vec<u8> {
    let mut response: Vec<u8> = vec![];
    let mut buf = [0u8; 16384];
    let mut last_data_at = Instant::now();
    loop {
        match stream.read(&mut buf) {
            Err(ref e)
                if (e.kind() == ErrorKind::WouldBlock) || (e.kind() == ErrorKind::TimedOut) =>
            {
                thread::sleep(Duration::from_millis(100));
            }
            Err(ref e) if (e.kind() == ErrorKind::ConnectionReset) && !response.is_empty() => break,
            Err(e) => panic!("Read error: {}", e),
            Ok(len) => {
                response.extend(&buf[..len]);
                if len > 0 {
                    last_data_at = Instant::now();
                }
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
    wallet.as_payer(public_key, &TEST_DEFAULT_CHAIN.rec().contract)
}

pub fn make_paying_wallet(secret: &[u8]) -> Wallet {
    let digest = secret.keccak256();
    Wallet::from(
        Bip32EncryptionKeyProvider::from_raw_secret(&digest)
            .expect("Invalid Secret for Bip32ECKeyPair"),
    )
}

//must stay without cfg(test) -- used in another crate
pub fn make_wallet(address: &str) -> Wallet {
    Wallet::from_str(&dummy_address_to_hex(address)).unwrap()
}

pub fn assert_eq_debug<T: Debug>(a: T, b: T) {
    let a_str = format!("{:?}", a);
    let b_str = format!("{:?}", b);
    assert_eq!(a_str, b_str);
}

//must stay without cfg(test) -- used in another crate
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TestRawTransaction {
    pub nonce: U256,
    pub to: Option<Address>,
    pub value: U256,
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    #[serde(rename = "gasLimit")]
    pub gas_limit: U256,
    pub data: Vec<u8>,
}

#[cfg(test)]
pub mod unshared_test_utils {
    use crate::accountant::DEFAULT_PENDING_TOO_LONG_SEC;
    use crate::apps::app_node;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::daemon::{ChannelFactory, DaemonBindMessage};
    use crate::database::db_initializer::DATABASE_FILE;
    use crate::db_config::config_dao_null::ConfigDaoNull;
    use crate::db_config::persistent_configuration::PersistentConfigurationReal;
    use crate::node_test_utils::DirsWrapperMock;
    use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
    use crate::sub_lib::neighborhood::{ConnectionProgressMessage, DEFAULT_RATE_PACK};
    use crate::sub_lib::utils::{
        NLSpawnHandleHolder, NLSpawnHandleHolderReal, NotifyHandle, NotifyLaterHandle,
    };
    use crate::test_utils::database_utils::bring_db_0_back_to_life_and_return_connection;
    use crate::test_utils::neighborhood_test_utils::MIN_HOPS_FOR_TEST;
    use crate::test_utils::persistent_configuration_mock::PersistentConfigurationMock;
    use crate::test_utils::recorder::{make_recorder, Recorder, Recording};
    use crate::test_utils::recorder_stop_conditions::{StopCondition, StopConditions};
    use crate::test_utils::unshared_test_utils::system_killer_actor::SystemKillerActor;
    use actix::{Actor, Addr, AsyncContext, Context, Handler, Recipient, System};
    use actix::{Message, SpawnHandle};
    use clap::ArgMatches;
    use crossbeam_channel::{unbounded, Receiver, Sender};
    use itertools::Either;
    use masq_lib::messages::{ToMessageBody, UiCrashRequest};
    use masq_lib::multi_config::MultiConfig;
    use masq_lib::ui_gateway::{NodeFromUiMessage, NodeToUiMessage};
    use masq_lib::utils::slice_of_strs_to_vec_of_strings;
    use std::any::TypeId;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::future::Future;
    use std::num::ParseIntError;
    use std::panic::AssertUnwindSafe;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::vec;
    use futures_util::FutureExt;

    #[derive(Message)]
    #[rtype(result = "()")]
    pub struct AssertionsMessage<A: Actor> {
        pub assertions: Box<dyn FnOnce(&mut A) + Send>,
    }

    pub async fn assert_on_initialization_with_panic_on_migration<F, A>(data_dir: PathBuf, act: A)
    where
        F: Future<Output = ()> + Send,
        A: Fn(PathBuf) -> F,
    {
        async fn assert_closure<S, F, A>(
            act: A,
            expected_panic_message: Either<(&str, &str), &str>,
            data_dir: PathBuf,
        ) where
            F: Future<Output = ()> + Send,
            A: Fn(PathBuf) -> F,
            S: AsRef<str> + 'static,
        {
            let future = act(data_dir);
            let caught_panic = AssertUnwindSafe(future).catch_unwind().await.unwrap_err();
            let panic_message = caught_panic.downcast_ref::<S>().unwrap();
            let panic_message_str: &str = panic_message.as_ref();
            match expected_panic_message {
                Either::Left((message_start, message_end)) => {
                    assert!(
                        panic_message_str.contains(message_start),
                        "We expected this message ('{}') to start with '{}'",
                        panic_message_str,
                        message_start
                    );
                    assert!(
                        panic_message_str.ends_with(message_end),
                        "We expected this message ('{}') to end with '{}'",
                        panic_message_str,
                        message_end
                    );
                }
                Either::Right(message) => assert_eq!(panic_message_str, message),
            }
        }
        let database_file_path = data_dir.join(DATABASE_FILE);
        assert_closure::<String, _, _>(
            &act,
            Either::Left((
                "Couldn't initialize database due to \"Nonexistent\" at \"generated",
                &format!("{}\"", DATABASE_FILE),
            )),
            data_dir.clone(),
        ).await;

        bring_db_0_back_to_life_and_return_connection(&database_file_path);
        assert_closure::<&str, _, _>(
            &act,
            Either::Right("Broken code: Migrating database at inappropriate place"),
            data_dir,
        ).await;
    }

    pub fn make_simplified_multi_config<const T: usize>(args: [&str; T]) -> MultiConfig {
        let mut app_args = vec!["MASQNode".to_string()];
        app_args.append(&mut slice_of_strs_to_vec_of_strings(&args));
        let arg_matches = app_node().get_matches_from(app_args);
        MultiConfig::from(arg_matches)
    }

    pub const ZERO: u32 = 0b0;
    pub const MAPPING_PROTOCOL: u32 = 0b000010;
    pub const ACCOUNTANT_CONFIG_PARAMS: u32 = 0b000100;
    pub const RATE_PACK: u32 = 0b001000;

    pub fn configure_default_persistent_config(bit_flag: u32) -> PersistentConfigurationMock {
        let config = default_persistent_config_just_base(PersistentConfigurationMock::new());
        let config = if (bit_flag & MAPPING_PROTOCOL) == MAPPING_PROTOCOL {
            config.mapping_protocol_result(Ok(None))
        } else {
            config
        };
        let config = if (bit_flag & ACCOUNTANT_CONFIG_PARAMS) == ACCOUNTANT_CONFIG_PARAMS {
            default_persistent_config_just_accountant_config(config)
        } else {
            config
        };
        let config = if (bit_flag & RATE_PACK) == RATE_PACK {
            config.rate_pack_result(Ok(DEFAULT_RATE_PACK))
        } else {
            config
        };
        config
    }

    pub fn default_persistent_config_just_base(
        persistent_config_mock: PersistentConfigurationMock,
    ) -> PersistentConfigurationMock {
        persistent_config_mock
            .earning_wallet_address_result(Ok(None))
            .earning_wallet_result(Ok(None))
            .consuming_wallet_private_key_result(Ok(None))
            .consuming_wallet_result(Ok(None))
            .past_neighbors_result(Ok(None))
            .gas_price_result(Ok(1))
            .blockchain_service_url_result(Ok(None))
            .min_hops_result(Ok(MIN_HOPS_FOR_TEST))
    }

    pub fn default_persistent_config_just_accountant_config(
        persistent_config_mock: PersistentConfigurationMock,
    ) -> PersistentConfigurationMock {
        persistent_config_mock
            .payment_thresholds_result(Ok(PaymentThresholds::default()))
            .scan_intervals_result(Ok(ScanIntervals::default()))
    }

    pub fn make_persistent_config_real_with_config_dao_null() -> PersistentConfigurationReal {
        PersistentConfigurationReal::new(Box::new(ConfigDaoNull::default()))
    }

    pub fn make_bc_with_defaults() -> BootstrapperConfig {
        let mut config = BootstrapperConfig::new();
        config.scan_intervals_opt = Some(ScanIntervals::default());
        config.suppress_initial_scans = false;
        config.when_pending_too_long_sec = DEFAULT_PENDING_TOO_LONG_SEC;
        config.payment_thresholds_opt = Some(PaymentThresholds::default());
        config
    }

    pub fn make_recipient_and_recording_arc<M: 'static>(
        stopping_message: Option<TypeId>,
    ) -> (Recipient<M>, Arc<Mutex<Recording>>)
    where
        M: Message + Send,
        <M as Message>::Result: Send,
        Recorder: Handler<M>,
    {
        let (recorder, _, recording_arc) = make_recorder();
        let recorder = match stopping_message {
            Some(type_id) => recorder.system_stop_conditions(StopConditions::All(vec![
                StopCondition::StopOnType(type_id),
            ])), // No need to write stop message after this
            None => recorder,
        };
        let addr = recorder.start();
        let recipient = addr.recipient::<M>();

        (recipient, recording_arc)
    }

    pub fn make_cpm_recipient() -> (Recipient<ConnectionProgressMessage>, Arc<Mutex<Recording>>) {
        make_recipient_and_recording_arc(None)
    }

    pub fn make_node_to_ui_recipient() -> (Recipient<NodeToUiMessage>, Arc<Mutex<Recording>>) {
        make_recipient_and_recording_arc(None)
    }

    pub fn make_daemon_bind_message(ui_gateway: Recorder) -> DaemonBindMessage {
        let (stub, _, _) = make_recorder();
        let stub_sub = stub.start().recipient::<NodeFromUiMessage>();
        let (daemon, _, _) = make_recorder();
        let crash_notification_recipient = daemon.start().recipient();
        let ui_gateway_sub = ui_gateway.start().recipient::<NodeToUiMessage>();
        DaemonBindMessage {
            to_ui_message_recipient: ui_gateway_sub,
            from_ui_message_recipient: stub_sub,
            from_ui_message_recipients: vec![],
            crash_notification_recipient,
        }
    }

    pub struct ChannelFactoryMock {
        make_results: RefCell<
            Vec<(
                Sender<HashMap<String, String>>,
                Receiver<HashMap<String, String>>,
            )>,
        >,
    }

    impl ChannelFactory for ChannelFactoryMock {
        fn make(
            &self,
        ) -> (
            Sender<HashMap<String, String>>,
            Receiver<HashMap<String, String>>,
        ) {
            self.make_results.borrow_mut().remove(0)
        }
    }

    impl ChannelFactoryMock {
        pub fn new() -> ChannelFactoryMock {
            ChannelFactoryMock {
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_result(
            self,
            sender: Sender<HashMap<String, String>>,
            receiver: Receiver<HashMap<String, String>>,
        ) -> Self {
            self.make_results.borrow_mut().push((sender, receiver));
            self
        }
    }

    pub fn prove_that_crash_request_handler_is_hooked_up<
        T: Actor<Context = actix::Context<T>> + actix::Handler<NodeFromUiMessage>,
    >(
        actor: T,
        crash_key: &str,
    ) {
        let system = System::new();
        let addr: Addr<T> = actor.start();
        let killer = SystemKillerActor::new(Duration::from_millis(2000));
        killer.start();

        addr.try_send(NodeFromUiMessage {
            client_id: 0,
            body: UiCrashRequest::new(crash_key, "panic message").tmb(0),
        })
        .unwrap();
        system.run();
        panic!("test failed")
    }

    pub fn make_pre_populated_mocked_directory_wrapper() -> DirsWrapperMock {
        DirsWrapperMock::new()
            .home_dir_result(Some(PathBuf::from("/unexisting_home/unexisting_alice")))
            .data_dir_result(Some(PathBuf::from(
                "/unexisting_home/unexisting_alice/mock_directory",
            )))
    }

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    pub mod system_killer_actor {
        use super::*;

        #[derive(Debug, Message, Clone)]
        #[rtype(result = "()")]
        pub struct CleanUpMessage {
            pub sleep_ms: u64,
        }

        pub struct SystemKillerActor {
            after: Duration,
            tx: Sender<()>,
            rx: Receiver<()>,
        }

        impl Actor for SystemKillerActor {
            type Context = Context<Self>;

            fn started(&mut self, ctx: &mut Self::Context) {
                ctx.notify_later(CleanUpMessage { sleep_ms: 0 }, self.after.clone());
            }
        }

        // Note: the sleep_ms field of the CleanUpMessage is unused; all we need is a time strobe.
        impl Handler<CleanUpMessage> for SystemKillerActor {
            type Result = ();

            fn handle(&mut self, _msg: CleanUpMessage, _ctx: &mut Self::Context) -> Self::Result {
                System::current().stop();
                self.tx.try_send(()).expect("Receiver is dead");
            }
        }

        impl SystemKillerActor {
            pub fn new(after: Duration) -> Self {
                let (tx, rx) = unbounded();
                Self { after, tx, rx }
            }

            pub fn receiver(&self) -> Receiver<()> {
                self.rx.clone()
            }
        }
    }

    pub mod notify_handlers {
        use super::*;

        pub struct NotifyLaterHandleMock<M> {
            notify_later_params: Arc<Mutex<Vec<(M, Duration)>>>,
            send_message_out: bool,
        }

        impl<M: Message> Default for NotifyLaterHandleMock<M> {
            fn default() -> Self {
                Self {
                    notify_later_params: Arc::new(Mutex::new(vec![])),
                    send_message_out: false,
                }
            }
        }

        impl<M: Message> NotifyLaterHandleMock<M> {
            pub fn notify_later_params(mut self, params: &Arc<Mutex<Vec<(M, Duration)>>>) -> Self {
                self.notify_later_params = params.clone();
                self
            }

            pub fn permit_to_send_out(mut self) -> Self {
                self.send_message_out = true;
                self
            }
        }

        impl<M, A> NotifyLaterHandle<M, A> for NotifyLaterHandleMock<M>
        where
            M: Message + 'static + Clone,
            A: Actor<Context = Context<A>> + Handler<M>,
        {
            fn notify_later<'a>(
                &'a self,
                msg: M,
                interval: Duration,
                ctx: &'a mut Context<A>,
            ) -> Box<dyn NLSpawnHandleHolder> {
                self.notify_later_params
                    .lock()
                    .unwrap()
                    .push((msg.clone(), interval));
                if self.send_message_out {
                    let handle = ctx.notify_later(msg, interval);
                    Box::new(NLSpawnHandleHolderReal::new(handle))
                } else {
                    Box::new(NLSpawnHandleHolderNull {})
                }
            }
        }

        pub struct NLSpawnHandleHolderNull {}

        impl NLSpawnHandleHolder for NLSpawnHandleHolderNull {
            fn handle(self) -> SpawnHandle {
                intentionally_blank!()
            }
        }

        pub struct NotifyHandleMock<M> {
            notify_params: Arc<Mutex<Vec<M>>>,
            send_message_out: bool,
        }

        impl<M: Message> Default for NotifyHandleMock<M> {
            fn default() -> Self {
                Self {
                    notify_params: Arc::new(Mutex::new(vec![])),
                    send_message_out: false,
                }
            }
        }

        impl<M: Message> NotifyHandleMock<M> {
            pub fn notify_params(mut self, params: &Arc<Mutex<Vec<M>>>) -> Self {
                self.notify_params = params.clone();
                self
            }

            pub fn permit_to_send_out(mut self) -> Self {
                self.send_message_out = true;
                self
            }
        }

        impl<M, A> NotifyHandle<M, A> for NotifyHandleMock<M>
        where
            M: Message + 'static + Clone,
            A: Actor<Context = Context<A>> + Handler<M>,
        {
            fn notify<'a>(&'a self, msg: M, ctx: &'a mut Context<A>) {
                self.notify_params.lock().unwrap().push(msg.clone());
                if self.send_message_out {
                    ctx.notify(msg)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sub_lib::cryptde::CryptData;
    use crate::sub_lib::hop::LiveHop;
    use crate::sub_lib::neighborhood::ExpectedService;
    use masq_lib::test_utils::arbitrary_id_stamp::ArbitraryIdStamp;
    use std::borrow::BorrowMut;
    use std::iter;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn characterize_zero_hop_route() {
        let cryptde = main_cryptde();
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
        let cryptde = main_cryptde();
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
        let cryptde = main_cryptde();
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
        let cryptde = main_cryptde();
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
            let log = check_log.as_ref().lock().unwrap();
            assert_eq!(*log, vec!["signaler", "waiter"]);
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
