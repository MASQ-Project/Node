// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::blockchains::chains::Chain;
use crate::crash_point::CrashPoint;
use crate::shared_schema::{
    ConfigFile, DataDirectory, LogLevel, MappingProtocol, MinHops, NeighborhoodMode, Neighbors,
    OnOff, PaymentThresholds, PublicKey, RatePack, ScanIntervals,
};
use crate::shared_schema::{GasPrice, InsecurePort, IpAddrs, PrivateKey, RealUser, VecU64, Wallet};
use clap::ArgMatches;
use dirs::{data_local_dir, home_dir};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use url::Url;

#[cfg(not(target_os = "windows"))]
mod not_win_cfg {
    pub use nix::sys::signal;
    pub use std::time::Duration;
}

const FIND_FREE_PORT_LOWEST: u16 = 32768;
const FIND_FREE_PORT_HIGHEST: u16 = 65535;

pub struct RunningTestData {
    test_is_running: bool,
    panic_message: Option<String>,
}

lazy_static! {
    pub static ref RUNNING_TEST_DATA: Arc<Mutex<RunningTestData>> =
        Arc::new(Mutex::new(RunningTestData {
            test_is_running: false,
            panic_message: None,
        }));
}

lazy_static! {
    static ref FIND_FREE_PORT_NEXT: Arc<Mutex<u16>> = Arc::new(Mutex::new(FIND_FREE_PORT_LOWEST));
}

//data-directory help
lazy_static! {
    pub static ref DATA_DIRECTORY_DAEMON_HELP: String = compute_data_directory_help();
}

fn compute_data_directory_help() -> String {
    let data_dir = data_local_dir().unwrap();
    let home_dir = home_dir().unwrap();
    let polygon_mainnet_dir = Path::new(&data_dir.to_str().unwrap())
        .join("MASQ")
        .join("polygon-mainnet");
    let polygon_mumbai_dir = Path::new(&data_dir.to_str().unwrap())
        .join("MASQ")
        .join("polygon-mumbai");
    format!("Directory in which the Node will store its persistent state, including at least its database \
        and by default its configuration file as well. By default, your data-directory is located in \
        your application directory, under your home directory e.g.: '{}'.\n\n\
        In case you change your chain to a different one, the data-directory path is automatically changed \
        to end with the name of your chain: e.g.: if you choose polygon-mumbai, then data-directory is \
        automatically changed to: '{}'.\n\n\
        You can specify your own data-directory to the Daemon in two different ways: \n\n\
        1. If you provide a path without the chain name on the end, the Daemon will automatically change \
        your data-directory to correspond with the chain. For example: {}/masq_home will be automatically \
        changed to: '{}/masq_home/polygon-mainnet'.\n\n\
        2. If you provide your data directory with the corresponding chain name on the end, eg: {}/masq_home/polygon-mainnet, \
        there will be no change until you set the chain parameter to a different value.",
            polygon_mainnet_dir.to_string_lossy().to_string().as_str(),
            polygon_mumbai_dir.to_string_lossy().to_string().as_str(),
            &home_dir.to_string_lossy().to_string().as_str(),
            &home_dir.to_string_lossy().to_string().as_str(),
            home_dir.to_string_lossy().to_string().as_str()
    )
}

pub trait ArgumentConverter {
    fn convert(&self, matches: &ArgMatches, key: &str) -> Option<String>;
}

macro_rules! argument_converter_for {
    ($exotic_type: ty, $converter_type: ident) => {
        struct $converter_type {}
        impl ArgumentConverter for $converter_type {
            fn convert(&self, matches: &ArgMatches, key: &str) -> Option<String> {
                matches.get_one::<$exotic_type>(key).map(|v| v.to_string())
            }
        }
    };
}

macro_rules! make_converter_entry {
    ($arg_name: literal, $converter_type: ident) => {
        (
            $arg_name,
            Box::new($converter_type {}) as Box<dyn ArgumentConverter>,
        )
    };
}

argument_converter_for!(Chain, ChainConverter);
argument_converter_for!(ConfigFile, ConfigFileConverter);
argument_converter_for!(CrashPoint, CrashPointConverter);
argument_converter_for!(DataDirectory, DataDirectoryConverter);
argument_converter_for!(GasPrice, GasPriceConverter);
argument_converter_for!(InsecurePort, InsecurePortConverter);
argument_converter_for!(IpAddr, IpAddrConverter);
argument_converter_for!(IpAddrs, IpAddrsConverter);
argument_converter_for!(LogLevel, LogLevelConverter);
argument_converter_for!(MappingProtocol, MappingProtocolConverter);
argument_converter_for!(MinHops, MinHopsConverter);
argument_converter_for!(NeighborhoodMode, NeighborhoodModeConverter);
argument_converter_for!(Neighbors, NeighborsConverter);
argument_converter_for!(OnOff, OnOffConverter);
argument_converter_for!(PaymentThresholds, PaymentThresholdsConverter);
argument_converter_for!(PrivateKey, PrivateKeyConverter);
argument_converter_for!(PublicKey, PublicKeyConverter);
argument_converter_for!(RatePack, RatePackConverter);
argument_converter_for!(RealUser, RealUserConverter);
argument_converter_for!(ScanIntervals, ScanIntervalsConverter);
argument_converter_for!(Url, UrlConverter);
argument_converter_for!(VecU64, VecU64Converter);
argument_converter_for!(Wallet, WalletConverter);

fn make_argument_converters() -> HashMap<&'static str, Box<dyn ArgumentConverter>> {
    HashMap::from([
        make_converter_entry!("blockchain-service-url", UrlConverter),
        make_converter_entry!("chain", ChainConverter),
        make_converter_entry!("clandestine-port", InsecurePortConverter),
        make_converter_entry!("config-file", ConfigFileConverter),
        make_converter_entry!("consuming-private-key", PrivateKeyConverter),
        make_converter_entry!("crash-point", CrashPointConverter),
        make_converter_entry!("data-directory", DataDirectoryConverter),
        make_converter_entry!("dns-servers", IpAddrsConverter),
        make_converter_entry!("earning-wallet", WalletConverter),
        make_converter_entry!("fake-public-key", PublicKeyConverter),
        make_converter_entry!("gas-price", GasPriceConverter),
        make_converter_entry!("ip", IpAddrConverter),
        make_converter_entry!("log-level", LogLevelConverter),
        make_converter_entry!("mapping-protocol", MappingProtocolConverter),
        make_converter_entry!("min-hops", MinHopsConverter),
        make_converter_entry!("neighborhood-mode", NeighborhoodModeConverter),
        make_converter_entry!("neighbors", NeighborsConverter),
        make_converter_entry!("payment-thresholds", PaymentThresholdsConverter),
        make_converter_entry!("rate-pack", RatePackConverter),
        make_converter_entry!("real-user", RealUserConverter),
        make_converter_entry!("scan-intervals", ScanIntervalsConverter),
        make_converter_entry!("scans", OnOffConverter),
    ])
}

pub fn get_argument_value_as_string(matches: &ArgMatches, key: &str) -> Option<String> {
    // TODO: We should find a way to make the map of converters a static constant
    match make_argument_converters().get(key) {
        None => matches
            .get_one::<String>(key)
            .map(|string_ref| string_ref.to_string()),
        Some(converter) => converter.convert(matches, key),
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum AutomapProtocol {
    Pmp,
    Pcp,
    Igdp,
}

impl Display for AutomapProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AutomapProtocol::Pmp => write!(f, "PMP"),
            AutomapProtocol::Pcp => write!(f, "PCP"),
            AutomapProtocol::Igdp => write!(f, "IGDP"),
        }
    }
}

impl FromStr for AutomapProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "PCP" => Ok(AutomapProtocol::Pcp),
            "PMP" => Ok(AutomapProtocol::Pmp),
            "IGDP" => Ok(AutomapProtocol::Igdp),
            _ => Err(format!(
                "Valid protocol names are PCP, PMP, and IGDP; not '{}'",
                s
            )),
        }
    }
}

impl AutomapProtocol {
    pub fn values() -> Vec<AutomapProtocol> {
        vec![
            AutomapProtocol::Pcp,
            AutomapProtocol::Pmp,
            AutomapProtocol::Igdp,
        ]
    }
}

fn next_port(port: u16) -> u16 {
    match port {
        p if p < FIND_FREE_PORT_HIGHEST => p + 1,
        _ => FIND_FREE_PORT_LOWEST,
    }
}

pub fn find_free_port() -> u16 {
    find_free_port_for_ip_addr(localhost())
}

pub fn find_free_port_0000() -> u16 {
    find_free_port_for_ip_addr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))
}

fn find_free_port_for_ip_addr(ip_addr: IpAddr) -> u16 {
    let mut current_port = FIND_FREE_PORT_NEXT.lock().unwrap();
    loop {
        let candidate = *current_port;
        *current_port = next_port(*current_port);
        if port_is_free_for_ip_addr(ip_addr, candidate) {
            return candidate;
        }
    }
}

fn port_is_free_for_ip_addr(ip_addr: IpAddr, port: u16) -> bool {
    let test_address = SocketAddr::new(ip_addr, port);
    fn result_checker<T>(result: io::Result<T>) -> bool {
        match result {
            Err(ref e)
                if (e.kind() == ErrorKind::AddrInUse)
                    || (e.kind() == ErrorKind::AddrNotAvailable) =>
            {
                false
            }
            Err(e) => panic!("Couldn't find free port: {:?}", e),
            Ok(_) => true,
        }
    }
    let result = TcpListener::bind(test_address);
    if !result_checker(result) {
        return false;
    }
    let result = UdpSocket::bind(test_address);
    if !result_checker(result) {
        return false;
    }
    true
}

pub fn add_masq_and_chain_directories(chain: Chain, local_data_dir: &Path) -> PathBuf {
    let masq_dir = PathBuf::from(local_data_dir).join("MASQ");
    add_chain_specific_directory(chain, masq_dir.as_path())
}

pub fn add_chain_specific_directory(chain: Chain, local_data_dir: &Path) -> PathBuf {
    match local_data_dir.ends_with(chain.rec().literal_identifier) {
        true => PathBuf::from(local_data_dir),
        false => PathBuf::from(local_data_dir).join(chain.rec().literal_identifier),
    }
}

pub fn localhost() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

pub const DERIVATION_PATH_ROOT: &str = "m/44'/60'/0'";

pub fn derivation_path(a: u8, b: u8) -> String {
    format!("{}/{}/{}", DERIVATION_PATH_ROOT, a, b)
}

lazy_static! {
    pub static ref DEFAULT_CONSUMING_DERIVATION_PATH: String = derivation_path(0, 0);
    pub static ref DEFAULT_EARNING_DERIVATION_PATH: String = derivation_path(0, 1);
}

#[allow(clippy::needless_range_loop)]
pub fn index_of<T>(haystack: &[T], needles: &[T]) -> Option<usize>
where
    T: PartialEq,
{
    if needles.is_empty() {
        return None;
    }
    for h in 0..haystack.len() {
        let mut mismatch = false;
        for n in 0..needles.len() {
            let i = h + n;
            if i >= haystack.len() {
                mismatch = true;
                break;
            }
            if haystack[i] != needles[n] {
                mismatch = true;
                break;
            }
        }
        if !mismatch {
            return Some(h);
        }
    }
    None
}

pub fn index_of_from<T>(haystack: &[T], needle: &T, start_at: usize) -> Option<usize>
where
    T: PartialEq,
{
    let mut index = start_at;
    while index < haystack.len() && (haystack[index] != *needle) {
        index += 1;
    }
    if index >= haystack.len() {
        None
    } else {
        Some(index)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum NeighborhoodModeLight {
    Standard,
    ConsumeOnly,
    OriginateOnly,
    ZeroHop,
}

impl Display for NeighborhoodModeLight {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::ConsumeOnly => write!(f, "consume-only"),
            Self::OriginateOnly => write!(f, "originate-only"),
            Self::ZeroHop => write!(f, "zero-hop"),
        }
    }
}

impl FromStr for NeighborhoodModeLight {
    type Err = String;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        Ok(match str {
            "standard" => Self::Standard,
            "consume-only" => Self::ConsumeOnly,
            "originate-only" => Self::OriginateOnly,
            "zero-hop" => Self::ZeroHop,
            x => return Err(format!("Invalid value read for neighborhood mode: {}", x)),
        })
    }
}

pub fn partition(s: &str, partition_size: usize) -> Result<Vec<String>, String> {
    if partition_size == 0 {
        return Err(String::from("partition_size must be greater than 0"));
    }
    if s.len() % partition_size != 0 {
        return Err(format!(
            "5-character string '{}' cannot be partitioned into {}-character substrings",
            s, partition_size
        ));
    }
    let init: (Vec<String>, String) = (vec![], String::new());
    let vector_and_blank_string = s.chars().fold(init, |so_far, c| {
        let (mut strings, mut in_progress) = so_far;
        in_progress.push(c);
        if in_progress.len() == partition_size {
            strings.push(in_progress);
            (strings, String::new())
        } else {
            (strings, in_progress)
        }
    });
    Ok(vector_and_blank_string.0)
}

const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];
pub fn hex_to_u128(digits: &str) -> Result<u128, String> {
    if digits.len() > 32 {
        return Err(format!(
            "Hex string too long to convert to u128: '{}'",
            digits
        ));
    }
    fn digit_value(c: char) -> Option<u8> {
        for (i, digit) in HEX_DIGITS.iter().enumerate() {
            if digit == &c.to_ascii_uppercase() {
                return Some(i as u8);
            }
        }
        None
    }
    let value_opt = digits
        .chars()
        .fold(Some(0u128), |so_far_opt, c| match so_far_opt {
            Some(so_far) => digit_value(c).map(|dv| (so_far << 4) + (dv as u128)),
            None => None,
        });
    match value_opt {
        Some(v) => Ok(v),
        None => Err(format!("Illegal hexadecimal number: '{}'", digits)),
    }
}

pub fn plus<T>(mut source: Vec<T>, item: T) -> Vec<T> {
    let mut result = vec![];
    result.append(&mut source);
    result.push(item);
    result
}

pub fn running_test() {
    let mut running_test_data = RUNNING_TEST_DATA.lock().unwrap();
    running_test_data.test_is_running = true;
}

fn set_test_data_message(message: &str) {
    let mut running_test_data = RUNNING_TEST_DATA.lock().expect("Thread died unexpectedly");
    running_test_data.panic_message = Some(message.to_string());
}

pub fn test_is_running() -> bool {
    RUNNING_TEST_DATA
        .lock()
        .expect("Thread died unexpectedly")
        .test_is_running
}

pub fn exit_process(code: i32, message: &str) -> ! {
    if test_is_running() {
        set_test_data_message(message);
        panic!("{}: {}", code, message);
    } else {
        eprintln!("{}", message);
        ::std::process::exit(code)
    }
}

pub fn get_test_panic_message() -> Option<String> {
    RUNNING_TEST_DATA.lock().unwrap().panic_message.clone()
}

#[cfg(not(target_os = "windows"))]
pub fn exit_process_with_sigterm(message: &str) {
    if test_is_running() {
        set_test_data_message(message);
        panic!("{}", message);
    } else {
        eprintln!("{}", message);
        not_win_cfg::signal::raise(not_win_cfg::signal::SIGTERM).expect("sigterm failure");
        //This function must not return, and the process will be terminated by another thread within micro- or milliseconds, so we wait here for death.
        std::thread::sleep(not_win_cfg::Duration::from_secs(600))
    }
}

pub fn slice_of_strs_to_vec_of_strings(slice: &[&str]) -> Vec<String> {
    slice
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
}

pub trait ExpectValue<T> {
    #[track_caller]
    fn expectv(self, msg: &str) -> T;
}

impl<T> ExpectValue<T> for Option<T> {
    #[inline]
    fn expectv(self, subject: &str) -> T {
        match self {
            Some(v) => v,
            None => expect_value_panic(subject, None),
        }
    }
}

impl<T, E: Debug> ExpectValue<T> for Result<T, E> {
    #[inline]
    fn expectv(self, subject: &str) -> T {
        match self {
            Ok(v) => v,
            Err(e) => expect_value_panic(subject, Some(&e)),
        }
    }
}

#[track_caller]
fn expect_value_panic(subject: &str, found: Option<&dyn fmt::Debug>) -> ! {
    panic!(
        "value for '{}' badly prepared{}",
        subject,
        found
            .map(|cause| format!(", got: {:?}", cause))
            .unwrap_or_else(|| "".to_string())
    )
}

pub fn type_name_of<T>(_examined: T) -> &'static str {
    std::any::type_name::<T>()
}

pub trait MutabilityConflictHelper<T>
where
    T: 'static,
{
    type Result;

    //note: you should not write your own impl of this defaulted method
    fn help<F>(&mut self, closure: F) -> Self::Result
    where
        F: FnOnce(&T, &mut Self) -> Self::Result,
    {
        //TODO we should seriously think about rewriting this in well tested unsafe code,
        // Rust is unnecessarily strict as for this conflicting situation
        let helper = self.helper_access().take().expectv("helper");
        let result = closure(&helper, self);
        self.helper_access().replace(helper);
        result
    }

    fn helper_access(&mut self) -> &mut Option<T>;
}

#[macro_export]
macro_rules! short_writeln {
    ($term_interface: expr) => (
             $term_interface.writeln("").await
    );
    ( $term_interface: expr, $($arg:tt)*) => {
         {
             $term_interface.writeln(&format!($($arg)*)).await
         };
    };
}

#[macro_export]
macro_rules! intentionally_blank {
    () => {
        panic!("Required method left unimplemented: should never be called.")
    };
}

#[macro_export]
macro_rules! declare_as_any {
    () => {
        #[cfg(test)]
        fn as_any(&self) -> &dyn Any {
            use masq_lib::intentionally_blank;
            intentionally_blank!()
        }
    };
}

#[macro_export]
macro_rules! implement_as_any {
    () => {
        #[cfg(test)]
        fn as_any(&self) -> &dyn Any {
            self
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_schema::shared_app;
    use clap::Command;
    use std::env::current_dir;
    use std::fmt::Write;
    use std::fs::{create_dir_all, File, OpenOptions};
    use std::io::Write as FmtWrite;

    #[test]
    fn constants_have_correct_values() {
        assert_eq!(
            DEFAULT_CONSUMING_DERIVATION_PATH.to_string(),
            "m/44'/60'/0'/0/0"
        );
        assert_eq!(
            DEFAULT_EARNING_DERIVATION_PATH.to_string(),
            "m/44'/60'/0'/0/1"
        );
        assert_eq!(FIND_FREE_PORT_LOWEST, 32768);
        assert_eq!(FIND_FREE_PORT_HIGHEST, 65535);
        assert_eq!(DERIVATION_PATH_ROOT, "m/44'/60'/0'");
    }

    #[test]
    fn get_argument_value_as_string_handles_exotic_types() {
        let command = shared_app(Command::new("test"));
        let matches = command
            .try_get_matches_from(&[
                "first",
                "--blockchain-service-url",
                "https://blockchain.client.net/api/jsonrpc",
                "--chain",
                "polygon-mainnet",
                "--clandestine-port",
                "1234",
                "--config-file",
                "../directory/file.toml",
                "--consuming-private-key",
                "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
                "--crash-point",
                "panic",
                "--data-directory",
                "~/grandfather/father/target",
                "--dns-servers",
                "1.2.3.4,2.3.4.5",
                "--earning-wallet",
                "0x0123456789abcdef0123456789abcdef01234567",
                "--fake-public-key",
                "Ym9vZ2EK",
                "--gas-price",
                "1234",
                "--ip",
                "3.4.5.6",
                "--log-level",
                "warn",
                "--mapping-protocol",
                "igdp",
                "--min-hops",
                "4",
                "--neighborhood-mode",
                "zero-hop",
                "--neighbors",
                "1.2.3.4:1234/2345/3456,2.3.4.5:2345/3456/4567",
                "--real-user",
                "4321:5432:/home/billy",
                "--scans",
                "off",
                "--scan-intervals",
                "10|20|30",
                "--rate-pack",
                "10|20|30|40",
                "--payment-thresholds",
                "10|20|30|40|50|60",
            ])
            .unwrap();
        let verifier = |key, expected_value: Option<&str>| {
            let result = get_argument_value_as_string(&matches, key);
            assert_eq!(result, expected_value.map(|v| v.to_string()))
        };

        verifier(
            "blockchain-service-url",
            Some("https://blockchain.client.net/api/jsonrpc"),
        );
        verifier("chain", Some("polygon-mainnet"));
        verifier("clandestine-port", Some("1234"));
        verifier("config-file", Some("../directory/file.toml"));
        verifier(
            "consuming-private-key",
            Some("00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100"),
        );
        verifier("crash-point", Some("panic"));
        verifier("data-directory", Some("~/grandfather/father/target"));
        verifier("dns-servers", Some("1.2.3.4,2.3.4.5"));
        verifier(
            "earning-wallet",
            Some("0x0123456789abcdef0123456789abcdef01234567"),
        );
        verifier("fake-public-key", Some("Ym9vZ2EK"));
        verifier("gas-price", Some("1234"));
        verifier("ip", Some("3.4.5.6"));
        verifier("log-level", Some("warn"));
        verifier("mapping-protocol", Some("igdp"));
        verifier("min-hops", Some("4"));
        verifier("neighborhood-mode", Some("zero-hop"));
        verifier(
            "neighbors",
            Some("1.2.3.4:1234/2345/3456,2.3.4.5:2345/3456/4567"),
        );
        verifier("real-user", Some("4321:5432:/home/billy"));
        verifier("scans", Some("off"));
        verifier("scan-intervals", Some("10|20|30"));
        verifier("rate-pack", Some("10|20|30|40"));
        verifier("payment-thresholds", Some("10|20|30|40|50|60"))
    }

    #[test]
    fn get_argument_value_as_string_handles_mundane_types() {
        let command = shared_app(Command::new("test"));
        let matches = command
            .try_get_matches_from(&["first", "--db-password", "boogety bop"])
            .unwrap();

        let result = get_argument_value_as_string(&matches, "db-password");

        assert_eq!(result, Some("boogety bop".to_string()));
    }

    #[test]
    fn automap_protocol_display_works() {
        let result = format!(
            "PCP: {}; PMP: {}; IGDP: {}",
            AutomapProtocol::Pcp,
            AutomapProtocol::Pmp,
            AutomapProtocol::Igdp
        );

        assert_eq!(&result, "PCP: PCP; PMP: PMP; IGDP: IGDP");
    }

    #[test]
    fn automap_protocol_values_works() {
        let result = AutomapProtocol::values();

        assert_eq!(
            result,
            vec![
                AutomapProtocol::Pcp,
                AutomapProtocol::Pmp,
                AutomapProtocol::Igdp
            ]
        )
    }

    #[test]
    fn automap_protocol_from_str_works() {
        let input = vec!["pcp", "PCP", "pmp", "PMP", "igdp", "IGDP"];

        let result: Vec<AutomapProtocol> = input
            .into_iter()
            .map(|s| AutomapProtocol::from_str(s).unwrap())
            .collect();

        assert_eq!(
            result,
            vec![
                AutomapProtocol::Pcp,
                AutomapProtocol::Pcp,
                AutomapProtocol::Pmp,
                AutomapProtocol::Pmp,
                AutomapProtocol::Igdp,
                AutomapProtocol::Igdp,
            ]
        );
    }

    #[test]
    fn automap_protocol_from_str_rejects_bad_name() {
        let result = AutomapProtocol::from_str("booga");

        assert_eq!(
            result,
            Err("Valid protocol names are PCP, PMP, and IGDP; not 'booga'".to_string())
        );
    }

    #[test]
    fn index_of_fails_to_find_nonexistent_needle_in_haystack() {
        let result = index_of("haystack".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_finds_needle_at_beginning_of_haystack() {
        let result = index_of("haystack haystack".as_bytes(), "haystack".as_bytes());

        assert_eq!(result, Some(0));
    }

    #[test]
    fn index_of_finds_needle_at_end_of_haystack() {
        let result = index_of("needle haystack".as_bytes(), "haystack".as_bytes());

        assert_eq!(result, Some(7));
    }

    #[test]
    fn index_of_fails_to_find_nonempty_needle_in_empty_haystack() {
        let result = index_of("".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_returns_none_for_empty_needle() {
        let result = index_of("haystack".as_bytes(), "".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_fails_to_find_needle_that_ends_past_end_of_haystack() {
        let result = index_of("haystack needl".as_bytes(), "needle".as_bytes());

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_fails_to_find_nonexistent_needle_in_haystack() {
        let haystack = vec![true, true, true, true];

        let result = index_of_from(&haystack, &false, 0);

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_fails_to_find_needle_in_empty_haystack() {
        let haystack: Vec<i32> = vec![];

        let result = index_of_from(&haystack, &-42, 0);

        assert_eq!(result, None);
    }

    #[test]
    fn index_of_from_finds_needle_at_beginning_of_search() {
        let haystack = vec![8, 7, 8, 3];

        let result = index_of_from(&haystack, &8, 2);

        assert_eq!(result, Some(2));
    }

    #[test]
    fn index_of_from_finds_needle_at_end_of_haystack() {
        let haystack = vec![8, 7, 8, 3];

        let result = index_of_from(&haystack, &3, 0);

        assert_eq!(result, Some(3));
    }

    #[test]
    fn partition_complains_if_partition_size_is_zero() {
        let result = partition("abcde", 0);

        assert_eq!(
            result,
            Err("partition_size must be greater than 0".to_string())
        )
    }

    #[test]
    fn partition_complains_if_length_is_not_evenly_divisible() {
        let result = partition("abcde", 4);

        assert_eq!(
            result,
            Err(
                "5-character string 'abcde' cannot be partitioned into 4-character substrings"
                    .to_string()
            )
        )
    }

    #[test]
    fn partition_works_if_length_is_evenly_divisible() {
        let result = partition("ab12cd34ef56gh78ij90", 2);

        let expected = vec!["ab", "12", "cd", "34", "ef", "56", "gh", "78", "ij", "90"]
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>();
        assert_eq!(result, Ok(expected))
    }

    #[test]
    fn hex_to_u128_complains_about_illegal_hex_digits() {
        let result = hex_to_u128("xy");

        assert_eq!(result, Err("Illegal hexadecimal number: 'xy'".to_string()))
    }

    #[test]
    fn hex_to_u128_complains_when_number_is_too_long() {
        let result = hex_to_u128("123456782234567832345678423456780");

        assert_eq!(
            result,
            Err(
                "Hex string too long to convert to u128: '123456782234567832345678423456780'"
                    .to_string()
            )
        )
    }

    #[test]
    fn hex_to_u128_happy_path() {
        let result = hex_to_u128("fedcba9876543210ABCDEF");

        assert_eq!(result, Ok(0xFEDCBA9876543210ABCDEF))
    }

    #[tokio::test]
    async fn short_writeln_write_text_properly() {
        let mut buffer = Vec::new();
        let mut string_buffer = String::new();
        short_writeln!(buffer, "This is the first line");
        short_writeln!(
            string_buffer,
            "{}\n{}",
            "This is another line",
            "Will this work?"
        );
        short_writeln!(string_buffer);

        assert_eq!(buffer.as_slice(), "This is the first line\n".as_bytes());
        assert_eq!(
            string_buffer,
            "This is another line\nWill this work?\n\n".to_string()
        );
    }

    #[tokio::test]
    #[should_panic(expected = "writeln failed")]
    async fn short_writeln_panic_politely_with_a_message() {
        let path = current_dir().unwrap();
        let path = path.join("tests").join("short_writeln");
        let _ = create_dir_all(&path);
        let full_path = path.join("short-writeln.txt");
        File::create(&full_path).unwrap();
        let mut read_only_file_handle = OpenOptions::new().read(true).open(full_path).unwrap();
        short_writeln!(
            read_only_file_handle,
            "This is the first line and others will come...maybe"
        );
    }

    #[test]
    fn neighborhood_mode_light_has_display() {
        assert_eq!(NeighborhoodModeLight::Standard.to_string(), "standard");
        assert_eq!(
            NeighborhoodModeLight::ConsumeOnly.to_string(),
            "consume-only"
        );
        assert_eq!(
            NeighborhoodModeLight::OriginateOnly.to_string(),
            "originate-only"
        );
        assert_eq!(NeighborhoodModeLight::ZeroHop.to_string(), "zero-hop")
    }

    #[test]
    fn neighborhood_mode_light_from_str() {
        assert_eq!(
            NeighborhoodModeLight::from_str("standard").unwrap(),
            NeighborhoodModeLight::Standard
        );
        assert_eq!(
            NeighborhoodModeLight::from_str("consume-only").unwrap(),
            NeighborhoodModeLight::ConsumeOnly
        );
        assert_eq!(
            NeighborhoodModeLight::from_str("originate-only").unwrap(),
            NeighborhoodModeLight::OriginateOnly
        );
        assert_eq!(
            NeighborhoodModeLight::from_str("zero-hop").unwrap(),
            NeighborhoodModeLight::ZeroHop
        );

        assert_eq!(
            NeighborhoodModeLight::from_str("blah"),
            Err(String::from(
                "Invalid value read for neighborhood mode: blah"
            ))
        )
    }

    #[test]
    #[should_panic(expected = "value for 'meaningful code' badly prepared")]
    fn expectv_panics_for_none() {
        let subject: Option<u16> = None;

        let _ = subject.expectv("meaningful code");
    }

    #[test]
    #[should_panic(expected = r#"value for 'safety feature' badly prepared, got: "alarm"#)]
    fn expectv_panics_for_error_variant() {
        let subject: Result<String, String> = Err("alarm".to_string());

        let _ = subject.expectv("safety feature");
    }

    #[test]
    fn expectv_unwraps_option() {
        let subject = Some(456);

        let result = subject.expectv("meaningful code");

        assert_eq!(result, 456)
    }

    #[test]
    fn expectv_unwraps_result() {
        let subject: Result<String, String> = Ok("all right".to_string());

        let result = subject.expectv("safety feature");

        assert_eq!(result, "all right".to_string())
    }

    fn find_test_port_from(port: u16) -> u16 {
        if super::port_is_free_for_ip_addr(localhost(), port) {
            port
        } else {
            find_test_port_from(port - 1)
        }
    }

    #[test]
    fn port_is_free_for_ip_addr() {
        let test_port = find_test_port_from(FIND_FREE_PORT_LOWEST - 1);
        // port_is_free_for_ip_addr claims this port is free for both; let's check
        {
            let result = UdpSocket::bind(SocketAddr::new(localhost(), test_port));
            match result {
                Ok(_) => (),
                x => panic!("{:?}", x),
            }
        }
        {
            let result = TcpListener::bind(SocketAddr::new(localhost(), test_port));
            match result {
                Ok(_) => (),
                x => panic!("{:?}", x),
            }
        }

        // Claim it for UDP and see if port_is_free_for_ip_addr can tell
        {
            let _socket = UdpSocket::bind(SocketAddr::new(localhost(), test_port)).unwrap();
            let result = super::port_is_free_for_ip_addr(localhost(), test_port);
            assert_eq!(result, false);
        }

        // Claim it for TCP and see if port_is_free_for_ip_addr can tell
        {
            let _listener = TcpListener::bind(SocketAddr::new(localhost(), test_port)).unwrap();
            let result = super::port_is_free_for_ip_addr(localhost(), test_port);
            assert_eq!(result, false);
        }

        // Claim it for both and see if port_is_free_for_ip_addr can tell
        {
            let _socket = UdpSocket::bind(SocketAddr::new(localhost(), test_port)).unwrap();
            let _listener = TcpListener::bind(SocketAddr::new(localhost(), test_port)).unwrap();
            let result = super::port_is_free_for_ip_addr(localhost(), test_port);
            assert_eq!(result, false);
        }
    }

    #[test]
    fn type_name_of_works() {
        let result = type_name_of(running_test);
        assert_eq!(result, "masq_lib::utils::running_test")
    }
}
