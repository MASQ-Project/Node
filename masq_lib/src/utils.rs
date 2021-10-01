// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use lazy_static::lazy_static;
use std::fmt;
use std::fmt::Debug;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

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

#[derive(PartialEq, Debug, Clone, Copy)]
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
    find_free_port_for_ip_addr(IpAddr::V4(Ipv4Addr::new (0, 0, 0, 0)))
}

fn find_free_port_for_ip_addr(ip_addr: IpAddr) -> u16 {
    let mut candidate = FIND_FREE_PORT_NEXT.lock().unwrap();
    loop {
        match TcpListener::bind(SocketAddr::new(ip_addr, *candidate)) {
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

fn test_is_running() -> bool {
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

pub fn array_of_borrows_to_vec(slice: &[&str]) -> Vec<String> {
    slice
        .iter()
        .map(|item| item.to_string())
        .collect::<Vec<String>>()
}

pub trait ExpectValue<T> {
    #[track_caller]
    fn expect_v(self, msg: &str) -> T;
}

impl<T> ExpectValue<T> for Option<T> {
    #[inline]
    fn expect_v(self, subject: &str) -> T {
        match self {
            Some(v) => v,
            None => expect_value_panic(subject, None),
        }
    }
}

impl<T, E: Debug> ExpectValue<T> for Result<T, E> {
    #[inline]
    fn expect_v(self, subject: &str) -> T {
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

pub trait WrapResult {
    fn wrap_to_ok<E>(self) -> Result<Self, E>
    where
        Self: Sized;
    fn wrap_to_err<T>(self) -> Result<T, Self>
    where
        Self: Sized;
}

impl<T> WrapResult for T {
    fn wrap_to_ok<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn wrap_to_err<V>(self) -> Result<V, Self> {
        Err(self)
    }
}

#[macro_export]
macro_rules! short_writeln {
    ($dst:expr) => (
         writeln!($dst).expect("writeln failed")
    );
    ( $form: expr, $($arg:tt)*) => {
         writeln!($form, $($arg)*).expect("writeln failed")
    };
}

#[macro_export]
macro_rules! intentionally_blank {
    () => {
        panic!("Required method left unimplemented: should never be called.")
    };
}

#[macro_export]
macro_rules! as_any_dcl {
    () => {
        #[cfg(test)]
        fn as_any(&self) -> &dyn Any {
            use masq_lib::intentionally_blank;
            intentionally_blank!()
        }
    };
}

#[macro_export]
macro_rules! as_any_impl {
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
    use std::env::current_dir;
    use std::fmt::Write;
    use std::fs::{create_dir_all, File, OpenOptions};
    use std::io::Write as FmtWrite;

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
    fn short_writeln_write_text_properly() {
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

    #[test]
    #[should_panic(expected = "writeln failed")]
    fn short_writeln_panic_politely_with_a_message() {
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
    #[should_panic(expected = "value for 'meaningful code' badly prepared")]
    fn expect_v_panics_for_none() {
        let subject: Option<u16> = None;

        let _ = subject.expect_v("meaningful code");
    }

    #[test]
    #[should_panic(expected = r#"value for 'safety feature' badly prepared, got: "alarm"#)]
    fn expect_v_panics_for_error_variant() {
        let subject: Result<String, String> = Err("alarm".to_string());

        let _ = subject.expect_v("safety feature");
    }

    #[test]
    fn expect_v_unwraps_option() {
        let subject = Some(456);

        let result = subject.expect_v("meaningful code");

        assert_eq!(result, 456)
    }

    #[test]
    fn expect_v_unwraps_result() {
        let subject: Result<String, String> = Ok("all right".to_string());

        let result = subject.expect_v("safety feature");

        assert_eq!(result, "all right".to_string())
    }
}
