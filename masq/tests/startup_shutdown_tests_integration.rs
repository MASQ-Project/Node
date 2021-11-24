// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fs::File;
use std::io::{Read};
use std::path::PathBuf;
use crate::utils::{DaemonProcess, MasqProcess};
use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
use masq_lib::utils::find_free_port;
use regex::Regex;
use std::thread;
use std::time::Duration;

mod utils;

#[test]
fn masq_without_daemon_integration() {
    let masq_handle = MasqProcess::new().start_noninteractive(vec!["setup"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stdout, "", "{}", stdout);
    assert!(
        stderr.contains("Can't connect to Daemon or Node"),
        "we got: {}",
        stderr
    );
    assert_eq!(exit_code.unwrap(), 1);
}

#[test]
fn masq_terminates_immediately_after_clap_gets_furious_about_params_which_it_does_not_recognize_integration(
) {
    let masq_handle = MasqProcess::new().start_noninteractive(vec!["uninvented-command"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stdout, "", "{}", stdout);
    assert!(stderr.contains("Found argument 'uninvented-command' which wasn't expected, or isn't valid in this context"),
        "we got: {}",
        stderr
    );
    assert_eq!(exit_code.unwrap(), 1);
}

#[test]
fn masq_propagates_errors_related_to_default_terminal_integration() {
    //the port is irrelevant; it hits the error before it gets to trying to connect to the Daemon
    let masq_handle = MasqProcess::new().start_interactive(22222, false);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(exit_code.unwrap(), 1);
    let regex = Regex::new(r"\x1B\[\?\d\d[lh]").unwrap();
    assert_eq!(regex.replace_all(&stdout, ""), "", "{}", stdout);
    #[cfg(not(target_os = "windows"))]
    let expected_error_message = "Pre-configuration error: Preparing terminal interface:";
    #[cfg(target_os = "windows")]
    let expected_error_message = "Pre-configuration error: Local terminal recognition: ";
    assert!(
        stderr.contains(expected_error_message),
        "unlike what we expected stderr was: {}",
        stderr
    );
}

#[test]
fn masq_terminates_based_on_loss_of_connection_to_the_daemon_integration() {
    let dir_path = ensure_node_home_directory_exists(
        "masq_integration_tests",
        "masq_terminates_based_on_loss_of_connection_to_the_daemon_integration",
    );
    let port = find_free_port();
    let daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(300));
    let mut masq_handle = MasqProcess::new().start_interactive(port, true);
    let mut stdin_handle = masq_handle.create_stdin_handle();
    stdin_handle.type_command(&format!(
        "setup --data-directory {}",
        dir_path.to_str().unwrap()
    ));
    thread::sleep(Duration::from_millis(300));

    daemon_handle.kill();

    let (stdout, stderr, exit_code) = masq_handle.stop();
    #[cfg(not(target_os = "windows"))]
    assert_eq!(exit_code, None);
    #[cfg(target_os = "windows")]
    assert_eq!(exit_code.unwrap(), 1);
    assert!(stdout.contains("neighborhood-mode      standard                                                         Default"));
    assert_eq!(
        stderr,
        "\nThe Daemon is no longer running; masq is terminating.\n\n"
    );
}

#[test]
fn handles_startup_and_shutdown_integration() {
    let dir_path = ensure_node_home_directory_exists(
        "masq_integration_tests",
        "handles_startup_and_shutdown_integration",
    );
    let port = find_free_port();
    let mut daemon_handle = DaemonProcess::new().start(port);
    thread::sleep(Duration::from_millis(200));

    let masq_handle = MasqProcess::new().start_noninteractive(vec![
        "--ui-port",
        &port.to_string(),
        "setup",
        "--log-level",
        "error",
        "--neighborhood-mode",
        "zero-hop",
        "--data-directory",
        dir_path.to_str().unwrap(),
    ]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "setup phase: {}", stderr);
    assert_eq!(
        stdout.contains("neighborhood-mode      zero-hop"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code.unwrap(), 0);

    let masq_handle =
        MasqProcess::new().start_noninteractive(vec!["--ui-port", &port.to_string(), "start"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "start phase: {}", stderr);
    assert_eq!(
        stdout.contains("MASQNode successfully started in process"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code.unwrap(), 0);

    let mut stdout_handle = daemon_handle.create_stdout_handle().unwrap();
    let mut buffer = [0_u8;1024];
    stdout_handle.read(&mut buffer).unwrap();
    let printable = String::from_utf8_lossy(&buffer).to_string();
    eprintln!("daemon's stdout output: {}",printable);
    let regex = Regex::new("Log is written to (.*MASQNode_daemon_rCURRENT.log)").unwrap();
    let capture = regex.captures(printable.as_str()).unwrap();
    let captured_path = capture.get(1).unwrap();
    eprintln!("captured path to the log file: {}",captured_path.as_str());
    let path_object = PathBuf::from(captured_path.as_str().to_string());
    let _deamon_drop_log_reader = DaemonDropLogReader::new(path_object);

    let masq_handle =
        MasqProcess::new().start_noninteractive(vec!["--ui-port", &port.to_string(), "shutdown"]);

    let (stdout, stderr, exit_code) = masq_handle.stop();

    assert_eq!(&stderr, "", "shutdown phase: {}", stderr);
    assert_eq!(
        stdout.contains("MASQNode was instructed to shut down and has broken its connection"),
        true,
        "{}",
        stdout
    );
    assert_eq!(exit_code.unwrap(), 0);

    daemon_handle.kill();
}

struct DaemonDropLogReader{
    path: PathBuf
}

impl DaemonDropLogReader{
    fn new(log_file_path:PathBuf)->Self{
        Self{
            path: log_file_path
        }
    }
}

impl Drop for DaemonDropLogReader{
    fn drop(&mut self) {
        let mut file = File::open(&self.path).unwrap();
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).unwrap();
        let readable = String::from_utf8_lossy(&buffer).to_string();
        eprintln!("{}",readable)
    }
}