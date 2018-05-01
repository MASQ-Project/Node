// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::env::temp_dir;
use std::thread;
use std::time::Duration;
use flexi_logger::LevelFilter;
use flexi_logger::Logger;
use flexi_logger::LogSpecification;
use logger_trait_lib::logger::LoggerInitializerWrapper;
use sub_lib::main_tools::StdStreams;
use sub_lib::main_tools::Command;
use sub_lib::socket_server::SocketServer;
use entry_dns_lib::dns_socket_server::new_dns_socket_server;
use bootstrapper::Bootstrapper;
use privilege_drop::PrivilegeDropper;
use privilege_drop::PrivilegeDropperReal;
//#[cfg(unix)]
//use daemonize::Daemonize;

pub struct ServerInitializer<P, D> where P: PrivilegeDropper, D: Daemonizer {
    dns_socket_server: Option<Box<SocketServer>>,
    bootstrapper: Option<Box<SocketServer>>,
    privilege_dropper: P,
    daemonizer: D,
    logger_initializer_wrapper: Box<LoggerInitializerWrapper>,
    lifetime_secs: u64
}

struct LoggerInitializerWrapperReal {}

impl LoggerInitializerWrapper for LoggerInitializerWrapperReal {
    fn init(&mut self) -> bool {
        match Logger::with(LogSpecification::default(LevelFilter::Trace).finalize())
            .log_to_file()
            .directory(&temp_dir ().to_str ().expect ("Bad temporary filename")[..])
            .print_message ()
            .duplicate_info ()
            .suppress_timestamp ()
            .start() {
            Ok (_) => true,
            Err (_) => false
        }
    }
}

impl<P, D> Command for ServerInitializer<P, D> where P: PrivilegeDropper, D: Daemonizer {
    fn go<'b> (&mut self, streams: &'b mut StdStreams<'b>, args: &Vec<String>) -> u8 {
        self.logger_initializer_wrapper.init ();
        let mut dns_socket_server_box = self.dns_socket_server.take ().expect ("DNS Socket Server missing");
        dns_socket_server_box.as_mut ().initialize_as_root (args, streams);
        let mut bootstrapper_box = self.bootstrapper.take ().expect ("Bootstrapper missing");
        bootstrapper_box.as_mut ().initialize_as_root (args, streams);
        self.privilege_dropper.drop_privileges();
        self.daemonizer.daemonize();
        thread::spawn (move || {
            dns_socket_server_box.as_mut ().serve_without_root();
        });
        thread::spawn (move || {
            bootstrapper_box.as_mut ().serve_without_root();
        });

        // Don't kill my child threads
        thread::sleep (Duration::from_secs (self.lifetime_secs));

        return 0
    }
}

impl ServerInitializer<PrivilegeDropperReal, DaemonizerReal> {
    pub fn new ()
            -> ServerInitializer<PrivilegeDropperReal, DaemonizerReal> {
        ServerInitializer {
            dns_socket_server: Some (Box::new (new_dns_socket_server())),
            bootstrapper: Some (Box::new (Bootstrapper::new ())),
            privilege_dropper: PrivilegeDropperReal::new (),
            daemonizer: DaemonizerReal::new (),
            logger_initializer_wrapper: Box::new (LoggerInitializerWrapperReal {}),
            lifetime_secs: 0xFFFFFFFFFFFFFFFF
        }
    }
}

pub trait Daemonizer {
    fn daemonize (&self);
}

#[cfg(unix)]
pub struct DaemonizerReal;

#[cfg(windows)]
pub struct DaemonizerReal;

#[cfg(unix)]
impl Daemonizer for DaemonizerReal {
    // Not unit tested
    fn daemonize(&self) {
//        match Daemonize::new ()
//            .working_directory ("/tmp")
//            .user ("nobody")
//            .group ("daemon")
//            .start () {
//            Ok (_) => (),
//            Err (e) => panic! ("Couldn't daemonize: {}", e.to_string ())
//        }
    }
}

#[cfg(windows)]
impl Daemonizer for DaemonizerReal {
    fn daemonize(&self) {
        // No daemonization for Windows yet
    }
}

#[cfg(unix)]
impl DaemonizerReal {
    fn new () -> DaemonizerReal {
        DaemonizerReal {}
    }
}

#[cfg(windows)]
impl DaemonizerReal {
    fn new () -> DaemonizerReal {
        DaemonizerReal {}
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::mpsc;
    use std::sync::mpsc::Sender;
    use std::sync::mpsc::Receiver;
    use sub_lib::limiter::Limiter;
    use sub_lib::logger;
    use test_utils::test_utils::FakeStreamHolder;
    use test_utils::test_utils::LoggerInitializerWrapperMock;
    use test_utils::test_utils::TestLogHandler;
    use test_utils::test_utils::ByteArrayWriter;
    use test_utils::test_utils::ByteArrayReader;

    struct SocketServerMock {
        name: String,
        rx: Receiver<String>,
        limiter: Limiter
    }

    impl SocketServer for SocketServerMock {
        fn name (&self) -> String {
            self.name.clone ()
        }

        fn initialize_as_root(&mut self, args: &Vec<String>, streams: &mut StdStreams) {
            logger::Logger::new (&self.name[..]).log (format! ("initialize_as_root: {:?}", args));
            let mut buf: [u8; 10] = [0; 10];
            let len = streams.stdin.read (&mut buf).unwrap ();
            streams.stdout.write (&buf[0..len]).is_ok ();
            streams.stderr.write (&buf[0..len]).is_ok ();
        }

        fn serve_without_root(&mut self) {
            let logger = logger::Logger::new (&self.name);
            logger.log (format! ("serve_without_root"));
            while self.limiter.should_continue () {
                let request = self.rx.recv ().unwrap ();
                if request == "panic" {
                    let msg = format! ("{} was instructed to panic", self.name);
                    panic! (msg);
                }
                logger.log (format! ("{}", request));
            }
        }
    }

    impl SocketServerMock {
        pub fn make(name: &str, limit: i32) -> (SocketServerMock, Sender<String>) {
            let (tx, rx) = mpsc::channel ();
            (SocketServerMock {
                name: String::from (name),
                rx,
                limiter: Limiter::with_only(limit)
            }, tx)
        }
    }

    struct PrivilegeDropperMock {
        tx: Sender<String>
    }

    impl PrivilegeDropper for PrivilegeDropperMock {
        fn drop_privileges(&self) {
            self.tx.send (String::from ("privileges dropped")).unwrap ();
        }
    }

    struct DaemonizerMock {
        tx: Sender<String>
    }

    impl Daemonizer for DaemonizerMock {
        fn daemonize(&self) {
            self.tx.send (String::from ("daemonized")).unwrap ();
        }
    }

    #[test]
    fn exits_after_all_socket_servers_exit () {
        let (tx, _rx) = mpsc::channel ();
        let (dns_socket_server, dns_tx) = SocketServerMock::make("EntryDnsServerMock1", 1);
        let (bootstrapper, bootstrapper_tx) = SocketServerMock::make("BootstrapperMock1", 1);
        let privilege_dropper = PrivilegeDropperMock {tx: tx.clone ()};
        let daemonizer = DaemonizerMock {tx: tx.clone ()};
        let args = vec! ();
        let mut subject = ServerInitializer {
            dns_socket_server: Some (Box::new (dns_socket_server)),
            bootstrapper: Some (Box::new (bootstrapper)),
            privilege_dropper,
            daemonizer,
            logger_initializer_wrapper: Box::new (LoggerInitializerWrapperMock::new ()),
            lifetime_secs: 0
        };

        let handle = thread::spawn (move || {
            let mut holder = FakeStreamHolder {
                stdin: ByteArrayReader::new ("first1....second1...".as_bytes ()),
                stdout: ByteArrayWriter::new (),
                stderr: ByteArrayWriter::new ()
            };
            subject.go(&mut holder.streams(), &args);
        });
        dns_tx.send (String::from ("request")).unwrap ();
        bootstrapper_tx.send (String::from ("request")).unwrap ();
        handle.join ().unwrap ();

        // Join succeeded; thread ended, test passed
    }

    #[test]
    fn runs_socket_servers_and_returns_zero () {
        let (tx, rx) = mpsc::channel ();
        let (dns_socket_server, dns_tx) = SocketServerMock::make("EntryDnsServerMock2", 2);
        let (bootstrapper, bootstrapper_tx) = SocketServerMock::make("BootstrapperMock2", 2);
        let privilege_dropper = PrivilegeDropperMock {tx: tx.clone ()};
        let daemonizer = DaemonizerMock {tx: tx.clone ()};
        let logger_initializer_wrapper = LoggerInitializerWrapperMock::new ();
        let args = vec! (String::from("glorp"));
        let mut subject = ServerInitializer {
            dns_socket_server: Some (Box::new (dns_socket_server)),
            bootstrapper: Some (Box::new (bootstrapper)),
            privilege_dropper,
            daemonizer,
            logger_initializer_wrapper: Box::new (logger_initializer_wrapper.clone ()),
            lifetime_secs: 0
        };
        let holder = FakeStreamHolder {
            stdin: ByteArrayReader::new ("first2....second2...".as_bytes ()),
            stdout: ByteArrayWriter::new (),
            stderr: ByteArrayWriter::new ()
        };
        let holder_t = Arc::new (Mutex::new (holder));
        let holder_m = holder_t.clone ();

        let handle = thread::spawn (move || {
            let mut locked = holder_t.lock ();
            let holder_ref = locked.as_mut ().unwrap ();
            let result = subject.go(&mut holder_ref.streams(), &args);
            assert_eq! (result, 0);
        });
        dns_tx.send (String::from ("one - first request")).unwrap ();
        dns_tx.send (String::from ("one - second request")).unwrap ();
        bootstrapper_tx.send (String::from ("two - first request")).unwrap ();
        bootstrapper_tx.send (String::from ("two - second request")).unwrap ();
        handle.join ().unwrap ();

        assert_eq! (rx.recv_timeout(Duration::from_millis(50)).unwrap (), String::from ("privileges dropped"));
        assert_eq! (rx.recv_timeout(Duration::from_millis(50)).unwrap (), String::from ("daemonized"));
        let holder_ref = holder_m.lock ().unwrap ();
        let stdout_string = holder_ref.stdout.get_string ();
        assert_contains (&stdout_string, "first2....second2...");
        let stderr_string = holder_ref.stderr.get_string ();
        assert_contains (&stderr_string, "first2....second2...");
        let tlh = TestLogHandler::new ();
        tlh.await_log_containing ("one - second request", 5000);
        tlh.await_log_containing ("two - second request", 5000);
        tlh.assert_logs_match_in_order(vec! (
            "EntryDnsServerMock2: initialize_as_root: \\[\"glorp\"\\]",
            "EntryDnsServerMock2: serve_without_root",
            "EntryDnsServerMock2: one - first request",
            "EntryDnsServerMock2: one - second request"
        ));
        tlh.assert_logs_match_in_order(vec! (
            "BootstrapperMock2: initialize_as_root: \\[\"glorp\"\\]",
            "BootstrapperMock2: serve_without_root",
            "BootstrapperMock2: two - first request",
            "BootstrapperMock2: two - second request"
        ));
        tlh.assert_logs_contain_in_order(vec! (
            "EntryDnsServerMock2: initialize_as_root: [\"glorp\"]",
            "BootstrapperMock2: two - first request",
        ));
        tlh.assert_logs_contain_in_order(vec! (
            "BootstrapperMock2: initialize_as_root: [\"glorp\"]",
            "EntryDnsServerMock2: one - first request",
        ));
    }

    fn assert_contains (string: &str, substring: &str) {
        assert_eq! (string.contains (substring), true, "'{}' is not contained in:\n'{}'\n", substring, string);
    }
}