// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::automap_core_functions::{remove_firewall_hole, remove_permanent_firewall_hole};
use crate::comm_layer::Transactor;
use rand::{thread_rng, Rng};
use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fmt, thread};

//so far, println!() is safer for testing, with immediate feedback
#[allow(clippy::result_unit_err)]
pub fn close_exposed_port(
    _stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
    params: LevelTwoShifter,
) -> Result<(), ()> {
    println!("Preparation for closing the forwarded port");
    match params.method {
        Method::Pmp | Method::Pcp | Method::Igdp(false) => {
            remove_firewall_hole(_stdout, _stderr, params)
        }
        Method::Igdp(true) => remove_permanent_firewall_hole(_stdout, _stderr, params),
    }
}

#[derive(PartialEq, Debug)]
pub enum Method {
    Pmp,
    Pcp,
    Igdp(bool),
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Method::Pmp => write!(f, "PMP protocol"),
            Method::Pcp => write!(f, "PCP protocol"),
            Method::Igdp(_flag) => write!(f, "IGDP protocol"),
        }
    }
}

#[allow(clippy::type_complexity)]
pub fn prepare_router_or_report_failure(
    test_pcp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_pmp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_igdp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String>>,
) -> Result<LevelTwoShifter, Vec<String>> {
    let mut collector: Vec<String> = vec![];
    match test_pcp() {
        Ok((ip, port, transactor)) => {
            return Ok(LevelTwoShifter {
                method: Method::Pcp,
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    match test_pmp() {
        Ok((ip, port, transactor)) => {
            return Ok(LevelTwoShifter {
                method: Method::Pmp,
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    match test_igdp() {
        Ok((ip, port, transactor, permanent)) => {
            return Ok(LevelTwoShifter {
                method: Method::Igdp(permanent),
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    if collector.len() == 3 {
        Err(collector)
    } else {
        panic!("shouldn't happen")
    }
}

pub struct LevelTwoShifter {
    pub method: Method,
    pub ip: IpAddr,
    pub port: u16,
    pub transactor: Box<dyn Transactor>,
}

fn deploy_background_listener(
    socket_addr: SocketAddr,
    listener_message_sync: &Arc<Mutex<Vec<(u16, String)>>>,
) -> std::io::Result<JoinHandle<()>> {
    let listener_message = listener_message_sync;
    let listener_message_clone = Arc::clone(&listener_message);
    let mut error_writer = String::new();
    thread::Builder::new().spawn(move || {
        let listener_opt = match TcpListener::bind(socket_addr) {
            Ok(listener) => Some(listener),
            Err(e) => {
                error_writer.push_str(&format!(
                    "Test is unsuccessful; starting to cancel it: {}",
                    e
                ));
                None
            }
        };
        if let Some(listener) = listener_opt {
            listener
                .set_nonblocking(true)
                .expect("Setting nonblocking connection failed");
            let mut loop_counter: u16 = 0;
            let connection_opt = loop {
                //os limit or intern limit for attempts up to around 508
                match listener.accept() {
                    Ok((stream, _)) => break Some(stream),
                    //check incoming connection request but at some point the attempts will get exhausted (gross 6000 millis)
                    Err(_) if loop_counter <= 300 => {
                        if loop_counter < 28 {
                            thread::sleep(Duration::from_millis(20));
                        } else if (28..=150).contains(&loop_counter) {
                            thread::sleep(Duration::from_millis(5));
                        } else {
                            thread::sleep(Duration::from_millis(15));
                        }
                        loop_counter += 1;
                        continue;
                    }
                    Err(_) if loop_counter > 300 => {
                        error_writer
                            .push_str("No incoming request of connecting; waiting too long. ");
                        break None;
                    }
                    _ => {
                        error_writer.push_str("should never happen; unexpected");
                        break None;
                    }
                }
            };
            if let Some(mut connection) = connection_opt {
                let mut buffer = [0u8; 2];
                connection
                    .set_nonblocking(false)
                    .expect("not successful to set blocking read");
                connection
                    .set_read_timeout(Some(Duration::from_secs(6)))
                    .expect("setting read timeout failed");
                match connection.read(&mut buffer) {
                    //shutdown signal elimination
                    Ok(num) if num > 1 => {
                        let converted_to_txt = u16::from_be_bytes(buffer);
                        listener_message_clone
                            .lock()
                            .unwrap()
                            .push((converted_to_txt, String::new()));
                    }
                    Ok(num) if num <= 1 => {
                        error_writer.push_str("Communication can't continue. Stream was muted. ");
                        mutex_shared_err_message(listener_message_clone, error_writer);
                    }
                    Err(_) => {
                        error_writer
                            .push_str("No incoming request of connecting; waiting too long. ");
                        mutex_shared_err_message(listener_message_clone, error_writer);
                    }
                    //untested but enforced by the compiler (match pattering must be exhaustive)
                    _ => {
                        error_writer.push_str("Unexpected value; terminating unsuccessful ");
                        mutex_shared_err_message(listener_message_clone, error_writer)
                    }
                }
            } else {
                mutex_shared_err_message(listener_message_clone, error_writer);
            }
        } else {
            mutex_shared_err_message(listener_message_clone, error_writer);
        }
    })
}

fn mutex_shared_err_message(reference: Arc<Mutex<Vec<(u16, String)>>>, message: String) {
    reference.lock().unwrap().push((0, message));
}

pub fn probe_researcher(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    server_address: &str,
    params: &mut LevelTwoShifter,
) -> bool {
    write!(
        stdout,
        "Test of a port forwarded by using {} is starting. \n\n",
        params.method
    )
    .expect("write failed");

    let success_sign = Cell::new(false);
    evaluate_research(stdout, stderr, server_address, params, &success_sign);

    stderr.flush().expect("failed to flush stdout");
    stdout.flush().expect("failed to flush stderr");

    success_sign.take()
}

fn evaluate_research(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    server_address: &str,
    params: &mut LevelTwoShifter,
    success_sign: &Cell<bool>,
) {
    let server_address =
        SocketAddr::from_str(server_address).expect("server socket address parsing error");
    let nonce = generate_nonce();
    let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
    let probe_listener_address = SocketAddr::from_str(&format!("0.0.0.0:{}", params.port))
        .expect("probe listener address parsing error");
    let thread_handle =
        match deploy_background_listener(probe_listener_address, &listener_result_arc_mut) {
            Ok(handle) => handle,
            Err(e) => {
                stderr
                    .write_all(e.to_string().as_ref())
                    .expect("write_all failed");
                return;
            } //untested but reasonably safe
        };
    let http_request = format!(
        "GET /probe_request?ip={}&port={}&nonce={} HTTP/1.1\r\n\r\n",
        params.ip, params.port, nonce
    );
    let mut connection: TcpStream = match TcpStream::connect(server_address) {
        Ok(conn) => conn,
        Err(_) => {
            stderr
                .write_all(
                    b"We couldn't connect to the \
             http server. Test is terminating.",
                )
                .expect("writing failed");
            return;
        }
    };
    match connection.write_all(http_request.as_bytes()) {
        Ok(_) => (),
        Err(_) => {
            stderr
                .write_all(
                    b"Sending an http request to \
                 the server failed. Test is terminating.",
                )
                .expect("writing failed");
            return;
        } // untested but safe
    }
    let mut buffer = [0u8; 1024];
    connection
        .set_nonblocking(false)
        .expect("not successful to set blocking read");
    connection
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("unsuccessful during setting nonblocking");
    let mut server_response = false;
    match connection.read(&mut buffer) {
        Ok(length) => {
            stdout
                .write_all(&buffer[..length])
                .expect("writing server response failed");
            server_response = true;
        }
        Err(_) => stderr
            .write_all(b"Request to the server was sent but no response came back. ")
            .expect("writing to stderr failed"),
    };
    thread_handle
        .join()
        .expect("failed to wait for the background thread");
    let probe_listener_findings =
        listener_result_arc_mut.lock().expect("poisoned mutex")[0].clone();
    if probe_listener_findings.0 != 0 {
        if nonce == probe_listener_findings.0 {
            stdout
                .write_all(b"\n\nThe received nonce was evaluated to be a match; test passed")
                .expect("write_all failed");
        } else {
            let failure_message = format!(
                "\n\nThe received nonce is different from that one which is expected; \
                 correct: {}, received:{}",
                nonce, probe_listener_findings.0
            );
            stdout
                .write_all(failure_message.as_bytes())
                .expect("write_all failed");
            return;
        }
    }

    if server_response {
        success_sign.set(true);
    }
}

fn generate_nonce() -> u16 {
    let mut rnd = thread_rng();
    rnd.gen_range(1000, 9999)
}

#[cfg(test)]
mod tests {
    use crate::comm_layer::pmp::PmpTransactor;
    use crate::comm_layer::Transactor;
    use crate::probe_researcher::{
        deploy_background_listener, generate_nonce, prepare_router_or_report_failure,
        probe_researcher, LevelTwoShifter, Method,
    };
    use std::io::{IoSlice, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn prepare_router_or_report_failure_retrieves_ip() {
        let result = prepare_router_or_report_failure(
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_common_test_finding_ip_and_doing_mapping),
            Box::new(mock_router_igdp_test_unsuccessful),
        );

        //sadly not all of those types implementing Transactor can implement PartialEq each
        assert!(result.is_ok());
        let unwrapped_result = result.unwrap();
        assert_eq!(unwrapped_result.ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(unwrapped_result.method, Method::Pmp);
        assert_eq!(unwrapped_result.port, 4444);
        //proof that I received an implementer of Transactor
        let _downcast_value: &PmpTransactor =
            unwrapped_result.transactor.as_any().downcast_ref().unwrap();
    }

    #[test]
    fn prepare_router_or_report_failure_reports_of_accumulated_errors() {
        let result = prepare_router_or_report_failure(
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_common_test_unsuccessful),
            Box::new(mock_router_igdp_test_unsuccessful),
        );

        let expected_message = String::from("Test ended unsuccessfully");

        assert_eq!(
            result.err().unwrap(),
            vec![
                expected_message.clone(),
                expected_message.clone(),
                expected_message
            ]
        )
    }

    #[test]
    fn deploy_background_listener_with_good_probe_works() {
        let port = 7000;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        test_stream_acceptor_and_probe_8875_imitator(true, 0, port);
        assert!(process_result.is_ok());
        //we need to wait for the execution in the background thread
        thread::sleep(Duration::from_millis(250));
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 8875);
        assert!(listener_result[0].1.is_empty())
    }

    #[test] //this test may not describe what can happen in the reality; I couldn't think up a better way to simulate connection interruption though
    fn deploy_background_listener_without_getting_echo_reports_that_correctly_after_connection_interrupted(
    ) {
        let port = 7001;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        test_stream_acceptor_and_probe_8875_imitator(false, 1, port);
        assert!(process_result.is_ok());
        thread::sleep(Duration::from_millis(200));
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 0);
        assert_eq!(
            listener_result[0].1,
            "Communication can't continue. Stream was muted. ".to_string()
        )
    }

    #[test]
    fn deploy_background_listener_without_getting_echo_terminates_alone_after_connection_lasts_too_long(
    ) {
        let port = 7003;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        //CAUTION: probably a leaking thread; this thread keeps the connection alive so that we can run out of patient with waiting
        // for the nonce message; thus deploy_background_listener terminates deliberately
        thread::spawn(move || test_stream_acceptor_and_probe_8875_imitator(false, 2, port));
        thread::sleep(Duration::from_millis(7000));
        assert!(process_result.is_ok());
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 0);
        assert_eq!(
            listener_result[0].1,
            "No incoming request of connecting; waiting too long. ".to_string()
        )
    }

    #[test]
    fn deploy_background_listener_ends_its_job_after_waiting_period_for_any_connection_but_none_was_sensed(
    ) {
        let port = 7004;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        assert!(process_result.is_ok());
        thread::sleep(Duration::from_millis(6500));
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 0);
        assert_eq!(
            listener_result[0].1,
            "No incoming request of connecting; waiting too long. ".to_string()
        )
    }

    #[test]
    fn generate_nonce_works() {
        (1..100).for_each(|_| {
            let nonce = generate_nonce();
            assert!(10000 > nonce && nonce > 999)
        });
    }

    #[test]
    #[ignore]
    //server must be running so that we can get this test green!
    fn probe_researcher_works() {
        let mut stdout = MockStream::new();
        let mut stderr = MockStream::new();
        let mut parameters_transferor = LevelTwoShifter {
            method: Method::Pmp,
            ip: IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            port: 3545,
            transactor: Box::new(PmpTransactor::default()),
        };
        let server_address = "127.0.0.1:7005";

        let result = probe_researcher(
            &mut stdout,
            &mut stderr,
            server_address,
            &mut parameters_transferor,
        );

        thread::sleep(Duration::from_secs(4));
        assert_eq!(result, true);
        assert_eq!(stdout.stream, "Test of a port forwarded by using PMP protocol is starting. \
         \n\nHTTP/1.1 200 OK\r\nContent-Length: 67\r\n\r\nconnection: success; writing: success; connection shutdown: \
         success\n\nThe received nonce was evaluated to be a match; test passed"
        );
        assert!(stderr.stream.is_empty());
        assert_eq!(stdout.flush_count, 1);
        assert_eq!(stderr.flush_count, 1);
    }

    #[test]
    fn probe_researcher_returns_failure_if_cannot_connect_to_the_http_server() {
        let mut stdout = MockStream::new();
        let mut stderr = MockStream::new();
        let mut parameters_transferor = LevelTwoShifter {
            method: Method::Pmp,
            ip: IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            port: 81,
            transactor: Box::new(PmpTransactor::default()),
        };
        let server_address = "127.0.0.1:7010";

        let result = probe_researcher(
            &mut stdout,
            &mut stderr,
            server_address,
            &mut parameters_transferor,
        );
        assert_eq!(result, false);
        assert_eq!(
            stderr.stream,
            "We couldn\'t connect to the http server. Test is terminating."
        );
        assert_eq!(
            stdout.stream,
            "Test of a port forwarded by using PMP protocol is starting. \n\n"
        );
        assert_eq!(stdout.flush_count, 1);
        assert_eq!(stderr.flush_count, 1);
    }

    #[test]
    fn probe_researcher_returns_failure_if_response_from_to_the_http_server_is_of_bad_news() {
        let mut stdout = MockStream::new();
        let mut stderr = MockStream::new();
        let mut parameters_transferor = LevelTwoShifter {
            method: Method::Pmp,
            ip: IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            port: 8000,
            transactor: Box::new(PmpTransactor::default()),
        };
        //fake server  -- caution: a leaking thread
        thread::spawn(move || {
            let listener =
                TcpListener::bind(SocketAddr::from_str("127.0.0.1:7006").unwrap()).unwrap();
            let (connection, _) = listener.accept().unwrap();
            //make busy without sleep
            loop {
                connection.peer_addr().unwrap();
            }
        });

        let server_address = "127.0.0.1:7006";

        let result = probe_researcher(
            &mut stdout,
            &mut stderr,
            server_address,
            &mut parameters_transferor,
        );
        assert_eq!(result, false);
        assert_eq!(
            stderr.stream,
            "Request to the server was sent but no response came back. "
        );
        assert_eq!(
            stdout.stream,
            "Test of a port forwarded by using PMP protocol is starting. \n\n"
        );
        assert_eq!(stdout.flush_count, 1);
        assert_eq!(stderr.flush_count, 1);
    }

    fn mock_router_common_test_finding_ip_and_doing_mapping(
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
        Ok((
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            4444,
            Box::new(PmpTransactor::new()),
        ))
    }

    fn mock_router_common_test_unsuccessful() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>
    {
        Err(String::from("Test ended unsuccessfully"))
    }

    fn mock_router_igdp_test_unsuccessful(
    ) -> Result<(IpAddr, u16, Box<dyn Transactor>, bool), String> {
        Err(String::from("Test ended unsuccessfully"))
    }

    fn test_stream_acceptor_and_probe_8875_imitator(send_probe: bool, test_option: u8, port: u16) {
        let connection = TcpStream::connect(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        if connection.is_ok() & send_probe {
            let message = u16_to_byte_array(8875);
            connection.unwrap().write_all(&message).unwrap();
        } else {
            if connection.is_ok() {
                if test_option == 1 {
                    connection.unwrap().shutdown(Shutdown::Both).unwrap();
                    //let's make this thread busy, without putting it in sleep
                } else if test_option == 2 {
                    let connection = connection.unwrap();
                    loop {
                        match connection.write_timeout() {
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    }

    fn u16_to_byte_array(x: u16) -> [u8; 2] {
        let b1: u8 = ((x >> 8) & 0xff) as u8;
        let b2: u8 = (x & 0xff) as u8;
        return [b1, b2];
    }

    struct MockStream {
        stream: String,
        flush_count: u8,
    }

    impl MockStream {
        fn new() -> Self {
            Self {
                stream: String::new(),
                flush_count: 0,
            }
        }
    }

    impl Write for MockStream {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            unimplemented!()
        }

        fn write_vectored(&mut self, _bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            unimplemented!()
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_count += 1;
            Ok(())
        }

        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            self.stream.push_str(std::str::from_utf8(buf).unwrap());
            Ok(())
        }

        fn by_ref(&mut self) -> &mut Self
        where
            Self: Sized,
        {
            unimplemented!()
        }
    }
}
