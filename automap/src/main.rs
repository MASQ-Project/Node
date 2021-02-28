// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::comm_layer::pmp::PmpTransactor;
use automap_lib::comm_layer::Transactor;
use automap_lib::first_level_test_bodies::{test_igdp, test_pcp, test_pmp};
use masq_lib::utils::find_free_port;
use std::io::{ErrorKind, Read, Write, Error};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub fn main() {
    prepare_router_or_report_failure(Box::new(test_pcp), Box::new(test_pmp), Box::new(test_igdp));
}

#[derive(PartialEq, Debug)]
enum Method {
    Pmp,
    Pcp,
    Igdp,
}

struct LevelTwoTransferor {
    method: Method,
    ip: IpAddr,
    port: u16,
    transactor: Box<dyn Transactor>,
}

fn prepare_router_or_report_failure(
    test_pcp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_pmp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
    test_igdp: Box<dyn FnOnce() -> Result<(IpAddr, u16, Box<dyn Transactor>), String>>,
) -> Result<LevelTwoTransferor, Vec<String>> {
    let mut collector: Vec<String> = vec![];
    match test_pcp() {
        Ok((ip, port, transactor)) => {
            return Ok(LevelTwoTransferor {
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
            return Ok(LevelTwoTransferor {
                method: Method::Pmp,
                ip,
                port,
                transactor,
            })
        }
        Err(e) => collector.push(e),
    };
    match test_igdp() {
        Ok((ip, port, transactor)) => {
            return Ok(LevelTwoTransferor {
                method: Method::Igdp,
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

//change that so you can use the error string messaging
fn deploy_background_listener(
    socket_addr: SocketAddr,
    listener_message_sync: &Arc<Mutex<Vec<(u16, String)>>>,
) -> Result<(), ()> {
    let listener_message = listener_message_sync;
    let listener_message_clone = Arc::clone(&listener_message);
    let mut error_writer = String::new();
    thread::spawn(move || {
        let listener_opt = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
                Ok(stream) => Some(stream),
                Err(e) => {
                    error_writer.push_str(&format!("Test is unsuccessful; starting to cancel it: {}", e));
                    None
                }
        };

        let mut buffer = [0u8; 2];
        if let Some(mut stream) = listener_opt {
            eprintln!("maaaaaaaaaaaaaaaaark");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)));
            stream.set_nonblocking(true);
            let mut loop_counter:u16 = 0;
            loop {
                if stream.peer_addr().is_ok() {
                    match stream.read(&mut buffer) {
                        Ok(_) => {
                            let converted_to_txt = u16::from_be_bytes(buffer);
                            eprintln!("maaaaaaaaaaaaaaaaark11111111");
                            listener_message_clone
                                .lock()
                                .unwrap()
                                .push((converted_to_txt, String::new()));
                            break
                        },
                        Err(e) if loop_counter < 10000 => {
                            &error_writer.push_str(&format!("{}", e));
                            eprintln!("maaaaaaaaaaaaaaaaark222222222");
                            thread::sleep(Duration::from_millis(1));
                            loop_counter += 1;
                            continue
                        },
                        Err(e) if loop_counter >= 10000 => {
                            &error_writer.push_str(&format!("{}", e));
                            eprintln!("maaaaaaaaaaaaaaaaark222222222");
                            listener_message_clone
                                .lock()
                                .unwrap()
                                .push((0, error_writer));
                            break
                        }
                        _ =>  {error_writer.push_str("Connection broke forcibly by the remote part");
                        listener_message_clone
                        .lock()
                        .unwrap()
                        .push((0, error_writer)); break}
                    }
                } else {
                    error_writer.push_str("Connection broke forcibly by the remote part");
                    listener_message_clone
                        .lock()
                        .unwrap()
                        .push((0, error_writer)); break}
            }
        } else {
            listener_message_clone
                .lock()
                .unwrap()
                .push((0, error_writer))
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        deploy_background_listener, mock_router_test_finding_ip_and_doing_mapping,
        mock_router_test_unsuccessful, prepare_router_or_report_failure,
        test_stream_acceptor_and_probe_8875_imitator, Method,
    };
    use automap_lib::comm_layer::pmp::PmpTransactor;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::thread;

    #[test]
    fn prepare_router_or_report_failure_retrieves_ip() {
        let result = prepare_router_or_report_failure(
            Box::new(mock_router_test_unsuccessful),
            Box::new(mock_router_test_finding_ip_and_doing_mapping),
            Box::new(mock_router_test_unsuccessful),
        );

        //sadly all those types implementing Transactor cannot implement PartialEq each
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
            Box::new(mock_router_test_unsuccessful),
            Box::new(mock_router_test_unsuccessful),
            Box::new(mock_router_test_unsuccessful),
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

    // #[test]
    // fn deploy_background_listener_terminates_itself_safely_after_time_limit_passes() {
    //     let start_point = std::time::Instant::now();
    //     deploy_background_listener();
    //     let time_difference = start_point.elapsed();
    //
    //     assert!(time_difference > Duration::from_secs(10));
    //     assert!(time_difference < Duration::from_millis(10100));
    // }

    #[test]
    fn deploy_background_listener_with_good_probe_works() {
        let port = 7000;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        test_stream_acceptor_and_probe_8875_imitator(true,None,port);
        assert!(process_result.is_ok());
        //we need to wait for the execution in the background thread
        thread::sleep(Duration::from_millis(200));
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 8875);
        assert!(listener_result[0].1.is_empty())
    }

    #[test]
    fn deploy_background_listener_without_getting_echo_reports_that_correctly_after_connection_interrupted() {
        let port = 7001;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![(0,String::new())]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        test_stream_acceptor_and_probe_8875_imitator(false,Some(5),port);
        assert!(process_result.is_ok());
        thread::sleep(Duration::from_millis(200));
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 0);
        assert_eq!(listener_result[0].1,"A connection attempt failed because the connected party did not \
         properly respond after a period of time, or established connection failed because connected host has failed to respond. (os error 10060)".to_string())
    }

    #[test]
    fn deploy_background_listener_without_getting_echo_terminates_alone_after_connection_lasts_too_long() {
        let port = 7003;
        let socket = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            port,
        ));
        let listener_result_arc_mut: Arc<Mutex<Vec<(u16, String)>>> = Arc::new(Mutex::new(vec![]));
        let process_result = deploy_background_listener(socket, &listener_result_arc_mut);
        test_stream_acceptor_and_probe_8875_imitator(false,Some(15),port);
        assert!(process_result.is_ok());
        let listener_result = listener_result_arc_mut.lock().unwrap();
        assert_eq!(listener_result[0].0, 0);
        assert_eq!(listener_result[0].1,"Test is unsuccessful; starting to cancel it".to_string())
    }


}

fn mock_router_test_finding_ip_and_doing_mapping(
) -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
    Ok((
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        4444,
        Box::new(PmpTransactor::new()),
    ))
}

fn mock_router_test_unsuccessful() -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
    Err(String::from("Test ended unsuccessfully"))
}

fn test_stream_acceptor_and_probe_8875_imitator(send_probe:bool,secs:Option<u64>,port:u16) {
    let listener = TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::from_str("127.0.0.1").unwrap(),
        port,
    ))
    .unwrap();
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) => continue,
        }
    };
    if send_probe {
        let message = u16_to_byte_array(8875);
        stream.write_all(&message).unwrap();
    } else { thread::sleep(Duration::from_secs(secs.unwrap())) }

}



fn u16_to_byte_array(x: u16) -> [u8; 2] {
    let b1: u8 = ((x >> 8) & 0xff) as u8;
    let b2: u8 = (x & 0xff) as u8;
    return [b1, b2];
}
















//change that so you can use the error string messaging
// fn deploy_background_listener(socket_addr: SocketAddrV4,listener_message_sync:Arc<Mutex<Vec<(u16,String)>>>)->Result<u16,String>{
//     let listener_message = listener_message_sync;
//     let listener_message_clone = Arc::clone(&listener_message);
//     let mut error_writer = String::new();
//     let handle = thread::spawn(move||{
//         let listener = TcpListener::bind(socket_addr)
//             .expect("failed to bind to the chosen port");
//         listener.set_nonblocking(true)
//             .expect("couldn't set up a nonblocking probe listener");
//         let mut counter = 0u8;
//         let stream: Option<TcpStream> = loop {
//             match listener.accept() {
//                 Ok((stream, _)) => break Some(stream),
//                 Err(e) if e.kind() == ErrorKind::ConnectionRefused && counter < 250 => {
//                     counter += 1;
//                     continue
//                 },
//                 Err(e) if e.kind() == ErrorKind::ConnectionRefused && counter == 250 =>
//                     {
//                         error_writer.push_str(&format!("Attempts exhausted: {};", e));
//                         break None
//                     },
//                 Err(e) => {
//                     error_writer.push_str(&format!("{};", e));
//                     break None
//                 }
//             }
//         };
//         let mut buffer = [0u8; 2];
//         if let Some(mut stream) = stream {
//             stream.set_read_timeout(Some(Duration::from_secs(9)))
//                 .expect("failed to set up read time out for probe listener");
//             match stream.read(&mut buffer){
//                 Ok(_) => {
//                     let converted_to_txt = u16::from_be_bytes(buffer);
//                     listener_message_clone.lock().unwrap().push((converted_to_txt,String::new()))
//                 },
//                 Err(e) => {error_writer.push_str(&format!("{}",e));
//                     listener_message_clone.lock().unwrap().push((0,error_writer))}
//             }
//         } else {listener_message_clone.lock().unwrap().push((0,error_writer))}
//     });
//
//     //must go away
//     handle.join().expect("thread of the probe listener is hanging");
//
//     Err(String::new())
// }
