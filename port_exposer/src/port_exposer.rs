// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use std::thread::JoinHandle;

static DEAD_STREAM_ERRORS: [ErrorKind; 5] = [
    ErrorKind::BrokenPipe,
    ErrorKind::ConnectionAborted,
    ErrorKind::ConnectionReset,
    ErrorKind::ConnectionRefused,
    ErrorKind::TimedOut,
];

#[derive(Debug, Clone)]
struct PortPair {
    loopback: u16,
    nic: u16,
}

#[derive(Debug)]
struct ListenerAndPort {
    listener: TcpListener,
    loopback_port: u16,
}

pub struct PortExposer {}

impl Default for PortExposer {
    fn default() -> PortExposer {
        PortExposer {}
    }
}

impl PortExposer {
    pub fn new() -> PortExposer {
        PortExposer {}
    }

    pub fn go(&self, args: Vec<String>) -> u8 {
        if args.len() <= 1 {
            panic!("Must provide port pairs: <loopback port>:<NIC port> ...")
        }
        eprintln!("Parameters are good: {:?}", args);

        let port_pairs = Self::make_port_pairs(args);
        eprintln!("Port pairs were parsed: {:?}", port_pairs);
        let laps = {
            port_pairs
                .into_iter()
                .map(|port_pair| {
                    eprintln!("Starting a listener on {:?}", port_pair);
                    let lap = Self::open_port(port_pair.clone());
                    eprintln!("Listener started on {:?}", port_pair);
                    lap
                })
                .collect::<Vec<ListenerAndPort>>()
        };
        eprintln!("Listeners and ports look good: {:?}", laps);
        let handles = laps
            .into_iter()
            .map(|lap| {
                thread::spawn(move || loop {
                    if let Ok((outside, inside)) = Self::make_connection(&lap) {
                        thread::spawn(move || {
                            Self::handle_stream(outside, inside);
                        });
                    }
                })
            })
            .collect::<Vec<JoinHandle<()>>>();
        eprintln!(
            "Main thread finished: waiting to join all of {} handles.",
            handles.len()
        );
        handles
            .into_iter()
            .for_each(|handle| handle.join().expect("Couldn't join thread"));
        0
    }

    fn make_port_pairs(args: Vec<String>) -> Vec<PortPair> {
        args.into_iter()
            .skip(1)
            .map(|arg| {
                let port_strs: Vec<&str> = arg.split(':').collect();
                if port_strs.len() != 2 {
                    panic!("A port pair is <loopback port>:<NIC port>, not {}", arg);
                }
                PortPair {
                    loopback: str::parse::<u16>(port_strs[0]).unwrap_or_else(|_| {
                        panic!("Couldn't convert '{}' to a port number", port_strs[0])
                    }),
                    nic: str::parse::<u16>(port_strs[1]).unwrap_or_else(|_| {
                        panic!("Couldn't convert '{}' to a port number", port_strs[1])
                    }),
                }
            })
            .collect()
    }

    fn open_port(port_pair: PortPair) -> ListenerAndPort {
        eprintln!(
            "Opening listener on port {} to connect to {}",
            port_pair.nic, port_pair.loopback
        );
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::from(0), port_pair.nic))
            .unwrap_or_else(|_| panic!("Couldn't bind TcpListener to 0.0.0.0:{}", port_pair.nic));
        eprintln!(
            "Opened listener on port {} to connect to {}",
            port_pair.nic, port_pair.loopback
        );
        ListenerAndPort {
            listener,
            loopback_port: port_pair.loopback,
        }
    }

    fn make_connection(lap: &ListenerAndPort) -> Result<(TcpStream, TcpStream), ()> {
        let local_addr = lap
            .listener
            .local_addr()
            .expect("No local address for listener");
        let (outside, peer_addr) = lap
            .listener
            .accept()
            .unwrap_or_else(|_| panic!("Couldn't accept incoming connection on {}", local_addr));
        eprintln!("Accepted connection from {} on {}", peer_addr, local_addr);
        let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, lap.loopback_port);
        match TcpStream::connect(target) {
            Ok(inside) => Ok((outside, inside)),
            Err(_) => {
                eprintln!("Couldn't connect from {} to {}", local_addr, target);
                outside
                    .shutdown(Shutdown::Both)
                    .expect("Couldn't shut down incoming connection");
                Err(())
            }
        }
    }

    fn handle_stream(outside_in: TcpStream, inside_out: TcpStream) {
        let outside_out = outside_in.try_clone().expect("Couldn't clone outside_in");
        let inside_in = inside_out.try_clone().expect("Couldn't clone inside_out");
        thread::spawn(move || Self::shovel_bits(outside_in, inside_out));
        Self::shovel_bits(inside_in, outside_out)
    }

    fn shovel_bits(mut in_stream: TcpStream, mut out_stream: TcpStream) {
        let mut buf = [0u8; 16384];
        loop {
            match in_stream.read(&mut buf) {
                Ok(0) => {
                    eprintln!(
                        "{} sent 0 bytes; closing connection",
                        in_stream.local_addr().unwrap()
                    );
                    out_stream.shutdown(Shutdown::Both).unwrap();
                    break;
                }
                Ok(len) => {
                    eprintln!(
                        "Shoveling {} bytes from {} to {}",
                        len,
                        in_stream.local_addr().unwrap(),
                        out_stream.local_addr().unwrap()
                    );
                    out_stream
                        .write_all(&buf[0..len])
                        .unwrap_or_else(|_| panic!("Couldn't write {} bytes", len));
                }
                Err(ref e) if DEAD_STREAM_ERRORS.contains(&e.kind()) => {
                    eprintln!(
                        "Connection from {} to {} died",
                        in_stream.local_addr().unwrap(),
                        out_stream.local_addr().unwrap()
                    );
                    break;
                }
                Err(e) => panic!("{}", e),
            }
        }
    }
}
