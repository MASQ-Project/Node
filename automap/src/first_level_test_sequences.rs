// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{AutomapError, Transactor};
use masq_lib::utils::find_free_port;
use masq_lib::short_writeln;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::io::Write;
use crate::probe_researcher::LevelTwoShifter;

pub fn test_pcp() -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
    let transactor = PcpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let (status, port) = test_common(status, router_ip, &transactor);
    if !status.cumulative_success {
        Err(String::from(
            "Either PCP is not implemented on your router or we're not doing it right\n",
        ))
    } else {
        Ok((router_ip, port, Box::new(transactor)))
    }
}

pub fn test_pmp() -> Result<(IpAddr, u16, Box<dyn Transactor>), String> {
    let transactor = PmpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let (status, port) = test_common(status, router_ip, &transactor);
    if !status.cumulative_success {
        Err(String::from(
            "Either PMP is not implemented on your router or we're not doing it right\n",
        ))
    } else {
        Ok((router_ip, port, Box::new(transactor)))
    }
}

pub fn test_igdp() -> Result<(IpAddr, u16, Box<dyn Transactor>,bool), String> {
    let transactor = IgdpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let status = seek_public_ip(status, router_ip, &transactor);
    let (mut port, mut status) = poke_firewall_hole(status, router_ip, &transactor);
    let mut permanent_hole= false;
    let status = if status.step_success {
        status // remove_firewall_hole(port, status, router_ip, &transactor)
    } else if status
        .step_error
        .as_ref()
        .expect("Step failure, but no error recorded!")
        == &AutomapError::AddMappingError("OnlyPermanentLeasesSupported".to_string())
    {
        println! ("This router doesn't like keeping track of holes and closing them on a schedule. We'll try a permanent one.");
        status.cumulative_success = true; // adjustment for retry
        let (port_permanent, status) = poke_permanent_firewall_hole(status, router_ip, &transactor);
        port = port_permanent;
        permanent_hole = true;
        // if status.step_success {
        //     remove_permanent_firewall_hole(port, status, router_ip, &transactor)
        // } else {
        status
        //}
    } else {
        status
    };
    if !status.cumulative_success {
        Err(String::from(
            "Either IGDP is not implemented on your router or we're not doing it right\n",
        ))
    } else {
        Ok((router_ip, port, Box::new(transactor),permanent_hole))
    }
}

fn test_common(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> (TestStatus, u16) {
    let status = seek_public_ip(status, router_ip, transactor);
    let (port, status) = poke_firewall_hole(status, router_ip, transactor);
    // if status.step_success {
    //     status = remove_firewall_hole(port, status, router_ip, transactor);
    // }
    (status, port)
}

fn find_router(status: TestStatus, transactor: &dyn Transactor) -> (IpAddr, TestStatus) {
    println!("{}. Looking for routers on the subnet...", status.step);
    let timer = Timer::new();
    match transactor.find_routers() {
        Ok(list) => {
            let found_router_ip = list[0];
            println!(
                "...found a router after {} at {}.",
                timer.ms(),
                found_router_ip
            );
            (found_router_ip, status.succeed())
        }
        Err(e) => {
            println!("...failed after {}: {:?}", timer.ms(), e);
            (IpAddr::from_str("0.0.0.0").unwrap(), status.fail(e))
        }
    }
}

fn seek_public_ip(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    println!("{}. Seeking public IP address...", status.step);
    let timer = Timer::new();
    match transactor.get_public_ip(router_ip) {
        Ok(public_ip) => {
            println! ("...found after {}: {}  Is that correct? (Maybe don't publish this without redacting it?)", timer.ms(), public_ip);
            status.succeed()
        }
        Err(e) => {
            println!("...failed after {}: {:?}", timer.ms(), e);
            status.fail(e)
        }
    }
}

fn poke_firewall_hole(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> (u16, TestStatus) {
    if status.fatal {
        return (0, status);
    }
    let port = find_free_port();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let _socket =
        match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)) {
            Ok(s) => s,
            Err(e) => {
                println!("Failed to open local port {}; giving up. ({:?})", port, e);
                return (
                    port,
                    status.abort(AutomapError::SocketBindingError(
                        format!("{:?}", e),
                        socket_addr,
                    )),
                );
            }
        };
    println!(
        "{}. Poking a 3-second hole in the firewall for port {}...",
        status.step, port
    );
    let timer = Timer::new();
    match transactor.add_mapping(router_ip, port, 5) {
        Ok(delay) => {
            println!(
                "...success after {}! Recommended remap delay is {} seconds.",
                timer.ms(),
                delay
            );
            (port, status.succeed())
        }
        Err(e) => {
            println!("...failed after {}: {:?}", timer.ms(), e);
            (port, status.fail(e))
        }
    }
}

fn poke_permanent_firewall_hole(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> (u16, TestStatus) {
    if status.fatal {
        return (0, status);
    }
    let port = find_free_port();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let _socket =
        match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)) {
            Ok(s) => s,
            Err(e) => {
                println!("Failed to open local port {}; giving up. ({:?})", port, e);
                return (
                    port,
                    status.abort(AutomapError::SocketBindingError(
                        format!("{:?}", e),
                        socket_addr,
                    )),
                );
            }
        };
    println!(
        "{}. Poking a permanent hole in the firewall for port {}...",
        status.step, port
    );
    let timer = Timer::new();
    match transactor.add_mapping(router_ip, port, 0) {
        Ok(delay) => {
            println!(
                "...success after {}! Recommended remap delay is {} seconds.",
                timer.ms(),
                delay
            );
            (port, status.succeed())
        }
        Err(e) => {
            println!("...failed after {}: {:?}", timer.ms(), e);
            (port, status.fail(e))
        }
    }
}

fn remove_firewall_hole(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    params: LevelTwoShifter,
) -> () {
    short_writeln!(stdout,
        "Removing the port-{} hole in the firewall...", params.port
    );
    let timer = Timer::new();
    match params.transactor.delete_mapping(params.ip, params.port) {
        Ok(_) => {
            short_writeln!(stdout,"...success after {}!", timer.ms());
        }
        Err(e) => {
            short_writeln!(stderr,"...failed after {}: {:?} (Note: the hole will disappear on its own in a few seconds.)", timer.ms(), e);
        }
    }
}

fn remove_permanent_firewall_hole(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    params: LevelTwoShifter,
) -> (){
    short_writeln!(stdout,
        "Removing the port-{} hole in the firewall...", params.port
    );
    let timer = Timer::new();
    match params.transactor.delete_mapping(params.ip, params.port) {
        Ok(_) => {
            short_writeln!(stdout,"...success after {}, but IGDP only works with permanent ports on this router. Argh.", timer.ms());
        }
        Err(e) => {
            short_writeln!(stderr,"...failed after {}: {:?}", timer.ms(), e);
            short_writeln!(stderr,"This is a problem! You have a permanent hole in your firewall that I can't");
            short_writeln!(stderr,
                "close. You'll need to close it yourself in your router's administration pages."
            );
            short_writeln!(stderr,"Sorry...I didn't do it on purpose...");
        }
    }
}

struct Timer {
    began_at: Instant,
}

impl Timer {
    pub fn new() -> Self {
        Self {
            began_at: Instant::now(),
        }
    }

    pub fn stop(self) -> Duration {
        let ended_at = Instant::now();
        ended_at.duration_since(self.began_at)
    }

    pub fn ms(self) -> String {
        let interval = self.stop();
        format!("{}ms", interval.as_millis())
    }
}

struct TestStatus {
    step: usize,
    step_success: bool,
    step_error: Option<AutomapError>,
    cumulative_success: bool,
    fatal: bool,
}

impl TestStatus {
    fn new() -> Self {
        Self {
            step: 1,
            step_success: true,
            step_error: None,
            cumulative_success: true,
            fatal: false,
        }
    }

    fn succeed(self) -> Self {
        Self {
            step: self.step + 1,
            step_success: true,
            step_error: None,
            cumulative_success: self.cumulative_success,
            fatal: false,
        }
    }

    fn fail(self, error: AutomapError) -> Self {
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: false,
        }
    }

    fn abort(self, error: AutomapError) -> Self {
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: true,
        }
    }
}
