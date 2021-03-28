// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{AutomapError, Transactor, Method, AutomapErrorCause};
use crate::probe_researcher::{request_probe};
use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::env::Args;
use masq_lib::utils::find_free_port;

#[derive (Clone)]
pub struct TestParameters {
    pub probe_server_address: SocketAddr,
    pub hole_port: u16,
    pub nopoke: bool,
    pub noremove: bool,
}

pub type Tester = Box<dyn FnOnce(TestStatus, &TestParameters) -> Result<(), AutomapErrorCause>>;

pub struct AutomapParameters {
    pub protocols: Vec<Method>,
    pub test_parameters: TestParameters,
}

impl AutomapParameters {
    pub fn new (args: Args, probe_server_address_str: &str) -> Self {
        let probe_server_address = SocketAddr::from_str(probe_server_address_str).expect("Bad SocketAddr format");
        let mut protocols = vec![];
        let mut hole_port = 0;
        let mut nopoke = false;
        let mut noremove = false;
        args.into_iter().skip (1).for_each(|arg| {
            match arg.as_str() {
                "pcp" => protocols.push (Method::Pcp),
                "pmp" => protocols.push (Method::Pmp),
                "igdp" => protocols.push (Method::Igdp),
                "nopoke" => nopoke = true,
                "noremove" => noremove = true,
                arg => hole_port = arg.parse::<u16> ().expect (&format! ("Bad port number: {}", arg)),
            }
        });
        if protocols.is_empty() {
            protocols = vec![Method::Pcp, Method::Pmp, Method::Igdp]
        }
        if hole_port == 0 {
            hole_port = find_free_port();
        }
        let test_parameters = TestParameters {probe_server_address, hole_port, nopoke, noremove};
        Self {protocols, test_parameters}
    }
}

pub fn tester_for (method: &Method) -> Tester {
    match method {
        &Method::Pcp => Box::new (test_pcp),
        &Method::Pmp => Box::new (test_pmp),
        &Method::Igdp => Box::new (test_igdp),
    }
}

pub fn test_pcp(status: TestStatus, test_parameters: &TestParameters) -> Result<(), AutomapErrorCause> {
    let transactor = PcpTransactor::default();
    let status = test_common(status, &transactor, test_parameters);
    analyze_status(status)
}

pub fn test_pmp(status: TestStatus, test_parameters: &TestParameters) -> Result<(), AutomapErrorCause> {
    let transactor = PmpTransactor::default();
    let status = test_common(status, &transactor, test_parameters);
    analyze_status(status)
}

pub fn test_igdp(status: TestStatus, test_parameters: &TestParameters) -> Result<(), AutomapErrorCause> {
    let transactor = IgdpTransactor::default();
    let status = test_common(status, &transactor, test_parameters);
    analyze_status(status)
}

fn test_common(
    status: TestStatus,
    transactor: &dyn Transactor,
    parameters: &TestParameters,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    info!("=============={}===============", &transactor.method());
    let (router_ip, status) = find_router(status, transactor);
    let (public_ip, status) = seek_public_ip(status, router_ip, transactor);
    let status = if parameters.nopoke {
        info!("{}. Expecting that a hole will already have been poked in the firewall at port {}", status.step, parameters.hole_port);
        status.succeed()
    }
    else {
        poke_firewall_hole(parameters.hole_port, status, router_ip, transactor)
    };
    let status = run_probe_test(status, parameters, public_ip);
    let status = if parameters.noremove {
        info!("{}. Terminating without closing firewall hole at port {}, as requested", status.step, parameters.hole_port);
        status.succeed()
    }
    else {
        remove_firewall_hole (parameters.hole_port, status, router_ip, transactor)
    };
    status
}

fn find_router(
    status: TestStatus,
    transactor: &dyn Transactor,
) -> (IpAddr, TestStatus) {
    if status.fatal {
        return (IpAddr::from_str("0.0.0.0:0").expect("Bad format"), status);
    }
    info!("{}. Looking for routers on the subnet...", status.step);
    let timer = Timer::new();
    match transactor.find_routers() {
        Ok(list) => {
            let found_router_ip = list[0];
            info!(
                "...found a router after {} at {}.",
                timer.ms(),
                found_router_ip
            );
            (found_router_ip, status.succeed())
        }
        Err(e) => {
            info!("...failed after {}: {:?}", timer.ms(), e);
            (IpAddr::from_str("0.0.0.0").unwrap(), status.fail(e))
        }
    }
}

fn seek_public_ip(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> (IpAddr, TestStatus) {
    let null_ip = IpAddr::from_str("127.0.0.0").expect("Bad IP address");
    if status.fatal {
        return (null_ip, status)
    }
    info!("{}. Seeking public IP address...", status.step);
    let timer = Timer::new();
    match transactor.get_public_ip(router_ip) {
        Ok(public_ip) => {
            info! ("...found after {}: {}  Is that correct? (Maybe don't publish this without redacting it?)", timer.ms(), public_ip);
            (public_ip, status.succeed())
        }
        Err(e) => {
            info!("...failed after {}: {:?}", timer.ms(), e);
            (null_ip, status.fail(e))
        }
    }
}

fn poke_firewall_hole(
    test_port: u16,
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), test_port);
        let _socket =
            match UdpSocket::bind(socket_addr) {
                Ok(s) => s,
                Err(e) => {
                    info!("Failed to open local port {}; giving up. ({:?})", test_port, e);
                    return status.abort(AutomapError::SocketBindingError(
                        format!("{:?}", e),
                        socket_addr,
                    ))
                }
            };
    }
    info!(
        "{}. Poking a 3-second hole in the firewall for port {}...",
        status.step, test_port
    );
    let timer = Timer::new();
    match transactor.add_mapping(router_ip, test_port, 5) {
        Ok(delay) => {
            info!(
                "...success after {}! Recommended remap delay is {} seconds.",
                timer.ms(),
                delay
            );
            status.succeed().permanent_only(false)
        }
        Err(e) if e == AutomapError::PermanentLeasesOnly => {
            let warning = format!(
                "{} detected but this router doesn't like keeping track of holes and closing them on a schedule. We'll try a permanent one.",
                transactor.method()
            );
            warn!("{}", warning);
            poke_permanent_firewall_hole(test_port, status.succeed().permanent_only(true), router_ip, transactor)
        }
        Err(e) => {
            info!("...failed after {}: {:?}", timer.ms(), e);
            status.fail(e)
        }
    }
}

fn poke_permanent_firewall_hole(
    test_port: u16,
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    info!(
        "{}. Poking a permanent hole in the firewall for port {}...",
        status.step, test_port
    );
    let timer = Timer::new();
    match transactor.add_permanent_mapping(router_ip, test_port) {
        Ok(delay) => {
            info!(
                "...success after {}! Recommended remap delay is {} seconds--should be forever.",
                timer.ms(),
                delay
            );
            status.succeed().permanent_only(true)
        }
        Err(e) => {
            info!("...failed after {}: {:?}", timer.ms(), e);
            status.fail(e)
        }
    }
}

pub fn run_probe_test(status: TestStatus, parameters: &TestParameters, public_ip: IpAddr) -> TestStatus {
    request_probe(status, parameters, public_ip, 3000, 5000)
}

#[allow(clippy::result_unit_err)]
pub fn remove_firewall_hole(
    test_port: u16,
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    info!(
        "{}. Removing the port-{} hole in the firewall...",
        status.step, test_port
    );
    let timer = Timer::new();
    match transactor.delete_mapping(router_ip, test_port) {
        Ok(_) => {
            info!("...success after {}!", timer.ms());
            status.succeed()
        }
        Err(e) => {
                warn!("...failed after {}: {:?}", timer.ms(), e);
                let warning =  format!("You'll need to close port {} yourself in your router's administration pages. \
            .\nYou may also look into the log. \nSorry...I didn't do it on purpose...", test_port);
                warn!("{}", warning);
            status.fail(e)
        }
    }
}

fn analyze_status (status: TestStatus) -> Result<(), AutomapErrorCause> {
    if !status.cumulative_success {
        Err (status.step_error.expect("Cumulative failure with no step error").cause())
    } else {
        Ok(())
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

#[derive (Clone)]
pub struct TestStatus {
    pub step: usize,
    pub step_success: bool,
    pub step_error: Option<AutomapError>,
    pub cumulative_success: bool,
    pub fatal: bool,
    pub permanent_only: Option<bool>,
}

impl TestStatus {
    pub fn new() -> Self {
        Self {
            step: 1,
            step_success: true,
            step_error: None,
            cumulative_success: true,
            fatal: false,
            permanent_only: None,
        }
    }

    pub fn succeed(self) -> Self {
        Self {
            step: self.step + 1,
            step_success: true,
            step_error: None,
            cumulative_success: self.cumulative_success,
            fatal: false,
            permanent_only: self.permanent_only,
        }
    }

    pub fn fail(self, error: AutomapError) -> Self {
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: false,
            permanent_only: self.permanent_only,
        }
    }

    pub fn abort(self, error: AutomapError) -> Self {
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: true,
            permanent_only: self.permanent_only,
        }
    }

    pub fn permanent_only(self, permanent_only: bool) -> Self {
        Self {
            step: self.step,
            step_success: self.step_success,
            step_error: self.step_error,
            cumulative_success: self.cumulative_success,
            fatal: self.fatal,
            permanent_only: Some(permanent_only),
        }
    }
}
