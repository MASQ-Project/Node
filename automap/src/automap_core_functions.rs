// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{AutomapError, AutomapErrorCause, Method, Transactor};
use crate::probe_researcher::request_probe;
use log::{info, warn};
use masq_lib::utils::find_free_port;
use std::env::Args;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Instant;

#[derive(Clone)]
pub struct TestParameters {
    pub probe_server_address: SocketAddr,
    pub hole_port: u16,
    pub user_specified_hole_port: bool,
    pub nopoke: bool,
    pub noremove: bool,
    pub permanent: bool,
}

pub type Tester = Box<dyn FnOnce(TestStatus, &TestParameters) -> Result<(), AutomapErrorCause>>;

pub struct AutomapParameters {
    pub protocols: Vec<Method>,
    pub test_parameters: TestParameters,
}

impl AutomapParameters {
    pub fn new(args: Args, probe_server_address_str: &str) -> Self {
        let probe_server_address =
            SocketAddr::from_str(probe_server_address_str).expect("Bad SocketAddr format");
        let mut protocols = vec![];
        let mut hole_port = 0;
        let mut user_specified_hole_port = true;
        let mut nopoke = false;
        let mut noremove = false;
        let mut permanent = false;
        args.into_iter().skip(1).for_each(|arg| match arg.as_str() {
            "pcp" => protocols.push(Method::Pcp),
            "pmp" => protocols.push(Method::Pmp),
            "igdp" => protocols.push(Method::Igdp),
            "nopoke" => nopoke = true,
            "noremove" => noremove = true,
            "permanent" => permanent = true,
            arg => {
                hole_port = arg
                    .parse::<u16>()
                    .unwrap_or_else(|_| panic!("Bad port number: {}", arg))
            }
        });
        if protocols.is_empty() {
            protocols = vec![Method::Pcp, Method::Pmp, Method::Igdp]
        }
        if hole_port == 0 {
            hole_port = find_free_port();
            user_specified_hole_port = false;
        }
        let test_parameters = TestParameters {
            probe_server_address,
            hole_port,
            user_specified_hole_port,
            nopoke,
            noremove,
            permanent,
        };
        Self {
            protocols,
            test_parameters,
        }
    }
}

pub fn tester_for(method: &Method) -> Tester {
    match *method {
        Method::Pcp => Box::new(test_pcp),
        Method::Pmp => Box::new(test_pmp),
        Method::Igdp => Box::new(test_igdp),
    }
}

pub fn test_pcp(
    status: TestStatus,
    test_parameters: &TestParameters,
) -> Result<(), AutomapErrorCause> {
    let transactor = PcpTransactor::default();
    let status = test_common(status, &transactor, test_parameters);
    analyze_status(status)
}

pub fn test_pmp(
    status: TestStatus,
    test_parameters: &TestParameters,
) -> Result<(), AutomapErrorCause> {
    let transactor = PmpTransactor::default();
    let status = test_common(status, &transactor, test_parameters);
    analyze_status(status)
}

pub fn test_igdp(
    status: TestStatus,
    test_parameters: &TestParameters,
) -> Result<(), AutomapErrorCause> {
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
    info!("");
    info!("=============={}===============", &transactor.method());
    let (router_ip, status) = find_router(status, transactor);
    let (public_ip, status) = seek_public_ip(status, router_ip, transactor);
    if status.fatal {
        return status;
    }
    let status = if parameters.nopoke {
        let status = status.begin_attempt(format!(
            "Expecting that a hole will already have been poked in the firewall at port {}",
            parameters.hole_port
        ));
        status.succeed()
    } else if parameters.permanent {
        poke_permanent_firewall_hole(parameters.hole_port, status, router_ip, transactor)
    }
    else {
        poke_firewall_hole(parameters.hole_port, status, router_ip, transactor)
    };
    let status = run_probe_test(status, parameters, public_ip);
    if status.fatal {
        return status;
    }
    if parameters.noremove {
        let status = status.begin_attempt(format!(
            "Terminating without closing firewall hole at port {}, as requested",
            parameters.hole_port
        ));
        status.succeed()
    } else {
        remove_firewall_hole(parameters.hole_port, status, router_ip, transactor)
    }
}

fn find_router(status: TestStatus, transactor: &dyn Transactor) -> (IpAddr, TestStatus) {
    if status.fatal {
        return (
            IpAddr::from_str("255.255.255.255").expect("Bad format"),
            status,
        );
    }
    let status = status.begin_attempt("Looking for routers on the subnet".to_string());
    match transactor.find_routers() {
        Ok(list) => {
            let found_router_ip = list[0];
            (found_router_ip, status.succeed())
        }
        Err(e) => (
            IpAddr::from_str("255.255.255.255").unwrap(),
            status.abort(e),
        ),
    }
}

fn seek_public_ip(
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> (IpAddr, TestStatus) {
    let null_ip = IpAddr::from_str("255.255.255.255").expect("Bad IP address");
    if status.fatal {
        return (null_ip, status);
    }
    let status = status.begin_attempt(format!(
        "Seeking public IP address from router at {}",
        router_ip
    ));
    match transactor.get_public_ip(router_ip) {
        Ok(public_ip) => (public_ip, status.succeed()),
        Err(e) => (null_ip, status.abort(e)),
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
    let status = status.begin_attempt(format!(
        "Poking a 3-second hole in the firewall for port {}...",
        test_port
    ));
    match transactor.add_mapping(router_ip, test_port, 5) {
        Ok(_) => status.succeed(),
        Err(e) if e == AutomapError::PermanentLeasesOnly => {
            poke_permanent_firewall_hole(test_port, status.permanent_only(), router_ip, transactor)
        }
        Err(e) => status.abort(e),
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
    let status = status.begin_attempt(format!(
        "Poking a permanent hole in the firewall for port {}...",
        test_port
    ));
    match transactor.add_permanent_mapping(router_ip, test_port) {
        Ok(_) => status.succeed(),
        Err(e) => status.abort(e),
    }
}

pub fn run_probe_test(
    status: TestStatus,
    parameters: &TestParameters,
    public_ip: IpAddr,
) -> TestStatus {
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
    let status = status.begin_attempt(format!(
        "Removing the port-{} hole in the firewall...",
        test_port
    ));
    match transactor.delete_mapping(router_ip, test_port) {
        Ok(_) => status.succeed(),
        Err(e) => {
            warn!(
                "You'll need to close port {} yourself in your router's administration pages. Sorry...I didn't do it on purpose...",
                test_port
            );
            status.fail(e)
        }
    }
}

fn analyze_status(status: TestStatus) -> Result<(), AutomapErrorCause> {
    if !status.cumulative_success {
        let msg = format!("Cumulative failure with no step error: {:?}", status);
        Err(status.step_error.expect(&msg).cause())
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TestStatus {
    pub step: usize,
    pub step_success: bool,
    pub step_error: Option<AutomapError>,
    pub cumulative_success: bool,
    pub fatal: bool,
    pub permanent_only: bool,
    pub started_at: Instant,
}

impl Default for TestStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl TestStatus {
    pub fn new() -> Self {
        Self {
            step: 1,
            step_success: true,
            step_error: None,
            cumulative_success: true,
            fatal: false,
            permanent_only: false,
            started_at: Instant::now(),
        }
    }

    pub fn begin_attempt(self, msg: String) -> Self {
        self.display(format!("{}. {}", self.step, msg));
        Self {
            step: self.step,
            step_success: self.step_success,
            step_error: self.step_error,
            cumulative_success: self.cumulative_success,
            fatal: self.fatal,
            permanent_only: self.permanent_only,
            started_at: Instant::now(),
        }
    }

    pub fn succeed(self) -> Self {
        let elapsed = Instant::now().duration_since(self.started_at);
        self.display(format!("...succeeded after {}ms", elapsed.as_millis()));
        Self {
            step: self.step + 1,
            step_success: true,
            step_error: self.step_error,
            cumulative_success: self.cumulative_success,
            fatal: false,
            permanent_only: self.permanent_only,
            started_at: self.started_at,
        }
    }

    pub fn fail(self, error: AutomapError) -> Self {
        let elapsed = Instant::now().duration_since(self.started_at);
        self.display(format!(
            "...failed after {}ms: {:?}",
            elapsed.as_millis(),
            &error
        ));
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: false,
            permanent_only: self.permanent_only,
            started_at: self.started_at,
        }
    }

    pub fn abort(self, error: AutomapError) -> Self {
        let elapsed = Instant::now().duration_since(self.started_at);
        self.display(format!(
            "...failed unrecoverably after {}ms: {:?}",
            elapsed.as_millis(),
            &error
        ));
        Self {
            step: self.step + 1,
            step_success: false,
            step_error: Some(error),
            cumulative_success: false,
            fatal: true,
            permanent_only: self.permanent_only,
            started_at: self.started_at,
        }
    }

    pub fn permanent_only(self) -> Self {
        let elapsed = Instant::now().duration_since(self.started_at);
        self.display(format!(
            "...failed after {}ms because this router accepts only permanent mappings",
            elapsed.as_millis()
        ));
        Self {
            step: self.step + 1,
            step_success: true,
            step_error: self.step_error,
            cumulative_success: self.cumulative_success,
            fatal: self.fatal,
            permanent_only: true,
            started_at: self.started_at,
        }
    }

    fn display(&self, msg: String) {
        info!("{}", msg);
    }
}
