// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use automap_lib::comm_layer::igdp::IgdpTransactor;
use automap_lib::comm_layer::pcp::PcpTransactor;
use automap_lib::comm_layer::pmp::PmpTransactor;
use automap_lib::comm_layer::{AutomapError, Transactor};
use masq_lib::utils::{find_free_port, localhost};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket, TcpListener};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Copy, Clone,PartialEq,Debug)]
struct TestConfig{
    test_to_run: [bool;3],
    port: Option<u16>,
    no_remove: bool
}

fn build_test_config(args: Vec<String>)->Result<TestConfig,String>{
    let mut pure_args = args.into_iter().skip(1).skip_while(|elem|elem.trim()=="automap");
    Ok(TestConfig{
        test_to_run:
    match pure_args.next() {
        name if name.is_none() => return Ok(TestConfig{
            test_to_run: [true,true,true],
            port: None,
            no_remove: false
        }),
        name if &*(name.as_ref().unwrap()) == "igdp" => [true,false,false],
        name if &*(name.as_ref().unwrap()) == "pmp" => [false,false,true],
        name if &*(name.as_ref().unwrap()) == "pcp" => [false,true,false],
        name => return Err(format!("Unknown argument: {}",name.unwrap()))
    },
        port: match pure_args.next(){
            Some(value) => match value.parse::<u16>(){
                Ok(port) => match TcpListener::bind(format!("{}:{}",localhost(),port)){
                    Ok(_) => Some(port),
                    Err(_) => return Err("The chosen port is not free".to_string())
                },
                Err(e) => return Err(format!("Port: {}",e))
            },
            None => None
        },
        no_remove:match pure_args.next(){
            None => false,
            Some(value) if &value == "noremove" => true,
            arg if arg.is_some() => return Err(format!("Unknown argument: {}",arg.unwrap())),
            _ => unreachable!()
        }
    })
}


#[cfg(test)]
mod tests{
    use crate::{TestConfig, build_test_config};
    use std::net::TcpListener;
    use masq_lib::utils::localhost;

    #[test]
    fn build_test_config_for_standard_automap(){

        let args = vec!["C:\\Users\\Public".to_string(),"automap".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Ok(TestConfig{
            test_to_run: [true,true,true],
            port: None,
            no_remove: false
        }))
    }

    #[test]
    fn build_test_config_for_standard_automap_not_counting_path(){

        let args = vec!["automap".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Ok(TestConfig{
            test_to_run: [true,true,true],
            port: None,
            no_remove: false
        }))
    }

    #[test]
    fn build_test_config_returns_error_if_unknown_parameter_after_automap(){

        let args = vec!["automap".to_string(),"super_test".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("Unknown argument: super_test".to_string()))
    }

    #[test]
    fn build_test_config_allows_to_choose_specific_test_type_and_returns_configuration_because_no_other_args_supplied(){

        let args_collection = vec![vec!["automap".to_string(),"pcp".to_string()],vec!["automap".to_string(),"pmp".to_string()],vec!["automap".to_string(),"igdp".to_string()]];

        let results = args_collection.into_iter().map(|vec|build_test_config(vec)).collect::<Vec<_>>();

        assert_eq!(results,
        vec![Ok(TestConfig{
            test_to_run: [false,true,false],
            port: None,
            no_remove: false
        }),
        Ok(TestConfig{
            test_to_run: [false,false,true],
            port: None,
            no_remove: false
        }),
        Ok(TestConfig{
            test_to_run: [true,false,false],
            port: None,
            no_remove: false
        }),
        ])
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_which_is_free(){

        let args = vec!["automap".to_string(),"igdp".to_string(),"16000".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Ok(TestConfig{
            test_to_run: [true,false,false],
            port: Some(16000),
            no_remove: false
        }))
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_but_bad_port(){

        let _ = TcpListener::bind(format!("{}:{}",localhost(),40)).unwrap();

        let args = vec!["automap".to_string(),"igdp".to_string(),"40".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("The chosen port is not free".to_string()))
    }

    #[test]
    fn build_test_config_specific_test_including_specific_port_but_cannot_produce_a_number(){

        let args = vec!["automap".to_string(),"igdp".to_string(),"45kk".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("Port: invalid digit found in string".to_string()))
    }

    #[test]
    fn build_test_config_with_all_params_supplied_works(){

        let args = vec!["automap".to_string(),"igdp".to_string(),"16444".to_string(),"noremove".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Ok(TestConfig{
            test_to_run: [true,false,false],
            port: Some(16444),
            no_remove: true
        }))
    }

    #[test]
    fn build_test_config_with_all_params_supplied_but_misspelled_3rd_value(){

        let args = vec!["automap".to_string(),"igdp".to_string(),"16444".to_string(),"norrrrremove".to_string()];

        let result = build_test_config(args);

        assert_eq!(result, Err("Unknown argument: norrrrremove".to_string()))
    }




}




pub fn main() {

    let config = TestConfig{
        test_to_run: [true,true,true],
        port: None,
        no_remove: false
    };

    config.test_to_run.iter().zip([test_igdp(config), test_pcp(config), test_pmp(config)].iter()).for_each(|test|if *test.0 {*test.1});
}

fn test_pcp(test_config:TestConfig) {
    println!("\n====== PCP TESTS ======");
    let transactor = PcpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let status = test_common(status, router_ip, &transactor,test_config);
    if status.cumulative_success {
        println!(
            "====== PCP is implemented on your router and we can successfully employ it ======\n"
        )
    } else {
        println! ("====== Either PCP is not implemented on your router or we're not doing it right ======\n")
    }
}

fn test_pmp(test_config:TestConfig) {
    println!("\n====== PMP TESTS ======");
    let transactor = PmpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let status = test_common(status, router_ip, &transactor,test_config);
    if status.cumulative_success {
        println!(
            "====== PMP is implemented on your router and we can successfully employ it ======\n"
        )
    } else {
        println! ("====== Either PMP is not implemented on your router or we're not doing it right ======\n")
    }
}

fn test_igdp(test_config:TestConfig) {
    println!("\n====== IGDP TESTS ======");
    let transactor = IgdpTransactor::default();
    let (router_ip, status) = find_router(TestStatus::new(), &transactor);
    let status = seek_public_ip(status, router_ip, &transactor);
    let (port, mut status) = poke_firewall_hole(status, router_ip, &transactor,test_config.port);
    let status = if !test_config.no_remove && status.step_success {
        remove_firewall_hole(port, status, router_ip, &transactor)
    } else if status
        .step_error
        .as_ref()
        .expect("Step failure, but no error recorded!")
        == &AutomapError::AddMappingError("OnlyPermanentLeasesSupported".to_string())
    {
        println! ("This router doesn't like keeping track of holes and closing them on a schedule. We'll try a permanent one.");
        status.cumulative_success = true; // adjustment for retry
        let (port, status) = poke_permanent_firewall_hole(status, router_ip, &transactor,test_config.port);
        if !test_config.no_remove && status.step_success {
            remove_permanent_firewall_hole(port, status, router_ip, &transactor)
        } else {
            status
        }
    } else {
        status
    };
    if status.cumulative_success {
        println!(
            "====== IGDP is implemented on your router and we can successfully employ it ======\n"
        )
    } else {
        println! ("====== Either IGDP is not implemented on your router or we're not doing it right ======\n")
    }
}

fn test_common(status: TestStatus, router_ip: IpAddr, transactor: &dyn Transactor,test_config:TestConfig) -> TestStatus {
    let status = seek_public_ip(status, router_ip, transactor);
    let (port, mut status) = poke_firewall_hole(status, router_ip, transactor,test_config.port);
    if !test_config.no_remove && status.step_success {
        status = remove_firewall_hole(port, status, router_ip, transactor);
    }
    status
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
    spec_port: Option<u16>
) -> (u16, TestStatus) {
    if status.fatal {
        return (0, status);
    }
    let port = if let Some(port) = spec_port{port} else {find_free_port()};
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
    spec_port: Option<u16>
) -> (u16, TestStatus) {
    if status.fatal {
        return (0, status);
    }
    let port = if let Some(port) = spec_port{port} else {find_free_port()};
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
    port: u16,
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    println!(
        "{}. Removing the port-{} hole in the firewall...",
        status.step, port
    );
    let timer = Timer::new();
    match transactor.delete_mapping(router_ip, port) {
        Ok(_) => {
            println!("...success after {}!", timer.ms());
            status.succeed()
        }
        Err(e) => {
            println! ("...failed after {}: {:?} (Note: the hole will disappear on its own in a few seconds.)", timer.ms(), e);
            status.fail(e)
        }
    }
}

fn remove_permanent_firewall_hole(
    port: u16,
    status: TestStatus,
    router_ip: IpAddr,
    transactor: &dyn Transactor,
) -> TestStatus {
    if status.fatal {
        return status;
    }
    println!(
        "{}. Removing the port-{} hole in the firewall...",
        status.step, port
    );
    let timer = Timer::new();
    match transactor.delete_mapping(router_ip, port) {
        Ok(_) => {
            println! ("...success after {}, but IGDP only works with permanent ports on this router. Argh.", timer.ms());
            status.succeed()
        }
        Err(e) => {
            println!("...failed after {}: {:?}", timer.ms(), e);
            println!("This is a problem! You have a permanent hole in your firewall that I can't");
            println!(
                "close. You'll need to close it yourself in your router's administration pages."
            );
            println!("Sorry...I didn't do it on purpose...");
            status.fail(e)
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
