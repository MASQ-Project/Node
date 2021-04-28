// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::{AutomapError, Transactor};
use masq_lib::utils::AutomapProtocol;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use std::net::IpAddr;

const MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive (PartialEq, Clone, Debug)]
pub enum AutomapChange {
    NewIp (IpAddr),
}

unsafe impl Send for AutomapChange {}

pub type ChangeHandler = Box<dyn Fn (AutomapChange) + Send>;

pub trait AutomapControl {
    fn establish_mapping (
        &mut self,
        port: u16,
        protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler
    ) -> Result<(AutomapProtocol, IpAddr), AutomapError>;

    fn remove_mapping(&self) -> Result<(), AutomapError>;
}

#[derive (PartialEq, Debug, Clone)]
struct AutomapControlRealInner {
    router_ip: IpAddr,
    protocol: AutomapProtocol,
    port: u16,
}

pub struct AutomapControlReal {
    transactors: Vec<Box<dyn Transactor>>,
    inner_opt: Option<AutomapControlRealInner>,
}

impl AutomapControl for AutomapControlReal {
    fn establish_mapping (
        &mut self,
        port: u16,
        protocol_opt: Option<AutomapProtocol>,
        change_handler: ChangeHandler,
    ) -> Result<(AutomapProtocol, IpAddr), AutomapError> {
        let box_change_handler = Box::new (change_handler);
        match protocol_opt {
            Some (protocol) => {
                let (_, router_ip, public_ip) = self.try_protocol (port, protocol)?;
                let transactor = self.transactors
                    .iter_mut()
                    .find (|t| t.method() == protocol).expect (&format!("Missing Transactor for {}", protocol));
                transactor.start_change_handler(box_change_handler)?;
                self.inner_opt = Some (AutomapControlRealInner {
                    router_ip,
                    protocol,
                    port
                });
                Ok((protocol, public_ip))
            },
            None => {
                let init: Option<(&mut Box<dyn Transactor>, IpAddr, IpAddr)> = None;
                let result = self.transactors.iter_mut().fold (init, |so_far, transactor| {
                    match so_far {
                        Some (_) => so_far,
                        None => match AutomapControlReal::try_transactor (port, transactor) {
                            Ok((_, router_ip, public_ip)) => Some ((transactor, router_ip, public_ip)),
                            Err (_) => None,
                        }
                    }
                });
                match result {
                    Some ((transactor, router_ip, public_ip)) => {
                        transactor.start_change_handler(box_change_handler)?;
                        self.inner_opt = Some (AutomapControlRealInner {
                            router_ip,
                            protocol: transactor.method(),
                            port
                        });
                        Ok ((transactor.method(), public_ip))
                    },
                    None => Err (AutomapError::AllProtocolsFailed),
                }
            },
        }
    }

    fn remove_mapping(&self) -> Result<(), AutomapError> {
        match &self.inner_opt {
            None => Err (AutomapError::DeleteMappingError("No port mapping to remove".to_string())),
            Some (inner) => {
                let transactor = self.find_transactor (inner.protocol);
                transactor.delete_mapping(inner.router_ip, inner.port)
            }
        }
    }
}

impl AutomapControlReal {
    pub fn new () -> Self {
        Self {
            transactors: vec![
                Box::new (PcpTransactor::default()),
                Box::new (PmpTransactor::default()),
                Box::new (IgdpTransactor::default()),
            ],
            inner_opt: None,
        }
    }

    fn try_protocol (
        &self,
        port: u16,
        protocol: AutomapProtocol,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let transactor = self.transactors.iter()
            .find (|t| t.method() == protocol)
            .expect (&format! ("Missing Transactor for {}", protocol));
        AutomapControlReal::try_transactor (port, transactor)
    }

    fn try_transactor (
        port: u16,
        transactor: &Box<dyn Transactor>,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let router_ips = transactor.find_routers()?;
        match router_ips.into_iter()
            .map (|router_ip| AutomapControlReal::try_router(port, transactor, router_ip))
            .find (|result| result.is_ok()) {
            Some (Ok (result)) => Ok (result),
            Some (Err (_)) => panic! ("Impossible!"),
            None => Err(AutomapError::AllRoutersFailed(transactor.method())),
        }
    }

    fn try_router (
        port: u16,
        transactor: &Box<dyn Transactor>,
        router_ip: IpAddr,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let public_ip = transactor.get_public_ip(router_ip)?;
        // TODO: Employ _remap_after
        let _remap_after = match transactor.add_mapping (router_ip, port, MAPPING_LIFETIME_SECONDS) {
            Ok (delay) => Ok (delay),
            Err (AutomapError::PermanentLeasesOnly) => Ok(transactor.add_permanent_mapping(router_ip, port)?),
            Err (e) => Err (e),
        }?;
        Ok((transactor.method(), router_ip, public_ip))
    }

    fn find_transactor (&self, protocol: AutomapProtocol) -> &Box<dyn Transactor> {
        &self.transactors[self.find_transactor_index(protocol)]
    }

    fn find_transactor_index (&self, protocol: AutomapProtocol) -> usize {
        (0..self.transactors.len()).into_iter ()
            .find (|idx| self.transactors[*idx].method() == protocol)
            .expect (&format! ("No Transactor for {}", protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::Transactor;
    use std::net::IpAddr;
    use std::any::Any;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use std::str::FromStr;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref ROUTER_IP: IpAddr = IpAddr::from_str ("1.2.3.4").unwrap();
        static ref PUBLIC_IP: IpAddr = IpAddr::from_str ("2.3.4.5").unwrap();
    }

    fn null_change_handler() -> ChangeHandler {
        Box::new (|_| {})
    }

    struct TransactorMock {
        protocol: AutomapProtocol,
        find_routers_results: RefCell<Vec<Result<Vec<IpAddr>, AutomapError>>>,
        get_public_ip_params: Arc<Mutex<Vec<IpAddr>>>,
        get_public_ip_results: RefCell<Vec<Result<IpAddr, AutomapError>>>,
        add_mapping_params: Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        add_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
        add_permanent_mapping_params: Arc<Mutex<Vec<(IpAddr, u16)>>>,
        add_permanent_mapping_results: RefCell<Vec<Result<u32, AutomapError>>>,
        delete_mapping_params: Arc<Mutex<Vec<(IpAddr, u16)>>>,
        delete_mapping_results: RefCell<Vec<Result<(), AutomapError>>>,
        set_change_handler_params: Arc<Mutex<Vec<ChangeHandler>>>,
        set_change_handler_results: RefCell<Vec<Result<(), AutomapError>>>,
    }

    impl Transactor for TransactorMock {
        fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
            self.find_routers_results.borrow_mut().remove (0)
        }

        fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
            self.get_public_ip_params.lock().unwrap().push (router_ip);
            self.get_public_ip_results.borrow_mut().remove (0)
        }

        fn add_mapping(&self, router_ip: IpAddr, hole_port: u16, lifetime: u32) -> Result<u32, AutomapError> {
            self.add_mapping_params.lock().unwrap().push ((router_ip, hole_port, lifetime));
            self.add_mapping_results.borrow_mut().remove (0)
        }

        fn add_permanent_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<u32, AutomapError> {
            self.add_permanent_mapping_params.lock().unwrap().push ((router_ip, hole_port));
            self.add_permanent_mapping_results.borrow_mut().remove (0)
        }

        fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
            self.delete_mapping_params.lock().unwrap().push ((router_ip, hole_port));
            self.delete_mapping_results.borrow_mut().remove (0)
        }

        fn method(&self) -> AutomapProtocol {
            self.protocol
        }

        fn start_change_handler(&mut self, change_handler: ChangeHandler) -> Result<(), AutomapError> {
            self.set_change_handler_params.lock().unwrap().push (change_handler);
            self.set_change_handler_results.borrow_mut().remove (0)
        }

        fn stop_change_handler(&mut self) {
            todo!()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl TransactorMock {
        pub fn new (protocol: AutomapProtocol) -> Self {
            Self {
                protocol,
                find_routers_results: RefCell::new(vec![]),
                get_public_ip_params: Arc::new(Mutex::new(vec![])),
                get_public_ip_results: RefCell::new(vec![]),
                add_mapping_params: Arc::new(Mutex::new(vec![])),
                add_mapping_results: RefCell::new(vec![]),
                add_permanent_mapping_params: Arc::new(Mutex::new(vec![])),
                add_permanent_mapping_results: RefCell::new(vec![]),
                delete_mapping_params: Arc::new(Mutex::new(vec![])),
                delete_mapping_results: RefCell::new(vec![]),
                set_change_handler_params: Arc::new(Mutex::new(vec![])),
                set_change_handler_results: RefCell::new(vec![]),
            }
        }

        pub fn find_routers_result (self, result: Result<Vec<IpAddr>, AutomapError>) -> Self {
            self.find_routers_results.borrow_mut().push (result);
            self
        }

        pub fn get_public_ip_params (mut self, params: &Arc<Mutex<Vec<IpAddr>>>) -> Self {
            self.get_public_ip_params = params.clone();
            self
        }

        pub fn get_public_ip_result (self, result: Result<IpAddr, AutomapError>) -> Self {
            self.get_public_ip_results.borrow_mut().push (result);
            self
        }

        pub fn add_mapping_params (mut self, params: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>) -> Self {
            self.add_mapping_params = params.clone();
            self
        }

        pub fn add_mapping_result (self, result: Result<u32, AutomapError>) -> Self {
            self.add_mapping_results.borrow_mut().push (result);
            self
        }

        pub fn add_permanent_mapping_params (mut self, params: &Arc<Mutex<Vec<(IpAddr, u16)>>>) -> Self {
            self.add_permanent_mapping_params = params.clone();
            self
        }

        pub fn add_permanent_mapping_result (self, result: Result<u32, AutomapError>) -> Self {
            self.add_permanent_mapping_results.borrow_mut().push (result);
            self
        }

        pub fn delete_mapping_params (mut self, params: &Arc<Mutex<Vec<(IpAddr, u16)>>>) -> Self {
            self.delete_mapping_params = params.clone();
            self
        }

        pub fn delete_mapping_result (self, result: Result<(), AutomapError>) -> Self {
            self.delete_mapping_results.borrow_mut().push (result);
            self
        }

        pub fn set_change_handler_result (self, result: Result<(), AutomapError>) -> Self {
            self.set_change_handler_results.borrow_mut().push (result);
            self
        }

        pub fn set_change_handler_params (mut self, params: &Arc<Mutex<Vec<ChangeHandler>>>) -> Self {
            self.set_change_handler_params = params.clone();
            self
        }
    }

    #[test]
    fn specific_establish_mapping_works_for_pcp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(AutomapProtocol::Pcp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Pcp), change_handler);

        assert_eq! (result, Ok((AutomapProtocol::Pcp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pcp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_establish_mapping_works_for_pmp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(AutomapProtocol::Pmp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Pmp), change_handler);

        assert_eq! (result, Ok((AutomapProtocol::Pmp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pmp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_establish_mapping_works_for_igdp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(AutomapProtocol::Igdp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Igdp), change_handler);

        assert_eq! (result, Ok((AutomapProtocol::Igdp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Igdp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_establish_mapping_works_for_pcp_failure() {
        let mut subject = make_specific_failure_subject (AutomapProtocol::Pcp);
        let change_handler = null_change_handler();

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Pcp), change_handler);

        assert_eq! (result, Err(AutomapError::ProtocolError("Booga!".to_string())));
        assert_eq! (subject.inner_opt, None);
    }

    #[test]
    fn specific_establish_mapping_works_for_pmp_failure() {
        let mut subject = make_specific_failure_subject (AutomapProtocol::Pmp);
        let change_handler = null_change_handler();

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Pmp), change_handler);

        assert_eq! (result, Err(AutomapError::ProtocolError("Booga!".to_string())));
        assert_eq! (subject.inner_opt, None);
    }

    #[test]
    fn specific_establish_mapping_works_for_igdp_failure() {
        let mut subject = make_specific_failure_subject (AutomapProtocol::Igdp);
        let change_handler = null_change_handler();

        let result = subject.establish_mapping (1234, Some(AutomapProtocol::Igdp), change_handler);

        assert_eq! (result, Err(AutomapError::ProtocolError("Booga!".to_string())));
        assert_eq! (subject.inner_opt, None);
    }

    #[test]
    fn general_establish_mapping_works_for_pcp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject (AutomapProtocol::Pcp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping(1234, None, change_handler);

        assert_eq! (result, Ok ((AutomapProtocol::Pcp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pcp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_establish_mapping_works_for_pmp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject (AutomapProtocol::Pmp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping(1234, None, change_handler);

        assert_eq! (result, Ok ((AutomapProtocol::Pmp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pmp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_establish_mapping_works_for_igdp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let set_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject (AutomapProtocol::Igdp,
            &get_public_ip_params_arc, &add_mapping_params_arc, &set_change_handler_params_arc);
        let outer_handler_data = Arc::new (Mutex::new ("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new (move |change: AutomapChange|
            inner_handler_data.lock().unwrap().push_str (&format!("{:?}", change)));

        let result = subject.establish_mapping(1234, None, change_handler);

        assert_eq! (result, Ok ((AutomapProtocol::Igdp, *PUBLIC_IP)));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Igdp,
            port: 1234
        }));
        assert_eq! (subject.inner_opt, Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Igdp,
            port: 1234
        }));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]);
        let set_change_handler_params = set_change_handler_params_arc.lock().unwrap();
        set_change_handler_params[0] (AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq! (*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_establish_mapping_works_for_all_failure() {
        let mut subject = make_general_failure_subject ();
        let change_handler = null_change_handler();

        let result = subject.establish_mapping(1234, None, change_handler);

        assert_eq! (result, Err(AutomapError::AllProtocolsFailed));
        assert_eq! (subject.inner_opt, None);
    }

    #[test]
    fn permanent_mapping_requirements_are_handled() {
        let add_permanent_mapping_params_arc = Arc::new (Mutex::new (vec![]));
        let transactor: Box<dyn Transactor> = Box::new (TransactorMock::new (AutomapProtocol::Igdp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
            .add_permanent_mapping_params (&add_permanent_mapping_params_arc)
            .add_permanent_mapping_result (Ok(300)));

        let result = AutomapControlReal::try_transactor(1234, &transactor);

        assert_eq! (result, Ok((AutomapProtocol::Igdp, *ROUTER_IP, *PUBLIC_IP)));
        let add_permanent_mapping_params = add_permanent_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_permanent_mapping_params, vec![
            (*ROUTER_IP, 1234)
        ])
    }

    #[test]
    fn all_found_routers_are_tried_success() {
        let router_ip1 = IpAddr::from_str ("8.8.8.1").unwrap();
        let router_ip2 = IpAddr::from_str ("8.8.8.2").unwrap();
        let router_ip3 = IpAddr::from_str ("8.8.8.3").unwrap();
        let transactor: Box<dyn Transactor> = Box::new (TransactorMock::new (AutomapProtocol::Igdp)
            .find_routers_result(Ok(vec![router_ip1, router_ip2, router_ip3]))
            .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
            .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_result(Ok(300)));

        let result = AutomapControlReal::try_transactor(1234, &transactor);

        assert_eq! (result, Ok((AutomapProtocol::Igdp, router_ip3, *PUBLIC_IP)));
    }

    #[test]
    fn all_found_routers_are_tried_failure() {
        let router_ip1 = IpAddr::from_str ("8.8.8.1").unwrap();
        let router_ip2 = IpAddr::from_str ("8.8.8.2").unwrap();
        let router_ip3 = IpAddr::from_str ("8.8.8.3").unwrap();
        let transactor: Box<dyn Transactor> = Box::new (TransactorMock::new (AutomapProtocol::Igdp)
            .find_routers_result(Ok(vec![router_ip1, router_ip2, router_ip3]))
            .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
            .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
            .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
            .add_mapping_result(Ok(300)));

        let result = AutomapControlReal::try_transactor(1234, &transactor);

        assert_eq! (result, Err(AutomapError::AllRoutersFailed(AutomapProtocol::Igdp)));
    }

    #[test]
    fn remove_mapping_complains_if_no_active_protocol() {
        let subject = make_null_subject();

        let result = subject.remove_mapping();

        assert_eq! (result, Err (AutomapError::DeleteMappingError("No port mapping to remove".to_string())))
    }

    #[test]
    fn remove_mapping_works_with_success() {
        let delete_mapping_params_arc = Arc::new (Mutex::new (vec![]));
        let subject = make_removal_success_subject(
            AutomapProtocol::Pmp,
            &delete_mapping_params_arc,
        );

        let result = subject.remove_mapping();

        assert_eq! (result, Ok(()));
        let delete_mapping_params = delete_mapping_params_arc.lock().unwrap();
        assert_eq! (*delete_mapping_params, vec![
            (*ROUTER_IP, 1234)
        ])
    }

    #[test]
    fn remove_mapping_works_with_failure() {
        let subject = make_removal_failure_subject(
            AutomapProtocol::Pmp,
        );

        let result = subject.remove_mapping();

        assert_eq! (result, Err(AutomapError::DeleteMappingError("Booga!".to_string())));
    }

    fn make_specific_success_subject(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        set_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>
    ) -> AutomapControlReal {
        let transactor = TransactorMock::new(protocol)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_params(get_public_ip_params_arc)
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_params(add_mapping_params_arc)
            .add_mapping_result(Ok(1000))
            .set_change_handler_params(set_change_handler_params_arc)
            .set_change_handler_result(Ok(()));
        replace_transactor (make_null_subject(), Box::new (transactor))
    }

    fn make_removal_success_subject(
        protocol: AutomapProtocol,
        delete_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16)>>>,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        subject.inner_opt = Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pmp,
            port: 1234
        });
        let transactor = TransactorMock::new(protocol)
            .delete_mapping_params(delete_mapping_params_arc)
            .delete_mapping_result(Ok(()));
        replace_transactor (subject, Box::new (transactor))
    }

    fn make_removal_failure_subject(
        protocol: AutomapProtocol,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        subject.inner_opt = Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            protocol: AutomapProtocol::Pmp,
            port: 1234
        });
        let transactor = TransactorMock::new(protocol)
            .delete_mapping_result(Err(AutomapError::DeleteMappingError("Booga!".to_string())));
        replace_transactor (subject, Box::new (transactor))
    }

    fn make_specific_failure_subject(protocol: AutomapProtocol) -> AutomapControlReal {
        replace_transactor (make_null_subject(), make_failure_transactor(protocol))
    }

    fn make_general_success_subject(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        set_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>
    ) -> AutomapControlReal {
        let subject = make_general_failure_subject();
        let success_transactor = make_params_success_transactor(
            protocol,
            get_public_ip_params_arc,
            add_mapping_params_arc,
            set_change_handler_params_arc,
        );
        replace_transactor (subject, success_transactor)
    }

    fn make_general_failure_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new();
        subject.transactors = subject.transactors.into_iter()
            .map (|t| make_failure_transactor (t.method()))
            .collect();
        subject
    }

    fn make_params_success_transactor (
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        set_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>
    ) -> Box<dyn Transactor> {
        Box::new (TransactorMock::new(protocol)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_params(get_public_ip_params_arc)
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_params(add_mapping_params_arc)
            .add_mapping_result(Ok(1000))
            .set_change_handler_params(set_change_handler_params_arc)
            .set_change_handler_result(Ok(())))
    }

    fn make_failure_transactor(protocol: AutomapProtocol) -> Box<dyn Transactor> {
        Box::new (TransactorMock::new(protocol)
            .find_routers_result(Err(AutomapError::ProtocolError("Booga!".to_string()))))
    }

    fn make_null_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new();
        subject.transactors = subject.transactors.into_iter()
            .map (|t| {
                let tm: Box<dyn Transactor> = Box::new (TransactorMock::new (t.method ()));
                tm
            })
            .collect();
        subject
    }

    fn replace_transactor (mut subject: AutomapControlReal, transactor: Box<dyn Transactor>) -> AutomapControlReal {
        let idx = subject.find_transactor_index(transactor.method());
        subject.transactors[idx] = transactor;
        subject
    }
}