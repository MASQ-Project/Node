// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{AutomapError, Transactor};
use masq_lib::utils::{plus, AutomapProtocol};
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;

const MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive(PartialEq, Clone, Debug)]
pub enum AutomapChange {
    NewIp(IpAddr),
    Error(AutomapError),
}

unsafe impl Send for AutomapChange {}

pub type ChangeHandler = Box<dyn Fn(AutomapChange) + Send>;

pub trait AutomapControl {
    fn get_public_ip(&mut self) -> Result<IpAddr, AutomapError>;
    fn add_mapping(&mut self, hole_port: u16) -> Result<u32, AutomapError>;
    fn delete_mappings(&mut self) -> Result<(), AutomapError>;
}

#[derive(PartialEq, Debug, Clone)]
struct AutomapControlRealInner {
    router_ip: IpAddr,
    transactor_idx: usize,
}

type TransactorExperiment<T> = Box<dyn Fn(&dyn Transactor, IpAddr) -> Result<T, AutomapError>>;

#[derive(PartialEq, Debug)]
struct ProtocolInfo<T: PartialEq + Debug> {
    payload: T,
    router_ip: IpAddr,
}

pub struct AutomapControlReal {
    transactors: Vec<Box<dyn Transactor>>,
    change_handler_opt: Option<ChangeHandler>,
    usual_protocol_opt: Option<AutomapProtocol>,
    hole_ports: HashSet<u16>,
    inner_opt: Option<AutomapControlRealInner>,
}

impl AutomapControl for AutomapControlReal {
    fn get_public_ip(&mut self) -> Result<IpAddr, AutomapError> {
        let experiment = Box::new(move |transactor: &dyn Transactor, router_ip: IpAddr| {
            transactor.get_public_ip(router_ip)
        });
        let protocol_info_result = match &self.inner_opt {
            Some(inner) => {
                let result = experiment(
                    self.transactors[inner.transactor_idx].as_ref(),
                    inner.router_ip,
                );
                result.map(|public_ip| ProtocolInfo {
                    payload: public_ip,
                    router_ip: inner.router_ip,
                })
            }
            None => self.choose_working_protocol(experiment),
        };
        match self.maybe_start_change_handler(&protocol_info_result) {
            Ok(_) => protocol_info_result.map(|protocol_info| protocol_info.payload),
            Err(e) => Err(e),
        }
    }

    fn add_mapping(&mut self, hole_port: u16) -> Result<u32, AutomapError> {
        let experiment = Box::new(move |transactor: &dyn Transactor, router_ip: IpAddr| {
            match transactor.add_mapping(router_ip, hole_port, MAPPING_LIFETIME_SECONDS) {
                Ok(remap_after) => Ok(remap_after),
                Err(AutomapError::PermanentLeasesOnly) => {
                    match transactor.add_permanent_mapping(router_ip, hole_port) {
                        Ok(remap_after) => Ok(remap_after),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        });
        let protocol_info_result = match &self.inner_opt {
            Some(inner) => {
                let result = experiment(
                    self.transactors[inner.transactor_idx].as_ref(),
                    inner.router_ip,
                );
                match result {
                    Ok(remap_after) => Ok(ProtocolInfo {
                        payload: remap_after,
                        router_ip: inner.router_ip,
                    }),
                    Err(e) => Err(e),
                }
            }
            None => match self.choose_working_protocol(experiment) {
                Ok(protocol_info) => {
                    let transactor_idx = self
                        .inner_opt
                        .as_ref()
                        .expect("inner disappeared")
                        .transactor_idx;
                    self.usual_protocol_opt = Some(self.transactors[transactor_idx].protocol());
                    self.hole_ports.insert(hole_port);
                    Ok(protocol_info)
                }
                Err(e) => Err(e),
            },
        };
        match self.maybe_start_change_handler(&protocol_info_result) {
            Ok(_) => protocol_info_result.map(|r| r.payload),
            Err(e) => Err(e),
        }
    }

    fn delete_mappings(&mut self) -> Result<(), AutomapError> {
        match &self.inner_opt {
            None => Err(AutomapError::DeleteMappingError(
                "No port mapping to remove".to_string(),
            )),
            Some(inner) => {
                let transactor = &mut self.transactors[inner.transactor_idx];
                let init: Vec<AutomapError> = vec![];
                let errors =
                    self.hole_ports.iter().fold(init, |so_far, hole_port| {
                        match transactor.delete_mapping(inner.router_ip, *hole_port) {
                            Ok(_) => so_far,
                            Err(e) => plus(so_far, e),
                        }
                    });
                transactor.stop_change_handler();
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors[0].clone())
                }
            }
        }
    }
}

impl AutomapControlReal {
    pub fn new(usual_protocol_opt: Option<AutomapProtocol>, change_handler: ChangeHandler) -> Self {
        Self {
            transactors: vec![
                Box::new(PcpTransactor::default()),
                Box::new(PmpTransactor::default()),
                Box::new(IgdpTransactor::default()),
            ],
            change_handler_opt: Some(change_handler),
            usual_protocol_opt,
            hole_ports: HashSet::new(),
            inner_opt: None,
        }
    }

    fn maybe_start_change_handler<T: PartialEq + Debug>(
        &mut self,
        protocol_info_result: &Result<ProtocolInfo<T>, AutomapError>,
    ) -> Result<(), AutomapError> {
        // Currently, starting the change handler surrenders ownership of it to the Transactor.
        // This means that we can't start the change handler, stop it, and then restart it, without
        // getting it from the client of AutomapControl again. It does turn out that in Rust
        // closures are Clone, which means that we could redesign this code to keep a copy of the
        // change handler against the time when we might want to start it up again. However, at the
        // moment, the signal that the change handler is already running is that change_handler_opt
        // is None, so adding the restart capability will require a little rearchitecture. At the
        // time of this writing, we don't need a restart capability, so we're deferring that work
        // until it's necessary, if ever.
        if let Some(change_handler) = self.change_handler_opt.take() {
            match (protocol_info_result, &self.inner_opt) {
                (Ok(_), None) => {
                    unreachable!("Experiment succeeded but produced no Inner structure")
                }
                (Ok(protocol_info), Some(inner)) => {
                    // TODO "We're throwing away the remap interval here; the change handler should be using it."
                    self.transactors[inner.transactor_idx]
                        .start_change_handler(change_handler, protocol_info.router_ip)
                },
                (Err(e), _) => {
                    self.change_handler_opt = Some(change_handler);
                    Err(e.clone())
                }
            }
        } else {
            Ok(())
        }
    }

    fn find_transactor_index(&self, protocol: AutomapProtocol) -> usize {
        (0..self.transactors.len())
            .into_iter()
            .find(|idx| self.transactors[*idx].protocol() == protocol)
            .unwrap_or_else(|| panic!("No Transactor for {}", protocol))
    }

    fn choose_working_protocol<T: PartialEq + Debug>(
        &mut self,
        experiment: TransactorExperiment<T>,
    ) -> Result<ProtocolInfo<T>, AutomapError> {
        if let Some(usual_protocol) = self.usual_protocol_opt {
            let transactor = self
                .transactors
                .iter()
                .find(|t| t.protocol() == usual_protocol)
                .expect("Missing Transactor");
            match Self::try_protocol(transactor, &experiment) {
                Ok((router_ip, t)) => {
                    self.inner_opt = Some(AutomapControlRealInner {
                        router_ip,
                        transactor_idx: self.find_transactor_index(usual_protocol),
                    });
                    return Ok(ProtocolInfo {
                        payload: t,
                        router_ip,
                    });
                }
                Err(_) => (),
            }
        }
        let init: Result<(AutomapProtocol, IpAddr, T), AutomapError> = Err(AutomapError::Unknown);
        let protocol_router_ip_and_experimental_outcome_result =
            self.transactors.iter().fold(init, |so_far, transactor| {
                match (so_far, self.usual_protocol_opt) {
                    (Ok(tuple), _) => Ok(tuple),
                    (Err(e), Some(usual_protocol)) if usual_protocol == transactor.protocol() => {
                        Err(e)
                    }
                    (Err(_), _) => Self::try_protocol(transactor, &experiment)
                        .map(|(router_ip, t)| (transactor.protocol(), router_ip, t)),
                }
            });
        match protocol_router_ip_and_experimental_outcome_result {
            Ok((protocol, router_ip, t)) => {
                self.inner_opt = Some(AutomapControlRealInner {
                    router_ip,
                    transactor_idx: self.find_transactor_index(protocol),
                });
                Ok(ProtocolInfo {
                    payload: t,
                    router_ip,
                })
            }
            Err(_) => Err(AutomapError::AllProtocolsFailed),
        }
    }

    fn try_protocol<T>(
        transactor: &Box<dyn Transactor>,
        experiment: &TransactorExperiment<T>,
    ) -> Result<(IpAddr, T), AutomapError> {
        let router_ips = match transactor.find_routers() {
            Ok(router_ips) if !router_ips.is_empty() => router_ips,
            _ => return Err(AutomapError::AllRoutersFailed(transactor.protocol())),
        };
        let init: Result<(IpAddr, T), AutomapError> = Err(AutomapError::Unknown);
        router_ips
            .into_iter()
            .fold(init, |so_far, router_ip| match so_far {
                Ok(tuple) => Ok(tuple),
                Err(_) => experiment(transactor.as_ref(), router_ip).map(|t| (router_ip, t)),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::{AutomapErrorCause, Transactor};
    use lazy_static::lazy_static;
    use std::any::Any;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    lazy_static! {
        static ref ROUTER_IP: IpAddr = IpAddr::from_str("1.2.3.4").unwrap();
        static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
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
        start_change_handler_params: Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
        start_change_handler_results: RefCell<Vec<Result<(), AutomapError>>>,
        stop_change_handler_params: Arc<Mutex<Vec<()>>>,
    }

    impl Transactor for TransactorMock {
        fn find_routers(&self) -> Result<Vec<IpAddr>, AutomapError> {
            self.find_routers_results.borrow_mut().remove(0)
        }

        fn get_public_ip(&self, router_ip: IpAddr) -> Result<IpAddr, AutomapError> {
            self.get_public_ip_params.lock().unwrap().push(router_ip);
            self.get_public_ip_results.borrow_mut().remove(0)
        }

        fn add_mapping(
            &self,
            router_ip: IpAddr,
            hole_port: u16,
            lifetime: u32,
        ) -> Result<u32, AutomapError> {
            self.add_mapping_params
                .lock()
                .unwrap()
                .push((router_ip, hole_port, lifetime));
            self.add_mapping_results.borrow_mut().remove(0)
        }

        fn add_permanent_mapping(
            &self,
            router_ip: IpAddr,
            hole_port: u16,
        ) -> Result<u32, AutomapError> {
            self.add_permanent_mapping_params
                .lock()
                .unwrap()
                .push((router_ip, hole_port));
            self.add_permanent_mapping_results.borrow_mut().remove(0)
        }

        fn delete_mapping(&self, router_ip: IpAddr, hole_port: u16) -> Result<(), AutomapError> {
            self.delete_mapping_params
                .lock()
                .unwrap()
                .push((router_ip, hole_port));
            self.delete_mapping_results.borrow_mut().remove(0)
        }

        fn protocol(&self) -> AutomapProtocol {
            self.protocol
        }

        fn start_change_handler(
            &mut self,
            change_handler: ChangeHandler,
            router_ip: IpAddr,
        ) -> Result<(), AutomapError> {
            self.start_change_handler_params
                .lock()
                .unwrap()
                .push((change_handler, router_ip));
            self.start_change_handler_results.borrow_mut().remove(0)
        }

        fn stop_change_handler(&mut self) {
            self.stop_change_handler_params.lock().unwrap().push(());
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    impl TransactorMock {
        pub fn new(protocol: AutomapProtocol) -> Self {
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
                start_change_handler_params: Arc::new(Mutex::new(vec![])),
                start_change_handler_results: RefCell::new(vec![]),
                stop_change_handler_params: Arc::new(Mutex::new(vec![])),
            }
        }

        pub fn find_routers_result(self, result: Result<Vec<IpAddr>, AutomapError>) -> Self {
            self.find_routers_results.borrow_mut().push(result);
            self
        }

        pub fn get_public_ip_params(mut self, params: &Arc<Mutex<Vec<IpAddr>>>) -> Self {
            self.get_public_ip_params = params.clone();
            self
        }

        pub fn get_public_ip_result(self, result: Result<IpAddr, AutomapError>) -> Self {
            self.get_public_ip_results.borrow_mut().push(result);
            self
        }

        pub fn add_mapping_params(mut self, params: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>) -> Self {
            self.add_mapping_params = params.clone();
            self
        }

        pub fn add_mapping_result(self, result: Result<u32, AutomapError>) -> Self {
            self.add_mapping_results.borrow_mut().push(result);
            self
        }

        pub fn add_permanent_mapping_params(
            mut self,
            params: &Arc<Mutex<Vec<(IpAddr, u16)>>>,
        ) -> Self {
            self.add_permanent_mapping_params = params.clone();
            self
        }

        pub fn add_permanent_mapping_result(self, result: Result<u32, AutomapError>) -> Self {
            self.add_permanent_mapping_results.borrow_mut().push(result);
            self
        }

        pub fn delete_mapping_params(mut self, params: &Arc<Mutex<Vec<(IpAddr, u16)>>>) -> Self {
            self.delete_mapping_params = params.clone();
            self
        }

        pub fn delete_mapping_result(self, result: Result<(), AutomapError>) -> Self {
            self.delete_mapping_results.borrow_mut().push(result);
            self
        }

        pub fn start_change_handler_result(self, result: Result<(), AutomapError>) -> Self {
            self.start_change_handler_results.borrow_mut().push(result);
            self
        }

        pub fn start_change_handler_params(
            mut self,
            params: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
        ) -> Self {
            self.start_change_handler_params = params.clone();
            self
        }

        pub fn stop_change_handler_params(mut self, params: &Arc<Mutex<Vec<()>>>) -> Self {
            self.stop_change_handler_params = params.clone();
            self
        }
    }

    fn choose_working_protocol_works_for_success(protocol: AutomapProtocol) {
        let mut subject = make_multirouter_specific_success_subject(
            protocol,
            vec![
                IpAddr::from_str("4.3.2.1").unwrap(),
                *ROUTER_IP,
                IpAddr::from_str("5.4.3.2").unwrap(),
            ],
        );
        let experiment: TransactorExperiment<String> =
            Box::new(|t, router_ip| match t.get_public_ip(router_ip) {
                Ok(_) if router_ip == *ROUTER_IP => Ok("Success!".to_string()),
                _ => Err(AutomapError::Unknown),
            });

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Success!".to_string(),
                router_ip: *ROUTER_IP
            })
        );
        assert_eq!(
            subject.inner_opt.unwrap(),
            AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: match protocol {
                    AutomapProtocol::Pcp => 0,
                    AutomapProtocol::Pmp => 1,
                    AutomapProtocol::Igdp => 2,
                },
            }
        );
    }

    #[test]
    fn choose_working_protocol_works_for_pcp_success() {
        choose_working_protocol_works_for_success(AutomapProtocol::Pcp);
    }

    #[test]
    fn choose_working_protocol_works_for_pmp_success() {
        choose_working_protocol_works_for_success(AutomapProtocol::Pmp);
    }

    #[test]
    fn choose_working_protocol_works_for_igdp_success() {
        choose_working_protocol_works_for_success(AutomapProtocol::Igdp);
    }

    #[test]
    fn choose_working_protocol_works_for_failure() {
        let mut subject = make_general_failure_subject();
        let experiment: TransactorExperiment<String> =
            Box::new(|t, router_ip| match t.get_public_ip(router_ip) {
                Err(_) => Err(AutomapError::Unknown),
                Ok(_) => panic!("For this test, get_public_ip() should never succeed"),
            });

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(result, Err(AutomapError::AllProtocolsFailed));
    }

    #[test]
    fn choose_working_protocol_works_when_a_protocol_says_no_routers() {
        let mut subject = make_no_routers_subject();
        let experiment: TransactorExperiment<String> =
            Box::new(|_t, _router_ip| Ok("Success!".to_string()));

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(result, Err(AutomapError::AllProtocolsFailed));
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn choose_working_protocol_works_when_routers_are_found_but_the_experiment_fails_on_all_protocols(
    ) {
        let mut subject = make_null_subject();
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|transactor| {
                make_params_success_transactor(
                    transactor.protocol(),
                    &Arc::new(Mutex::new(vec![])),
                    &Arc::new(Mutex::new(vec![])),
                    &Arc::new(Mutex::new(vec![])),
                )
            })
            .collect();
        let experiment: TransactorExperiment<String> =
            Box::new(|_t, _router_ip| Err(AutomapError::Unknown));

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(result, Err(AutomapError::AllProtocolsFailed));
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn find_protocol_without_usual_protocol_traverses_available_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = None;
        let outer_protocol_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> = Box::new(move |t, _router_ip| {
            inner_protocol_log_arc.lock().unwrap().push(t.protocol());
            if t.protocol() == AutomapProtocol::Pmp {
                Ok("Success!".to_string())
            } else {
                Err(AutomapError::Unknown)
            }
        });

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Success!".to_string(),
                router_ip: *ROUTER_IP
            })
        );
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried PCP, failed. Tried PMP, worked. Didn't bother with IGDP.
        assert_eq!(
            *protocol_log,
            vec![AutomapProtocol::Pcp, AutomapProtocol::Pmp]
        );
    }

    #[test]
    fn find_protocol_with_successful_usual_protocol_does_not_try_other_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = Some(AutomapProtocol::Pmp);
        let outer_protocol_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> = Box::new(move |t, _router_ip| {
            inner_protocol_log_arc.lock().unwrap().push(t.protocol());
            if t.protocol() == AutomapProtocol::Pmp {
                Ok("Success!".to_string())
            } else {
                Err(AutomapError::Unknown)
            }
        });

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Success!".to_string(),
                router_ip: *ROUTER_IP
            })
        );
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried usual PMP first; succeeded.
        assert_eq!(*protocol_log, vec![AutomapProtocol::Pmp]);
    }

    #[test]
    fn find_protocol_with_failing_usual_protocol_tries_other_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = Some(AutomapProtocol::Pmp);
        let outer_protocol_log_arc = Arc::new(Mutex::new(vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> = Box::new(move |t, _router_ip| {
            inner_protocol_log_arc.lock().unwrap().push(t.protocol());
            if t.protocol() == AutomapProtocol::Igdp {
                Ok("Success!".to_string())
            } else {
                Err(AutomapError::Unknown)
            }
        });

        let result = subject.choose_working_protocol(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Success!".to_string(),
                router_ip: *ROUTER_IP
            })
        );
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried usual PMP; failed. Tried PCP, failed. Skipped PMP (already tried), tried IGDP; succeeded.
        assert_eq!(
            *protocol_log,
            vec![
                AutomapProtocol::Pmp,
                AutomapProtocol::Pcp,
                AutomapProtocol::Igdp
            ]
        );
    }

    #[test]
    fn early_get_public_ip_starts_change_handler_and_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push(change);
        };
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = Some(Box::new(change_handler));
        subject.inner_opt = None;

        let result = subject.get_public_ip();

        assert_eq!(result, Ok(*PUBLIC_IP));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        assert!(add_mapping_params_arc.lock().unwrap().is_empty());
        let (actual_change_handler, router_ip) =
            start_change_handler_params_arc.lock().unwrap().remove(0);
        assert_eq!(router_ip, *ROUTER_IP);
        let change = AutomapChange::Error(AutomapError::ProtocolError("Booga!".to_string()));
        actual_change_handler(change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq!(*change_handler_log, vec![change])
    }

    #[test]
    fn early_get_public_ip_passes_on_error_from_failing_to_start_change_handler() {
        let subject = make_null_subject();
        let mut subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pcp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .get_public_ip_result(Ok(*PUBLIC_IP))
                    .start_change_handler_result(Err(AutomapError::Unknown)),
            ),
        );
        subject.change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = None;

        let result = subject.get_public_ip();

        assert_eq!(result, Err(AutomapError::Unknown));
    }

    #[test]
    fn late_get_public_ip_does_not_start_change_handler_but_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.get_public_ip();

        assert_eq!(result, Ok(*PUBLIC_IP));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        assert!(add_mapping_params_arc.lock().unwrap().is_empty());
        assert!(start_change_handler_params_arc.lock().unwrap().is_empty());
    }

    #[test]
    fn early_add_mapping_timed_starts_change_handler_and_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push(change);
        };
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.inner_opt = None;
        subject.change_handler_opt = Some(Box::new(change_handler));

        let result = subject.add_mapping(4567);

        assert_eq!(result, Ok(1000));
        assert_eq!(subject.usual_protocol_opt, Some(AutomapProtocol::Pcp));
        assert_eq!(
            subject.hole_ports.iter().collect::<Vec<&u16>>(),
            vec![&4567]
        );
        assert!(get_public_ip_params_arc.lock().unwrap().is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
        let (actual_change_handler, router_ip) =
            start_change_handler_params_arc.lock().unwrap().remove(0);
        assert_eq!(router_ip, *ROUTER_IP);
        let change = AutomapChange::Error(AutomapError::ProtocolError("Booga!".to_string()));
        actual_change_handler(change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq!(*change_handler_log, vec![change])
    }

    #[test]
    fn early_add_mapping_passes_on_error_from_failing_to_start_change_handler() {
        let subject = make_null_subject();
        let mut subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pcp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .add_mapping_result(Ok(12345))
                    .start_change_handler_result(Err(AutomapError::Unknown)),
            ),
        );
        subject.change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = None;

        let result = subject.add_mapping(1234);

        assert_eq!(result, Err(AutomapError::Unknown));
    }

    #[test]
    fn late_add_mapping_timed_does_not_start_change_handler_but_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(result, Ok(1000));
        assert!(get_public_ip_params_arc.lock().unwrap().is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
        assert!(start_change_handler_params_arc.lock().unwrap().is_empty());
    }

    #[test]
    fn late_add_mapping_timed_handles_mapping_error() {
        let mut subject = make_general_failure_subject();
        subject.transactors[0] = Box::new(
            TransactorMock::new(AutomapProtocol::Pcp)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_result(Err(AutomapError::AddMappingError("Booga!".to_string()))),
        );

        subject.change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(
            result,
            Err(AutomapError::AddMappingError("Booga!".to_string()))
        );
    }

    #[test]
    fn late_add_mapping_permanent_handles_mapping_error() {
        let mut subject = make_general_failure_subject();
        subject.transactors[2] = Box::new(
            TransactorMock::new(AutomapProtocol::Pcp)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
                .add_permanent_mapping_result(Err(AutomapError::AddMappingError(
                    "Booga!".to_string(),
                ))),
        );

        subject.change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 2,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(
            result,
            Err(AutomapError::AddMappingError("Booga!".to_string()))
        );
    }

    #[test]
    fn late_add_mapping_permanent_does_not_start_change_handler_but_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let add_permanent_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
        );
        subject.transactors[0] = Box::new(
            TransactorMock::new(AutomapProtocol::Pcp)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_params(&get_public_ip_params_arc)
                .add_mapping_params(&add_mapping_params_arc)
                .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
                .add_permanent_mapping_params(&add_permanent_mapping_params_arc)
                .add_permanent_mapping_result(Ok(1000))
                .start_change_handler_params(&start_change_handler_params_arc),
        );
        subject.change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(result, Ok(1000));
        assert!(get_public_ip_params_arc.lock().unwrap().is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
        let add_permanent_mapping_params = add_permanent_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_permanent_mapping_params, vec![(*ROUTER_IP, 4567)]);
        assert!(start_change_handler_params_arc.lock().unwrap().is_empty());
    }

    #[test]
    fn delete_mappings_complains_if_no_active_protocol() {
        let mut subject = make_null_subject();

        let result = subject.delete_mappings();

        assert_eq!(
            result,
            Err(AutomapError::DeleteMappingError(
                "No port mapping to remove".to_string()
            ))
        )
    }

    #[test]
    fn delete_mappings_works_with_success() {
        let delete_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let stop_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let subject = make_active_two_port_subject(1);
        let transactor = TransactorMock::new(AutomapProtocol::Pmp)
            .delete_mapping_params(&delete_mapping_params_arc)
            .delete_mapping_result(Ok(()))
            .delete_mapping_result(Ok(()))
            .stop_change_handler_params(&stop_change_handler_params_arc);
        let mut subject = replace_transactor(subject, Box::new(transactor));

        let result = subject.delete_mappings();

        assert_eq!(result, Ok(()));
        let delete_mapping_params = delete_mapping_params_arc.lock().unwrap();
        vec![(*ROUTER_IP, 4567), (*ROUTER_IP, 5678)]
            .into_iter()
            .for_each(|pair| {
                assert!(delete_mapping_params.contains(&pair));
            });
        let stop_change_handler_params = stop_change_handler_params_arc.lock().unwrap();
        assert_eq!(*stop_change_handler_params, vec![()]);
    }

    #[test]
    fn delete_mappings_works_with_failure() {
        let delete_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let stop_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let subject = make_active_two_port_subject(1);
        let transactor = TransactorMock::new(AutomapProtocol::Pmp)
            .delete_mapping_params(&delete_mapping_params_arc)
            .delete_mapping_result(Ok(()))
            .delete_mapping_result(Err(AutomapError::DeleteMappingError("Booga!".to_string())))
            .stop_change_handler_params(&stop_change_handler_params_arc);
        let mut subject = replace_transactor(subject, Box::new(transactor));

        let result = subject.delete_mappings();

        assert_eq!(
            result,
            Err(AutomapError::DeleteMappingError("Booga!".to_string()))
        );
        let delete_mapping_params = delete_mapping_params_arc.lock().unwrap();
        vec![(*ROUTER_IP, 4567), (*ROUTER_IP, 5678)]
            .into_iter()
            .for_each(|pair| {
                assert!(delete_mapping_params.contains(&pair));
            });
        let stop_change_handler_params = stop_change_handler_params_arc.lock().unwrap();
        assert_eq!(*stop_change_handler_params, vec![()]);
    }

    #[test]
    fn maybe_start_change_handler_handles_first_experiment_failure() {
        let mut subject = make_null_subject();
        subject.change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = None;
        let protocol_info_result: Result<ProtocolInfo<u32>, AutomapError> =
            Err(AutomapError::Unknown);

        let result = subject.maybe_start_change_handler(&protocol_info_result);

        assert_eq!(result, Err(AutomapError::Unknown));
        assert!(subject.change_handler_opt.is_some());
    }

    #[test]
    fn maybe_start_change_handler_handles_later_experiment_failure() {
        let mut subject = make_null_subject();
        subject.change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });
        let protocol_info_result: Result<ProtocolInfo<u32>, AutomapError> =
            Err(AutomapError::Unknown);

        let result = subject.maybe_start_change_handler(&protocol_info_result);

        assert_eq!(result, Err(AutomapError::Unknown));
        assert!(subject.change_handler_opt.is_some());
    }

    fn make_multirouter_specific_success_subject(
        protocol: AutomapProtocol,
        router_ips: Vec<IpAddr>,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        for candidate_protocol in AutomapProtocol::values() {
            if candidate_protocol != protocol {
                let transactor = TransactorMock::new(candidate_protocol).find_routers_result(Err(
                    AutomapError::FindRouterError(
                        "Can't find routers".to_string(),
                        AutomapErrorCause::NetworkConfiguration,
                    ),
                ));
                subject = replace_transactor(subject, Box::new(transactor));
            }
        }
        let router_ip_count = router_ips.len();
        let mut transactor = TransactorMock::new(protocol)
            .find_routers_result(Ok(router_ips))
            .start_change_handler_result(Ok(()));
        for _ in 0..router_ip_count {
            transactor = transactor
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_result(Ok(1000));
        }
        replace_transactor(subject, Box::new(transactor))
    }

    fn make_active_two_port_subject(transactor_idx: usize) -> AutomapControlReal {
        let mut subject = make_null_subject();
        subject.hole_ports = vec![4567, 5678].into_iter().collect::<HashSet<u16>>();
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx,
        });
        subject
    }

    fn make_general_success_subject(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_change_handler_params_arc: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
    ) -> AutomapControlReal {
        let subject = make_general_failure_subject();
        let success_transactor = make_params_success_transactor(
            protocol,
            get_public_ip_params_arc,
            add_mapping_params_arc,
            start_change_handler_params_arc,
        );
        replace_transactor(subject, success_transactor)
    }

    fn make_general_failure_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| make_failure_transactor(t.protocol()))
            .collect();
        subject
    }

    fn make_params_success_transactor(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_change_handler_params_arc: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
    ) -> Box<dyn Transactor> {
        Box::new(
            TransactorMock::new(protocol)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_params(get_public_ip_params_arc)
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_params(add_mapping_params_arc)
                .add_mapping_result(Ok(1000))
                .start_change_handler_params(start_change_handler_params_arc)
                .start_change_handler_result(Ok(())),
        )
    }

    fn make_failure_transactor(protocol: AutomapProtocol) -> Box<dyn Transactor> {
        Box::new(
            TransactorMock::new(protocol)
                .find_routers_result(Err(AutomapError::ProtocolError("Booga!".to_string()))),
        )
    }

    fn make_no_router_transactor(protocol: AutomapProtocol) -> Box<dyn Transactor> {
        Box::new(TransactorMock::new(protocol).find_routers_result(Ok(vec![])))
    }

    fn make_null_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| {
                let tm: Box<dyn Transactor> = Box::new(TransactorMock::new(t.protocol()));
                tm
            })
            .collect();
        subject
    }

    fn make_all_routers_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| {
                let transactor: Box<dyn Transactor> = Box::new(
                    TransactorMock::new(t.protocol())
                        .find_routers_result(Ok(vec![*ROUTER_IP]))
                        .find_routers_result(Ok(vec![*ROUTER_IP])),
                );
                transactor
            })
            .collect();
        subject
    }

    fn make_no_routers_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| make_no_router_transactor(t.protocol()))
            .collect();
        subject
    }

    fn replace_transactor(
        mut subject: AutomapControlReal,
        transactor: Box<dyn Transactor>,
    ) -> AutomapControlReal {
        let idx = subject.find_transactor_index(transactor.protocol());
        subject.transactors[idx] = transactor;
        subject
    }
}
