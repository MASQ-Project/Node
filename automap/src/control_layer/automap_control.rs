// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{AutomapError, Transactor};
use masq_lib::utils::AutomapProtocol;
use std::net::IpAddr;
use std::collections::HashSet;

const MAPPING_LIFETIME_SECONDS: u32 = 600; // ten minutes

#[derive(PartialEq, Clone, Debug)]
pub enum AutomapChange {
    NewIp(IpAddr),
    Error(AutomapError),
}

unsafe impl Send for AutomapChange {}

pub type ChangeHandler = Box<dyn Fn(AutomapChange) + Send>;

pub trait AutomapControl {
    fn get_public_ip (&mut self) -> Result<IpAddr, AutomapError>;
    fn add_mapping(&mut self, hole_port: u16) -> Result<u32, AutomapError>;
    fn delete_mappings(&self) -> Result<(), AutomapError>;
}

#[derive(PartialEq, Debug, Clone)]
struct AutomapControlRealInner {
    router_ip: IpAddr,
    transactor_idx: usize,
    port: u16,
}

type TransactorExperiment<T> = Box<dyn Fn (&dyn Transactor, IpAddr) -> Option<T>>;

pub struct AutomapControlReal {
    transactors: Vec<Box<dyn Transactor>>,
    change_handler_opt: Option<ChangeHandler>,
    usual_protocol_opt: Option<AutomapProtocol>,
    hole_ports: HashSet<u16>,
    inner_opt: Option<AutomapControlRealInner>,
}

impl AutomapControl for AutomapControlReal {
    fn get_public_ip (&mut self) -> Result<IpAddr, AutomapError> {
        let experiment = Box::new (move |transactor: &dyn Transactor, router_ip: IpAddr| {
            match transactor.get_public_ip (router_ip) {
                Ok(public_ip) => Some (public_ip),
                Err (e) => None,
            }
        });
        let public_ip_result = match &self.inner_opt {
            Some (inner) => self.transactors[inner.transactor_idx].get_public_ip(inner.router_ip),
            None => {
                self.find_working_protocol::<IpAddr> (experiment)
            },
        };
        if let Some(change_handler) = self.change_handler_opt.take() {
            match (&public_ip_result, &self.inner_opt) {
                (Ok(_), Some(inner)) => {
                    self.transactors[inner.transactor_idx].start_change_handler(change_handler);
                },
                _ => (),
            }
        }
        public_ip_result
    }

    fn add_mapping(
        &mut self,
        hole_port: u16,
    ) -> Result<u32, AutomapError> {
        match &self.inner_opt {
            Some (inner) => todo! ("Use what's already here"),
            None => {
                let result = self.find_working_protocol::<u32>(Box::new (move |transactor, router_ip| {
                    let remap_after = match transactor.add_mapping(router_ip, hole_port, MAPPING_LIFETIME_SECONDS) {
                        Ok(remap_after) => {
                            Some(remap_after)
                        },
                        Err(AutomapError::PermanentLeasesOnly) => match transactor.add_permanent_mapping (router_ip, hole_port) {
                            Ok (remap_after) => {
                                Some (remap_after)
                            },
                            Err (_) => None, // TODO Maybe log this error?
                        }
                        Err(_) => None, // TODO Maybe log this error?
                    }?;
                    Some (remap_after)
                }));
                if result.is_ok() {
                    self.hole_ports.insert (hole_port); // TODO SPIKE
                }
                result
            }
        }
        // let box_change_handler = Box::new(change_handler);
        // match protocol_opt {
        //     Some(protocol) => {
        //         let (_, router_ip, public_ip) = self.try_protocol(hole_port, protocol)?;
        //         let transactor = self
        //             .transactors
        //             .iter_mut()
        //             .find(|t| t.protocol() == protocol)
        //             .unwrap_or_else(|| panic!("Missing Transactor for {}", protocol));
        //         transactor.start_change_handler(box_change_handler)?;
        //         self.inner_opt = Some(AutomapControlRealInner {
        //             router_ip,
        //             protocol,
        //             port: hole_port,
        //         });
        //         Ok((protocol, public_ip))
        //     }
        //     None => {
        //         let init: Option<(&mut Box<dyn Transactor>, IpAddr, IpAddr)> = None;
        //         let result = self
        //             .transactors
        //             .iter_mut()
        //             .fold(init, |so_far, transactor| match so_far {
        //                 Some(_) => so_far,
        //                 None => match AutomapControlReal::try_transactor(hole_port, transactor.as_ref()) {
        //                     Ok((_, router_ip, public_ip)) => {
        //                         Some((transactor, router_ip, public_ip))
        //                     }
        //                     Err(_) => None,
        //                 },
        //             });
        //         match result {
        //             Some((transactor, router_ip, public_ip)) => {
        //                 transactor.start_change_handler(box_change_handler)?;
        //                 self.inner_opt = Some(AutomapControlRealInner {
        //                     router_ip,
        //                     protocol: transactor.protocol(),
        //                     port: hole_port,
        //                 });
        //                 Ok((transactor.protocol(), public_ip))
        //             }
        //             None => Err(AutomapError::AllProtocolsFailed),
        //         }
        //     }
        // }
    }

    fn delete_mappings(&self) -> Result<(), AutomapError> {
        match &self.inner_opt {
            None => Err(AutomapError::DeleteMappingError(
                "No port mapping to remove".to_string(),
            )),
            Some(inner) => {
                let transactor = &self.transactors[inner.transactor_idx];
                transactor.delete_mapping(inner.router_ip, inner.port)
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
            change_handler_opt: Some (change_handler),
            usual_protocol_opt,
            hole_ports: HashSet::new(),
            inner_opt: None,
        }
    }

    fn try_protocol_old(
        &self,
        port: u16,
        protocol: AutomapProtocol,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let transactor = self
            .transactors
            .iter()
            .find(|t| t.protocol() == protocol)
            .unwrap_or_else(|| panic!("Missing Transactor for {}", protocol));
        AutomapControlReal::try_transactor(port, transactor.as_ref())
    }

    fn try_transactor(
        port: u16,
        transactor: &dyn Transactor,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let router_ips = transactor.find_routers()?;
        match router_ips
            .into_iter()
            .map(|router_ip| AutomapControlReal::try_router(port, transactor, router_ip))
            .find(|result| result.is_ok())
        {
            Some(Ok(result)) => Ok(result),
            Some(Err(_)) => panic!("Impossible!"),
            None => Err(AutomapError::AllRoutersFailed(transactor.protocol())),
        }
    }

    fn try_router(
        port: u16,
        transactor: &dyn Transactor,
        router_ip: IpAddr,
    ) -> Result<(AutomapProtocol, IpAddr, IpAddr), AutomapError> {
        let public_ip = transactor.get_public_ip(router_ip)?;
        // TODO: Employ _remap_after
        let _remap_after = match transactor.add_mapping(router_ip, port, MAPPING_LIFETIME_SECONDS) {
            Ok(delay) => Ok(delay),
            Err(AutomapError::PermanentLeasesOnly) => {
                Ok(transactor.add_permanent_mapping(router_ip, port)?)
            }
            Err(e) => Err(e),
        }?;
        Ok((transactor.protocol(), router_ip, public_ip))
    }

    fn find_transactor(&self, protocol: AutomapProtocol) -> &dyn Transactor {
        self.transactors[self.find_transactor_index(protocol)].as_ref()
    }

    fn find_transactor_index(&self, protocol: AutomapProtocol) -> usize {
        (0..self.transactors.len())
            .into_iter()
            .find(|idx| self.transactors[*idx].protocol() == protocol)
            .unwrap_or_else(|| panic!("No Transactor for {}", protocol))
    }

    fn find_working_protocol<T>(&mut self, experiment: TransactorExperiment<T>) -> Result<T, AutomapError> {
        if let Some (usual_protocol) = self.usual_protocol_opt {
            let transactor = self.transactors.iter()
                .find (|t| t.protocol() == usual_protocol)
                .expect ("Missing Transactor");
            match Self::try_protocol (transactor, &experiment) {
                Some ((router_ip, t)) => {
                    self.inner_opt = Some(AutomapControlRealInner {
                        router_ip,
                        transactor_idx: self.find_transactor_index(usual_protocol),
                        port: 0, // TODO: Doesn't belong in this struct
                    });
                    return Ok (t)
                },
                None => (),
            }
        }
        let init: Option<(AutomapProtocol, IpAddr, T)> = None;
        let protocol_router_ip_and_experimental_outcome_opt = self.transactors.iter()
            .fold(init, |so_far, transactor| {
            match (so_far, self.usual_protocol_opt) {
                (Some(tuple), _) => Some (tuple),
                (None, Some (usual_protocol)) if usual_protocol == transactor.protocol() => None,
                (None, _) => Self::try_protocol (transactor, &experiment).map (|(router_ip, t)| {
                    (transactor.protocol(), router_ip, t)
                })
            }
        });
        match protocol_router_ip_and_experimental_outcome_opt {
            Some ((protocol, router_ip, t)) => {
                self.inner_opt = Some(AutomapControlRealInner {
                    router_ip,
                    transactor_idx: self.find_transactor_index (protocol),
                    port: 0, // TODO: Doesn't belong in this struct
                });
                Ok (t)
            },
            None => Err(AutomapError::AllProtocolsFailed),
        }
    }

    fn try_protocol<T> (transactor: &Box<dyn Transactor>, experiment: &TransactorExperiment<T>) -> Option<(IpAddr, T)> {
        let router_ips = match transactor.find_routers() {
            Ok(router_ips) if !router_ips.is_empty () => router_ips,
            _ => return None,
        };
        let init: Option<(IpAddr, T)> = None;
        router_ips.into_iter()
            .fold (init, |so_far, router_ip| {
                match so_far {
                    Some (tuple) => Some (tuple),
                    None => {
                        experiment(transactor.as_ref(), router_ip)
                            .map (|t| (router_ip, t))
                    }
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::{Transactor, AutomapErrorCause};
    use lazy_static::lazy_static;
    use std::any::Any;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::iter::FromIterator;

    lazy_static! {
        static ref ROUTER_IP: IpAddr = IpAddr::from_str("1.2.3.4").unwrap();
        static ref PUBLIC_IP: IpAddr = IpAddr::from_str("2.3.4.5").unwrap();
    }

    fn null_change_handler() -> ChangeHandler {
        Box::new(|_| {})
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
        start_change_handler_params: Arc<Mutex<Vec<ChangeHandler>>>,
        start_change_handler_results: RefCell<Vec<Result<(), AutomapError>>>,
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
        ) -> Result<(), AutomapError> {
            self.start_change_handler_params
                .lock()
                .unwrap()
                .push(change_handler);
            self.start_change_handler_results.borrow_mut().remove(0)
        }

        fn stop_change_handler(&mut self) {
            todo!()
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
            params: &Arc<Mutex<Vec<ChangeHandler>>>,
        ) -> Self {
            self.start_change_handler_params = params.clone();
            self
        }
    }

    fn find_working_protocol_works_for_success(protocol: AutomapProtocol) {
        let mut subject = make_multirouter_specific_success_subject(
            protocol,
            vec![
                IpAddr::from_str ("4.3.2.1").unwrap(),
                *ROUTER_IP,
                IpAddr::from_str("5.4.3.2").unwrap()
            ]
        );
        let experiment: TransactorExperiment<String> = Box::new (|t, router_ip| {
            match t.get_public_ip(router_ip) {
                Ok (_) if router_ip == *ROUTER_IP => Some ("Success!".to_string()),
                _ => None,
            }
        });

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Ok("Success!".to_string()));
        assert_eq!(subject.inner_opt.unwrap(), AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: match protocol {
                AutomapProtocol::Pcp => 0,
                AutomapProtocol::Pmp => 1,
                AutomapProtocol::Igdp => 2,
            },
            port: 0
        });
    }

    #[test]
    fn find_working_protocol_works_for_pcp_success() {
        find_working_protocol_works_for_success (AutomapProtocol::Pcp);
    }

    #[test]
    fn find_working_protocol_works_for_pmp_success() {
        find_working_protocol_works_for_success (AutomapProtocol::Pmp);
    }

    #[test]
    fn find_working_protocol_works_for_igdp_success() {
        find_working_protocol_works_for_success (AutomapProtocol::Igdp);
    }

    #[test]
    fn find_working_protocol_works_for_failure() {
        let mut subject = make_general_failure_subject();
        let experiment: TransactorExperiment<String> = Box::new (|t, router_ip| {
            match t.get_public_ip(router_ip) {
                Err (_) => None,
                Ok (_) => panic! ("For this test, get_public_ip() should never succeed"),
            }
        });

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Err(AutomapError::AllProtocolsFailed));
    }

    #[test]
    fn find_working_protocol_works_when_a_protocol_says_no_routers() {
        let mut subject = make_no_routers_subject();
        let experiment: TransactorExperiment<String> =
            Box::new (|t, router_ip| Some ("Success!".to_string()));

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Err (AutomapError::AllProtocolsFailed));
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn find_working_protocol_works_when_routers_are_found_but_the_experiment_fails_on_all_protocols() {
        let mut subject = make_null_subject();
        subject.transactors = subject.transactors.into_iter().map (|transactor| {
            make_params_success_transactor (
                transactor.protocol(),
                &Arc::new(Mutex::new(vec![])),
                &Arc::new(Mutex::new(vec![])),
                &Arc::new(Mutex::new(vec![])),
            )
        }).collect();
        let experiment: TransactorExperiment<String> =
            Box::new (|t, router_ip| None);

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Err (AutomapError::AllProtocolsFailed));
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn find_protocol_without_usual_protocol_traverses_available_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = None;
        let outer_protocol_log_arc = Arc::new (Mutex::new (vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> =
            Box::new (move |t, router_ip| {
                inner_protocol_log_arc.lock().unwrap ().push (t.protocol());
                if t.protocol() == AutomapProtocol::Pmp {
                    Some ("Success!".to_string())
                }
                else {
                    None
                }
            });

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Ok("Success!".to_string()));
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried PCP, failed. Tried PMP, worked. Didn't bother with IGDP.
        assert_eq!(*protocol_log, vec![AutomapProtocol::Pcp, AutomapProtocol::Pmp]);
    }

    #[test]
    fn find_protocol_with_successful_usual_protocol_does_not_try_other_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = Some (AutomapProtocol::Pmp);
        let outer_protocol_log_arc = Arc::new (Mutex::new (vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> =
            Box::new (move |t, router_ip| {
                inner_protocol_log_arc.lock().unwrap ().push (t.protocol());
                if t.protocol() == AutomapProtocol::Pmp {
                    Some ("Success!".to_string())
                }
                else {
                    None
                }
            });

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Ok("Success!".to_string()));
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried usual PMP first; succeeded.
        assert_eq!(*protocol_log, vec![AutomapProtocol::Pmp]);
    }

    #[test]
    fn find_protocol_with_failing_usual_protocol_tries_other_protocols() {
        let mut subject = make_all_routers_subject();
        subject.usual_protocol_opt = Some (AutomapProtocol::Pmp);
        let outer_protocol_log_arc = Arc::new (Mutex::new (vec![]));
        let inner_protocol_log_arc = outer_protocol_log_arc.clone();
        let experiment: TransactorExperiment<String> =
            Box::new (move |t, router_ip| {
                inner_protocol_log_arc.lock().unwrap ().push (t.protocol());
                if t.protocol() == AutomapProtocol::Igdp {
                    Some ("Success!".to_string())
                }
                else {
                    None
                }
            });

        let result = subject.find_working_protocol (experiment);

        assert_eq!(result, Ok("Success!".to_string()));
        let protocol_log = outer_protocol_log_arc.lock().unwrap();
        // Tried usual PMP; failed. Tried PCP, failed. Skipped PMP (already tried), tried IGDP; succeeded.
        assert_eq!(*protocol_log, vec![AutomapProtocol::Pmp, AutomapProtocol::Pcp, AutomapProtocol::Igdp]);
    }

    #[test]
    fn early_get_public_ip_starts_change_handler_and_delegates_to_transactor () {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new (Mutex::new (vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push (change);
        };
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = Some (Box::new (change_handler));

        let result = subject.get_public_ip();

        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        assert! (add_mapping_params_arc.lock().unwrap().is_empty());
        let actual_change_handler = start_change_handler_params_arc.lock().unwrap().remove(0);
        let change = AutomapChange::Error(AutomapError::ProtocolError("Booga!".to_string()));
        actual_change_handler(change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq! (*change_handler_log, vec![change])
    }

    #[test]
    fn late_get_public_ip_does_not_start_change_handler_but_delegates_to_transactor () {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &Arc::new(Mutex::new(vec![])),
        );
        subject.change_handler_opt = None;
        subject.inner_opt = Some (AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
            port: 0
        });

        let result = subject.get_public_ip();

        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq! (*get_public_ip_params, vec![*ROUTER_IP]);
        assert! (add_mapping_params_arc.lock().unwrap().is_empty());
    }

    #[test]
    fn early_add_mapping_timed_starts_change_handler_and_delegates_to_transactor () {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new (Mutex::new (vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push (change);
        };
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = Some (Box::new (change_handler));

        let result = subject.add_mapping (4567);

        assert! (get_public_ip_params_arc.lock().unwrap().is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq! (*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
        let actual_change_handler = start_change_handler_params_arc.lock().unwrap().remove(0);
        let change = AutomapChange::Error(AutomapError::ProtocolError("Booga!".to_string()));
        actual_change_handler(change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq! (*change_handler_log, vec![change])
    }

    #[test]
    fn late_add_mapping_timed_does_not_start_change_handler_but_delegates_to_transactor () {
        todo! ("Complete me")
    }

    #[test]
    fn late_add_mapping_permanent_does_not_start_change_handler_but_delegates_to_transactor () {
        todo! ("Complete me")
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////

    #[test]
    fn specific_add_mapping_works_for_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_single_success_subject(
            false,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        subject.change_handler_opt = Some (null_change_handler());

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1000));
        assert_eq!(subject.hole_ports, HashSet::from_iter (vec![1234].into_iter()));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 0,
                port: 0
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert!(get_public_ip_params.is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        assert! (start_change_handler_params.is_empty());
    }

    #[test]
    fn specific_add_mapping_works_for_pcp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.usual_protocol_opt = Some (AutomapProtocol::Pcp);
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 0,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_add_mapping_works_for_pmp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(
            AutomapProtocol::Pmp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.usual_protocol_opt = Some (AutomapProtocol::Pmp);
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 1,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_add_mapping_works_for_igdp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_specific_success_subject(
            AutomapProtocol::Igdp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.usual_protocol_opt = Some (AutomapProtocol::Igdp);
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 2,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn specific_add_mapping_works_for_pcp_failure() {
        let mut subject = make_specific_failure_subject(AutomapProtocol::Pcp);
        subject.usual_protocol_opt = Some (AutomapProtocol::Pcp);

        let result = subject.add_mapping(1234);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn specific_add_mapping_works_for_pmp_failure() {
        let mut subject = make_specific_failure_subject(AutomapProtocol::Pmp);
        subject.usual_protocol_opt = Some (AutomapProtocol::Pmp);

        let result = subject.add_mapping(1234);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn specific_add_mapping_works_for_igdp_failure() {
        let mut subject = make_specific_failure_subject(AutomapProtocol::Igdp);
        subject.usual_protocol_opt = Some (AutomapProtocol::Igdp);

        let result = subject.add_mapping(1234);

        assert_eq!(
            result,
            Err(AutomapError::ProtocolError("Booga!".to_string()))
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn general_add_mapping_works_for_pcp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 0,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_add_mapping_works_for_pmp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pmp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 1,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_add_mapping_works_for_igdp_success() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let mut subject = make_general_success_subject(
            AutomapProtocol::Igdp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
        );
        let outer_handler_data = Arc::new(Mutex::new("".to_string()));
        let inner_handler_data = outer_handler_data.clone();
        let change_handler = Box::new(move |change: AutomapChange| {
            inner_handler_data
                .lock()
                .unwrap()
                .push_str(&format!("{:?}", change))
        });
        subject.change_handler_opt = Some (change_handler);

        let result = subject.add_mapping(1234);

        assert_eq!(result, Ok(1));
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 2,
                port: 1234
            })
        );
        assert_eq!(
            subject.inner_opt,
            Some(AutomapControlRealInner {
                router_ip: *ROUTER_IP,
                transactor_idx: 2,
                port: 1234
            })
        );
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(
            *add_mapping_params,
            vec![(*ROUTER_IP, 1234, MAPPING_LIFETIME_SECONDS)]
        );
        let start_change_handler_params = start_change_handler_params_arc.lock().unwrap();
        start_change_handler_params[0](AutomapChange::NewIp(IpAddr::from_str("4.3.2.1").unwrap()));
        assert_eq!(*outer_handler_data.lock().unwrap(), "NewIp(4.3.2.1)");
    }

    #[test]
    fn general_add_mapping_works_for_all_failure() {
        let mut subject = make_general_failure_subject();

        let result = subject.add_mapping(1234);

        assert_eq!(result, Err(AutomapError::AllProtocolsFailed));
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn permanent_mapping_requirements_are_handled() {
        let add_permanent_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let transactor: Box<dyn Transactor> = Box::new(
            TransactorMock::new(AutomapProtocol::Igdp)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
                .add_permanent_mapping_params(&add_permanent_mapping_params_arc)
                .add_permanent_mapping_result(Ok(300)),
        );

        let result = AutomapControlReal::try_transactor(1234, transactor.as_ref());

        assert_eq!(result, Ok((AutomapProtocol::Igdp, *ROUTER_IP, *PUBLIC_IP)));
        let add_permanent_mapping_params = add_permanent_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_permanent_mapping_params, vec![(*ROUTER_IP, 1234)])
    }

    #[test]
    fn all_found_routers_are_tried_success() {
        let router_ip1 = IpAddr::from_str("8.8.8.1").unwrap();
        let router_ip2 = IpAddr::from_str("8.8.8.2").unwrap();
        let router_ip3 = IpAddr::from_str("8.8.8.3").unwrap();
        let transactor: Box<dyn Transactor> = Box::new(
            TransactorMock::new(AutomapProtocol::Igdp)
                .find_routers_result(Ok(vec![router_ip1, router_ip2, router_ip3]))
                .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
                .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_result(Ok(300)),
        );

        let result = AutomapControlReal::try_transactor(1234, transactor.as_ref());

        assert_eq!(result, Ok((AutomapProtocol::Igdp, router_ip3, *PUBLIC_IP)));
    }

    #[test]
    fn all_found_routers_are_tried_failure() {
        let router_ip1 = IpAddr::from_str("8.8.8.1").unwrap();
        let router_ip2 = IpAddr::from_str("8.8.8.2").unwrap();
        let router_ip3 = IpAddr::from_str("8.8.8.3").unwrap();
        let transactor: Box<dyn Transactor> = Box::new(
            TransactorMock::new(AutomapProtocol::Igdp)
                .find_routers_result(Ok(vec![router_ip1, router_ip2, router_ip3]))
                .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
                .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
                .get_public_ip_result(Err(AutomapError::CantFindDefaultGateway))
                .add_mapping_result(Ok(300)),
        );

        let result = AutomapControlReal::try_transactor(1234, transactor.as_ref());

        assert_eq!(
            result,
            Err(AutomapError::AllRoutersFailed(AutomapProtocol::Igdp))
        );
    }

    #[test]
    fn delete_mappings_complains_if_no_active_protocol() {
        let subject = make_null_subject();

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
        let subject =
            make_removal_success_subject(AutomapProtocol::Pmp, &delete_mapping_params_arc);

        let result = subject.delete_mappings();

        assert_eq!(result, Ok(()));
        let delete_mapping_params = delete_mapping_params_arc.lock().unwrap();
        assert_eq!(*delete_mapping_params, vec![(*ROUTER_IP, 1234)])
    }

    #[test]
    fn delete_mappings_works_with_failure() {
        let subject = make_removal_failure_subject(AutomapProtocol::Pmp);

        let result = subject.delete_mappings();

        assert_eq!(
            result,
            Err(AutomapError::DeleteMappingError("Booga!".to_string()))
        );
    }

    fn make_single_success_subject(
        use_usual_protocol: bool,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>,
    ) -> AutomapControlReal {
        let transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_params(get_public_ip_params_arc)
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_params(add_mapping_params_arc)
            .add_mapping_result(Ok(1000))
            .start_change_handler_params(start_change_handler_params_arc)
            .start_change_handler_result(Ok(()));
        let mut subject = AutomapControlReal::new(
            if use_usual_protocol {Some (AutomapProtocol::Pcp)} else {None},
            Box::new (|_x| {})
        );
        subject.transactors = vec![Box::new (transactor)];
        subject
    }

    fn make_specific_success_subject(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>,
    ) -> AutomapControlReal {
        let transactor = TransactorMock::new(protocol)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_params(get_public_ip_params_arc)
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_params(add_mapping_params_arc)
            .add_mapping_result(Ok(1000))
            .start_change_handler_params(start_change_handler_params_arc)
            .start_change_handler_result(Ok(()));
        replace_transactor(make_null_subject(), Box::new(transactor))
    }

    fn make_multirouter_specific_success_subject(
        protocol: AutomapProtocol,
        router_ips: Vec<IpAddr>,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        for candidate_protocol in AutomapProtocol::values() {
            if candidate_protocol != protocol {
                let transactor = TransactorMock::new (candidate_protocol)
                    .find_routers_result (Err(AutomapError::FindRouterError(
                        "Can't find routers".to_string(),
                        AutomapErrorCause::NetworkConfiguration
                    )));
                subject = replace_transactor(subject, Box::new (transactor));
            }
        }
        let router_ip_count = router_ips.len();
        let mut transactor = TransactorMock::new(protocol)
            .find_routers_result(Ok(router_ips))
            .start_change_handler_result(Ok(()));
        for _ in 0..router_ip_count {
            transactor = transactor
                .get_public_ip_result (Ok(*PUBLIC_IP))
                .add_mapping_result(Ok(1000));
        };
        replace_transactor (subject, Box::new (transactor))
    }

    fn make_removal_success_subject(
        protocol: AutomapProtocol,
        delete_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16)>>>,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 1,
            port: 1234,
        });
        let transactor = TransactorMock::new(protocol)
            .delete_mapping_params(delete_mapping_params_arc)
            .delete_mapping_result(Ok(()));
        replace_transactor(subject, Box::new(transactor))
    }

    fn make_removal_failure_subject(protocol: AutomapProtocol) -> AutomapControlReal {
        let mut subject = make_null_subject();
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 1,
            port: 1234,
        });
        let transactor = TransactorMock::new(protocol)
            .delete_mapping_result(Err(AutomapError::DeleteMappingError("Booga!".to_string())));
        replace_transactor(subject, Box::new(transactor))
    }

    fn make_specific_failure_subject(protocol: AutomapProtocol) -> AutomapControlReal {
        replace_transactor(make_null_subject(), make_failure_transactor(protocol))
    }

    fn make_general_success_subject(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>,
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
        let mut subject = AutomapControlReal::new(None, Box::new (|_x| {}));
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
        start_change_handler_params_arc: &Arc<Mutex<Vec<ChangeHandler>>>,
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
        Box::new(
            TransactorMock::new(protocol)
                .find_routers_result(Ok(vec![])),
        )
    }

    fn make_null_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new (|_x| {}));
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
        let mut subject = AutomapControlReal::new(None, Box::new (|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| {
                let transactor: Box<dyn Transactor> = Box::new (TransactorMock::new (t.protocol())
                        .find_routers_result(Ok(vec![*ROUTER_IP]))
                        .find_routers_result(Ok(vec![*ROUTER_IP]))
                );
                transactor
            })
            .collect();
        subject
    }

    fn make_no_routers_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new (|_x| {}));
        subject.transactors = subject
            .transactors
            .into_iter()
            .map(|t| {
                make_no_router_transactor(t.protocol())
            })
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
