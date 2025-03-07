// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::comm_layer::igdp::IgdpTransactor;
use crate::comm_layer::pcp::PcpTransactor;
use crate::comm_layer::pmp::PmpTransactor;
use crate::comm_layer::{
    AutomapError, HousekeepingThreadCommand, Transactor, DEFAULT_MAPPING_LIFETIME_SECONDS,
};
use crossbeam_channel::Sender;
use masq_lib::debug;
use masq_lib::logger::Logger;
use masq_lib::utils::{plus, AutomapProtocol};
use std::cell::{RefCell, RefMut};
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum AutomapChange {
    NewIp(IpAddr),
    Error(AutomapError),
}

pub type ChangeHandler = Box<dyn Fn(AutomapChange) + Send>;

pub trait AutomapControl: Send {
    fn get_public_ip(&mut self) -> Result<IpAddr, AutomapError>;
    fn add_mapping(&mut self, hole_port: u16) -> Result<(), AutomapError>;
    fn delete_mappings(&mut self) -> Result<(), AutomapError>;
    fn get_mapping_protocol(&self) -> Option<AutomapProtocol>;
}

#[derive(PartialEq, Eq, Debug)]
struct AutomapControlRealInner {
    router_ip: IpAddr,
    transactor_idx: usize,
}

type TransactorExperiment<T> = Box<dyn Fn(&dyn Transactor, IpAddr) -> Result<T, AutomapError>>;

#[derive(PartialEq, Eq, Debug)]
struct ProtocolInfo<T: PartialEq + Debug> {
    payload: T,
    router_ip: IpAddr,
}

struct HousekeepingTools {
    change_handler_opt: Option<ChangeHandler>,
    housekeeping_thread_commander_opt: Option<Sender<HousekeepingThreadCommand>>,
}

pub struct AutomapControlReal {
    transactors: RefCell<Vec<Box<dyn Transactor>>>,
    housekeeping_tools: RefCell<HousekeepingTools>,
    usual_protocol_opt: Option<AutomapProtocol>,
    hole_ports: HashSet<u16>,
    inner_opt: Option<AutomapControlRealInner>,
    logger: Logger,
}

impl AutomapControl for AutomapControlReal {
    fn get_public_ip(&mut self) -> Result<IpAddr, AutomapError> {
        debug!(self.logger, "Seeking public IP");
        let experiment = Box::new(move |transactor: &dyn Transactor, router_ip: IpAddr| {
            transactor.get_public_ip(router_ip)
        });
        let protocol_info = self.calculate_protocol_info(experiment)?;
        debug!(self.logger, "Public IP {:?}", protocol_info.payload);
        Ok(protocol_info.payload)
    }

    fn add_mapping(&mut self, hole_port: u16) -> Result<(), AutomapError> {
        debug!(self.logger, "Adding mapping for port {}", hole_port);
        let experiment = Box::new(move |transactor: &dyn Transactor, router_ip: IpAddr| {
            match transactor.add_mapping(router_ip, hole_port, DEFAULT_MAPPING_LIFETIME_SECONDS) {
                Ok(remap_after_sec) => Ok(remap_after_sec),
                Err(AutomapError::PermanentLeasesOnly) => {
                    transactor.add_permanent_mapping(router_ip, hole_port)
                }
                Err(e) => Err(e),
            }
        });
        let protocol_info = self.calculate_protocol_info(experiment)?;
        let transactor_idx = self
            .inner_opt
            .as_ref()
            .expect("inner disappeared")
            .transactor_idx;
        self.usual_protocol_opt = Some(self.transactors.borrow()[transactor_idx].protocol());
        self.hole_ports.insert(hole_port);
        let remap_after_sec: u32 = protocol_info.payload;
        self.housekeeping_tools
            .borrow()
            .housekeeping_thread_commander_opt
            .as_ref()
            .expect("housekeeping_thread_commander was unpopulated after maybe_start_housekeeper()")
            .send(HousekeepingThreadCommand::SetRemapIntervalMs(
                remap_after_sec as u64 * 1000u64,
            ))
            .expect("Housekeeping thread is dead");
        Ok(())
    }

    fn delete_mappings(&mut self) -> Result<(), AutomapError> {
        match &self.inner_opt {
            None => Err(AutomapError::DeleteMappingError(
                "No port mapping to remove".to_string(),
            )),
            Some(inner) => {
                debug!(self.logger, "Deleting public mappings");
                let transactor = &mut self.transactors.borrow_mut()[inner.transactor_idx];
                let init: Vec<AutomapError> = vec![];
                let errors =
                    self.hole_ports.iter().fold(init, |so_far, hole_port| {
                        match transactor.delete_mapping(inner.router_ip, *hole_port) {
                            Ok(_) => so_far,
                            Err(e) => plus(so_far, e),
                        }
                    });
                let _ = transactor.stop_housekeeping_thread();
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors[0].clone())
                }
            }
        }
    }

    fn get_mapping_protocol(&self) -> Option<AutomapProtocol> {
        self.usual_protocol_opt
    }
}

impl AutomapControlReal {
    pub fn new(usual_protocol_opt: Option<AutomapProtocol>, change_handler: ChangeHandler) -> Self {
        Self {
            transactors: RefCell::new(vec![
                Box::<PcpTransactor>::default(),
                Box::<PmpTransactor>::default(),
                Box::<IgdpTransactor>::default(),
            ]),
            housekeeping_tools: RefCell::new(HousekeepingTools {
                change_handler_opt: Some(change_handler),
                housekeeping_thread_commander_opt: None,
            }),
            usual_protocol_opt,
            hole_ports: HashSet::new(),
            inner_opt: None,
            logger: Logger::new("AutomapControl"),
        }
    }

    fn maybe_start_housekeeper(
        &self,
        transactor: &mut dyn Transactor,
        router_ip: IpAddr,
    ) -> Result<(), AutomapError> {
        let mut housekeeping_tools = self.housekeeping_tools.borrow_mut(); //to avoid multiple borrows a time
        if let Some(change_handler) = housekeeping_tools.change_handler_opt.take() {
            debug!(self.logger, "Attempting to start housekeeping thread");
            match transactor.start_housekeeping_thread(change_handler, router_ip) {
                Err(AutomapError::HousekeeperAlreadyRunning) => {
                    debug!(
                        self.logger,
                        "Housekeeping thread cannot start: already running"
                    );
                    Self::put_change_handler_back(transactor, &mut housekeeping_tools);
                    Ok(())
                }
                Err(e) => {
                    debug!(self.logger, "Housekeeping thread failed: {:?}", e);
                    Self::put_change_handler_back(transactor, &mut housekeeping_tools);
                    Err(e)
                }
                Ok(commander) => {
                    debug!(self.logger, "Housekeeping thread running");
                    housekeeping_tools.housekeeping_thread_commander_opt = Some(commander);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }

    fn put_change_handler_back(
        transactor: &mut dyn Transactor,
        housekeeping_tools: &mut RefMut<HousekeepingTools>,
    ) {
        let change_handler = match transactor.stop_housekeeping_thread() {
            Ok(ch) => ch,
            Err(e) => todo!("{:?}", e),
        };
        housekeeping_tools
            .change_handler_opt
            .replace(change_handler);
    }

    fn find_transactor_index(
        transactors: RefMut<Vec<Box<dyn Transactor>>>,
        protocol: AutomapProtocol,
    ) -> usize {
        (0..transactors.len())
            .find(|idx| transactors[*idx].protocol() == protocol)
            .unwrap_or_else(|| panic!("No Transactor for {}", protocol))
    }

    fn prepare_and_perform_experiment<T: PartialEq + Debug>(
        &self,
        inner: &AutomapControlRealInner,
        experiment: TransactorExperiment<T>,
    ) -> Result<ProtocolInfo<T>, AutomapError> {
        self.maybe_start_housekeeper(
            self.transactors.borrow_mut()[inner.transactor_idx].as_mut(),
            inner.router_ip,
        )?;
        let result = experiment(
            self.transactors.borrow_mut()[inner.transactor_idx].as_ref(),
            inner.router_ip,
        );
        result.map(|payload| ProtocolInfo {
            payload,
            router_ip: inner.router_ip,
        })
    }

    fn choose_working_protocol<T: PartialEq + Debug>(
        &mut self,
        experiment: TransactorExperiment<T>,
    ) -> Result<ProtocolInfo<T>, AutomapError> {
        let mut transactors_ref_mut = self.transactors.borrow_mut();
        if let Some(usual_protocol) = self.usual_protocol_opt {
            debug!(
                self.logger,
                "Trying a predetermined protocol: {}", usual_protocol
            );
            let transactor = transactors_ref_mut
                .iter_mut()
                .find(|t| t.protocol() == usual_protocol)
                .expect("Missing Transactor");
            if let Ok((router_ip, t)) = self.try_protocol(transactor.as_mut(), &experiment) {
                self.inner_opt = Some(AutomapControlRealInner {
                    router_ip,
                    transactor_idx: Self::find_transactor_index(
                        transactors_ref_mut,
                        usual_protocol,
                    ),
                });
                return Ok(ProtocolInfo {
                    payload: t,
                    router_ip,
                });
            }
        }
        let init: Result<(AutomapProtocol, IpAddr, T), Vec<(AutomapProtocol, AutomapError)>> =
            Err(vec![]);
        let protocol_router_ip_and_experimental_outcome_result = transactors_ref_mut
            .iter_mut()
            .fold(init, |so_far, transactor| {
                match (so_far, self.usual_protocol_opt) {
                    (Ok(tuple), _) => Ok(tuple),
                    (Err(e), Some(usual_protocol)) if usual_protocol == transactor.protocol() => {
                        Err(e)
                    }
                    (Err(existing_errors), _) => self
                        .try_protocol(transactor.as_mut(), &experiment)
                        .map(|(router_ip, t)| (transactor.protocol(), router_ip, t))
                        .map_err(|e| plus(existing_errors, (transactor.protocol(), e))),
                }
            });
        match protocol_router_ip_and_experimental_outcome_result {
            Ok((protocol, router_ip, t)) => {
                self.inner_opt = Some(AutomapControlRealInner {
                    router_ip,
                    transactor_idx: Self::find_transactor_index(transactors_ref_mut, protocol),
                });
                self.usual_protocol_opt = Some(protocol);
                Ok(ProtocolInfo {
                    payload: t,
                    router_ip,
                })
            }
            Err(errors) => Err(AutomapError::AllProtocolsFailed(errors)),
        }
    }

    fn try_protocol<T>(
        &self,
        transactor: &mut dyn Transactor,
        experiment: &TransactorExperiment<T>,
    ) -> Result<(IpAddr, T), AutomapError> {
        let router_ips = transactor.find_routers()?;
        if router_ips.is_empty() {
            return Err(AutomapError::FindRouterError(
                "No routers found".to_string(),
            ));
        }
        let init: Result<(IpAddr, T), AutomapError> = Err(AutomapError::Unknown);
        router_ips
            .into_iter()
            .fold(init, |so_far, router_ip| match so_far {
                Ok(tuple) => Ok(tuple),
                Err(_) => {
                    self.maybe_start_housekeeper(transactor, router_ip)?;
                    match experiment(transactor, router_ip).map(|t| (router_ip, t)) {
                        Ok(pair) => Ok(pair),
                        Err(e) => {
                            let change_handler = match transactor.stop_housekeeping_thread() {
                                Ok(ch) => ch,
                                Err(e) => todo!("{:?}", e),
                            };
                            let mut housekeeping_tools = self.housekeeping_tools.borrow_mut();
                            let _ = housekeeping_tools
                                .change_handler_opt
                                .replace(change_handler);
                            Err(e)
                        }
                    }
                }
            })
    }

    fn calculate_protocol_info<T: PartialEq + Debug>(
        &mut self,
        experiment: TransactorExperiment<T>,
    ) -> Result<ProtocolInfo<T>, AutomapError> {
        if let Some(inner) = self.inner_opt.as_ref() {
            // Protocol's already chosen and running; just run the code
            self.prepare_and_perform_experiment(inner, experiment)
        } else {
            // Nothing's set up yet; repeat the experiment until we find the right protocol
            self.choose_working_protocol(experiment)
        }
    }
}

#[cfg(any(test, not(feature = "no_test_share")))]
pub fn replace_transactor(
    subject: AutomapControlReal,
    transactor: Box<dyn Transactor>,
) -> AutomapControlReal {
    let idx = AutomapControlReal::find_transactor_index(
        subject.transactors.borrow_mut(),
        transactor.protocol(),
    );
    subject.transactors.borrow_mut()[idx] = transactor;
    subject
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comm_layer::Transactor;
    use crate::mocks::{TransactorMock, PUBLIC_IP, ROUTER_IP};
    use crossbeam_channel::{unbounded, TryRecvError};
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::ptr::addr_of;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

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

        assert_all_protocols_failed(
            result,
            AutomapError::ProtocolError("Booga!".to_string()),
            AutomapError::ProtocolError("Booga!".to_string()),
            AutomapError::ProtocolError("Booga!".to_string()),
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn choose_working_protocol_works_when_all_protocol_say_no_routers() {
        let mut subject = make_no_routers_subject();
        let experiment: TransactorExperiment<String> =
            Box::new(|_t, _router_ip| Ok("Success!".to_string()));

        let result = subject.choose_working_protocol(experiment);

        assert_all_protocols_failed(
            result,
            AutomapError::FindRouterError("No routers found".to_string()),
            AutomapError::FindRouterError("No routers found".to_string()),
            AutomapError::FindRouterError("No routers found".to_string()),
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn choose_working_protocol_works_when_routers_are_found_but_the_experiment_fails_on_all_protocols(
    ) {
        let mut subject = make_null_subject();
        let transactors_adjustment = subject
            .transactors
            .borrow()
            .iter()
            .map(|transactor| {
                make_params_success_transactor(
                    transactor.protocol(),
                    &Arc::new(Mutex::new(vec![])),
                    &Arc::new(Mutex::new(vec![])),
                    &Arc::new(Mutex::new(vec![])),
                    unbounded().0,
                )
            })
            .collect();
        subject.transactors = RefCell::new(transactors_adjustment);
        let experiment: TransactorExperiment<String> =
            Box::new(|_t, _router_ip| Err(AutomapError::Unknown));

        let result = subject.choose_working_protocol(experiment);

        assert_all_protocols_failed(
            result,
            AutomapError::Unknown,
            AutomapError::Unknown,
            AutomapError::Unknown,
        );
        assert_eq!(subject.inner_opt, None);
    }

    #[test]
    fn find_protocol_without_usual_protocol_traverses_available_protocols() {
        let mut subject = make_fully_populated_subject();
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
        let subject = make_null_subject();
        let (tx, _) = unbounded();
        let transactor = Box::new(
            TransactorMock::new(AutomapProtocol::Pmp)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .start_housekeeping_thread_result(Ok(tx)),
        );
        let mut subject = replace_transactor(subject, transactor);
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
        let mut subject = make_fully_populated_subject();
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
    fn get_public_ip_starts_housekeeping_thread_and_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push(change);
        };
        let (tx, rx) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
            tx,
        );
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(change_handler));
        subject.inner_opt = None;

        let result = subject.get_public_ip();

        assert_eq!(result, Ok(*PUBLIC_IP));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
        assert!(add_mapping_params_arc.lock().unwrap().is_empty());
        let (actual_change_handler, router_ip) =
            start_change_handler_params_arc.lock().unwrap().remove(0);
        assert_eq!(router_ip, *ROUTER_IP);
        // Run a change through this handler to make sure it's the same one we sent in
        let change = AutomapChange::Error(AutomapError::ProtocolError("Booga!".to_string()));
        actual_change_handler(change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq!(*change_handler_log, vec![change])
    }

    #[test]
    fn get_public_ip_passes_on_error_from_failing_to_start_housekeeping_thread() {
        let subject = make_null_subject();
        let subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pcp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .start_housekeeping_thread_result(Err(AutomapError::Unknown))
                    .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
            ),
        );
        let subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pmp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .start_housekeeping_thread_result(Err(AutomapError::NoLocalIpAddress))
                    .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
            ),
        );
        let mut subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Igdp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .start_housekeeping_thread_result(Err(AutomapError::PermanentLeasesOnly))
                    .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
            ),
        );
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = None;

        let result = subject.get_public_ip();

        assert_all_protocols_failed(
            result,
            AutomapError::Unknown,
            AutomapError::NoLocalIpAddress,
            AutomapError::PermanentLeasesOnly,
        );
    }

    #[test]
    fn get_public_ip_does_not_start_housekeeping_thread_but_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = unbounded();
        let subject = make_null_subject();
        let mut transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .get_public_ip_params(&get_public_ip_params_arc)
            .get_public_ip_result(Ok(*PUBLIC_IP));
        transactor.housekeeping_thread_started = true;
        let mut subject = replace_transactor(subject, Box::new(transactor));
        subject.housekeeping_tools = RefCell::new(HousekeepingTools {
            change_handler_opt: None,
            housekeeping_thread_commander_opt: Some(tx),
        });
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.get_public_ip();

        assert_eq!(result, Ok(*PUBLIC_IP));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        let get_public_ip_params = get_public_ip_params_arc.lock().unwrap();
        assert_eq!(*get_public_ip_params, vec![*ROUTER_IP]);
    }

    #[test]
    fn get_public_ip_reports_experiment_failure() {
        let subject = make_null_subject();
        let mut subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pcp)
                    .find_routers_result(Ok(vec![*ROUTER_IP]))
                    .start_housekeeping_thread_result(Ok(unbounded().0))
                    .get_public_ip_result(Err(AutomapError::HousekeeperAlreadyRunning))
                    .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
            ),
        );
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.get_public_ip();

        assert_eq!(result, Err(AutomapError::HousekeeperAlreadyRunning));
    }

    #[test]
    fn add_mapping_timed_starts_housekeeping_thread_and_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_change_handler_params_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let change_handler_log_arc_inner = change_handler_log_arc.clone();
        let change_handler = move |change: AutomapChange| {
            change_handler_log_arc_inner.lock().unwrap().push(change);
        };
        let (tx, rx) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &get_public_ip_params_arc,
            &add_mapping_params_arc,
            &start_change_handler_params_arc,
            tx,
        );
        subject.inner_opt = None;
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(change_handler));
        subject
            .housekeeping_tools
            .borrow_mut()
            .housekeeping_thread_commander_opt = None;

        subject.add_mapping(4567).unwrap();

        assert_eq!(
            rx.try_recv(),
            Ok(HousekeepingThreadCommand::SetRemapIntervalMs(1000000))
        );
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
    fn add_mapping_passes_on_error_from_failing_to_start_housekeeping_thread() {
        let mut subject = make_null_subject();
        fn add_transactor(
            subject: AutomapControlReal,
            protocol: AutomapProtocol,
            start_thread_error: AutomapError,
        ) -> AutomapControlReal {
            replace_transactor(
                subject,
                Box::new(
                    TransactorMock::new(protocol)
                        .find_routers_result(Ok(vec![*ROUTER_IP]))
                        .start_housekeeping_thread_result(Err(start_thread_error))
                        .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
                ),
            )
        }
        subject = add_transactor(subject, AutomapProtocol::Pcp, AutomapError::Unknown);
        subject = add_transactor(
            subject,
            AutomapProtocol::Pmp,
            AutomapError::NoLocalIpAddress,
        );
        subject = add_transactor(
            subject,
            AutomapProtocol::Igdp,
            AutomapError::CantFindDefaultGateway,
        );
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = None;

        let result = subject.add_mapping(1234);

        assert_all_protocols_failed(
            result,
            AutomapError::Unknown,
            AutomapError::NoLocalIpAddress,
            AutomapError::CantFindDefaultGateway,
        );
    }

    #[test]
    fn add_mapping_timed_does_not_start_housekeeping_thread_but_delegates_to_transactor() {
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = unbounded();
        let subject = make_null_subject();
        let mut transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Ok(1000));
        transactor.housekeeping_thread_started = true;
        let mut subject = replace_transactor(subject, Box::new(transactor));
        subject.housekeeping_tools = RefCell::new(HousekeepingTools {
            change_handler_opt: None,
            housekeeping_thread_commander_opt: Some(tx),
        });
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        subject.add_mapping(4567).unwrap();

        assert_eq!(
            rx.try_recv(),
            Ok(HousekeepingThreadCommand::SetRemapIntervalMs(1000000))
        );
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
    }

    #[test]
    fn late_add_mapping_timed_handles_mapping_error() {
        let mut subject = make_general_failure_subject();
        let mut transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_result(Err(AutomapError::PermanentMappingError(
                "Booga!".to_string(),
            )));
        transactor.housekeeping_thread_started = true;
        subject.transactors.borrow_mut()[0] = Box::new(transactor);

        subject.housekeeping_tools.borrow_mut().change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError("Booga!".to_string()))
        );
    }

    #[test]
    fn add_mapping_permanent_handles_mapping_error() {
        let mut subject = make_general_failure_subject();
        let mut transactor = TransactorMock::new(AutomapProtocol::Igdp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_result(Ok(*PUBLIC_IP))
            .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
            .add_permanent_mapping_result(Err(AutomapError::PermanentMappingError(
                "Booga!".to_string(),
            )));
        transactor.housekeeping_thread_started = true;
        subject.transactors.borrow_mut()[2] = Box::new(transactor);

        subject.housekeeping_tools.borrow_mut().change_handler_opt = None;
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 2,
        });

        let result = subject.add_mapping(4567);

        assert_eq!(
            result,
            Err(AutomapError::PermanentMappingError("Booga!".to_string()))
        );
    }

    #[test]
    fn add_mapping_permanent_does_not_start_housekeeping_thread_but_delegates_to_transactor() {
        let get_public_ip_params_arc = Arc::new(Mutex::new(vec![]));
        let add_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let add_permanent_mapping_params_arc = Arc::new(Mutex::new(vec![]));
        let start_housekeeping_thread_params_arc = Arc::new(Mutex::new(vec![]));
        let (tx, rx) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            tx.clone(),
        );
        let mut transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .find_routers_result(Ok(vec![*ROUTER_IP]))
            .get_public_ip_params(&get_public_ip_params_arc)
            .add_mapping_params(&add_mapping_params_arc)
            .add_mapping_result(Err(AutomapError::PermanentLeasesOnly))
            .add_permanent_mapping_params(&add_permanent_mapping_params_arc)
            .add_permanent_mapping_result(Ok(1000))
            .start_housekeeping_thread_params(&start_housekeeping_thread_params_arc);
        transactor.housekeeping_thread_started = true;
        subject.transactors.borrow_mut()[0] = Box::new(transactor);
        subject.housekeeping_tools.borrow_mut().change_handler_opt = None;
        subject
            .housekeeping_tools
            .borrow_mut()
            .housekeeping_thread_commander_opt = Some(tx);
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        subject.add_mapping(4567).unwrap();

        assert_eq!(
            rx.try_recv(),
            Ok(HousekeepingThreadCommand::SetRemapIntervalMs(1000000))
        );
        assert!(get_public_ip_params_arc.lock().unwrap().is_empty());
        let add_mapping_params = add_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_mapping_params, vec![(*ROUTER_IP, 4567, 600)]);
        let add_permanent_mapping_params = add_permanent_mapping_params_arc.lock().unwrap();
        assert_eq!(*add_permanent_mapping_params, vec![(*ROUTER_IP, 4567)]);
        assert!(start_housekeeping_thread_params_arc
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn add_mapping_reports_experiment_failure() {
        let subject = make_general_failure_subject();
        let (tx, _) = unbounded();
        let failure_transactor = TransactorMock::new(AutomapProtocol::Pcp)
            .add_mapping_result(Err(AutomapError::NoLocalIpAddress))
            .start_housekeeping_thread_result(Ok(tx));
        let mut subject = replace_transactor(subject, Box::new(failure_transactor));
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });

        let result = subject.add_mapping(6666);

        assert_eq!(result, Err(AutomapError::NoLocalIpAddress));
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
            .stop_housekeeping_thread_params(&stop_change_handler_params_arc)
            .stop_housekeeping_thread_result(Ok(Box::new(|_| ())));
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
            .stop_housekeeping_thread_params(&stop_change_handler_params_arc)
            .stop_housekeeping_thread_result(Ok(Box::new(|_| ())));
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
    fn get_mapping_protocol_returns_usual_mapping_protocol_opt() {
        let mut subject = make_null_subject();
        subject.usual_protocol_opt = Some(AutomapProtocol::Pmp);

        let result = subject.get_mapping_protocol();

        assert_eq!(result, Some(AutomapProtocol::Pmp));
    }

    #[test]
    fn get_public_ip_establishes_usual_mapping_protocol() {
        let (tx, _rx) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            tx,
        );
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| {}));
        subject.inner_opt = None;

        let _ = subject.get_public_ip();

        assert_eq!(subject.get_mapping_protocol(), Some(AutomapProtocol::Pcp));
    }

    #[test]
    fn add_mapping_establishes_usual_mapping_protocol() {
        let (tx, _rx) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            tx,
        );
        subject.inner_opt = None;
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| {}));
        subject
            .housekeeping_tools
            .borrow_mut()
            .housekeeping_thread_commander_opt = None;

        subject.add_mapping(4567).unwrap();

        assert_eq!(subject.get_mapping_protocol(), Some(AutomapProtocol::Pcp));
    }

    #[test]
    fn maybe_start_housekeeper_handles_housekeeper_already_running() {
        let mut subject = make_null_subject();
        let change_handler_log_arc = Arc::new(Mutex::new(vec![]));
        let chla_inner = change_handler_log_arc.clone();
        let change_handler = Box::new(move |change| chla_inner.lock().unwrap().push(change));
        subject.housekeeping_tools.borrow_mut().change_handler_opt = Some(Box::new(|_| ()));
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 0,
        });
        let mut transactor = TransactorMock::new(AutomapProtocol::Igdp)
            .start_housekeeping_thread_result(Err(AutomapError::HousekeeperAlreadyRunning))
            .stop_housekeeping_thread_result(Ok(change_handler));

        let result = subject.maybe_start_housekeeper(&mut transactor, *ROUTER_IP);

        assert_eq!(result, Ok(()));
        // Make sure the change handler that's back in housekeeping_tools is the one that writes to our log
        let expected_change = AutomapChange::Error(AutomapError::NoLocalIpAddress);
        subject
            .housekeeping_tools
            .borrow_mut()
            .change_handler_opt
            .as_ref()
            .unwrap()(expected_change.clone());
        let change_handler_log = change_handler_log_arc.lock().unwrap();
        assert_eq!(*change_handler_log, vec![expected_change]);
    }

    #[test]
    fn calculate_protocol_info_chooses_protocol_when_necessary() {
        let (tx, _) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            tx,
        );
        let experiment: TransactorExperiment<String> = Box::new(|_, _| Ok("Booga!".to_string()));

        let result = subject.calculate_protocol_info(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Booga!".to_string(),
                router_ip: *ROUTER_IP
            })
        )
    }

    #[test]
    fn calculate_protocol_info_uses_existing_protocol_when_necessary() {
        let (tx, _) = unbounded();
        let mut subject = make_general_success_subject(
            AutomapProtocol::Pcp,
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            &Arc::new(Mutex::new(vec![])),
            tx.clone(),
        );
        let start_housekeeping_thread_params_arc = Arc::new(Mutex::new(vec![]));
        subject = replace_transactor(
            subject,
            Box::new(
                TransactorMock::new(AutomapProtocol::Pmp)
                    .start_housekeeping_thread_params(&start_housekeeping_thread_params_arc)
                    .start_housekeeping_thread_result(Ok(tx)),
            ),
        );
        subject.inner_opt = Some(AutomapControlRealInner {
            router_ip: *ROUTER_IP,
            transactor_idx: 1,
        });
        let experiment: TransactorExperiment<String> = Box::new(|_, _| Ok("Booga!".to_string()));

        let result = subject.calculate_protocol_info(experiment);

        assert_eq!(
            result,
            Ok(ProtocolInfo {
                payload: "Booga!".to_string(),
                router_ip: *ROUTER_IP
            })
        );
        let start_housekeeping_thread_params = start_housekeeping_thread_params_arc.lock().unwrap();
        assert_eq!(start_housekeeping_thread_params[0].1, *ROUTER_IP)
    }

    #[test]
    fn try_protocol_stops_housekeeping_threads_for_failed_experiments() {
        let stop_housekeeping_thread_params_arc = Arc::new(Mutex::new(vec![]));
        let mut transactor = TransactorMock::new(AutomapProtocol::Pmp)
            .find_routers_result(Ok(vec![
                IpAddr::from_str("1.2.3.4").unwrap(),
                IpAddr::from_str("2.3.4.5").unwrap(),
                IpAddr::from_str("3.4.5.6").unwrap(),
            ]))
            .start_housekeeping_thread_result(Ok(unbounded().0))
            .start_housekeeping_thread_result(Ok(unbounded().0))
            .start_housekeeping_thread_result(Ok(unbounded().0))
            .stop_housekeeping_thread_params(&stop_housekeeping_thread_params_arc)
            .stop_housekeeping_thread_result(Ok(Box::new(|_| ())))
            .stop_housekeeping_thread_result(Ok(Box::new(|_| ())));
        // Any third attempt to stop housekeeping thread should fail the test
        let experiment: TransactorExperiment<String> = Box::new(|_, router_ip| {
            if router_ip == IpAddr::from_str("3.4.5.6").unwrap() {
                Ok("Success!".to_string())
            } else {
                Err(AutomapError::NoLocalIpAddress)
            }
        });
        let subject = AutomapControlReal::new(None, Box::new(|_| ()));

        let result = subject.try_protocol(&mut transactor, &experiment);

        assert_eq!(
            result,
            Ok((IpAddr::from_str("3.4.5.6").unwrap(), "Success!".to_string()))
        );
        let stop_housekeeping_thread_params = stop_housekeeping_thread_params_arc.lock().unwrap();
        assert_eq!(*stop_housekeeping_thread_params, vec![(), ()]); // two calls, not three
    }

    #[test]
    fn try_protocol_preserves_change_handler_when_experiment_fails() {
        // In real life these two would be the same, but that's hard to do and unnecessary in this test
        let initial_change_handler = Box::new(|_| ());
        let extracted_change_handler = Box::new(|_| ());
        let expected_change_handler_identity = addr_of!(*extracted_change_handler);
        let mut transactor = TransactorMock::new(AutomapProtocol::Pmp)
            .find_routers_result(Ok(vec![IpAddr::from_str("1.2.3.4").unwrap()]))
            .start_housekeeping_thread_result(Ok(unbounded().0))
            .stop_housekeeping_thread_result(Ok(extracted_change_handler));
        let experiment: TransactorExperiment<String> =
            Box::new(|_, _| Err(AutomapError::NoLocalIpAddress));
        let subject = AutomapControlReal::new(None, initial_change_handler);

        let result = subject.try_protocol(&mut transactor, &experiment);

        assert_eq!(result, Err(AutomapError::NoLocalIpAddress));
        let actual_change_handler = subject
            .housekeeping_tools
            .borrow_mut()
            .change_handler_opt
            .take()
            .unwrap();
        let actual_change_handler_identity = addr_of!(*actual_change_handler);
        assert_eq!(
            actual_change_handler_identity,
            expected_change_handler_identity
        );
    }

    fn make_multirouter_specific_success_subject(
        protocol: AutomapProtocol,
        router_ips: Vec<IpAddr>,
    ) -> AutomapControlReal {
        let mut subject = make_null_subject();
        for candidate_protocol in AutomapProtocol::values() {
            if candidate_protocol != protocol {
                let transactor = TransactorMock::new(candidate_protocol).find_routers_result(Err(
                    AutomapError::FindRouterError("Can't find routers".to_string()),
                ));
                subject = replace_transactor(subject, Box::new(transactor));
            }
        }
        let router_ip_count = router_ips.len();
        let mut transactor = TransactorMock::new(protocol).find_routers_result(Ok(router_ips));
        for _ in 0..router_ip_count {
            transactor = transactor
                .start_housekeeping_thread_result(Ok(unbounded().0))
                .stop_housekeeping_thread_result(Ok(Box::new(|_| ())))
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
        start_housekeeping_thread_params_arc: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
        housekeeper_commander: Sender<HousekeepingThreadCommand>,
    ) -> AutomapControlReal {
        let subject = make_general_failure_subject();
        let success_transactor = make_params_success_transactor(
            protocol,
            get_public_ip_params_arc,
            add_mapping_params_arc,
            start_housekeeping_thread_params_arc,
            housekeeper_commander,
        );
        replace_transactor(subject, success_transactor)
    }

    fn make_general_failure_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        let modified_transactors = RefCell::new(
            subject
                .transactors
                .borrow()
                .iter()
                .map(|t| make_failure_transactor(t.protocol()))
                .collect(),
        );
        subject.transactors = modified_transactors;
        subject
    }

    fn make_params_success_transactor(
        protocol: AutomapProtocol,
        get_public_ip_params_arc: &Arc<Mutex<Vec<IpAddr>>>,
        add_mapping_params_arc: &Arc<Mutex<Vec<(IpAddr, u16, u32)>>>,
        start_housekeeping_thread_params_arc: &Arc<Mutex<Vec<(ChangeHandler, IpAddr)>>>,
        housekeeper_commander: Sender<HousekeepingThreadCommand>,
    ) -> Box<dyn Transactor> {
        Box::new(
            TransactorMock::new(protocol)
                .find_routers_result(Ok(vec![*ROUTER_IP]))
                .get_public_ip_params(get_public_ip_params_arc)
                .get_public_ip_result(Ok(*PUBLIC_IP))
                .add_mapping_params(add_mapping_params_arc)
                .add_mapping_result(Ok(1000))
                .start_housekeeping_thread_params(start_housekeeping_thread_params_arc)
                .start_housekeeping_thread_result(Ok(housekeeper_commander))
                .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
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
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| ()));
        let adjustment = RefCell::new(
            subject
                .transactors
                .borrow()
                .iter()
                .map(|t| {
                    let tm: Box<dyn Transactor> = Box::new(TransactorMock::new(t.protocol()));
                    tm
                })
                .collect(),
        );
        subject.transactors = adjustment;
        subject
    }

    fn make_fully_populated_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        let adjustment = RefCell::new(
            subject
                .transactors
                .borrow()
                .iter()
                .map(|t| {
                    let transactor: Box<dyn Transactor> = Box::new(
                        TransactorMock::new(t.protocol())
                            .find_routers_result(Ok(vec![*ROUTER_IP]))
                            .start_housekeeping_thread_result(Ok(unbounded().0))
                            .stop_housekeeping_thread_result(Ok(Box::new(|_| ()))),
                    );
                    transactor
                })
                .collect(),
        );
        subject.transactors = adjustment;
        subject
    }

    fn make_no_routers_subject() -> AutomapControlReal {
        let mut subject = AutomapControlReal::new(None, Box::new(|_x| {}));
        let modified_transactors = RefCell::new(
            subject
                .transactors
                .borrow()
                .iter()
                .map(|t| make_no_router_transactor(t.protocol()))
                .collect(),
        );
        subject.transactors = modified_transactors;
        subject
    }

    fn assert_all_protocols_failed<T: Debug + PartialEq>(
        result: Result<T, AutomapError>,
        pcp: AutomapError,
        pmp: AutomapError,
        igdp: AutomapError,
    ) {
        assert_eq!(
            result,
            Err(AutomapError::AllProtocolsFailed(vec![
                (AutomapProtocol::Pcp, pcp),
                (AutomapProtocol::Pmp, pmp),
                (AutomapProtocol::Igdp, igdp),
            ]))
        )
    }
}
