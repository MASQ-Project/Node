// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::proxy_client::resolver_wrapper::ResolverWrapper;
use crate::proxy_client::resolver_wrapper::ResolverWrapperFactory;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveError;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::rdata::{A as RData_A, AAAA as RData_AAAA};
use hickory_resolver::proto::rr::RData::{A, AAAA};
use hickory_resolver::proto::rr::{DNSClass, Record, RecordType};
use hickory_resolver::Name;
use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use async_trait::async_trait;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::unbounded_channel;

pub struct ResolverWrapperMock {
    lookup_ip_results: RefCell<Vec<Result<LookupIp, ResolveError>>>,
    lookup_ip_params: Arc<Mutex<Vec<String>>>,
}

unsafe impl Sync for ResolverWrapperMock {}

#[async_trait]
impl ResolverWrapper for ResolverWrapperMock {
    async fn lookup_ip(&self, host: &str) -> Result<LookupIp, ResolveError> {
        self.lookup_ip_params.lock()?.push(host.to_string());
        self.lookup_ip_results.borrow_mut().remove(0)
    }
}

impl ResolverWrapperMock {
    pub fn new() -> ResolverWrapperMock {
        ResolverWrapperMock {
            lookup_ip_results: RefCell::new(vec![]),
            lookup_ip_params: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn lookup_ip_success(self, ip_addrs: Vec<IpAddr>) -> Self {
        self.lookup_ip_result(Ok(ip_addrs))
    }

    pub fn lookup_ip_result(self, result: Result<Vec<IpAddr>, ResolveError>) -> Self {
        match result {
            Ok(ip_addrs) => {
                // We don't have any use for the query in the results, so we just create a dummy one
                let query = Query::new();
                let record_vec = ip_addrs
                    .into_iter()
                    .map(|ip_addr| {
                        match ip_addr {
                            IpAddr::V4(ipv4addr) => {
                                let mut record = Record::new();
                                record.set_name(Name::new()); // Garbage; may have to change one day
                                record.set_rr_type(RecordType::A);
                                record.set_dns_class(DNSClass::IN);
                                record.set_ttl(0);
                                record.set_data(Some(A(RData_A(ipv4addr))));
                                record
                            }
                            IpAddr::V6(ipv6addr) => {
                                let mut record = Record::new();
                                record.set_name(Name::new()); // Garbage; may have to change one day
                                record.set_rr_type(RecordType::AAAA);
                                record.set_dns_class(DNSClass::IN);
                                record.set_ttl(0);
                                record.set_data(Some(AAAA(RData_AAAA(ipv6addr))));
                                record
                            }
                        }
                    })
                    .collect::<Vec<Record>>();
                let records_arc: Arc<[Record]> = Arc::from(record_vec.into_boxed_slice());
                let lookup = Lookup::new_with_max_ttl(query, records_arc);
                let lookup_ip = LookupIp::from(lookup);
                self.lookup_ip_results.borrow_mut().push(Ok(lookup_ip));
            }
            Err(e) => self.lookup_ip_results.borrow_mut().push(Err(e)),
        }
        self
    }

    pub fn lookup_ip_params(mut self, parameters: &Arc<Mutex<Vec<String>>>) -> ResolverWrapperMock {
        self.lookup_ip_params = parameters.clone();
        self
    }
}

pub struct ResolverWrapperFactoryMock {
    make_parameters: Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>,
    make_results: RefCell<Vec<Box<dyn ResolverWrapper>>>,
}
impl ResolverWrapperFactory for ResolverWrapperFactoryMock {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<dyn ResolverWrapper> {
        self.make_parameters.lock().unwrap().push((config, options));
        self.make_results.borrow_mut().remove(0)
    }
}
impl ResolverWrapperFactoryMock {
    pub fn new() -> ResolverWrapperFactoryMock {
        ResolverWrapperFactoryMock {
            make_parameters: Arc::new(Mutex::new(vec![])),
            make_results: RefCell::new(vec![]),
        }
    }

    pub fn make_result(self, result: Box<dyn ResolverWrapper>) -> ResolverWrapperFactoryMock {
        self.make_results.borrow_mut().push(result);
        self
    }

    pub fn make_params(
        mut self,
        parameters: &Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>,
    ) -> ResolverWrapperFactoryMock {
        self.make_parameters = parameters.clone();
        self
    }
}

pub fn make_send_error<T>(msg: T) -> Result<(), SendError<T>> {
    let (tx, _) = unbounded_channel();
    tx.send(msg)
}
