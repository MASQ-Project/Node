// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use futures::future;
use futures::sync::mpsc::unbounded;
use futures::sync::mpsc::SendError;
use resolver_wrapper::ResolverWrapper;
use resolver_wrapper::ResolverWrapperFactory;
use resolver_wrapper::WrappedLookupIpFuture;
use std::cell::RefCell;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use trust_dns_proto::rr::RData;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::Lookup;

pub struct ResolverWrapperMock {
    lookup_ip_results: RefCell<Vec<Box<WrappedLookupIpFuture>>>,
    lookup_ip_parameters: Arc<Mutex<Vec<String>>>,
}

impl ResolverWrapper for ResolverWrapperMock {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture> {
        self.lookup_ip_parameters
            .lock()
            .unwrap()
            .push(String::from(host));
        self.lookup_ip_results.borrow_mut().remove(0)
    }
}

impl ResolverWrapperMock {
    pub fn new() -> ResolverWrapperMock {
        ResolverWrapperMock {
            lookup_ip_results: RefCell::new(vec![]),
            lookup_ip_parameters: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn lookup_ip_success(self, ip_addrs: Vec<IpAddr>) -> ResolverWrapperMock {
        let rdatas: Vec<RData> = ip_addrs
            .into_iter()
            .map(|ip_addr| match ip_addr {
                IpAddr::V4(ip_addr) => RData::A(ip_addr).into(),
                IpAddr::V6(ip_addr) => RData::AAAA(ip_addr).into(),
            })
            .collect();
        let lookup_ip = Lookup::new_with_max_ttl(Arc::new(rdatas)).into();
        self.lookup_ip_results
            .borrow_mut()
            .push(Box::new(future::ok(lookup_ip)));
        self
    }

    pub fn lookup_ip_failure(self, error: ResolveError) -> ResolverWrapperMock {
        self.lookup_ip_results
            .borrow_mut()
            .push(Box::new(future::err(error)));
        self
    }

    pub fn lookup_ip_parameters(
        mut self,
        parameters: &Arc<Mutex<Vec<String>>>,
    ) -> ResolverWrapperMock {
        self.lookup_ip_parameters = parameters.clone();
        self
    }
}

pub struct ResolverWrapperFactoryMock {
    factory_results: RefCell<Vec<Box<ResolverWrapper>>>,
    factory_parameters: RefCell<Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>>,
}

impl ResolverWrapperFactory for ResolverWrapperFactoryMock {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<ResolverWrapper> {
        let parameters_ref_mut = self.factory_parameters.borrow_mut();
        let mut parameters_guard = parameters_ref_mut.lock().unwrap();
        parameters_guard.push((config, options));
        self.factory_results.borrow_mut().remove(0)
    }
}

impl ResolverWrapperFactoryMock {
    pub fn new() -> ResolverWrapperFactoryMock {
        ResolverWrapperFactoryMock {
            factory_results: RefCell::new(vec![]),
            factory_parameters: RefCell::new(Arc::new(Mutex::new(vec![]))),
        }
    }

    pub fn new_result(self, result: Box<ResolverWrapper>) -> ResolverWrapperFactoryMock {
        self.factory_results.borrow_mut().push(result);
        self
    }

    pub fn new_parameters(
        self,
        parameters: &mut Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>,
    ) -> ResolverWrapperFactoryMock {
        *parameters = self.factory_parameters.borrow_mut().clone();
        self
    }
}

pub fn make_send_error<T>(msg: T) -> Result<(), SendError<T>> {
    let (tx, _) = unbounded();
    tx.unbounded_send(msg)
}
