// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::io;
use std::net::IpAddr;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::error::ResolveResult;

pub trait ResolverWrapper: Send {
    fn lookup_ip(&self, host: &str) -> ResolveResult<Vec<IpAddr>>;
}

pub trait ResolverWrapperFactory {
    fn new(&self, config: ResolverConfig, options: ResolverOpts) -> io::Result<Box<ResolverWrapper>>;
}

pub struct ResolverWrapperReal {
    delegate: Resolver
}

impl ResolverWrapper for ResolverWrapperReal {
    fn lookup_ip(&self, host: &str) -> ResolveResult<Vec<IpAddr>> {
        let lookup_ip = self.delegate.lookup_ip (host)?;
        Ok (lookup_ip.iter ().collect ())
    }
}

pub struct ResolverWrapperFactoryReal {}

impl ResolverWrapperFactory for ResolverWrapperFactoryReal {
    fn new(&self, config: ResolverConfig, options: ResolverOpts) -> io::Result<Box<ResolverWrapper>> {
        let delegate = Resolver::new (config, options)?;
        Ok (Box::new (ResolverWrapperReal {delegate}))
    }
}

#[cfg (test)]
pub mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;

    pub struct ResolverWrapperMock {
        lookup_ip_results: RefCell<Vec<ResolveResult<Vec<IpAddr>>>>,
        lookup_ip_parameters: RefCell<Arc<Mutex<Vec<String>>>>,
    }

    impl ResolverWrapper for ResolverWrapperMock {
        fn lookup_ip(&self, host: &str) -> ResolveResult<Vec<IpAddr>> {
            let lookup_ip_parameters_ref_mut = self.lookup_ip_parameters.borrow_mut ();
            lookup_ip_parameters_ref_mut.as_ref ().lock ().unwrap ().push (String::from (host));
            self.lookup_ip_results.borrow_mut ().remove (0)
        }
    }

    impl ResolverWrapperMock {
        pub fn new () -> ResolverWrapperMock {
            ResolverWrapperMock {
                lookup_ip_results: RefCell::new (vec! ()),
                lookup_ip_parameters: RefCell::new (Arc::new (Mutex::new (vec! ()))),
            }
        }

        pub fn lookup_ip_result (self, result: ResolveResult<Vec<IpAddr>>) -> ResolverWrapperMock {
            self.lookup_ip_results.borrow_mut ().push (result);
            self
        }

        pub fn lookup_ip_parameters (self, parameters: &mut Arc<Mutex<Vec<String>>>) -> ResolverWrapperMock {
            *parameters = self.lookup_ip_parameters.borrow_mut ().clone ();
            self
        }
    }

    pub struct ResolverWrapperFactoryMock {
        factory_results: RefCell<Vec<io::Result<Box<ResolverWrapper>>>>,
        factory_parameters: RefCell<Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>>
    }

    impl ResolverWrapperFactory for ResolverWrapperFactoryMock {
        fn new(&self, config: ResolverConfig, options: ResolverOpts) -> io::Result<Box<ResolverWrapper>> {
            let parameters_ref_mut = self.factory_parameters.borrow_mut ();
            let mut parameters_guard = parameters_ref_mut.lock ().unwrap ();
            parameters_guard.push ((config, options));
            self.factory_results.borrow_mut ().remove (0)
        }
    }

    impl ResolverWrapperFactoryMock {
        pub fn new () -> ResolverWrapperFactoryMock {
            ResolverWrapperFactoryMock {
                factory_results: RefCell::new (vec! ()),
                factory_parameters: RefCell::new (Arc::new (Mutex::new (vec! ())))
            }
        }

        pub fn new_result(self, result: io::Result<Box<ResolverWrapper>>) -> ResolverWrapperFactoryMock {
            self.factory_results.borrow_mut ().push (result);
            self
        }

        pub fn new_parameters(self, parameters: &mut Arc<Mutex<Vec<(ResolverConfig, ResolverOpts)>>>) -> ResolverWrapperFactoryMock {
            *parameters = self.factory_parameters.borrow_mut ().clone ();
            self
        }
    }

    #[test]
    fn nothing () {}
}
