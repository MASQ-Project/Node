// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use tokio::prelude::Future;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::ResolverFuture;

pub type WrappedLookupIpFuture = Future<Item = LookupIp, Error = ResolveError> + Send;

pub trait ResolverWrapper {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture>;
}

pub trait ResolverWrapperFactory {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<ResolverWrapper>;
}

pub struct ResolverWrapperReal {
    delegate: Box<ResolverFuture>,
}

impl ResolverWrapper for ResolverWrapperReal {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture> {
        Box::new(self.delegate.lookup_ip(host))
    }
}

pub struct ResolverWrapperFactoryReal;
impl ResolverWrapperFactory for ResolverWrapperFactoryReal {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<ResolverWrapper> {
        // THIS HAPPENS ONLY ONCE AT STARTUP during ProxyClient bind. So don't worry about the `wait()`.
        let delegate = Box::new(
            ResolverFuture::new(config, options)
                .wait()
                .expect("couldn't create resolver future"),
        );

        Box::new(ResolverWrapperReal { delegate })
    }
}
