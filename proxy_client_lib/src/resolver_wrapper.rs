// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::ResolverFuture;
use tokio_core::reactor::Handle;
use trust_dns_resolver::error::ResolveError;
use tokio::prelude::Future;
use trust_dns_resolver::lookup_ip::LookupIp;

pub type WrappedLookupIpFuture = Future<Item = LookupIp, Error = ResolveError>;

pub trait ResolverWrapper {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture>;
}

pub trait ResolverWrapperFactory {
    fn make(&self, config: ResolverConfig, options: ResolverOpts, reactor: &Handle) -> Box<ResolverWrapper>;
}

pub struct ResolverWrapperReal {
    delegate: ResolverFuture
}

impl ResolverWrapper for ResolverWrapperReal {
    fn lookup_ip(&self, host: &str) -> Box<WrappedLookupIpFuture> {
        Box::new (self.delegate.lookup_ip (host))
    }
}

pub struct ResolverWrapperFactoryReal;
impl ResolverWrapperFactory for ResolverWrapperFactoryReal {
    fn make(&self, config: ResolverConfig, options: ResolverOpts, reactor: &Handle) -> Box<ResolverWrapper> {
        Box::new (ResolverWrapperReal {delegate: ResolverFuture::new (config, options, reactor)})
    }
}
