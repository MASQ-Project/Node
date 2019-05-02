// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use tokio::prelude::Future;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::AsyncResolver;

pub type WrappedLookupIpFuture = dyn Future<Item = LookupIp, Error = ResolveError> + Send;

pub trait ResolverWrapper: Send {
    fn lookup_ip(&self, host: Option<String>) -> Box<WrappedLookupIpFuture>;
}

pub trait ResolverWrapperFactory {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<dyn ResolverWrapper>;
}

pub struct ResolverWrapperReal {
    delegate: Box<AsyncResolver>,
}

impl ResolverWrapper for ResolverWrapperReal {
    fn lookup_ip(&self, host_opt: Option<String>) -> Box<WrappedLookupIpFuture> {
        //TODO: SC-855 This is likely not optimal, we need to figure out how to return a LookupIpFuture Error
        let host = host_opt.unwrap_or(String::from("<unspecified>"));
        Box::new(self.delegate.lookup_ip(host.as_str()))
    }
}

pub struct ResolverWrapperFactoryReal;
impl ResolverWrapperFactory for ResolverWrapperFactoryReal {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<dyn ResolverWrapper> {
        let (resolver, background_worker) = AsyncResolver::new(config, options);
        tokio::spawn(background_worker);
        let delegate = Box::new(resolver);

        Box::new(ResolverWrapperReal { delegate })
    }
}
