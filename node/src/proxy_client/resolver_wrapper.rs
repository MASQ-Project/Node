// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::error::ResolveError;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::name_server::TokioRuntimeProvider;
use hickory_resolver::{AsyncResolver};

pub trait ResolverWrapper: Send {
    async fn lookup_ip(&self, host: &str) -> Result<LookupIp, ResolveError>;
}

pub trait ResolverWrapperFactory {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<dyn ResolverWrapper>;
}

pub struct ResolverWrapperReal {
    delegate: Box<AsyncResolver<TokioRuntimeProvider>>,
}

impl ResolverWrapper for ResolverWrapperReal {
    async fn lookup_ip(&self, host: &str) -> Result<LookupIp, ResolveError> {
        self.delegate.lookup_ip(host)
    }
}

pub struct ResolverWrapperFactoryReal;
impl ResolverWrapperFactory for ResolverWrapperFactoryReal {
    fn make(&self, config: ResolverConfig, options: ResolverOpts) -> Box<dyn ResolverWrapper> {
        let runtime_provider = TokioRuntimeProvider::new();
        let resolver = AsyncResolver::new(config, options, runtime_provider);
        Box::new(ResolverWrapperReal {
            delegate: Box::new(resolver),
        })
    }
}
