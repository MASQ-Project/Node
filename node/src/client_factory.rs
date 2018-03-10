// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use std::sync::Arc;
use std::sync::Mutex;
use std::net::SocketAddr;
use sub_lib::hopper::Hopper;
use sub_lib::neighborhood::Neighborhood;
use sub_lib::proxy_client::ProxyClient;
use sub_lib::cryptde_null::CryptDENull;
use hopper_lib::hopper::HopperReal;
use proxy_client_lib::proxy_client::ProxyClientReal;
use temporary::TemporaryNeighborhoodReal;

pub trait ClientFactory: Send {
    fn make_neighborhood (&self) -> Arc<Mutex<Neighborhood>>;
    fn make_hopper (&self) -> Arc<Mutex<Hopper>>;
    fn make_proxy_client (&self, dns_servers: Vec<SocketAddr>) -> Arc<Mutex<ProxyClient>>;
}

pub struct ClientFactoryReal {}

impl ClientFactory for ClientFactoryReal {
    fn make_neighborhood(&self) -> Arc<Mutex<Neighborhood>> {
        Arc::new (Mutex::new (TemporaryNeighborhoodReal::new ()))
    }

    fn make_hopper(&self) -> Arc<Mutex<Hopper>> {
        Arc::new (Mutex::new (HopperReal::new (Box::new (CryptDENull::new ()))))
    }

    fn make_proxy_client(&self, dns_servers: Vec<SocketAddr>) -> Arc<Mutex<ProxyClient>> {
        Arc::new (Mutex::new (ProxyClientReal::new (Box::new (CryptDENull::new ()), dns_servers)))
    }
}

impl ClientFactoryReal {
    pub fn new () -> ClientFactoryReal {
        ClientFactoryReal {}
    }
}
