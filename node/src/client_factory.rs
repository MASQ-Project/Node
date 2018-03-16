// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::marker::Send;
use std::sync::Arc;
use std::sync::Mutex;
use sub_lib::neighborhood::Neighborhood;
use temporary::TemporaryNeighborhoodReal;

pub trait ClientFactory: Send {
    fn make_neighborhood (&self) -> Arc<Mutex<Neighborhood>>;
}

pub struct ClientFactoryReal {}

impl ClientFactory for ClientFactoryReal {
    fn make_neighborhood(&self) -> Arc<Mutex<Neighborhood>> {
        Arc::new (Mutex::new (TemporaryNeighborhoodReal::new ()))
    }
}

impl ClientFactoryReal {
    pub fn new () -> ClientFactoryReal {
        ClientFactoryReal {}
    }
}
