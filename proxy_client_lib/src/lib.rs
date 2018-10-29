// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#[cfg_attr(test, macro_use)]
extern crate actix;
extern crate futures;
extern crate serde_cbor;
extern crate tokio;
extern crate tokio_core;
extern crate trust_dns_resolver;
extern crate sub_lib;

#[cfg (test)]
extern crate test_utils;
#[cfg(test)]
extern crate trust_dns_proto;

pub mod proxy_client;
mod resolver_wrapper;
mod stream_establisher;
mod stream_handler_pool;
mod stream_reader;
mod stream_writer;
#[cfg(test)]
mod local_test_utils;
