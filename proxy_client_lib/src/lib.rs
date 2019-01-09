// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#[cfg_attr(test, macro_use)]
extern crate actix;
extern crate futures;
extern crate serde_cbor;
extern crate sub_lib;
extern crate tokio_core;
#[cfg(test)]
extern crate trust_dns_proto;
extern crate trust_dns_resolver;

#[cfg(test)]
extern crate test_utils;
extern crate tokio;

#[cfg(test)]
mod local_test_utils;
pub mod proxy_client;
mod resolver_wrapper;
mod stream_establisher;
mod stream_handler_pool;
mod stream_reader;
mod stream_writer;
