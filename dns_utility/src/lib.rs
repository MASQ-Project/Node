// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;

#[cfg (test)]
extern crate test_utils;

pub mod dns_utility;
pub mod dns_modifier;
pub mod dns_modifier_factory;

#[cfg (unix)]
pub mod resolv_conf_dns_modifier;
