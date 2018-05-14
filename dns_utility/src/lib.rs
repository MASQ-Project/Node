// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate regex;
extern crate sub_lib;

#[cfg (windows)]
extern crate winreg;

#[cfg (test)]
extern crate test_utils;

pub mod dns_utility;
pub mod dns_modifier;
pub mod dns_modifier_factory;
pub mod winreg_dns_modifier;
pub mod resolv_conf_dns_modifier;
