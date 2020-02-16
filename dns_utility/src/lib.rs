// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

#[cfg(target_os = "windows")]
extern crate winreg;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;

#[cfg(target_os = "windows")]
pub mod adapter_wrapper;
pub mod dns_modifier;
pub mod dns_modifier_factory;
pub mod dns_utility;
pub mod dynamic_store_dns_modifier;
#[cfg(target_os = "windows")]
pub mod ipconfig_wrapper;
#[cfg(target_os = "windows")]
pub mod netsh;
pub mod resolv_conf_dns_modifier;
pub mod utils;
#[cfg(target_os = "windows")]
pub mod win_dns_modifier;
