// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

#[cfg(target_os = "windows")]
extern crate winreg;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;

#[cfg(target_os = "windows")]
mod adapter_wrapper;
#[allow(clippy::module_inception)]
pub mod dns_inspector;
pub mod dns_inspector_factory;
mod dynamic_store_dns_inspector;
mod resolv_conf_dns_inspector;
mod utils;
#[cfg(target_os = "windows")]
mod win_dns_inspector;

use crate::daemon::dns_inspector::dns_inspector_factory::DnsInspectorFactory;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

#[derive(Clone, PartialEq)]
pub enum DnsInspectionError {
    NotConnected,
    BadEntryFormat(String),
    InvalidConfigFile(String),
    ConflictingEntries(usize, usize),
    RegistryQueryOsError(String),
    ConfigValueTypeError(String),
}

impl Debug for DnsInspectionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DnsInspectionError::NotConnected => write!(f, "This system does not appear to be connected to a network"),
            DnsInspectionError::BadEntryFormat(msg) => write! (f, "Bad entry format: {}", msg),
            DnsInspectionError::InvalidConfigFile(msg) => write! (f, "Invalid config file: {}", msg),
            DnsInspectionError::ConflictingEntries(interfaces, gateways) => write! (f, "This system has {} active network interfaces configured with {} different default gateways. Cannot summarize DNS settings.", interfaces, gateways),
            DnsInspectionError::RegistryQueryOsError(msg) => write! (f, "{}", msg),
            DnsInspectionError::ConfigValueTypeError(msg) => write! (f, "Config value is not of the correct type: {}", msg),
        }
    }
}

pub fn dns_servers(
    factory: Box<dyn DnsInspectorFactory>,
) -> Result<Vec<IpAddr>, DnsInspectionError> {
    let inspector = factory.make().unwrap();
    inspector.inspect()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::daemon::dns_inspector::dns_inspector_factory::{
        DnsInspectorFactory, DnsInspectorFactoryReal,
    };

    #[test]
    fn dns_inspection_errors_render_properly() {
        let strings = vec![
            DnsInspectionError::NotConnected,
            DnsInspectionError::BadEntryFormat("bad entry format".to_string()),
            DnsInspectionError::InvalidConfigFile("invalid config file".to_string()),
            DnsInspectionError::ConflictingEntries(1234, 4321),
            DnsInspectionError::RegistryQueryOsError("registry query os error".to_string()),
            DnsInspectionError::ConfigValueTypeError("type error".to_string()),
        ]
        .into_iter()
        .map(|e| format!("{:?}", e))
        .collect::<Vec<String>>();

        assert_eq! (strings, vec![
            "This system does not appear to be connected to a network".to_string(),
            "Bad entry format: bad entry format".to_string(),
            "Invalid config file: invalid config file".to_string(),
            "This system has 1234 active network interfaces configured with 4321 different default gateways. Cannot summarize DNS settings.".to_string(),
            "registry query os error".to_string(),
            "Config value is not of the correct type: type error".to_string(),
        ])
    }

    #[test]
    fn dns_servers_works() {
        let factory = DnsInspectorFactoryReal::new();
        let inspector = factory.make().unwrap();
        let expected_result = inspector.inspect();

        let actual_result = dns_servers(Box::new(factory));

        assert_eq!(actual_result, expected_result);
    }
}
