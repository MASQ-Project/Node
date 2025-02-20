// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::dns_modifier::DnsModifier;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use crate::resolv_conf_dns_modifier::ResolvConfDnsModifier;

#[cfg(target_os = "macos")]
use crate::dynamic_store_dns_modifier::DynamicStoreDnsModifier;
#[cfg(target_os = "windows")]
use crate::win_dns_modifier::WinDnsModifier;

pub trait DnsModifierFactory {
    fn make(&self) -> Option<Box<dyn DnsModifier>>;
}

#[derive(Default)]
pub struct DnsModifierFactoryReal {}

impl DnsModifierFactory for DnsModifierFactoryReal {
    fn make(&self) -> Option<Box<dyn DnsModifier>> {
        let qualifier_factory_refref = QUALIFIER_FACTORIES
            .iter()
            .find(|qf_refref| (*qf_refref).system_qualifies())?;
        Some((*qualifier_factory_refref).make())
    }
}

impl DnsModifierFactoryReal {
    pub fn new() -> Self {
        Default::default()
    }
}

const QUALIFIER_FACTORIES: [&dyn QualifierFactory; 3] = [
    &DynamicStoreQualifierFactory {},
    &WinQualifierFactory {},
    &ResolvConfQualifierFactory {},
];

trait QualifierFactory {
    fn system_qualifies(&self) -> bool;
    fn make(&self) -> Box<dyn DnsModifier>;
}

struct ResolvConfQualifierFactory;
#[cfg(target_os = "linux")]
impl QualifierFactory for ResolvConfQualifierFactory {
    fn system_qualifies(&self) -> bool {
        File::open(Path::new("/etc/resolv.conf")).is_ok()
    }
    fn make(&self) -> Box<dyn DnsModifier> {
        Box::new(ResolvConfDnsModifier::new())
    }
}

#[cfg(not(target_os = "linux"))]
impl QualifierFactory for ResolvConfQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<dyn DnsModifier> {
        panic!("Should never be called")
    }
}

struct WinQualifierFactory {}
#[cfg(target_os = "windows")]
impl QualifierFactory for WinQualifierFactory {
    fn system_qualifies(&self) -> bool {
        true
    }

    fn make(&self) -> Box<dyn DnsModifier> {
        Box::new(WinDnsModifier::default())
    }
}

#[cfg(not(target_os = "windows"))]
impl QualifierFactory for WinQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<dyn DnsModifier> {
        panic!("Should never be called")
    }
}

struct DynamicStoreQualifierFactory;
#[cfg(target_os = "macos")]
impl QualifierFactory for DynamicStoreQualifierFactory {
    fn system_qualifies(&self) -> bool {
        true
    }
    fn make(&self) -> Box<dyn DnsModifier> {
        Box::new(DynamicStoreDnsModifier::new())
    }
}
#[cfg(not(target_os = "macos"))]
impl QualifierFactory for DynamicStoreQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<dyn DnsModifier> {
        panic!("Should never be called")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name_of_val;

    #[test]
    fn resolv_conf_qualifier_factory_works_on_this_os() {
        let subject = ResolvConfQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg(target_os = "linux")]
        {
            if File::open(Path::new("/etc/resolv.conf")).is_ok() {
                assert_eq!(result, true)
            } else {
                assert_eq!(result, false)
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(result, false)
        }
    }

    #[test]
    fn win_qualifier_factory_works_on_this_os() {
        let subject = WinQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg(target_os = "windows")]
        {
            assert_eq!(result, true)
        }

        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(result, false)
        }
    }

    #[test]
    fn dynamic_store_qualifier_factory_works_on_this_os() {
        let subject = DynamicStoreQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg(target_os = "macos")]
        {
            assert_eq!(result, true)
        }

        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(result, false)
        }
    }

    #[test]
    fn dns_modifier_factory_makes_something_on_this_os() {
        let subject = DnsModifierFactoryReal::new();

        let _result = subject.make();

        // no panic; test passes
    }
}
