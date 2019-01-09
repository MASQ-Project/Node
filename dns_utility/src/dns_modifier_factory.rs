// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![allow (unused_imports)]

use std::fs::File;
use std::path::Path;
use dns_modifier::DnsModifier;

#[cfg (unix)]
use resolv_conf_dns_modifier::ResolvConfDnsModifier;

#[cfg (windows)]
use winreg_dns_modifier::WinRegDnsModifier;

#[cfg (target_os = "macos")]
use dynamic_store_dns_modifier::DynamicStoreDnsModifier;

pub trait DnsModifierFactory {
    fn make (&self) -> Option<Box<DnsModifier>>;
}

pub struct DnsModifierFactoryReal {}

impl DnsModifierFactory for DnsModifierFactoryReal {
    fn make (&self) -> Option<Box<DnsModifier>> {
        let qualifier_factory_refref = QUALIFIER_FACTORIES.iter ().find (|qf_refref| {
            (*qf_refref).system_qualifies()
        })?;
        Some ((*qualifier_factory_refref).make ())
    }
}

impl DnsModifierFactoryReal {
    pub fn new () -> DnsModifierFactoryReal {
        DnsModifierFactoryReal {}
    }
}

const QUALIFIER_FACTORIES: [&QualifierFactory; 3] = [
    &DynamicStoreQualifierFactory {},
    &WinRegQualifierFactory {},
    &ResolvConfQualifierFactory {}
];

trait QualifierFactory {
    fn system_qualifies (&self) -> bool;
    fn make (&self) -> Box<DnsModifier>;
}

struct ResolvConfQualifierFactory;
#[cfg (target_os = "linux")]
impl QualifierFactory for ResolvConfQualifierFactory {
    fn system_qualifies(&self) -> bool {
        File::open (Path::new ("/etc/resolv.conf")).is_ok ()
    }
    fn make(&self) -> Box<DnsModifier> {
        Box::new (ResolvConfDnsModifier::new ())
    }
}
#[cfg (not (target_os = "linux"))]
impl QualifierFactory for ResolvConfQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<DnsModifier> {
        panic!("Should never be called")
    }
}

struct WinRegQualifierFactory;
#[cfg (windows)]
impl QualifierFactory for WinRegQualifierFactory {
    fn system_qualifies(&self) -> bool {
        true
    }
    fn make(&self) -> Box<DnsModifier> {
        Box::new(WinRegDnsModifier::new())
    }
}
#[cfg (not (windows))]
impl QualifierFactory for WinRegQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<DnsModifier> {
        panic!("Should never be called")
    }
}

struct DynamicStoreQualifierFactory;
#[cfg (target_os = "macos")]
impl QualifierFactory for DynamicStoreQualifierFactory {
    fn system_qualifies(&self) -> bool {
        true
    }
    fn make(&self) -> Box<DnsModifier> {
        Box::new (DynamicStoreDnsModifier::new ())
    }
}
#[cfg (not (target_os = "macos"))]
impl QualifierFactory for DynamicStoreQualifierFactory {
    fn system_qualifies(&self) -> bool {
        false
    }
    fn make(&self) -> Box<DnsModifier> {
        panic!("Should never be called")
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_qualifier_factory_works_on_this_os () {
        let subject = ResolvConfQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg (target_os = "linux")]
        {
            if File::open (Path::new ("/etc/resolv.conf")).is_ok () {
                assert_eq!(result, true)
            }
            else {
                assert_eq!(result, false)
            }
        }

        #[cfg (not (target_os = "linux"))]
        {
            assert_eq! (result, false)
        }
    }

    #[test]
    fn win_reg_qualifier_factory_works_on_this_os () {
        let subject = WinRegQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg (windows)]
        {
            assert_eq!(result, true)
        }

        #[cfg (not (windows))]
        {
            assert_eq! (result, false)
        }
    }

    #[test]
    fn dynamic_store_qualifier_factory_works_on_this_os () {
        let subject = DynamicStoreQualifierFactory {};

        let result = subject.system_qualifies();

        #[cfg (target_os = "macos")]
        {
            assert_eq!(result, true)
        }

        #[cfg (not (target_os = "macos"))]
        {
            assert_eq! (result, false)
        }
    }

    #[test]
    #[allow (unused_variables)]
    fn dns_modifier_factory_makes_something_on_this_os () {
        let subject = DnsModifierFactoryReal::new ();

        let result = subject.make ();

        // no panic; test passes
    }
}
