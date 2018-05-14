// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::fs::File;
use std::path::Path;
use dns_modifier::DnsModifier;
use resolv_conf_dns_modifier::ResolvConfDnsModifier;
use winreg_dns_modifier::WinRegDnsModifier;

#[allow (dead_code)]
const WINDOWS: u64 = 1;
#[allow (dead_code)]
const NOT_WINDOWS: u64 = 2;

#[cfg (windows)]
const OS_TYPE: u64 = WINDOWS;

#[cfg (not (windows))]
const OS_TYPE: u64 = NOT_WINDOWS;

pub trait DnsModifierFactory {
    fn make (&self) -> Option<Box<DnsModifier>>;
}

pub struct DnsModifierFactoryReal {}

impl DnsModifierFactory for DnsModifierFactoryReal {
    fn make (&self) -> Option<Box<DnsModifier>> {
        if OS_TYPE == WINDOWS {
            Some(Box::new(WinRegDnsModifier::new()))
        }
        else if DnsModifierFactoryReal::supports_resolv_conf_dns_modifier() {
            Some (Box::new (ResolvConfDnsModifier::new ()))
        }
        else {
            unimplemented ! ()
        }
    }
}

impl DnsModifierFactoryReal {
    pub fn new () -> DnsModifierFactoryReal {
        DnsModifierFactoryReal {

        }
    }

    fn supports_resolv_conf_dns_modifier () -> bool {
        File::open (Path::new ("/etc/resolv.conf")).is_ok ()
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn should_provide_resolv_conf_dns_modifier_if_appropriate () {
        if !DnsModifierFactoryReal::supports_resolv_conf_dns_modifier () {
            println! ("should_provide_resolv_conf_dns_modifier_if_appropriate doesn't apply in this environment");
            return
        }
        let subject = DnsModifierFactoryReal::new ();

        let modifier_box = subject.make ().unwrap ();
        let modifier = modifier_box.as_ref ();
        assert_eq! (modifier.type_name (), "ResolvConfDnsModifier");
    }

    #[test]
    fn should_provide_winreg_dns_modifier_if_appropriate () {
        if OS_TYPE != WINDOWS {
            println! ("should_provide_winreg_dns_modifier_if_appropriate doesn't apply in this environment");
            return
        }
        let subject = DnsModifierFactoryReal::new ();

        let modifier_box = subject.make ().unwrap ();
        let modifier = modifier_box.as_ref ();
        assert_eq! (modifier.type_name (), "WinRegDnsModifier");
    }
}