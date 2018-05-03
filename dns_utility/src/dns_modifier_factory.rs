// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use std::fs::File;
use std::path::Path;
use dns_modifier::DnsModifier;

#[cfg (unix)]
use resolv_conf_dns_modifier::ResolvConfDnsModifier;

pub trait DnsModifierFactory {
    fn make (&self) -> Option<Box<DnsModifier>>;
}

pub struct DnsModifierFactoryReal {

}

impl DnsModifierFactory for DnsModifierFactoryReal {
    #[cfg (unix)]
    fn make (&self) -> Option<Box<DnsModifier>> {
        if DnsModifierFactoryReal::supports_resolv_conf_dns_modifier() {
            Some (Box::new (ResolvConfDnsModifier::new ()))
        }
        else {
            unimplemented!()
        }
    }

    #[cfg (windows)]
    fn make (&self) -> Option<Box<DnsModifier>> {
        unimplemented! ()
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
}