// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::dns_inspector::DnsInspectionError;
use std::net::IpAddr;

pub trait DnsInspector {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError>;
}
