// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::daemon::dns_inspector::DnsInspectionError;
use std::net::IpAddr;

pub trait DnsInspector {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError>;
}
