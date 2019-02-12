// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg(target_os = "linux")]

use dns_utility_lib::resolv_conf_dns_modifier::ResolvConfDnsModifier;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;

pub fn get_nameserver_entries(contents: &str) -> Vec<String> {
    let active_nameservers: Vec<String> = ResolvConfDnsModifier::new()
        .active_nameservers(contents)
        .iter()
        .map(|entry| entry.0.clone())
        .collect();
    active_nameservers
}

pub fn get_file_contents() -> io::Result<String> {
    let path = Path::new("/")
        .join(Path::new("etc"))
        .join(Path::new("resolv.conf"));
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

pub fn is_subverted(entries: &Vec<String>) -> bool {
    let first_entry = match entries.first() {
        None => return false,
        Some(x) => x,
    };
    ResolvConfDnsModifier::is_substratum_ip(&first_entry)
}
