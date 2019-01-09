// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate sub_lib;

mod utils;

use sub_lib::crash_point::CrashPoint;
use utils::CommandConfig;

#[cfg(unix)]
#[test]
fn node_exits_from_future_panic_integration() {
    let panic_config = CommandConfig {
        crash_point: CrashPoint::Panic,
    };
    let mut node = utils::SubstratumNode::start(Some(panic_config));

    let exit_code = node.wait();
    assert_eq!(exit_code, Some(1));
}

#[cfg(windows)]
#[test]
fn node_exits_from_future_panic_integration() {
    let panic_config = CommandConfig {
        crash_point: CrashPoint::Panic,
    };
    let mut node = utils::SubstratumNode::start(Some(panic_config));

    let exit_code = node.wait();
    // Sometimes 1, sometimes 101
    assert_ne!(exit_code, Some(0));
}
