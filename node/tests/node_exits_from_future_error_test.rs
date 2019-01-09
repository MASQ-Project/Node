// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate entry_dns_lib;
extern crate sub_lib;

mod utils;

use sub_lib::crash_point::CrashPoint;
use utils::CommandConfig;

#[cfg(unix)]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig {
        crash_point: CrashPoint::Error,
    };
    let mut node = utils::SubstratumNode::start(Some(panic_config));

    let exit_status = node.wait();
    assert_eq!(exit_status, Some(1));
}

#[cfg(windows)]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig {
        crash_point: CrashPoint::Error,
    };
    let mut node = utils::SubstratumNode::start(Some(panic_config));

    let exit_status = node.wait();
    // Sometimes 1, sometimes 101
    assert_ne!(exit_status, Some(0));
}
