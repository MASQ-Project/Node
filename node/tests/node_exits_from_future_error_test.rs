// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

mod utils;

use crate::utils::CommandConfig;

#[cfg(not(target_os = "windows"))]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig::new().pair("--crash-point", "error");
    let mut node = utils::SubstratumNode::start_standard(Some(panic_config));

    let exit_status = node.wait_for_exit(1000);
    assert_ne!(Some(0), exit_status);
}

#[cfg(target_os = "windows")]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig::new().pair("--crash-point", "error");
    let mut node = utils::SubstratumNode::start_standard(Some(panic_config));

    let exit_status = node.wait_for_exit(1000);
    // Sometimes 1, sometimes 101
    assert_ne!(Some(0), exit_status);
}
