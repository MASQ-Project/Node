// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub mod utils;

use crate::utils::CommandConfig;

#[cfg(not(target_os = "windows"))]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig::new().pair("--crash-point", "error");
    let mut node = utils::MASQNode::start_standard(Some(panic_config));

    let exit_code = node.wait_for_exit().unwrap().status.code();
    assert_ne!(Some(0), exit_code);
}

#[cfg(target_os = "windows")]
#[test]
fn node_exits_from_future_error_integration() {
    let panic_config = CommandConfig::new().pair("--crash-point", "error");
    let mut node = utils::MASQNode::start_standard(Some(panic_config));

    let exit_code = node.wait_for_exit().unwrap().status.code();
    // Sometimes 1, sometimes 101
    assert_ne!(Some(0), exit_code);
}
