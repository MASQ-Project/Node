// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

pub fn main() {
    let args = &std::env::args().collect();
    let exit_code = node_lib::sub_lib::main_tools::main_with_args(args);
    ::std::process::exit(exit_code);
}
