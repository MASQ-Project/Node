// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use flexi_logger::{DeferredNow, FileSpec, LevelFilter, LogSpecBuilder, Logger, Record};
use std::env::current_dir;

pub fn initiate_logger() {
    let file_spec = FileSpec::default()
        .directory(current_dir().expect("working directory cannot be identified"))
        .discriminant("rCURRENT")
        .suppress_timestamp();
    let logger = Logger::with(LogSpecBuilder::new().default(LevelFilter::Info).build())
        .log_to_file(file_spec)
        .format(brief_format)
        .print_message();

    logger.start().expect("Logging subsystem failed to start");
}

fn brief_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(w, "{}:   {}", record.level(), record.args())
}
