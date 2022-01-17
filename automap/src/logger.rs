// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use flexi_logger::{DeferredNow, LevelFilter, LogSpecBuilder, Logger, Record};
use lazy_static::lazy_static;
use std::env::current_dir;
use std::path::PathBuf;

lazy_static! {
    static ref WORKING_PATH: PathBuf =
        current_dir().expect("working directory cannot be identified");
    static ref LOG_FILE_PATH: PathBuf = WORKING_PATH.join("automap_rCURRENT");
}

pub fn initiate_logger() {
    let logger = Logger::with(LogSpecBuilder::new().default(LevelFilter::Info).build())
        .log_to_file()
        .directory(WORKING_PATH.as_path())
        .format(brief_format)
        .print_message()
        .suppress_timestamp();

    logger.start().expect("Logging subsystem failed to start");
}

fn brief_format(
    w: &mut dyn std::io::Write,
    _now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(w, "{}:   {}", record.level(), record.args())
}
