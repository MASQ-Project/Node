// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MasqProcess;
use std::env::current_dir;
use std::fs;

mod utils;

#[test]
fn assure_that_all_subcommands_hang_on_the_help_root_integration() {
    let help_handle = MasqProcess::new().start_noninteractive(vec!["--help"]);
    let (stdout, _, _) = help_handle.stop();
    let index = stdout.find("SUBCOMMANDS:").unwrap();
    let trimmed_help = (&stdout[index..]).to_owned();
    let commands_files = current_dir().unwrap().join("src").join("commands");
    let list: Vec<_> = fs::read_dir(&commands_files)
        .unwrap()
        .flat_map(|file| {
            let file_name_long = file.unwrap().path();
            let file_name_long = file_name_long.file_name().unwrap().to_str().unwrap();
            if !file_name_long.starts_with("mod") && !file_name_long.starts_with("commands_common")
            {
                let mut short_name = String::from("    ");
                let suffix = file_name_long
                    .trim_end_matches("_command.rs")
                    .replace("_", "-");
                short_name.push_str(&suffix);
                if trimmed_help.contains(&short_name) {
                    None
                } else {
                    Some(short_name)
                }
            } else {
                None
            }
        })
        .collect();
    assert!(list.is_empty(), "{:?}", list)
}
