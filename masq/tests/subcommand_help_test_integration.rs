// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::utils::MasqProcess;
use masq_lib::test_utils::utils::check_if_source_code_is_attached;
use masq_lib::test_utils::utils::ShouldWeRunTheTest::Skip;
use regex::Regex;
use std::env::current_dir;
use std::fs;

mod utils;

#[test]
fn assure_that_all_subcommands_hang_on_the_help_root_integration() {
    let current_dir = current_dir().unwrap();
    if Skip == check_if_source_code_is_attached(&current_dir) {
        return;
    }
    let help_handle = MasqProcess::new().start_noninteractive(vec!["--help"]);
    let (stdout, _, _) = help_handle.stop();
    let index = stdout.find("SUBCOMMANDS:").unwrap();
    let trimmed_help = (&stdout[index..]).to_owned();
    let commands_files = current_dir.join("src").join("commands");
    let list: Vec<_> = fs::read_dir(&commands_files)
        .unwrap()
        .flat_map(|file| {
            let entry_name_path = file.unwrap().path();
            let entry_name_long = entry_name_path.file_name().unwrap().to_str().unwrap();
            if !entry_name_long.starts_with("mod")
                && !entry_name_long.starts_with("commands_common")
            {
                let regex = Regex::new(r#"(.+)_command(\.rs|$)"#)
                    .unwrap_or_else(|_| panic!("didn't find a match for {}", entry_name_long));
                let entity_key_word_captures = regex.captures(entry_name_long).unwrap();
                let entity_key_word = entity_key_word_captures.get(1).unwrap().as_str();
                let short_name = format!("    {}", entity_key_word.replace("_", "-"));
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
