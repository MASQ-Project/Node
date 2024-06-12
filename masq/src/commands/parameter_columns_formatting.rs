// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::commands::commands_common::STANDARD_COLUMN_WIDTH;
use crate::terminal::TerminalWriter;
use futures::future::join_all;
use masq_lib::short_writeln;

pub async fn dump_parameter_line(
    stdout: &TerminalWriter,
    name: &str,
    char_after_name_opt: Option<char>,
    value: &str,
) {
    dump_already_formatted_parameter_line(
        stdout,
        0,
        &format!(
            "{:width$} {}",
            add_char_after(name, char_after_name_opt),
            value,
            width = STANDARD_COLUMN_WIDTH
        ),
    )
    .await
}

pub async fn dump_single_line_parameters(
    stdout: &TerminalWriter,
    parameter_names_and_values: Vec<(&str, &str)>,
) {
    let _ = join_all(
        parameter_names_and_values
            .iter()
            .map(|(name, value)| dump_parameter_line(stdout, name, Some(':'), value)),
    )
    .await;
}

pub async fn dump_already_formatted_parameter_line(
    stdout: &TerminalWriter,
    indention: usize,
    formatted_line: &str,
) {
    short_writeln!(
        stdout,
        "{:indention$}{}",
        "",
        formatted_line,
        indention = indention,
    );
}

pub fn add_char_after(plain_name: &str, char_opt: Option<char>) -> String {
    format!(
        "{}{}",
        plain_name,
        char_opt
            .map(|char| char.to_string())
            .unwrap_or("".to_string())
    )
}
