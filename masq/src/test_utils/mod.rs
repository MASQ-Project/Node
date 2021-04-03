// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use linefeed::memory::{Lines, MemoryTerminal};

pub mod client_utils;
pub mod mocks;

pub fn result_wrapper_for_in_memory_terminal() -> std::io::Result<MemoryTerminal> {
    Ok(MemoryTerminal::new())
}

pub fn written_output_by_line_number(mut lines_from_memory: Lines, line_number: usize) -> String {
    //Lines isn't an iterator unfortunately
    if line_number < 1 || 24 < line_number {
        panic!("The number must be between 1 and 24")
    }
    for _ in 0..line_number - 1 {
        lines_from_memory.next();
    }
    one_line_collector(lines_from_memory.next().unwrap()).replace("*/-", "")
}

pub fn written_output_all_lines(mut lines_from_memory: Lines, separator: bool) -> String {
    (0..24)
        .flat_map(|_| {
            lines_from_memory
                .next()
                .map(|chars| one_line_collector(chars))
        })
        .collect::<String>()
        .replace("*/-", if separator { " | " } else { " " })
        .trim_end()
        .to_string()
}

fn one_line_collector(line_chars: &[char]) -> String {
    let string_raw = line_chars
        .iter()
        .map(|char| char)
        .collect::<String>()
        .split(' ')
        .map(|word| {
            if word != "" {
                format!("{} ", word)
            } else {
                "".to_string()
            }
        })
        .collect::<String>();
    (0..1)
        .map(|_| string_raw.strip_suffix("*/- ").unwrap_or(&string_raw))
        .map(|str| str.strip_suffix(" ").unwrap_or(&string_raw).to_string())
        .collect::<String>()
}
