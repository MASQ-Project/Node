// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use linefeed::memory::MemoryTerminal;

pub mod client_utils;
pub mod mocks;

pub fn result_wrapper_for_in_memory_terminal() -> std::io::Result<MemoryTerminal> {
    Ok(MemoryTerminal::new())
}
