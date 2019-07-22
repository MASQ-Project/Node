// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::node_configurator::DirsWrapper;
use std::path::PathBuf;

pub struct MockDirsWrapper {}

impl DirsWrapper for MockDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        Some(PathBuf::from("mocked/path"))
    }
}

pub struct BadMockDirsWrapper {}

impl DirsWrapper for BadMockDirsWrapper {
    fn data_dir(&self) -> Option<PathBuf> {
        None
    }
}

pub struct ArgsBuilder {
    args: Vec<String>,
}

impl Into<Vec<String>> for ArgsBuilder {
    fn into(self) -> Vec<String> {
        self.args
    }
}

impl ArgsBuilder {
    pub fn new() -> ArgsBuilder {
        ArgsBuilder {
            args: vec!["command".to_string()],
        }
    }

    pub fn opt(mut self, option: &str) -> ArgsBuilder {
        self.args.push(option.to_string());
        self
    }

    pub fn param(self, option: &str, value: &str) -> ArgsBuilder {
        self.opt(option).opt(value)
    }
}
