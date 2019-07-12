// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::node_configurator::node_configurator::DirsWrapper;
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
