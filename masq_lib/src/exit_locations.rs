// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::ExitLocation;
use std::fmt::{Display, Formatter};

pub struct ExitLocationSet {
    pub locations: Vec<ExitLocation>,
}

impl Display for ExitLocationSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        for exit_location in self.locations.iter() {
            write!(
                f,
                "Country Codes: {:?} - Priority: {}; ",
                exit_location.country_codes, exit_location.priority
            )?;
        }
        Ok(())
    }
}
