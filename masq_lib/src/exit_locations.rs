// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::messages::ExitLocation;
use itertools::Itertools;
use std::fmt::{Display, Formatter};

pub struct ExitLocationSet {
    pub locations: Vec<ExitLocation>,
}

impl Display for ExitLocationSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let exit_location_string = self
            .locations
            .iter()
            .map(|exit_location| {
                format!(
                    "Country Codes: {:?} - Priority: {}",
                    exit_location.country_codes, exit_location.priority
                )
            })
            .collect_vec()
            .join("; ");
        write!(f, "{}", exit_location_string)?;
        Ok(())
    }
}
