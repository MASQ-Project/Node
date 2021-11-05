// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use serde_derive::{Deserialize, Serialize};

//TODO what is this for? It seems unused.

#[derive(Deserialize, Serialize)]
#[serde(remote = "ethsign::Signature")]
pub struct SerializableSignature {
    pub v: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl SerializableSignature {}
