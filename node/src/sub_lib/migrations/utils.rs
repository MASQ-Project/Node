// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor::Value;
use std::fmt::Debug;

pub fn value_to_type<T: Serialize + DeserializeOwned + Debug>(value: &Value) -> Option<T> {
    let serialized = serde_cbor::ser::to_vec(value).expect("Serialization error");
    match serde_cbor::de::from_slice::<T>(&serialized) {
        Err(_) => None,
        Ok(t) => Some(t),
    }
}
