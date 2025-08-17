// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod app_rpc_web3_error_kind;
pub mod masq_error;

use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
use crate::blockchain::errors::blockchain_db_error::masq_error::MASQError;
use serde::de::{Error, MapAccess};
use serde::{Deserialize as DeserializeTrait, Serialize as SerializeTrait};
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};

impl SerializeTrait for Box<dyn BlockchainDbError> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json_value: serde_json::Value = serde_json::from_str(
            &self
                .serialize_fn()
                .map_err(|e| serde::ser::Error::custom(e))?,
        ) // TODO tested?
        .map_err(|e| serde::ser::Error::custom(e))?; // TODO tested?
        json_value.serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for Box<dyn BlockchainDbError> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json_value: serde_json::Value = serde_json::Value::deserialize(deserializer)?; //TODO tested?
        let json_str =
            serde_json::to_string(&json_value).map_err(|e| serde::de::Error::custom(e))?; //  TODO tested?

        if let Ok(error) = AppRpcWeb3ErrorKind::deserialize_fn(&json_str) {
            return Ok(error);
        }

        if let Ok(error) = MASQError::deserialize_fn(&json_str) {
            return Ok(error);
        }

        Err(serde::de::Error::custom(format!(
            "Unable to deserialize BlockchainDbError from: {}",
            json_str
        )))
    }
}

impl Clone for Box<dyn BlockchainDbError> {
    fn clone(&self) -> Self {
        self.dup()
    }
}

impl PartialEq for Box<dyn BlockchainDbError> {
    fn eq(&self, other: &Self) -> bool {
        self.partial_eq(other)
    }
}

impl Hash for Box<dyn BlockchainDbError> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.costume_hash_fn(state)
    }
}

impl Eq for Box<dyn BlockchainDbError> {}

pub trait BlockchainDbError: Debug {
    fn serialize_fn(&self) -> Result<String, serde_json::Error>;
    fn deserialize_fn(str: &str) -> Result<Box<dyn BlockchainDbError>, serde_json::Error>
    where
        Self: Sized;
    fn partial_eq(&self, other: &Box<dyn BlockchainDbError>) -> bool;
    fn costume_hash_fn(&self, hasher: &mut dyn Hasher);
    fn dup(&self) -> Box<dyn BlockchainDbError>;
    as_any_ref_in_trait!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialization_fails() {
        let str = "\"bluh\"";

        let err = serde_json::from_str::<Box<dyn BlockchainDbError>>(str).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Unable to deserialize BlockchainDbError from: \"bluh\""
        )
    }
}
