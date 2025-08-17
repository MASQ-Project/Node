// Copyright (c) 2025, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

pub mod app_rpc_web3_error_kind;
pub mod masq_error_kind;

use crate::blockchain::errors::blockchain_db_error::app_rpc_web3_error_kind::AppRpcWeb3ErrorKind;
use crate::blockchain::errors::blockchain_db_error::masq_error_kind::MASQErrorKind;
use crate::blockchain::errors::custom_common_methods::CustomCommonMethods;
use serde::{Deserialize as DeserializeTrait, Serialize as SerializeTrait};
use serde_json::Value;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

pub trait BlockchainDbError: CustomSeDe + CustomHash + Debug {
    fn as_common_methods(&self) -> &dyn CustomCommonMethods<Box<dyn BlockchainDbError>>;
}

pub trait CustomSeDe {
    fn costume_serialize(&self) -> Result<Value, serde_json::Error>;
    fn costume_deserialize(str: &str) -> Result<Box<dyn BlockchainDbError>, serde_json::Error>
    where
        Self: Sized;
}

pub trait CustomHash {
    fn costume_hash(&self, hasher: &mut dyn Hasher);
}

impl SerializeTrait for Box<dyn BlockchainDbError> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.costume_serialize()
            .map_err(|e| serde::ser::Error::custom(e))?
            .serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for Box<dyn BlockchainDbError> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json_value: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        let json_str =
            serde_json::to_string(&json_value).map_err(|e| serde::de::Error::custom(e))?; // Untested error

        if let Ok(error) = AppRpcWeb3ErrorKind::costume_deserialize(&json_str) {
            return Ok(error);
        }

        if let Ok(error) = MASQErrorKind::costume_deserialize(&json_str) {
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
        self.as_common_methods().dup()
    }
}

impl PartialEq for Box<dyn BlockchainDbError> {
    fn eq(&self, other: &Self) -> bool {
        self.as_common_methods().partial_eq(other)
    }
}

impl Hash for Box<dyn BlockchainDbError> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.costume_hash(state)
    }
}

impl Eq for Box<dyn BlockchainDbError> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::errors::test_utils::BlockchainDbErrorMock;

    #[test]
    fn deserialization_fails() {
        let str = "\"bluh\"";

        let err = serde_json::from_str::<Box<dyn BlockchainDbError>>(str).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Unable to deserialize BlockchainDbError from: \"bluh\""
        )
    }

    #[test]
    fn pre_serialization_costume_error_is_well_arranged() {
        let mock = BlockchainDbErrorMock::default();
        let subject: Box<dyn BlockchainDbError> = Box::new(mock);

        let res = serde_json::to_string(&subject).unwrap_err();

        assert_eq!(
            res.to_string(),
            "invalid type: character `a`, expected null"
        );
    }

    #[test]
    fn deserialization_other_error() {
        let result =
            serde_json::from_str::<Box<dyn BlockchainDbError>>(r#"{"key":invalid_json_value}"#)
                .unwrap_err();

        assert_eq!(result.to_string(), "expected value at line 1 column 8");
    }
}
