// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::sub_lib::cryptde::PlainData;
use rustc_hex::{FromHex, ToHex};
use crate::database::connection_wrapper::TransactionWrapper;

#[derive(Debug, PartialEq)]
pub enum TypedConfigLayerError {
    BadNumberFormat (String),
    BadHexFormat (String),
}

pub trait TypedConfigLayer {
    fn decode_u64(&self, string_opt: Option<String>) -> Result<Option<u64>, TypedConfigLayerError>;
    fn decode_bytes(&self, string_opt: Option<String>) -> Result<Option<PlainData>, TypedConfigLayerError>;
    fn encode_u64(&self, value_opt: Option<u64>) -> Result<Option<String>, TypedConfigLayerError>;
    fn encode_bytes(&self, value_opt: Option<&PlainData>) -> Result<Option<String>, TypedConfigLayerError>;
}

struct TypedConfigLayerReal {}

impl TypedConfigLayer for TypedConfigLayerReal {
    fn decode_u64(
        &self,
        string_opt: Option<String>,
    ) -> Result<Option<u64>, TypedConfigLayerError> {
        match string_opt {
            None => unimplemented!(),
            Some (string) => match string.parse::<u64> () {
                Err (e) => unimplemented! ("{:?}", e),
                Ok (number) => Ok (Some (number)),
            }
        }
    }

    fn decode_bytes(
        &self,
        string_opt: Option<String>,
    ) -> Result<Option<PlainData>, TypedConfigLayerError> {
        unimplemented!();
        // match self.scl.get (name, db_password_opt)? {
        //     Some (string) => match string.from_hex::<Vec<u8>>() {
        //         Ok(bytes) => Ok (Some (PlainData::from (bytes))),
        //         Err(_) => Err (TypedConfigLayerError::TypeError),
        //     },
        //     None => Ok (None),
        // }
    }

    fn encode_u64(
        &self,
        value_opt: Option<u64>,
    ) -> Result<Option<String>, TypedConfigLayerError> {
        unimplemented!();
        // match value_opt {
        //     Some (number) => Ok (self.scl.set (name, Some (&format!("{}", number)), db_password_opt)?),
        //     None => Ok(self.scl.set (name, None, db_password_opt)?),
        // }
    }

    fn encode_bytes(
        &self,
        value_opt: Option<&PlainData>,
    ) -> Result<Option<String>, TypedConfigLayerError> {
        unimplemented!();
        // match value_opt {
        //     Some (bytes) => Ok (self.scl.set (name, Some (&bytes.as_slice().to_hex::<String>()), db_password_opt)?),
        //     None => Ok(self.scl.set (name, None, db_password_opt)?),
        // }
    }
}

impl TypedConfigLayerReal {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use rustc_hex::ToHex;

    #[test]
    fn decode_u64_handles_present_good_value() {
        let subject = TypedConfigLayerReal::new();

        let result = subject.decode_u64(Some("1234".to_string()));

        assert_eq! (result, Ok(Some (1234)));
    }

    // #[test]
    // fn get_u64_handles_present_bad_value() {
    //     let scl = SecureConfigLayerMock::new()
    //         .get_result(Ok(Some ("booga".to_string())));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.decode_u64("parameter_name", Some("password"));
    //
    //     assert_eq! (result, Err(TypedConfigLayerError::TypeError));
    // }
    //
    // #[test]
    // fn get_u64_handles_absent_value() {
    //     let scl = SecureConfigLayerMock::new()
    //         .get_result(Ok(None));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.decode_u64("parameter_name", Some("password"));
    //
    //     assert_eq! (result, Ok(None));
    // }
    //
    // #[test]
    // fn get_bytes_handles_present_good_value() {
    //     let get_params_arc = Arc::new(Mutex::new(vec![]));
    //     let value = PlainData::new (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    //     let value_string: String = value.as_slice().to_hex();
    //     let scl = SecureConfigLayerMock::new()
    //         .get_params(&get_params_arc)
    //         .get_result(Ok(Some (value_string)));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.decode_bytes("parameter_name", Some("password"));
    //
    //     assert_eq!(result, Ok(Some(value)));
    //     let get_params = get_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *get_params,
    //         vec![("parameter_name".to_string(), Some("password".to_string()))]
    //     )
    // }
    //
    // #[test]
    // fn get_bytes_handles_present_bad_value() {
    //     let scl = SecureConfigLayerMock::new()
    //         .get_result(Ok(Some ("I am not a valid hexadecimal string".to_string())));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.decode_bytes("parameter_name", Some("password"));
    //
    //     assert_eq!(result, Err(TypedConfigLayerError::TypeError));
    // }
    //
    // #[test]
    // fn get_bytes_handles_absent_value() {
    //     let scl = SecureConfigLayerMock::new()
    //         .get_result(Ok(None));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.decode_bytes("parameter_name", Some("password"));
    //
    //     assert_eq! (result, Ok(None));
    // }

    // #[test]
    // fn set_u64_handles_present_value() {
    //     let set_params_arc = Arc::new(Mutex::new(vec![]));
    //     let scl = SecureConfigLayerMock::new()
    //         .set_params(&set_params_arc)
    //         .set_result(Err(SecureConfigLayerError::TransactionError));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.encode_u64("parameter_name", Some (1234), Some("password"));
    //
    //     assert_eq!(result, Err(TypedConfigLayerError::TransactionError));
    //     let set_params = set_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_params,
    //         vec![("parameter_name".to_string(), Some ("1234".to_string()), Some("password".to_string()))]
    //     )
    // }
    //
    // #[test]
    // fn set_u64_handles_absent_value() {
    //     let set_params_arc = Arc::new(Mutex::new(vec![]));
    //     let scl = SecureConfigLayerMock::new()
    //         .set_params(&set_params_arc)
    //         .set_result(Err(SecureConfigLayerError::DatabaseError ("booga".to_string())));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.encode_u64("parameter_name", None, Some("password"));
    //
    //     assert_eq!(result, Err(TypedConfigLayerError::DatabaseError ("booga".to_string())));
    //     let set_params = set_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_params,
    //         vec![("parameter_name".to_string(), None, Some("password".to_string()))]
    //     )
    // }
    //
    // #[test]
    // fn set_bytes_handles_present_value() {
    //     let set_params_arc = Arc::new(Mutex::new(vec![]));
    //     let bytes = PlainData::new (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    //     let bytes_hex: String = bytes.as_slice().to_hex();
    //     let scl = SecureConfigLayerMock::new()
    //         .set_params(&set_params_arc)
    //         .set_result(Ok(()));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.encode_bytes("parameter_name", Some (&bytes), Some("password"));
    //
    //     assert_eq!(result, Ok(()));
    //     let set_params = set_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_params,
    //         vec![("parameter_name".to_string(), Some (bytes_hex), Some("password".to_string()))]
    //     )
    // }
    //
    // #[test]
    // fn set_bytes_handles_absent_value() {
    //     let set_params_arc = Arc::new(Mutex::new(vec![]));
    //     let scl = SecureConfigLayerMock::new()
    //         .set_params(&set_params_arc)
    //         .set_result(Err(SecureConfigLayerError::NotPresent));
    //     let subject = TypedConfigLayerReal::new(Box::new(scl));
    //
    //     let result = subject.encode_bytes("parameter_name", None, Some("password"));
    //
    //     assert_eq!(result, Err(TypedConfigLayerError::NotPresent));
    //     let set_params = set_params_arc.lock().unwrap();
    //     assert_eq!(
    //         *set_params,
    //         vec![("parameter_name".to_string(), None, Some("password".to_string()))]
    //     )
    // }
}
