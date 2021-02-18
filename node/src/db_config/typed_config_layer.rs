// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::sub_lib::cryptde::PlainData;
use rustc_hex::{FromHex, ToHex};

#[derive(Debug, PartialEq)]
pub enum TypedConfigLayerError {
    BadNumberFormat(String),
    BadHexFormat(String),
}

pub fn decode_u64(string_opt: Option<String>) -> Result<Option<u64>, TypedConfigLayerError> {
    match string_opt {
        None => Ok(None),
        Some(string) => match string.parse::<u64>() {
            Err(_) => Err(TypedConfigLayerError::BadNumberFormat(string)),
            Ok(number) => Ok(Some(number)),
        },
    }
}

pub fn decode_bytes(
    string_opt: Option<String>,
) -> Result<Option<PlainData>, TypedConfigLayerError> {
    match string_opt {
        None => Ok(None),
        Some(string) => match string.from_hex::<Vec<u8>>() {
            Err(_) => Err(TypedConfigLayerError::BadHexFormat(string)),
            Ok(bytes) => Ok(Some(PlainData::from(bytes))),
        },
    }
}

pub fn encode_u64(value_opt: Option<u64>) -> Result<Option<String>, TypedConfigLayerError> {
    match value_opt {
        None => Ok(None),
        Some(number) => Ok(Some(format!("{}", number))),
    }
}

pub fn encode_bytes(value_opt: Option<PlainData>) -> Result<Option<String>, TypedConfigLayerError> {
    match value_opt {
        Some(bytes) => Ok(Some(bytes.as_slice().to_hex::<String>())),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use rustc_hex::ToHex;

    #[test]
    fn decode_u64_handles_present_good_value() {
        let result = decode_u64(Some("1234".to_string()));

        assert_eq!(result, Ok(Some(1234)));
    }

    #[test]
    fn decode_u64_handles_present_bad_value() {
        let result = decode_u64(Some("booga".to_string()));

        assert_eq!(
            result,
            Err(TypedConfigLayerError::BadNumberFormat("booga".to_string()))
        );
    }

    #[test]
    fn get_u64_handles_absent_value() {
        let result = decode_u64(None);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn decode_bytes_handles_present_good_value() {
        let value = PlainData::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let value_string: String = value.as_slice().to_hex();

        let result = decode_bytes(Some(value_string));

        assert_eq!(result, Ok(Some(value)));
    }

    #[test]
    fn decode_bytes_handles_present_bad_value() {
        let result = decode_bytes(Some("I am not a valid hexadecimal string".to_string()));

        assert_eq!(
            result,
            Err(TypedConfigLayerError::BadHexFormat(
                "I am not a valid hexadecimal string".to_string()
            ))
        );
    }

    #[test]
    fn decode_bytes_handles_absent_value() {
        let result = decode_bytes(None);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn encode_u64_handles_present_value() {
        let result = encode_u64(Some(1234));

        assert_eq!(result, Ok(Some("1234".to_string())));
    }

    #[test]
    fn encode_u64_handles_absent_value() {
        let result = encode_u64(None);

        assert_eq!(result, Ok(None));
    }

    #[test]
    fn encode_bytes_handles_present_value() {
        let bytes = PlainData::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let bytes_hex: String = bytes.as_slice().to_hex();

        let result = encode_bytes(Some(bytes));

        assert_eq!(result, Ok(Some(bytes_hex)));
    }

    #[test]
    fn encode_bytes_handles_absent_value() {
        let result = encode_bytes(None);

        assert_eq!(result, Ok(None));
    }
}
