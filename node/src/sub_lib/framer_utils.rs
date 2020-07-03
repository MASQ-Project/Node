// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use masq_lib::utils::index_of;

#[derive(PartialEq, Debug)]
pub struct ChunkOffsetLength {
    pub offset: usize,
    pub length: usize,
}

pub const CRLF: &[u8; 2] = b"\r\n";

pub fn find_chunk_offset_length(data_so_far: &[u8]) -> Option<ChunkOffsetLength> {
    // TODO: Optimization: Only look at new-data length + 17 characters maximum
    let mut accumulated_offset = 0;
    loop {
        match find_next_chunk_offset_length(&data_so_far[accumulated_offset..]) {
            Err(0) => return None,
            Err(next_offset) => accumulated_offset += next_offset,
            Ok(result) => {
                return Some(ChunkOffsetLength {
                    offset: result.offset + accumulated_offset,
                    length: result.length,
                });
            }
        }
    }
}

fn find_next_chunk_offset_length(data_so_far: &[u8]) -> Result<ChunkOffsetLength, usize> {
    match index_of(data_so_far, CRLF) {
        None => Err(0),
        Some(0) => Err(CRLF.len()),
        Some(crlf_offset) => match evaluate_hex_digit(data_so_far[crlf_offset - 1]) {
            None => Err(crlf_offset + CRLF.len()),
            Some(_digit) => {
                let reversed_digits = find_reversed_digits(data_so_far, crlf_offset);
                Ok(ChunkOffsetLength {
                    offset: crlf_offset - reversed_digits.len(),
                    length: value_of_reversed_digits(&reversed_digits)
                        + CRLF.len()
                        + reversed_digits.len(),
                })
            }
        },
    }
}

fn find_reversed_digits(data_so_far: &[u8], backward_from: usize) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];
    let mut idx = backward_from;
    while (result.len() < 8) && (idx > 0) {
        idx -= 1;
        match evaluate_hex_digit(data_so_far[idx]) {
            None => break,
            Some(value) => result.push(value),
        }
    }
    result
}

fn value_of_reversed_digits(reversed_digits: &[u8]) -> usize {
    let mut multiplier: usize = 1;
    let mut result: usize = 0;
    for digit in reversed_digits {
        result += (*digit as usize) * multiplier;
        multiplier <<= 4;
    }
    result
}

fn evaluate_hex_digit(digit: u8) -> Option<u8> {
    match position_in_range(digit, b'0', b'9') {
        Some(pos) => Some(pos),
        None => match position_in_range(digit, b'A', b'F') {
            Some(pos) => Some(10 + pos),
            None => match position_in_range(digit, b'a', b'f') {
                Some(pos) => Some(10 + pos),
                None => None,
            },
        },
    }
}

fn position_in_range(digit: u8, first: u8, last: u8) -> Option<u8> {
    if digit < first {
        return None;
    }
    if digit > last {
        return None;
    }
    Some(digit - first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn returns_none_if_no_crlf() {
        let data_so_far = b"no crlf in this data";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(result, None);
    }

    #[test]
    pub fn returns_none_if_just_crlf() {
        let data_so_far = b"\r\nWABBLE";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(result, None);
    }

    #[test]
    pub fn returns_none_if_crlf_preceded_by_other_than_hexadecimal_digit() {
        let data_so_far = b"text ends with\r\n";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(result, None);
    }

    #[test]
    pub fn returns_data_for_single_capital_hexadecimal_digit() {
        let data_so_far = b"GLORF\r\nWABBLE";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(
            result,
            Some(ChunkOffsetLength {
                offset: 4,
                length: 15 + 3
            })
        );
    }

    #[test]
    pub fn returns_data_for_eight_capital_hexadecimal_digits() {
        let data_so_far = b"FEDCBA9876543210123456789ABCDEF\r\nWABBLE";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(
            result,
            Some(ChunkOffsetLength {
                offset: 23,
                length: 0x89ABCDEF + 10
            })
        );
    }

    #[test]
    pub fn returns_data_for_eight_lowercase_hexadecimal_digits() {
        let data_so_far = b"fedcba9876543210123456789abcdef\r\nWABBLE";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(
            result,
            Some(ChunkOffsetLength {
                offset: 23,
                length: 0x89ABCDEF + 10
            })
        );
    }

    #[test]
    pub fn returns_data_for_hexadecimal_number_hiding_behind_crlf() {
        let data_so_far = b"\r\n glabble 64\r\nWABBLE";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(
            result,
            Some(ChunkOffsetLength {
                offset: 11,
                length: 0x64 + 4
            })
        );
    }

    #[test]
    pub fn returns_data_for_hexadecimal_number_hiding_behind_multiple_crlfs() {
        let data_so_far = b"\r\n\r\n\r\n\r\n89abcdef\r\n";

        let result = find_chunk_offset_length(data_so_far);

        assert_eq!(
            result,
            Some(ChunkOffsetLength {
                offset: 8,
                length: 0x89ABCDEF + 10
            })
        );
    }
}
