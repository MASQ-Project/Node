// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::cryptde::PlainData;

pub struct BinaryTraverser<'a> {
    plain_data: &'a PlainData,
    position: usize,
}

impl<'a> BinaryTraverser<'a> {
    pub fn new(plain_data: &'a PlainData) -> BinaryTraverser<'a> {
        BinaryTraverser {
            plain_data,
            position: 0,
        }
    }

    pub fn offset(&self) -> usize {
        self.position
    }

    pub fn is_valid(&self) -> bool {
        self.position < self.plain_data.len()
    }

    #[allow(clippy::result_unit_err)]
    pub fn next_bytes(&mut self, count: usize) -> Result<&[u8], ()> {
        let position = self.offset();
        self.advance(count)?;
        Ok(&self.plain_data.as_slice()[position..(position + count)])
    }

    #[allow(clippy::result_unit_err)]
    pub fn advance(&mut self, bytes: usize) -> Result<(), ()> {
        self.position += bytes;
        if self.position > self.plain_data.len() {
            Err(())
        } else {
            Ok(())
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_u8(&mut self) -> Result<u8, ()> {
        self.advance(1)?;
        Self::convert_result(self.plain_data.get_u8(self.position - 1))
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_u16(&mut self) -> Result<u16, ()> {
        self.advance(2)?;
        Self::convert_result(self.plain_data.get_u16(self.position - 2))
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_u24(&mut self) -> Result<u32, ()> {
        self.advance(3)?;
        Self::convert_result(self.plain_data.get_u24(self.position - 3))
    }

    #[allow(clippy::result_unit_err)]
    pub fn get_u32(&mut self) -> Result<u32, ()> {
        self.advance(4)?;
        Self::convert_result(self.plain_data.get_u32(self.position - 4))
    }

    #[allow(clippy::result_unit_err)]
    fn convert_result<T>(option: Option<T>) -> Result<T, ()> {
        match option {
            Some(value) => Ok(value),
            None => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_is_initialized_to_zero() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let subject = BinaryTraverser::new(&plain_data);

        let result = subject.offset();

        assert_eq!(0, result);
        assert_eq!(true, subject.is_valid());
    }

    #[test]
    fn advance_changes_offset_when_successful_and_leaves_valid_if_more_available() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);

        let result = subject.advance(7);

        assert_eq!(Ok(()), result);
        assert_eq!(7, subject.offset());
        assert_eq!(true, subject.is_valid());
    }

    #[test]
    fn advance_changes_offset_when_successful_but_invalidates_if_at_end() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);

        let result = subject.advance(8);

        assert_eq!(Ok(()), result);
        assert_eq!(8, subject.offset());
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn advance_changes_offset_when_unsuccessful_to_invalidate_further_operations() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);

        let result = subject.advance(9);

        assert_eq!(Err(()), result);
        assert_eq!(9, subject.offset());
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn next_bytes_succeeds_under_good_conditions() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(1).unwrap();

        let result = subject.next_bytes(6);

        assert_eq!(Ok(&[1u8, 2u8, 3u8, 4u8, 5u8, 6u8][..]), result);
        assert_eq!(7, subject.offset());
        assert_eq!(true, subject.is_valid());
    }

    #[test]
    fn next_bytes_invalidates_under_good_conditions() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(1).unwrap();

        let result = subject.next_bytes(8);

        assert_eq!(Err(()), result);
        assert_eq!(9, subject.offset());
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn get_u8_changes_offset_when_successful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(7).unwrap();

        let result = subject.get_u8();

        assert_eq!(Ok(0x07), result);
        assert_eq!(8, subject.offset());
    }

    #[test]
    fn get_u8_invalidates_when_unsuccessful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(8).unwrap();

        let result = subject.get_u8();

        assert_eq!(Err(()), result);
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn get_u16_changes_offset_when_successful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(6).unwrap();

        let result = subject.get_u16();

        assert_eq!(Ok(0x0607), result);
        assert_eq!(8, subject.offset());
    }

    #[test]
    fn get_u16_invalidates_when_unsuccessful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(7).unwrap();

        let result = subject.get_u16();

        assert_eq!(Err(()), result);
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn get_u24_changes_offset_when_successful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(5).unwrap();

        let result = subject.get_u24();

        assert_eq!(Ok(0x050607), result);
        assert_eq!(8, subject.offset());
    }

    #[test]
    fn get_u24_invalidates_when_unsuccessful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(6).unwrap();

        let result = subject.get_u24();

        assert_eq!(Err(()), result);
        assert_eq!(false, subject.is_valid());
    }

    #[test]
    fn get_u32_changes_offset_when_successful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(4).unwrap();

        let result = subject.get_u32();

        assert_eq!(Ok(0x04050607), result);
        assert_eq!(8, subject.offset());
    }

    #[test]
    fn get_u32_invalidates_when_unsuccessful() {
        let plain_data = PlainData::new(&[0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8]);
        let mut subject = BinaryTraverser::new(&plain_data);
        subject.advance(5).unwrap();

        let result = subject.get_u32();

        assert_eq!(Err(()), result);
        assert_eq!(false, subject.is_valid());
    }
}
