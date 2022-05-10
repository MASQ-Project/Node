// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::fmt::Debug;
use std::ops::Deref;

pub trait NonNegativeSigned: Copy + Debug + PartialEq + Deref {
    type Signed;
    type Unsigned;
    fn try_assign_signed(num: Self::Signed) -> Result<Self, ErrorFromSignOperation>;
    fn try_assign_unsigned(num: Self::Unsigned) -> Result<Self, ErrorFromSignOperation>;
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct NonNegativeSigned128 {
    num: i128,
}

impl NonNegativeSigned for NonNegativeSigned128 {
    type Signed = i128;
    type Unsigned = u128;

    fn try_assign_signed(num: Self::Signed) -> Result<Self, ErrorFromSignOperation> {
        todo!()
    }

    fn try_assign_unsigned(num: Self::Unsigned) -> Result<Self, ErrorFromSignOperation> {
        todo!()
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorFromSignOperation {
    LowerBoundCrossed,
    UpperBoundCrossed,
}

impl Deref for NonNegativeSigned128 {
    type Target = i128;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nns128_assign_value_under_lower_bound() {
        let result: Result<NonNegativeSigned128, ErrorFromSignOperation> =
            NonNegativeSigned128::try_assign_signed(-1);

        assert_eq!(result, Err(ErrorFromSignOperation::LowerBoundCrossed))
    }

    #[test]
    fn nns128_assign_value_above_upper_bound() {
        let result: Result<NonNegativeSigned128, ErrorFromSignOperation> =
            NonNegativeSigned128::try_assign_unsigned(i128::MAX as u128 + 1);

        assert_eq!(result, Err(ErrorFromSignOperation::UpperBoundCrossed))
    }

    #[test]
    fn nns128_zero_works_fine_for_signed() {
        let assignment_result: NonNegativeSigned128 =
            NonNegativeSigned128::try_assign_signed(0).unwrap();

        assert_eq!(*assignment_result, 0_i128);
    }
}
