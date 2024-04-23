// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use num::integer::mod_floor;
use num::CheckedAdd;
use num::CheckedSub;
use num::{CheckedDiv, CheckedMul, Integer};
use std::any::type_name;
use std::fmt::Debug;
use std::ops::Mul;

// It's designed for a storage of values from 0 to 100, after which it can be used to compute
// the corresponding portion of many integer types. It should also take care of the least significant
// digit in order to diminish the effect of a precision loss genuinly implied by this kind of math
// operations done on integers.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Percentage {
    per_cent: u8,
}

impl Percentage {
    pub fn new(num: u8) -> Self {
        match num {
            0..=100 => Self { per_cent: num },
            x => panic!("Accepts only range from 0 to 100 but {} was supplied", x),
        }
    }

    pub fn of<N>(&self, num: N) -> N
    where
        N: From<u8> + CheckedMul + CheckedAdd + CheckedDiv + PartialOrd + Integer + Debug + Copy,
    {
        let zero = N::from(0);
        if num == zero || N::from(self.per_cent) == zero {
            return zero;
        }

        let a = N::from(self.per_cent)
            .checked_mul(&num)
            .unwrap_or_else(|| panic!(
                "Overflow when using 'Percentage' for num {:?} of type {}, trying to compute {} per \
                cent of it.", num, type_name::<N>(),self.per_cent
            ));
        if a < N::from(10) {
            return N::from(0);
        }

        let rounding = if Percentage::should_be_rounded_down(a) {
            N::from(0)
        } else {
            N::from(1)
        };

        let hundred = N::from(100);

        if a < hundred {
            rounding
        } else {
            a.checked_div(&hundred)
                .expect("div failed")
                .checked_add(&rounding)
                .expect("rounding failed")
        }
    }

    pub fn add_percent_to<N>(&self, num: N) -> N
    where
        N: From<u8> + CheckedMul + CheckedAdd + CheckedDiv + PartialOrd + Integer + Debug + Copy,
    {
        self.of(num).checked_add(&num).unwrap_or_else(|| {
            panic!(
                "Overflowed during addition of {} per cent, that is {:?}, to {:?} of type {}.",
                self.per_cent,
                self.of(num),
                num,
                type_name::<N>()
            )
        })
    }

    pub fn subtract_percent_from<N>(&self, num: N) -> N
    where
        N: From<u8>
            + CheckedMul
            + CheckedAdd
            + CheckedSub
            + CheckedDiv
            + PartialOrd
            + Integer
            + Debug
            + Copy,
    {
        num.checked_sub(&self.of(num))
            .expect("should never happen by its principle")
    }

    fn should_be_rounded_down<N>(num: N) -> bool
    where
        N: From<u8> + PartialEq + PartialOrd + Mul<N, Output = N> + CheckedMul + Integer + Copy,
    {
        let ten = N::from(10);
        let upper_limit = ten * ten;
        let enough_limit = ten;
        if num == upper_limit {
            true
        } else if num >= enough_limit {
            let modulo = mod_floor(num, upper_limit);
            modulo
                < N::from(5)
                    .checked_mul(&ten)
                    .expect("Couldn't create limit to compare with")
        } else {
            unreachable!("Check to prevent numbers with fewer than two digits failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::percentage::Percentage;
    use std::panic::catch_unwind;

    #[test]
    fn zero() {
        assert_eq!(Percentage::new(45).of(0), 0);
        assert_eq!(Percentage::new(0).of(33), 0)
    }

    #[test]
    fn end_to_end_test() {
        let range = 0..=100;

        let round_returned_range = range
            .clone()
            .into_iter()
            .map(|per_cent| Percentage::new(per_cent).of(100_u64))
            .collect::<Vec<u64>>();

        let expected = range
            .into_iter()
            .map(|num| num as u64)
            .collect::<Vec<u64>>();
        assert_eq!(round_returned_range, expected)
    }

    #[test]
    fn only_numbers_up_to_100_are_accepted() {
        (101..=u8::MAX)
            .map(|num| {
                (
                    catch_unwind(|| Percentage::new(num)).expect_err("expected panic"),
                    num,
                )
            })
            .map(|(panic, num)| {
                (
                    panic
                        .downcast_ref::<String>()
                        .expect("couldn't downcast to String")
                        .to_owned(),
                    num,
                )
            })
            .for_each(|(panic_msg, num)| {
                assert_eq!(
                    panic_msg,
                    format!("Accepts only range from 0 to 100 but {} was supplied", num)
                )
            });
    }

    #[test]
    fn too_low_values() {
        vec![((10, 1), 0), ((9, 1), 0), ((5, 14), 1), ((55, 40), 22)]
            .into_iter()
            .for_each(|((per_cent, examined_number), expected_result)| {
                let result = Percentage::new(per_cent).of(examined_number);
                assert_eq!(
                    result, expected_result,
                    "For {} per cent and number {} the expected result was {} but we got {}",
                    per_cent, examined_number, expected_result, result
                )
            })
    }

    #[test]
    fn should_be_rounded_down_works_for_last_but_one_digit() {
        [
            (787879, false),
            (1114545, true),
            (100, true),
            (49, true),
            (50, false),
        ]
        .into_iter()
        .for_each(|(num, expected_result)| {
            assert_eq!(Percentage::should_be_rounded_down(num), expected_result)
        })
    }

    #[test]
    fn add_percent_to_works() {
        let percentage = Percentage::new(13);

        let result = percentage.add_percent_to(100);

        assert_eq!(result, 113)
    }

    #[test]
    #[should_panic(expected = "Overflowed during addition of 1 per cent, that is \
    184467440737095516, to 18446744073709551615 of type u64.")]
    fn add_percent_to_hits_overflow() {
        let _ = Percentage::new(1).add_percent_to(u64::MAX);
    }

    #[test]
    fn subtract_percent_from_works() {
        let percentage = Percentage::new(55);

        let result = percentage.subtract_percent_from(100);

        assert_eq!(result, 45)
    }

    #[test]
    #[should_panic(
        expected = "Overflow when using 'Percentage' for num 18446744073709551615 of type u64, \
        trying to compute 2 per cent of it"
    )]
    fn hits_upper_overflow() {
        let _: u64 = Percentage::new(2).of(u64::MAX);
    }

    #[test]
    #[should_panic(
        expected = "internal error: entered unreachable code: Check to prevent numbers with fewer \
        than two digits failed"
    )]
    fn broken_code_for_violation_of_already_checked_range() {
        let _ = Percentage::should_be_rounded_down(2);
    }
}
