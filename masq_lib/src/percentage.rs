// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use num::CheckedAdd;
use num::CheckedSub;
use num::{CheckedDiv, CheckedMul, Integer};
use std::any::type_name;
use std::fmt::Debug;
use std::ops::Rem;

pub trait PercentageInteger:
    TryFrom<i8>
    + CheckedMul
    + CheckedAdd
    + CheckedSub
    + CheckedDiv
    + PartialOrd
    + Rem<Output = Self>
    + Integer
    + Debug
    + Copy
{
}

macro_rules! impl_percentage_integer {
    ($($num_type: ty),+) => {
        $(impl PercentageInteger for $num_type {})+
    }
}

impl_percentage_integer!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

// Designed to store values from 0 to 100 and offer a set of handy methods for PurePercentage
// operations over a wide variety of integer types. It is also to look after the least significant
// digit on the resulted number in order to avoid the effect of a loss on precision that genuinely
// comes with division on integers if a remainder is left over. The percents are always represented
// by an unsigned integer. On the contrary, the numbers that it is applied on can take on both
// positive and negative values.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurePercentage {
    degree: u8,
}

impl TryFrom<u8> for PurePercentage {
    type Error = String;

    fn try_from(degree: u8) -> Result<Self, Self::Error> {
        match degree {
            0..=100 => Ok(Self { degree }),
            x => Err(format!(
                "Accepts only range from 0 to 100, but {} was supplied",
                x
            )),
        }
    }
}

trait PurePercentageInternalMethods<N>
where
    Self: Sized,
{
    fn _of(&self, num: N) -> N;
    fn __check_zero_and_maybe_return_it(&self, num: N) -> Option<N>;
    fn __abs(num: N, is_signed: bool) -> N;
    fn __derive_rounding_increment(remainder: N) -> N;
    fn _increase_by_percent_for(&self, num: N) -> N;
    fn _decrease_by_percent_for(&self, num: N) -> N;
    fn __handle_upper_overflow(&self, num: N) -> N;
}

impl<N> PurePercentageInternalMethods<N> for PurePercentage
where
    N: PercentageInteger,
    <N as TryFrom<i8>>::Error: Debug,
    i16: TryFrom<N>,
    <i16 as TryFrom<N>>::Error: Debug,
{
    fn _of(&self, num: N) -> N {
        if let Some(zero) = self.__check_zero_and_maybe_return_it(num) {
            return zero;
        }

        let product_before_final_div = match N::try_from(self.degree as i8)
            .expect("Each integer has 100")
            .checked_mul(&num)
        {
            Some(num) => num,
            None => return self.__handle_upper_overflow(num),
        };

        let (base, remainder) = base_and_rem_from_div_100(product_before_final_div);

        base + Self::__derive_rounding_increment(remainder)
    }

    fn __check_zero_and_maybe_return_it(&self, num: N) -> Option<N> {
        let zero = N::try_from(0).expect("Each integer has 0");
        if num == zero || N::try_from(self.degree as i8).expect("Each integer has 100") == zero {
            Some(zero)
        } else {
            None
        }
    }

    fn __abs(num: N, is_negative: bool) -> N {
        if is_negative {
            N::try_from(-1)
                .expect("Negative 1 must be possible for a confirmed signed integer")
                .checked_mul(&num)
                .expect("Must be possible for these low values")
        } else {
            num
        }
    }

    // This function helps to correct the last digit of the resulting integer to be as close
    // as possible to the hypothetical fractional number, if we could go beyond the decimal point.
    fn __derive_rounding_increment(remainder: N) -> N {
        let is_negative = remainder < N::try_from(0).expect("Each integer has 0");
        let is_minor =
            Self::__abs(remainder, is_negative) < N::try_from(50).expect("Each integer has 50");
        let addition = match (is_negative, is_minor) {
            (false, true) => 0,
            (false, false) => 1,
            (true, true) => 0,
            (true, false) => -1,
        };
        N::try_from(addition).expect("Each integer has 1, or -1 if signed")
    }

    fn _increase_by_percent_for(&self, num: N) -> N {
        let to_add = self._of(num);
        num.checked_add(&to_add).unwrap_or_else(|| {
            panic!(
                "Overflowed during addition of {} percent, that is an extra {:?} for {:?} of type {}.",
                self.degree,
                to_add,
                num,
                type_name::<N>()
            )
        })
    }

    fn _decrease_by_percent_for(&self, num: N) -> N {
        let to_subtract = self._of(num);
        num.checked_sub(&to_subtract)
            .expect("Mathematically impossible")
    }

    fn __handle_upper_overflow(&self, num: N) -> N {
        let (base, remainder) = base_and_rem_from_div_100(num);
        let percents = N::try_from(self.degree as i8).expect("Each integer has 100");
        let percents_of_base = base * percents;
        let (percents_of_remainder, nearly_lost_tail) =
            base_and_rem_for_ensured_i16(remainder, percents);
        let final_rounding_element = Self::__derive_rounding_increment(nearly_lost_tail);

        percents_of_base + percents_of_remainder + final_rounding_element
    }
}

impl PurePercentage {
    pub fn of<N>(&self, num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        self._of(num)
    }

    pub fn increase_by_percent_for<N>(&self, num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        self._increase_by_percent_for(num)
    }

    pub fn decrease_by_percent_for<N>(&self, num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        self._decrease_by_percent_for(num)
    }
}

fn base_and_rem_for_ensured_i16<N>(a: N, b: N) -> (N, N)
where
    N: PercentageInteger,
    <N as TryFrom<i8>>::Error: Debug,
    i16: TryFrom<N>,
    <i16 as TryFrom<N>>::Error: Debug,
{
    let num = i16::try_from(a)
        .expect("Remainder: Each integer can go up to 100, or down to -100 if signed")
        * i16::try_from(b)
            .expect("Percents: Each integer can go up to 100, or down to -100 if signed");

    let (base, remainder) = base_and_rem_from_div_100(num);

    (
        N::try_from(base as i8)
            .expect("Base: Each integer can go up to 100, or down to -100 if signed"),
        N::try_from(remainder as i8)
            .expect("Remainder: Each integer can go up to 100, or down to -100 if signed"),
    )
}

fn base_and_rem_from_div_100<N>(num: N) -> (N, N)
where
    N: PercentageInteger,
    <N as TryFrom<i8>>::Error: Debug,
{
    let hundred = N::try_from(100i8).expect("Each integer has 100");
    let modulo = num % hundred;
    (num / hundred, modulo)
}

// This is a wider type that allows to specify cumulative percents of more than only 100.
// The expected use of this would look like requesting percents meaning possibly multiples of 100%,
// roughly, of a certain base number. Similarly to the PurePercentage type, also signed numbers
// would be accepted.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoosePercentage {
    multiplier_of_100_percent: u32,
    degrees_from_remainder: PurePercentage,
}

impl LoosePercentage {
    pub fn new(percents: u32) -> Self {
        let multiples_of_100_percent = percents / 100;
        let remainder = (percents % 100) as u8;
        let degrees_from_remainder =
            PurePercentage::try_from(remainder).expect("Should never happen.");
        Self {
            multiplier_of_100_percent: multiples_of_100_percent,
            degrees_from_remainder,
        }
    }

    // If this returns an overflow error, you may want to precede this by converting the base
    // number to a larger integer
    pub fn of<N>(&self, num: N) -> Result<N, BaseTypeOverflow>
    where
        N: PercentageInteger + TryFrom<u32>,
        <N as TryFrom<i8>>::Error: Debug,
        <N as TryFrom<u32>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let multiplier = match N::try_from(self.multiplier_of_100_percent) {
            Ok(n) => n,
            Err(e) => {
                return Err(BaseTypeOverflow {
                    msg: format!(
                        "Couldn't init multiplier {} to type {} due to {:?}.",
                        self.multiplier_of_100_percent,
                        type_name::<N>(),
                        e
                    ),
                })
            }
        };

        let wholes = match num.checked_mul(&multiplier) {
            Some(n) => n,
            None => {
                return Err(BaseTypeOverflow {
                    msg: format!(
                        "Multiplication failed between {:?} and {:?} for type {}.",
                        num,
                        multiplier,
                        type_name::<N>()
                    ),
                })
            }
        };

        let remainder = self.degrees_from_remainder.of(num);

        match wholes.checked_add(&remainder) {
            Some(res) => Ok(res),
            None => Err(BaseTypeOverflow {
                msg: format!(
                    "Final addition failed on {:?} and {:?} for type {}.",
                    wholes,
                    remainder,
                    type_name::<N>()
                ),
            }),
        }
    }

    // Note that functions like 'add_percents_to' or 'subtract_percents_from' don't need to be
    // implemented here, even though they are at the 'PurePercentage'. You can substitute them
    // simply by querying 100 + <your desired addition in percents> or 100 - <your desired
    // subtraction in percents in the interval (1..=99) >
}

#[derive(Debug, PartialEq, Eq)]
pub struct BaseTypeOverflow {
    msg: String,
}

#[cfg(test)]
mod tests {
    use crate::percentage::{
        BaseTypeOverflow, LoosePercentage, PercentageInteger, PurePercentage,
        PurePercentageInternalMethods,
    };
    use std::fmt::Debug;

    #[test]
    fn percentage_is_implemented_for_all_rust_integers() {
        let subject = PurePercentage::try_from(50).unwrap();

        assert_positive_integer_compatibility(&subject, u8::MAX, 128);
        assert_positive_integer_compatibility(&subject, u16::MAX, 32768);
        assert_positive_integer_compatibility(&subject, u32::MAX, 2147483648);
        assert_positive_integer_compatibility(&subject, u64::MAX, 9223372036854775808);
        assert_positive_integer_compatibility(
            &subject,
            u128::MAX,
            170141183460469231731687303715884105728,
        );
        assert_negative_integer_compatibility(&subject, i8::MIN, -64);
        assert_negative_integer_compatibility(&subject, i16::MIN, -16384);
        assert_negative_integer_compatibility(&subject, i32::MIN, -1073741824);
        assert_negative_integer_compatibility(&subject, i64::MIN, -4611686018427387904);
        assert_negative_integer_compatibility(
            &subject,
            i128::MIN,
            -85070591730234615865843651857942052864,
        );
    }

    fn assert_positive_integer_compatibility<N>(
        subject: &PurePercentage,
        num: N,
        expected_literal_num: N,
    ) where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        assert_against_literal_value(subject, num, expected_literal_num);

        let trivially_calculated_half = num / N::try_from(2).unwrap();
        // Widening the bounds to compensate the extra rounding
        let one = N::try_from(1).unwrap();
        assert!(
            trivially_calculated_half <= expected_literal_num
                && expected_literal_num <= (trivially_calculated_half + one),
            "We expected {:?} to be {:?} or {:?}",
            expected_literal_num,
            trivially_calculated_half,
            trivially_calculated_half + one
        )
    }

    fn assert_negative_integer_compatibility<N>(
        subject: &PurePercentage,
        num: N,
        expected_literal_num: N,
    ) where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        assert_against_literal_value(subject, num, expected_literal_num);

        let trivially_calculated_half = num / N::try_from(2).unwrap();
        // Widening the bounds to compensate the extra rounding
        let one = N::try_from(1).unwrap();
        assert!(
            trivially_calculated_half >= expected_literal_num
                && expected_literal_num >= trivially_calculated_half - one,
            "We expected {:?} to be {:?} or {:?}",
            expected_literal_num,
            trivially_calculated_half,
            trivially_calculated_half - one
        )
    }

    fn assert_against_literal_value<N>(subject: &PurePercentage, num: N, expected_literal_num: N)
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let percents_of_num = subject.of(num);

        assert_eq!(
            percents_of_num, expected_literal_num,
            "Expected {:?}, but was {:?}",
            expected_literal_num, percents_of_num
        );
    }

    #[test]
    fn zeros_for_pure_percentage() {
        assert_eq!(PurePercentage::try_from(45).unwrap().of(0), 0);
        assert_eq!(PurePercentage::try_from(0).unwrap().of(33), 0)
    }

    #[test]
    fn pure_percentage_end_to_end_test_for_unsigned() {
        let base_value = 100;
        let act = |percent, base| PurePercentage::try_from(percent).unwrap().of(base);
        let expected_values = (0..=100).collect::<Vec<i8>>();

        test_end_to_end(act, base_value, expected_values)
    }

    #[test]
    fn pure_percentage_end_to_end_test_for_signed() {
        let base_value = -100;
        let act = |percent, base| PurePercentage::try_from(percent).unwrap().of(base);
        let expected_values = (-100..=0).rev().collect::<Vec<i8>>();

        test_end_to_end(act, base_value, expected_values)
    }

    fn test_end_to_end<F>(act: F, base: i8, expected_values: Vec<i8>)
    where
        F: Fn(u8, i8) -> i8,
    {
        let range = 0_u8..=100;

        let round_returned_range = range
            .into_iter()
            .map(|percent| act(percent, base))
            .collect::<Vec<i8>>();

        assert_eq!(round_returned_range, expected_values)
    }

    #[test]
    fn only_numbers_up_to_100_are_accepted() {
        (101..=u8::MAX)
            .map(|num| (PurePercentage::try_from(num), num))
            .for_each(|(res, num)| {
                assert_eq!(
                    res,
                    Err(format!(
                        "Accepts only range from 0 to 100, but {} was supplied",
                        num
                    ))
                )
            });
    }

    struct Case {
        requested_percent: u32,
        examined_base_number: i64,
        expected_result: i64,
    }

    #[test]
    fn too_low_values() {
        vec![
            Case {
                requested_percent: 49,
                examined_base_number: 1,
                expected_result: 0,
            },
            Case {
                requested_percent: 9,
                examined_base_number: 1,
                expected_result: 0,
            },
            Case {
                requested_percent: 5,
                examined_base_number: 14,
                expected_result: 1,
            },
            Case {
                requested_percent: 55,
                examined_base_number: 41,
                expected_result: 23,
            },
            Case {
                requested_percent: 55,
                examined_base_number: 40,
                expected_result: 22,
            },
        ]
        .into_iter()
        .for_each(|case| {
            let result = PurePercentage::try_from(u8::try_from(case.requested_percent).unwrap())
                .unwrap()
                .of(case.examined_base_number);
            assert_eq!(
                result, case.expected_result,
                "For {} percent and number {} the expected result was {}, but we got {}",
                case.requested_percent, case.examined_base_number, case.expected_result, result
            )
        })
    }

    #[test]
    fn should_be_rounded_to_works_for_last_but_one_digit() {
        [
            (49, 0),
            (50, 1),
            (51, 1),
            (5, 0),
            (99,1),
            (0,0)
        ]
        .into_iter()
        .for_each(
            |(num, expected_abs_result)| {
                let result = PurePercentage::__derive_rounding_increment(num);
                assert_eq!(
                    result,
                    expected_abs_result,
                    "Unsigned number {} was identified for rounding as {:?}, but it should've been {:?}",
                    num,
                    result,
                    expected_abs_result
            );
                let signed = num as i64 * -1;
                let result = PurePercentage::__derive_rounding_increment(signed);
                let expected_neg_result = expected_abs_result * -1;
                assert_eq!(
                result,
                expected_neg_result,
                "Signed number {} was identified for rounding as {:?}, but it should've been {:?}",
                signed,
                result,
                expected_neg_result
            )
            },
        )
    }

    #[test]
    fn increase_by_percent_for_works() {
        let subject = PurePercentage::try_from(13).unwrap();

        let unsigned = subject.increase_by_percent_for(100);
        let signed = subject.increase_by_percent_for(-100);

        assert_eq!(unsigned, 113);
        assert_eq!(signed, -113)
    }

    #[test]
    #[should_panic(expected = "Overflowed during addition of 1 percent, that is \
    an extra 184467440737095516 for 18446744073709551615 of type u64.")]
    fn increase_by_percent_for_hits_overflow() {
        let _ = PurePercentage::try_from(1)
            .unwrap()
            .increase_by_percent_for(u64::MAX);
    }

    #[test]
    fn decrease_by_percent_for_works() {
        let subject = PurePercentage::try_from(55).unwrap();

        let unsigned = subject.decrease_by_percent_for(100);
        let signed = subject.decrease_by_percent_for(-100);

        assert_eq!(unsigned, 45);
        assert_eq!(signed, -45)
    }

    #[test]
    fn preventing_early_upper_overflow() {
        // The standard algorithm begins by a multiplication with this 61, which would cause
        // an overflow, so for such large numbers like this one we switch the order of operations.
        // We're going to divide it by 100 first and multiple after it. (However, we'd lose some
        // precision in smaller numbers that same way). Why that much effort? I don't want to see
        // an overflow happen where most people wouldn't anticipate it: when going for
        // a PurePercentage from their number, implying a request to receive another number, but
        // always smaller than that passed in.
        let case_one = PurePercentage::try_from(61).unwrap().of(u64::MAX / 60);
        // There is more going on under the hood, which shows better on the following example:
        // if we divide 255 by 100, we get 2. Then multiplied by 30, it amounts to 60. The right
        // result, though, is 77 (with an extra 1 from rounding). Therefor there is another
        // piece of code whose charge is to treat the remainder of modulo 100 that is pushed off
        // the scoped, and if ignored, it would cause the result to be undervalued. This remainder
        // is again treated the by the primary (reversed) methodology with num * percents done
        // first, followed by the final division, keeping just one hundredth.
        let case_two = PurePercentage::try_from(30).unwrap().of(u8::MAX);
        // We apply the rounding even here. That's why we'll see the result drop by one compared to
        // the previous case. As 254 * 30 is 7620, the two least significant digits come rounded
        // by 100 as 0 which means 7620 divided by 100 makes 76.
        let case_three = PurePercentage::try_from(30).unwrap().of(u8::MAX - 1);

        assert_eq!(case_one, 187541898082713775);
        assert_eq!(case_two, 77);
        assert_eq!(case_three, 76)
        // Note: Interestingly, this isn't a threat on the negative numbers, even the extremes.
    }

    #[test]
    fn zeroes_for_loose_percentage() {
        assert_eq!(LoosePercentage::new(45).of(0).unwrap(), 0);
        assert_eq!(LoosePercentage::new(0).of(33).unwrap(), 0)
    }

    #[test]
    fn loose_percentage_end_to_end_test_for_standard_values_unsigned() {
        let base_value = 100;
        let act = |percent, base| LoosePercentage::new(percent as u32).of(base).unwrap();
        let expected_values = (0..=100).collect::<Vec<i8>>();

        test_end_to_end(act, base_value, expected_values)
    }

    #[test]
    fn loose_percentage_end_to_end_test_for_standard_values_signed() {
        let base_value = -100;
        let act = |percent, base| LoosePercentage::new(percent as u32).of(base).unwrap();
        let expected_values = (-100..=0).rev().collect::<Vec<i8>>();

        test_end_to_end(act, base_value, expected_values)
    }

    const TEST_SET: [Case; 5] = [
        Case {
            requested_percent: 101,
            examined_base_number: 10000,
            expected_result: 10100,
        },
        Case {
            requested_percent: 150,
            examined_base_number: 900,
            expected_result: 1350,
        },
        Case {
            requested_percent: 999,
            examined_base_number: 10,
            expected_result: 100,
        },
        Case {
            requested_percent: 1234567,
            examined_base_number: 20,
            expected_result: 12345 * 20 + (67 * 20 / 100),
        },
        Case {
            requested_percent: u32::MAX,
            examined_base_number: 1,
            expected_result: (u32::MAX / 100) as i64 + 1,
        },
    ];

    #[test]
    fn loose_percentage_for_large_values_unsigned() {
        TEST_SET.into_iter().for_each(|case| {
            let result = LoosePercentage::new(case.requested_percent)
                .of(case.examined_base_number)
                .unwrap();
            assert_eq!(
                result, case.expected_result,
                "Expected {} does not match actual {}. Percents {} of base {}.",
                case.expected_result, result, case.requested_percent, case.examined_base_number
            )
        })
    }

    #[test]
    fn loose_percentage_end_to_end_test_for_large_values_signed() {
        TEST_SET
            .into_iter()
            .map(|mut case| {
                case.examined_base_number *= -1;
                case.expected_result *= -1;
                case
            })
            .for_each(|case| {
                let result = LoosePercentage::new(case.requested_percent)
                    .of(case.examined_base_number)
                    .unwrap();
                assert_eq!(
                    result, case.expected_result,
                    "Expected {} does not match actual {}. Percents {} of base {}.",
                    case.expected_result, result, case.requested_percent, case.examined_base_number
                )
            })
    }

    #[test]
    fn loose_percentage_multiple_of_percent_hits_limit() {
        let percents = (u8::MAX as u32 + 1) * 100;
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(1);

        assert_eq!(
            result,
            Err(BaseTypeOverflow {
                msg: "Couldn't init multiplier 256 to type u8 due to TryFromIntError(())."
                    .to_string()
            })
        )
    }

    #[test]
    fn loose_percentage_hits_limit_at_multiplication() {
        let percents = 200;
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(u8::MAX);

        assert_eq!(
            result,
            Err(BaseTypeOverflow {
                msg: "Multiplication failed between 255 and 2 for type u8.".to_string()
            })
        )
    }

    #[test]
    fn loose_percentage_hits_limit_at_addition_from_remainder() {
        let percents = 101;
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(u8::MAX);

        assert_eq!(
            result,
            Err(BaseTypeOverflow {
                msg: "Final addition failed on 255 and 3 for type u8.".to_string()
            })
        )
    }
}
