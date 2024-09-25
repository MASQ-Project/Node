// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use num::CheckedAdd;
use num::CheckedSub;
use num::{CheckedDiv, CheckedMul, Integer};
use std::any::type_name;
use std::fmt::Debug;
use std::ops::Rem;
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

// This is a wider type that allows to specify cumulative percents of more than only 100.
// The expected use of this would look like requesting percents meaning possibly multiples of 100%,
// roughly, of a certain base number. Similarly to the PurePercentage type, also signed numbers
// would be accepted.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoosePercentage {
    multiples_of_100_percent: u32,
    degrees_from_remainder: PurePercentage,
}

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

impl LoosePercentage {
    pub fn new(percents: u32) -> Self {
        let multiples_of_100_percent = percents / 100;
        let remainder = (percents % 100) as u8;
        let degrees_from_remainder =
            PurePercentage::try_from(remainder).expect("should never happen");
        Self {
            multiples_of_100_percent,
            degrees_from_remainder,
        }
    }

    // If this overflows you probably want to precede the operation by converting your base number
    // to a larger integer type
    pub fn of<N>(&self, num: N) -> Result<N, BaseTypeOverflow>
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        N: TryFrom<u32>,
        <N as TryFrom<u32>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let multiples = match N::try_from(self.multiples_of_100_percent) {
            Ok(num) => num,
            Err(_) => return Err(BaseTypeOverflow {}),
        };

        let by_wholes = match num.checked_mul(&multiples) {
            Some(num) => num,
            None => return Err(BaseTypeOverflow {}),
        };

        let by_remainder = self.degrees_from_remainder.of(num);

        match by_wholes.checked_add(&by_remainder) {
            Some(res) => Ok(res),
            None => Err(BaseTypeOverflow {}),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BaseTypeOverflow {}

impl TryFrom<u8> for PurePercentage {
    type Error = String;

    fn try_from(degree: u8) -> Result<Self, Self::Error> {
        match degree {
            0..=100 => Ok(Self { degree }),
            x => Err(format!(
                "Accepts only range from 0 to 100 but {} was supplied",
                x
            )),
        }
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
        if let Some(zero) = self.return_zero(num) {
            return zero;
        }

        let product_before_final_div = match N::try_from(self.degree as i8)
            .expect("Each type has 100")
            .checked_mul(&num)
        {
            Some(num) => num,
            None => return self.handle_upper_overflow(num),
        };

        Self::div_by_100_and_round(product_before_final_div)
    }

    fn return_zero<N>(&self, num: N) -> Option<N>
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
    {
        let zero = N::try_from(0).expect("Each type has 0");
        if num == zero || N::try_from(self.degree as i8).expect("Each type has 100") == zero {
            Some(zero)
        } else {
            None
        }
    }

    fn div_by_100_and_round<N>(num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
    {
        let divisor = N::try_from(100).expect("Each type has 100");
        let rounded_rule = Self::should_be_rounded_as(num, divisor);
        let significant_digits_only = num.checked_div(&divisor).expect("Division failed");

        macro_rules! adjust_num {
            ($significant_digits: expr, $method_add_or_sub: ident, $msg_in_expect: literal) => {
                $significant_digits
                    .$method_add_or_sub(&N::try_from(1).expect("Each type has 1"))
                    .expect($msg_in_expect)
            };
        }

        match rounded_rule {
            RoundingRule::ToBiggerPositive => {
                adjust_num!(significant_digits_only, checked_add, "Addition failed")
            }
            RoundingRule::ToBiggerNegative => {
                adjust_num!(significant_digits_only, checked_sub, "Subtraction failed")
            }
            RoundingRule::ToSmallerNegative | RoundingRule::ToSmallerPositive => {
                significant_digits_only
            }
        }
    }

    fn should_be_rounded_as<N>(num: N, divisor: N) -> RoundingRule
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
    {
        let least_significant_digits: N = num % divisor;
        let is_signed = num < N::try_from(0).expect("Each type has 0");
        let divider = N::try_from(50).expect("Each type has 50");
        let abs_of_significant_digits =
            Self::abs_of_least_significant_digits(least_significant_digits, is_signed);
        let is_minor: bool = if abs_of_significant_digits == divider {
            false
        } else if abs_of_significant_digits > divider {
            false
        } else {
            true
        };
        match (is_signed, is_minor) {
            (false, true) => RoundingRule::ToSmallerPositive,
            (false, false) => RoundingRule::ToBiggerPositive,
            (true, true) => RoundingRule::ToSmallerNegative,
            (true, false) => RoundingRule::ToBiggerNegative,
        }
    }

    fn abs_of_least_significant_digits<N>(least_significant_digits: N, is_signed: bool) -> N
    where
        N: TryFrom<i8> + CheckedMul,
        <N as TryFrom<i8>>::Error: Debug,
    {
        if is_signed {
            N::try_from(-1)
                .expect("Negative 1 must be possible for a confirmed signed integer")
                .checked_mul(&least_significant_digits)
                .expect("Must be possible in these low values")
        } else {
            least_significant_digits
        }
    }

    pub fn add_percent_to<N>(&self, num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let to_add = self.of(num);
        num.checked_add(&to_add).unwrap_or_else(|| {
            panic!(
                "Overflowed during addition of {} percent, that is {:?}, to {:?} of type {}.",
                self.degree,
                to_add,
                num,
                type_name::<N>()
            )
        })
    }

    pub fn subtract_percent_from<N>(&self, num: N) -> N
    where
        N: PercentageInteger + CheckedSub,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let to_subtract = self.of(num);
        num.checked_sub(&to_subtract)
            .expect("should never happen by its principle")
    }

    fn handle_upper_overflow<N>(&self, num: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let hundred = N::try_from(100).expect("Each type has 100");
        let modulo = num % hundred;
        let percent = N::try_from(self.degree as i8).expect("Each type has 100");

        let without_treated_remainder = (num / hundred) * percent;
        let final_remainder_treatment = Self::treat_remainder(modulo, percent);
        without_treated_remainder + final_remainder_treatment
    }

    fn treat_remainder<N>(modulo: N, percent: N) -> N
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        let extended_remainder_prepared_for_rounding = i16::try_from(modulo)
            .unwrap_or_else(|_| panic!("u16 from -100..=100 failed at modulo {:?}", modulo))
            * i16::try_from(percent).expect("i16 from within 0..=100 failed at multiplier");
        let rounded = Self::div_by_100_and_round(extended_remainder_prepared_for_rounding);
        N::try_from(rounded as i8).expect("Each type has 0 up to 100")
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RoundingRule {
    ToBiggerPositive,
    ToBiggerNegative,
    ToSmallerPositive,
    ToSmallerNegative,
}

#[cfg(test)]
mod tests {
    use crate::percentage::{
        BaseTypeOverflow, LoosePercentage, PercentageInteger, PurePercentage, RoundingRule,
    };
    use std::fmt::Debug;

    #[test]
    fn percentage_is_implemented_for_all_rust_integers() {
        let subject = PurePercentage::try_from(50).unwrap();

        assert_integer_compatibility(&subject, u8::MAX, 128);
        assert_integer_compatibility(&subject, u16::MAX, 32768);
        assert_integer_compatibility(&subject, u32::MAX, 2147483648);
        assert_integer_compatibility(&subject, u64::MAX, 9223372036854775808);
        assert_integer_compatibility(&subject, u128::MAX, 170141183460469231731687303715884105728);
        assert_integer_compatibility(&subject, i8::MIN, -64);
        assert_integer_compatibility(&subject, i16::MIN, -16384);
        assert_integer_compatibility(&subject, i32::MIN, -1073741824);
        assert_integer_compatibility(&subject, i64::MIN, -4611686018427387904);
        assert_integer_compatibility(&subject, i128::MIN, -85070591730234615865843651857942052864);
    }

    fn assert_integer_compatibility<N>(subject: &PurePercentage, num: N, expected: N)
    where
        N: PercentageInteger,
        <N as TryFrom<i8>>::Error: Debug,
        i16: TryFrom<N>,
        <i16 as TryFrom<N>>::Error: Debug,
    {
        assert_eq!(subject.of(num), expected);
        let half = num / N::try_from(2).unwrap();
        let one = N::try_from(1).unwrap();
        assert!((half - one) <= half && half <= (half + one))
    }

    #[test]
    fn zeros_for_pure_percentage() {
        assert_eq!(PurePercentage::try_from(45).unwrap().of(0), 0);
        assert_eq!(PurePercentage::try_from(0).unwrap().of(33), 0)
    }

    #[test]
    fn pure_percentage_end_to_end_test_for_unsigned() {
        let expected_values = (0..=100).collect::<Vec<i8>>();

        test_end_to_end(100, expected_values, |percent, base| {
            PurePercentage::try_from(percent).unwrap().of(base)
        })
    }

    #[test]
    fn pure_percentage_end_to_end_test_for_signed() {
        let expected_values = (-100..=0).rev().collect::<Vec<i8>>();

        test_end_to_end(-100, expected_values, |percent, base| {
            PurePercentage::try_from(percent).unwrap().of(base)
        })
    }

    fn test_end_to_end<F>(
        base: i8,
        expected_values: Vec<i8>,
        create_percentage_and_apply_it_on_number: F,
    ) where
        F: Fn(u8, i8) -> i8,
    {
        let range = 0_u8..=100;

        let round_returned_range = range
            .into_iter()
            .map(|percent| create_percentage_and_apply_it_on_number(percent, base))
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
                        "Accepts only range from 0 to 100 but {} was supplied",
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
                "For {} percent and number {} the expected result was {} but we got {}",
                case.requested_percent, case.examined_base_number, case.expected_result, result
            )
        })
    }

    #[test]
    fn should_be_rounded_as_works_for_last_but_one_digit() {
        [
            (
                49,
                RoundingRule::ToSmallerPositive,
                RoundingRule::ToSmallerNegative,
            ),
            (
                50,
                RoundingRule::ToBiggerPositive,
                RoundingRule::ToBiggerNegative,
            ),
            (
                51,
                RoundingRule::ToBiggerPositive,
                RoundingRule::ToBiggerNegative,
            ),
            (
                5,
                RoundingRule::ToSmallerPositive,
                RoundingRule::ToSmallerNegative,
            ),
            (
                100,
                RoundingRule::ToSmallerPositive,
                RoundingRule::ToSmallerNegative,
            ),
            (
                787879,
                RoundingRule::ToBiggerPositive,
                RoundingRule::ToBiggerNegative,
            ),
            (
                898784545,
                RoundingRule::ToSmallerPositive,
                RoundingRule::ToSmallerNegative,
            ),
        ]
        .into_iter()
        .for_each(
            |(num, expected_result_for_unsigned_base, expected_result_for_signed_base)| {
                let result = PurePercentage::should_be_rounded_as(num, 100);
                assert_eq!(
                result,
                expected_result_for_unsigned_base,
                "Unsigned number {} was identified for rounding as {:?} but it should've been {:?}",
                num,
                result,
                expected_result_for_unsigned_base
            );
                let signed = num as i64 * -1;
                let result = PurePercentage::should_be_rounded_as(signed, 100);
                assert_eq!(
                result,
                expected_result_for_signed_base,
                "Signed number {} was identified for rounding as {:?} but it should've been {:?}",
                signed,
                result,
                expected_result_for_signed_base
            )
            },
        )
    }

    #[test]
    fn add_percent_to_works() {
        let subject = PurePercentage::try_from(13).unwrap();

        let unsigned = subject.add_percent_to(100);
        let signed = subject.add_percent_to(-100);

        assert_eq!(unsigned, 113);
        assert_eq!(signed, -113)
    }

    #[test]
    #[should_panic(expected = "Overflowed during addition of 1 percent, that is \
    184467440737095516, to 18446744073709551615 of type u64.")]
    fn add_percent_to_hits_overflow() {
        let _ = PurePercentage::try_from(1)
            .unwrap()
            .add_percent_to(u64::MAX);
    }

    #[test]
    fn subtract_percent_from_works() {
        let subject = PurePercentage::try_from(55).unwrap();

        let unsigned = subject.subtract_percent_from(100);
        let signed = subject.subtract_percent_from(-100);

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
        //Note: Interestingly, this isn't a threat on the negative numbers, even the extremes.
    }

    #[test]
    fn zeroes_for_loose_percentage() {
        assert_eq!(LoosePercentage::new(45).of(0).unwrap(), 0);
        assert_eq!(LoosePercentage::new(0).of(33).unwrap(), 0)
    }

    #[test]
    fn loose_percentage_end_to_end_test_for_standard_values_unsigned() {
        let expected_values = (0..=100).collect::<Vec<i8>>();

        test_end_to_end(100, expected_values, |percent, base| {
            LoosePercentage::new(percent as u32).of(base).unwrap()
        })
    }

    #[test]
    fn loose_percentage_end_to_end_test_for_standard_values_signed() {
        let expected_values = (-100..=0).rev().collect::<Vec<i8>>();

        test_end_to_end(-100, expected_values, |percent, base| {
            LoosePercentage::new(percent as u32).of(base).unwrap()
        })
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
        let percents = ((u8::MAX as u32 + 1) * 100);
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(1);

        assert_eq!(result, Err(BaseTypeOverflow {}))
    }

    #[test]
    fn loose_percentage_multiplying_input_number_hits_limit() {
        let percents = 200;
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(u8::MAX);

        assert_eq!(result, Err(BaseTypeOverflow {}))
    }

    #[test]
    fn loose_percentage_adding_portion_from_remainder_hits_limit() {
        let percents = 101;
        let subject = LoosePercentage::new(percents);

        let result: Result<u8, BaseTypeOverflow> = subject.of(u8::MAX);

        assert_eq!(result, Err(BaseTypeOverflow {}))
    }
}
