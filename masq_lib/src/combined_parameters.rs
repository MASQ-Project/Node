// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::combined_parameters::CombinedParamsDataTypes::{I64, U64};
use crate::constants::COMBINED_PARAMETERS_DELIMITER;
use crate::utils::ExpectValue;
use serde_derive::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::time::Duration;

//please, alphabetical order
#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct PaymentCurves {
    pub balance_decreases_for_sec: i64,
    pub balance_to_decrease_from_gwei: i64,
    pub payment_grace_before_ban_sec: i64,
    pub payment_suggested_after_sec: i64,
    pub permanent_debt_allowed_gwei: i64,
    pub unban_when_balance_below_gwei: i64,
}

//this code is used in tests in Accountant
impl PaymentCurves {
    pub fn sugg_and_grace(&self, now: i64) -> i64 {
        now - self.payment_suggested_after_sec - self.payment_grace_before_ban_sec
    }

    pub fn sugg_thru_decreasing(&self, now: i64) -> i64 {
        self.sugg_and_grace(now) - self.balance_decreases_for_sec
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct RatePack {
    pub routing_byte_rate: u64,
    pub routing_service_rate: u64,
    pub exit_byte_rate: u64,
    pub exit_service_rate: u64,
}

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct ScanIntervals {
    pub pending_payable_scan_interval: Duration,
    pub payable_scan_interval: Duration,
    pub receivable_scan_interval: Duration,
}

#[derive(PartialEq, Debug)]
pub enum CombinedParamsDataTypes {
    U64,
    I64,
    U128,
}

#[derive(PartialEq, Debug)]
pub enum CombinedParamsValueRetriever {
    U64(u64),
    I64(i64),
    U128(u128),
}

impl CombinedParamsValueRetriever {
    fn parse(str_value: &str, data_type: &CombinedParamsDataTypes) -> Result<Self, String> {
        fn parse<T>(str_value: &str) -> Result<T, String>
        where
            T: std::str::FromStr,
            <T as std::str::FromStr>::Err: ToString,
        {
            str_value.parse::<T>().map_err(|e| e.to_string())
        }
        match data_type {
            CombinedParamsDataTypes::U64 => {
                Ok(CombinedParamsValueRetriever::U64(parse(str_value)?))
            }
            CombinedParamsDataTypes::I64 => {
                Ok(CombinedParamsValueRetriever::I64(parse(str_value)?))
            }
            CombinedParamsDataTypes::U128 => {
                Ok(CombinedParamsValueRetriever::U128(parse(str_value)?))
            }
        }
    }

    pub fn get_value<T: 'static + Copy>(
        map: &HashMap<String, CombinedParamsValueRetriever>,
        parameter_name: &str,
    ) -> T {
        let dynamic: &dyn Any = match map.get(parameter_name).expectv(parameter_name) {
            CombinedParamsValueRetriever::U64(num) => num,
            CombinedParamsValueRetriever::I64(num) => num,
            CombinedParamsValueRetriever::U128(num) => num,
        };
        *dynamic
            .downcast_ref::<T>()
            .unwrap_or_else(|| panic!("expected Some() of {}", std::any::type_name::<T>()))
    }
}

#[derive(Debug)]
enum CombinedParams {
    RatePack(Option<RatePack>),
    PaymentCurves(Option<PaymentCurves>),
    ScanIntervals(Option<ScanIntervals>),
}

impl CombinedParams {
    pub fn parse(&self, parameters_str: &str) -> Result<Self, String> {
        let parsed_values = Self::parse_combined_params(
            parameters_str,
            COMBINED_PARAMETERS_DELIMITER,
            self.into(),
        )?;
        Ok(self.initiate_objects(parsed_values))
    }

    fn parse_combined_params(
        input: &str,
        delimiter: char,
        expected_collection: &[(&str, CombinedParamsDataTypes)],
    ) -> Result<HashMap<String, CombinedParamsValueRetriever>, String> {
        let check = |count: usize| {
            if count != expected_collection.len() {
                return Err(format!(
                    "Wrong number of values: expected {} but {} supplied{}",
                    expected_collection.len(),
                    count,
                    if count == 1 {
                        format!(". Did you use the correct delimiter '{}'?", delimiter)
                    } else {
                        "".to_string()
                    }
                ));
            }
            Ok(())
        };
        let pieces: Vec<&str> = input.split(delimiter).collect();
        check(pieces.len())?;
        let zipped = pieces.into_iter().zip(expected_collection.into_iter());
        Ok(zipped
            .map(|(piece, (param_name, data_type))| {
                (
                    param_name.to_string(),
                    CombinedParamsValueRetriever::parse(piece, &data_type).expectv("numeric value"),
                )
            })
            .collect())
    }

    fn initiate_objects(
        &self,
        parsed_values: HashMap<String, CombinedParamsValueRetriever>,
    ) -> Self {
        match self {
            Self::RatePack(None) => Self::RatePack(Some(RatePack {
                routing_byte_rate: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "routing_byte_rate",
                ),
                routing_service_rate: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "routing_service_rate",
                ),
                exit_byte_rate: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "exit_byte_rate",
                ),
                exit_service_rate: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "exit_service_rate",
                ),
            })),
            Self::PaymentCurves(None) => Self::PaymentCurves(Some(PaymentCurves {
                payment_suggested_after_sec: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "payment_suggested_after_sec",
                ),
                payment_grace_before_ban_sec: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "payment_grace_before_ban_sec",
                ),
                permanent_debt_allowed_gwei: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "permanent_debt_allowed_gwei",
                ),
                balance_to_decrease_from_gwei: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "balance_to_decrease_from_gwei",
                ),
                balance_decreases_for_sec: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "balance_decreases_for_sec",
                ),
                unban_when_balance_below_gwei: CombinedParamsValueRetriever::get_value(
                    &parsed_values,
                    "unban_when_balance_below_gwei",
                ),
            })),
            Self::ScanIntervals(None) => Self::ScanIntervals(Some(ScanIntervals {
                pending_payable_scan_interval: Duration::from_secs(
                    CombinedParamsValueRetriever::get_value(
                        &parsed_values,
                        "pending_payable_scan_interval",
                    ),
                ),
                payable_scan_interval: Duration::from_secs(
                    CombinedParamsValueRetriever::get_value(
                        &parsed_values,
                        "payable_scan_interval",
                    ),
                ),
                receivable_scan_interval: Duration::from_secs(
                    CombinedParamsValueRetriever::get_value(
                        &parsed_values,
                        "receivable_scan_interval",
                    ),
                ),
            })),
            _ => panic!(
                "should be called only on uninitialized object, not: {:?}",
                self
            ),
        }
    }
}

impl Into<&[(&str, CombinedParamsDataTypes)]> for &CombinedParams {
    fn into(self) -> &'static [(&'static str, CombinedParamsDataTypes)] {
        match self {
            CombinedParams::RatePack(None) => &[
                ("routing_byte_rate", U64),
                ("routing_service_rate", U64),
                ("exit_byte_rate", U64),
                ("exit_service_rate", U64),
            ],
            CombinedParams::PaymentCurves(None) => &[
                ("balance_decreases_for_sec", I64),
                ("balance_to_decrease_from_gwei", I64),
                ("payment_grace_before_ban_sec", I64),
                ("payment_suggested_after_sec", I64),
                ("permanent_debt_allowed_gwei", I64),
                ("unban_when_balance_below_gwei", I64),
            ],
            CombinedParams::ScanIntervals(None) => &[
                ("pending_payable_scan_interval", U64),
                ("payable_scan_interval", U64),
                ("receivable_scan_interval", U64),
            ],
            _ => panic!(
                "should be called only on uninitialized object, not: {:?}",
                self
            ),
        }
    }
}

impl Display for ScanIntervals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}",
            self.pending_payable_scan_interval.as_secs(),
            self.payable_scan_interval.as_secs(),
            self.receivable_scan_interval.as_secs()
        )
    }
}

impl TryFrom<&str> for ScanIntervals {
    type Error = String;

    fn try_from(parameters: &str) -> Result<Self, String> {
        if let CombinedParams::ScanIntervals(Some(scan_intervals)) =
            CombinedParams::ScanIntervals(None).parse(parameters)?
        {
            Ok(scan_intervals)
        } else {
            unreachable!("technically should never happen")
        }
    }
}

impl Display for PaymentCurves {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}|{}",
            self.balance_decreases_for_sec,
            self.balance_to_decrease_from_gwei,
            self.payment_grace_before_ban_sec,
            self.payment_suggested_after_sec,
            self.permanent_debt_allowed_gwei,
            self.unban_when_balance_below_gwei
        )
    }
}

impl TryFrom<&str> for PaymentCurves {
    type Error = String;

    fn try_from(parameters: &str) -> Result<Self, String> {
        if let CombinedParams::PaymentCurves(Some(payment_curves)) =
            CombinedParams::PaymentCurves(None).parse(parameters)?
        {
            Ok(payment_curves)
        } else {
            unreachable!("technically should never happen")
        }
    }
}

impl Display for RatePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}",
            self.routing_byte_rate,
            self.routing_service_rate,
            self.exit_byte_rate,
            self.exit_service_rate
        )
    }
}

impl TryFrom<&str> for RatePack {
    type Error = String;

    fn try_from(parameters: &str) -> Result<Self, String> {
        if let CombinedParams::RatePack(Some(rate_pack)) =
            CombinedParams::RatePack(None).parse(parameters)?
        {
            Ok(rate_pack)
        } else {
            unreachable!("technically should never happen")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combined_parameters::CombinedParamsDataTypes::U128;
    use crate::constants::{DEFAULT_PAYMENT_CURVES, DEFAULT_RATE_PACK, DEFAULT_SCAN_INTERVALS};
    use std::panic::catch_unwind;

    #[test]
    fn parse_combined_params_with_delimiters_happy_path() {
        let input = "555|123|8989";

        let result = CombinedParams::parse_combined_params(
            input,
            '|',
            &[
                ("first_parameter", U64),
                ("second_parameter", U128),
                ("third_parameter", U64),
            ],
        )
        .unwrap();

        assert_eq!(
            CombinedParamsValueRetriever::get_value::<u64>(&result, "first_parameter"),
            555
        );
        assert_eq!(
            CombinedParamsValueRetriever::get_value::<u128>(&result, "second_parameter"),
            123
        );
        assert_eq!(
            CombinedParamsValueRetriever::get_value::<u64>(&result, "third_parameter"),
            8989
        );
    }

    #[test]
    fn parse_combined_params_with_delimiters_wrong_number_of_parameters() {
        let input = "555|123|8989|11|557";

        let result: Result<HashMap<String, CombinedParamsValueRetriever>, String> =
            CombinedParams::parse_combined_params(
                input,
                '|',
                &[
                    ("first_parameter", U64),
                    ("second_parameter", U64),
                    ("third_parameter", U64),
                    ("fourth_parameter", U64),
                ],
            );

        assert_eq!(
            result,
            Err("Wrong number of values: expected 4 but 5 supplied".to_string())
        )
    }

    #[test]
    fn parse_combined_params_with_delimiters_not_separable() {
        let input = "555|123|8989|11|557";

        let result: Result<HashMap<String, CombinedParamsValueRetriever>, String> =
            CombinedParams::parse_combined_params(
                input,
                '@',
                &[
                    ("first_parameter", U64),
                    ("second_parameter", U64),
                    ("third_parameter", U64),
                    ("fourth_parameter", U64),
                ],
            );

        assert_eq!(
            result,
            Err("Wrong number of values: expected 4 but 1 supplied. Did you use the correct delimiter '@'?".to_string())
        )
    }

    #[test]
    fn combined_params_can_be_converted_to_type_arrays() {
        let rate_pack: &[(&str, CombinedParamsDataTypes)] =
            (&CombinedParams::RatePack(None)).into();
        assert_eq!(
            rate_pack,
            &[
                ("routing_byte_rate", U64),
                ("routing_service_rate", U64),
                ("exit_byte_rate", U64),
                ("exit_service_rate", U64),
            ]
        );
        let scan_interval: &[(&str, CombinedParamsDataTypes)] =
            (&CombinedParams::ScanIntervals(None)).into();
        assert_eq!(
            scan_interval,
            &[
                ("pending_payable_scan_interval", U64),
                ("payable_scan_interval", U64),
                ("receivable_scan_interval", U64),
            ]
        );
        let payment_curves: &[(&str, CombinedParamsDataTypes)] =
            (&CombinedParams::PaymentCurves(None)).into();
        assert_eq!(
            payment_curves,
            &[
                ("balance_decreases_for_sec", I64),
                ("balance_to_decrease_from_gwei", I64),
                ("payment_grace_before_ban_sec", I64),
                ("payment_suggested_after_sec", I64),
                ("permanent_debt_allowed_gwei", I64),
                ("unban_when_balance_below_gwei", I64)
            ]
        );
    }

    #[test]
    fn array_type_conversion_should_use_uninitialized_instances_only() {
        let panic_1 = catch_unwind(|| {
            let _: &[(&str, CombinedParamsDataTypes)] =
                (&CombinedParams::RatePack(Some(DEFAULT_RATE_PACK))).into();
        })
        .unwrap_err();
        let panic_1_msg = panic_1.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_1_msg,
            &format!(
                "should be called only on uninitialized object, not: RatePack(Some({:?}))",
                DEFAULT_RATE_PACK
            )
        );

        let panic_2 = catch_unwind(|| {
            let _: &[(&str, CombinedParamsDataTypes)] =
                (&CombinedParams::PaymentCurves(Some(*DEFAULT_PAYMENT_CURVES))).into();
        })
        .unwrap_err();
        let panic_2_msg = panic_2.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_2_msg,
            &format!(
                "should be called only on uninitialized object, not: PaymentCurves(Some({:?}))",
                *DEFAULT_PAYMENT_CURVES
            )
        );

        let panic_3 = catch_unwind(|| {
            let _: &[(&str, CombinedParamsDataTypes)] =
                (&CombinedParams::ScanIntervals(Some(*DEFAULT_SCAN_INTERVALS))).into();
        })
        .unwrap_err();
        let panic_3_msg = panic_3.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_3_msg,
            &format!(
                "should be called only on uninitialized object, not: ScanIntervals(Some({:?}))",
                *DEFAULT_SCAN_INTERVALS
            )
        );
    }

    #[test]
    fn initiate_objects_should_use_uninitialized_instances_only() {
        let panic_1 = catch_unwind(|| {
            (&CombinedParams::RatePack(Some(DEFAULT_RATE_PACK))).initiate_objects(HashMap::new());
        })
        .unwrap_err();
        let panic_1_msg = panic_1.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_1_msg,
            &format!(
                "should be called only on uninitialized object, not: RatePack(Some({:?}))",
                DEFAULT_RATE_PACK
            )
        );

        let panic_2 = catch_unwind(|| {
            (&CombinedParams::PaymentCurves(Some(*DEFAULT_PAYMENT_CURVES)))
                .initiate_objects(HashMap::new());
        })
        .unwrap_err();
        let panic_2_msg = panic_2.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_2_msg,
            &format!(
                "should be called only on uninitialized object, not: PaymentCurves(Some({:?}))",
                *DEFAULT_PAYMENT_CURVES
            )
        );

        let panic_3 = catch_unwind(|| {
            (&CombinedParams::ScanIntervals(Some(*DEFAULT_SCAN_INTERVALS)))
                .initiate_objects(HashMap::new());
        })
        .unwrap_err();
        let panic_3_msg = panic_3.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_3_msg,
            &format!(
                "should be called only on uninitialized object, not: ScanIntervals(Some({:?}))",
                *DEFAULT_SCAN_INTERVALS
            )
        );
    }

    #[test]
    fn rate_pack_from_combined_params() {
        let rate_pack_str = "8|9|11|13";

        let result = RatePack::try_from(rate_pack_str).unwrap();

        assert_eq!(
            result,
            RatePack {
                routing_byte_rate: 8,
                routing_service_rate: 9,
                exit_byte_rate: 11,
                exit_service_rate: 13
            }
        )
    }

    #[test]
    fn rate_pack_to_combined_params() {
        let scan_intervals = RatePack {
            routing_byte_rate: 18,
            routing_service_rate: 19,
            exit_byte_rate: 21,
            exit_service_rate: 22,
        };

        let result = scan_intervals.to_string();

        assert_eq!(result, "18|19|21|22".to_string());
    }

    #[test]
    fn scan_intervals_from_combined_params() {
        let scan_intervals_str = "110|115|113";

        let result = ScanIntervals::try_from(scan_intervals_str).unwrap();

        assert_eq!(
            result,
            ScanIntervals {
                pending_payable_scan_interval: Duration::from_secs(110),
                payable_scan_interval: Duration::from_secs(115),
                receivable_scan_interval: Duration::from_secs(113)
            }
        )
    }

    #[test]
    fn scan_intervals_to_combined_params() {
        let scan_intervals = ScanIntervals {
            pending_payable_scan_interval: Duration::from_secs(60),
            payable_scan_interval: Duration::from_secs(70),
            receivable_scan_interval: Duration::from_secs(100),
        };

        let result = scan_intervals.to_string();

        assert_eq!(result, "60|70|100".to_string());
    }

    #[test]
    fn payment_curves_from_combined_params() {
        let payment_curves_str = "10020|5000010|100|120|20000|18000";

        let result = PaymentCurves::try_from(payment_curves_str).unwrap();

        assert_eq!(
            result,
            PaymentCurves {
                balance_decreases_for_sec: 10020,
                balance_to_decrease_from_gwei: 5000010,
                payment_grace_before_ban_sec: 100,
                payment_suggested_after_sec: 120,
                permanent_debt_allowed_gwei: 20000,
                unban_when_balance_below_gwei: 18000
            }
        )
    }

    #[test]
    fn payment_curves_to_combined_params() {
        let payment_curves = PaymentCurves {
            balance_decreases_for_sec: 30020,
            balance_to_decrease_from_gwei: 5000010,
            payment_grace_before_ban_sec: 123,
            payment_suggested_after_sec: 120,
            permanent_debt_allowed_gwei: 20000,
            unban_when_balance_below_gwei: 111,
        };

        let result = payment_curves.to_string();

        assert_eq!(result, "30020|5000010|123|120|20000|111".to_string());
    }
}
