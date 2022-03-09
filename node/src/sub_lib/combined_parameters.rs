// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::accountant::{PaymentThresholds, ScanIntervals};
use crate::sub_lib::combined_parameters::CombinedParamsDataTypes::{I64, U64};
use crate::sub_lib::neighborhood::RatePack;
use masq_lib::constants::COMBINED_PARAMETERS_DELIMITER;
use masq_lib::utils::ExpectValue;
use paste::paste;
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::time::Duration;

macro_rules! initiate_struct{
    ($struct_type: ident, $hash_map: expr, $($field:literal),+) =>{
        paste!{
            $struct_type{
                $([<$field>]: CombinedParamsValueRetriever::get_value(
                        $hash_map,
                        $field
                )),+
            }
        }
    };
    ($struct_type: ident, $hash_map: expr,  $value_convertor: expr, $($field:literal),+) =>{
        paste!{
            $struct_type{
                $([<$field>]: $value_convertor(CombinedParamsValueRetriever::get_value(
                        $hash_map,
                        $field
                ))),+
            }
        }
    }
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
    PaymentThresholds(Option<PaymentThresholds>),
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
        let zipped = pieces.into_iter().zip(expected_collection.iter());
        Ok(zipped
            .map(|(piece, (param_name, data_type))| {
                (
                    param_name.to_string(),
                    CombinedParamsValueRetriever::parse(piece, data_type).expectv("numeric value"),
                )
            })
            .collect())
    }

    fn initiate_objects(
        &self,
        parsed_values: HashMap<String, CombinedParamsValueRetriever>,
    ) -> Self {
        match self {
            Self::RatePack(None) => Self::RatePack(Some(initiate_struct!(
                RatePack,
                &parsed_values,
                "routing_byte_rate",
                "routing_service_rate",
                "exit_byte_rate",
                "exit_service_rate"
            ))),
            Self::PaymentThresholds(None) => Self::PaymentThresholds(Some(initiate_struct!(
                PaymentThresholds,
                &parsed_values,
                "maturity_threshold_sec",
                "payment_grace_period_sec",
                "permanent_debt_allowed_gwei",
                "debt_threshold_gwei",
                "threshold_interval_sec",
                "unban_below_gwei"
            ))),
            Self::ScanIntervals(None) => Self::ScanIntervals(Some(initiate_struct!(
                ScanIntervals,
                &parsed_values,
                Duration::from_secs,
                "pending_payable_scan_interval",
                "payable_scan_interval",
                "receivable_scan_interval"
            ))),
            _ => panic!(
                "should be called only on uninitialized object, not: {:?}",
                self
            ),
        }
    }
}

impl From<&CombinedParams> for &[(&str, CombinedParamsDataTypes)] {
    fn from(params: &CombinedParams) -> &'static [(&'static str, CombinedParamsDataTypes)] {
        match params {
            CombinedParams::RatePack(None) => &[
                ("routing_byte_rate", U64),
                ("routing_service_rate", U64),
                ("exit_byte_rate", U64),
                ("exit_service_rate", U64),
            ],
            CombinedParams::PaymentThresholds(None) => &[
                ("debt_threshold_gwei", I64),
                ("maturity_threshold_sec", I64),
                ("payment_grace_period_sec", I64),
                ("permanent_debt_allowed_gwei", I64),
                ("threshold_interval_sec", I64),
                ("unban_below_gwei", I64),
            ],
            CombinedParams::ScanIntervals(None) => &[
                ("pending_payable_scan_interval", U64),
                ("payable_scan_interval", U64),
                ("receivable_scan_interval", U64),
            ],
            _ => panic!(
                "should be called only on uninitialized object, not: {:?}",
                params
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
        match CombinedParams::ScanIntervals(None).parse(parameters) {
            Ok(CombinedParams::ScanIntervals(Some(scan_intervals))) => Ok(scan_intervals),
            Err(e) => Err(e),
            _ => unreachable(),
        }
    }
}

impl Display for PaymentThresholds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}|{}",
            self.debt_threshold_gwei,
            self.maturity_threshold_sec,
            self.payment_grace_period_sec,
            self.permanent_debt_allowed_gwei,
            self.threshold_interval_sec,
            self.unban_below_gwei
        )
    }
}

impl TryFrom<&str> for PaymentThresholds {
    type Error = String;

    fn try_from(parameters: &str) -> Result<Self, String> {
        match CombinedParams::PaymentThresholds(None).parse(parameters) {
            Ok(CombinedParams::PaymentThresholds(Some(payment_thresholds))) => {
                Ok(payment_thresholds)
            }
            Err(e) => Err(e),
            _ => unreachable(),
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
        match CombinedParams::RatePack(None).parse(parameters) {
            Ok(CombinedParams::RatePack(Some(rate_pack))) => Ok(rate_pack),
            Err(e) => Err(e),
            _ => unreachable(),
        }
    }
}

fn unreachable() -> ! {
    unreachable!("technically shouldn't be possible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::accountant::{DEFAULT_PAYMENT_THRESHOLDS, DEFAULT_SCAN_INTERVALS};
    use crate::sub_lib::combined_parameters::CombinedParamsDataTypes::U128;
    use crate::sub_lib::neighborhood::DEFAULT_RATE_PACK;
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
    fn combined_params_can_be_converted_to_collection_of_typed_parametres() {
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
        let payment_thresholds: &[(&str, CombinedParamsDataTypes)] =
            (&CombinedParams::PaymentThresholds(None)).into();
        assert_eq!(
            payment_thresholds,
            &[
                ("debt_threshold_gwei", I64),
                ("maturity_threshold_sec", I64),
                ("payment_grace_period_sec", I64),
                ("permanent_debt_allowed_gwei", I64),
                ("threshold_interval_sec", I64),
                ("unban_below_gwei", I64)
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
                (&CombinedParams::PaymentThresholds(Some(*DEFAULT_PAYMENT_THRESHOLDS))).into();
        })
        .unwrap_err();
        let panic_2_msg = panic_2.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_2_msg,
            &format!(
                "should be called only on uninitialized object, not: PaymentThresholds(Some({:?}))",
                *DEFAULT_PAYMENT_THRESHOLDS
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
            (&CombinedParams::PaymentThresholds(Some(*DEFAULT_PAYMENT_THRESHOLDS)))
                .initiate_objects(HashMap::new());
        })
        .unwrap_err();
        let panic_2_msg = panic_2.downcast_ref::<String>().unwrap();

        assert_eq!(
            panic_2_msg,
            &format!(
                "should be called only on uninitialized object, not: PaymentThresholds(Some({:?}))",
                *DEFAULT_PAYMENT_THRESHOLDS
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
    fn payment_thresholds_from_combined_params() {
        let payment_thresholds_str = "5000010|120|100|20000|10020|18000";

        let result = PaymentThresholds::try_from(payment_thresholds_str).unwrap();

        assert_eq!(
            result,
            PaymentThresholds {
                debt_threshold_gwei: 5000010,
                maturity_threshold_sec: 120,
                payment_grace_period_sec: 100,
                permanent_debt_allowed_gwei: 20000,
                threshold_interval_sec: 10020,
                unban_below_gwei: 18000
            }
        )
    }

    #[test]
    fn payment_thresholds_to_combined_params() {
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 30020,
            debt_threshold_gwei: 5000010,
            payment_grace_period_sec: 123,
            maturity_threshold_sec: 120,
            permanent_debt_allowed_gwei: 20000,
            unban_below_gwei: 111,
        };

        let result = payment_thresholds.to_string();

        assert_eq!(result, "5000010|120|123|20000|30020|111".to_string());
    }
}
