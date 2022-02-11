// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::constants::COUPLED_PARAMETERS_DELIMITER;
use crate::coupled_parameters::CoupledParamsDataTypes::{I64, U64};
use crate::utils::ExpectValue;
use serde_derive::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt;
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

impl fmt::Display for RatePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}+{}b route {}+{}b exit",
            self.routing_service_rate,
            self.routing_byte_rate,
            self.exit_service_rate,
            self.exit_byte_rate
        )
    }
}

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub struct ScanIntervals {
    pub pending_payable_scan_interval: Duration,
    pub payable_scan_interval: Duration,
    pub receivable_scan_interval: Duration,
}

#[derive(PartialEq, Debug)]
pub enum CoupledParamsDataTypes {
    U64,
    I64,
    U128,
}

#[derive(PartialEq, Debug)]
pub enum CoupledParamsValueRetriever {
    U64(u64),
    I64(i64),
    U128(u128),
}

impl CoupledParamsValueRetriever {
    fn parse(str_value: &str, data_type: &CoupledParamsDataTypes) -> Result<Self, String> {
        fn parse<T>(str_value: &str) -> Result<T, String>
        where
            T: std::str::FromStr,
            <T as std::str::FromStr>::Err: ToString,
        {
            str_value.parse::<T>().map_err(|e| e.to_string())
        }
        match data_type {
            CoupledParamsDataTypes::U64 => Ok(CoupledParamsValueRetriever::U64(parse(str_value)?)),
            CoupledParamsDataTypes::I64 => Ok(CoupledParamsValueRetriever::I64(parse(str_value)?)),
            CoupledParamsDataTypes::U128 => {
                Ok(CoupledParamsValueRetriever::U128(parse(str_value)?))
            }
        }
    }

    pub fn get_value<T: 'static + Copy>(
        map: &HashMap<String, CoupledParamsValueRetriever>,
        parameter_name: &str,
    ) -> T {
        let dynamic: &dyn Any = match map.get(parameter_name).expectv(parameter_name) {
            CoupledParamsValueRetriever::U64(num) => num,
            CoupledParamsValueRetriever::I64(num) => num,
            CoupledParamsValueRetriever::U128(num) => num,
        };
        *dynamic
            .downcast_ref::<T>()
            .unwrap_or_else(|| panic!("expected Some() of {}", std::any::type_name::<T>()))
    }
}

fn parse_coupled_params_with_delimiters(
    input: &str,
    delimiter: char,
    expected_collection: &[(&str, CoupledParamsDataTypes)],
) -> Result<HashMap<String, CoupledParamsValueRetriever>, String> {
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
                CoupledParamsValueRetriever::parse(piece, &data_type).expectv("numeric value"),
            )
        })
        .collect())
}

pub struct CoupledParams {}

impl CoupledParams {
    pub fn parse_rate_pack(parameters: &str) -> Result<RatePack, String> {
        if let CoupledParamsInner::RatePack(Some(rate_pack)) =
            CoupledParamsInner::RatePack(None).parse(parameters)?
        {
            Ok(rate_pack)
        } else {
            unimplemented!()
        }
    }

    pub fn parse_payment_curves(parameters: &str) -> Result<PaymentCurves, String> {
        if let CoupledParamsInner::PaymentCurves(Some(payment_curves)) =
            CoupledParamsInner::PaymentCurves(None).parse(parameters)?
        {
            Ok(payment_curves)
        } else {
            unimplemented!()
        }
    }

    pub fn parse_scan_intervals(parameters: &str) -> Result<ScanIntervals, String> {
        if let CoupledParamsInner::ScanIntervals(Some(scan_intervals)) =
            CoupledParamsInner::ScanIntervals(None).parse(parameters)?
        {
            Ok(scan_intervals)
        } else {
            unimplemented!()
        }
    }
}

#[derive(Debug)]
enum CoupledParamsInner {
    RatePack(Option<RatePack>),
    PaymentCurves(Option<PaymentCurves>),
    ScanIntervals(Option<ScanIntervals>),
}

impl CoupledParamsInner {
    pub fn parse(&self, parameters_str: &str) -> Result<Self, String> {
        let parsed_values = parse_coupled_params_with_delimiters(
            parameters_str,
            COUPLED_PARAMETERS_DELIMITER,
            self.into(),
        )?;
        Ok(match self {
            Self::RatePack(None) => Self::RatePack(Some(RatePack {
                routing_byte_rate: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "routing_byte_rate",
                ),
                routing_service_rate: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "routing_service_rate",
                ),
                exit_byte_rate: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "exit_byte_rate",
                ),
                exit_service_rate: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "exit_service_rate",
                ),
            })),
            Self::PaymentCurves(None) => Self::PaymentCurves(Some(PaymentCurves {
                payment_suggested_after_sec: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "payment_suggested_after_sec",
                ),
                payment_grace_before_ban_sec: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "payment_grace_before_ban_sec",
                ),
                permanent_debt_allowed_gwei: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "permanent_debt_allowed_gwei",
                ),
                balance_to_decrease_from_gwei: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "balance_to_decrease_from_gwei",
                ),
                balance_decreases_for_sec: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "balance_decreases_for_sec",
                ),
                unban_when_balance_below_gwei: CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "unban_when_balance_below_gwei",
                ),
            })),
            Self::ScanIntervals(None) => Self::ScanIntervals(Some(ScanIntervals {
                pending_payable_scan_interval: Duration::from_secs(
                    CoupledParamsValueRetriever::get_value(
                        &parsed_values,
                        "pending_payable_scan_interval",
                    ),
                ),
                payable_scan_interval: Duration::from_secs(CoupledParamsValueRetriever::get_value(
                    &parsed_values,
                    "payable_scan_interval",
                )),
                receivable_scan_interval: Duration::from_secs(
                    CoupledParamsValueRetriever::get_value(
                        &parsed_values,
                        "receivable_scan_interval",
                    ),
                ),
            })),
            _ => unimplemented!(),
        })
    }
}

impl Into<&[(&str, CoupledParamsDataTypes)]> for &CoupledParamsInner {
    fn into(self) -> &'static [(&'static str, CoupledParamsDataTypes)] {
        match self {
            CoupledParamsInner::RatePack(None) => &[
                ("routing_byte_rate", U64),
                ("routing_service_rate", U64),
                ("exit_byte_rate", U64),
                ("exit_service_rate", U64),
            ],
            CoupledParamsInner::PaymentCurves(None) => &[
                ("balance_decreases_for_sec", I64),
                ("balance_to_decrease_from_gwei", I64),
                ("payment_grace_before_ban_sec", I64),
                ("payment_suggested_after_sec", I64),
                ("permanent_debt_allowed_gwei", I64),
                ("unban_when_balance_below_gwei", I64),
            ],
            CoupledParamsInner::ScanIntervals(None) => &[
                ("pending_payable_scan_interval", U64),
                ("payable_scan_interval", U64),
                ("receivable_scan_interval", U64),
            ],
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coupled_parameters::CoupledParamsDataTypes::U128;
    #[test]
    fn parse_coupled_params_with_delimiters_happy_path() {
        let input = "555|123|8989";

        let result = parse_coupled_params_with_delimiters(
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
            CoupledParamsValueRetriever::get_value::<u64>(&result, "first_parameter"),
            555
        );
        assert_eq!(
            CoupledParamsValueRetriever::get_value::<u128>(&result, "second_parameter"),
            123
        );
        assert_eq!(
            CoupledParamsValueRetriever::get_value::<u64>(&result, "third_parameter"),
            8989
        );
    }

    #[test]
    fn parse_coupled_params_with_delimiters_wrong_number_of_parameters() {
        let input = "555|123|8989|11|557";

        let result: Result<HashMap<String, CoupledParamsValueRetriever>, String> =
            parse_coupled_params_with_delimiters(
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
    fn parse_coupled_params_with_delimiters_not_separable() {
        let input = "555|123|8989|11|557";

        let result: Result<HashMap<String, CoupledParamsValueRetriever>, String> =
            parse_coupled_params_with_delimiters(
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
    fn coupled_params_can_be_converted_to_type_arrays() {
        let rate_pack: &[(&str, CoupledParamsDataTypes)] =
            (&CoupledParamsInner::RatePack(None)).into();
        assert_eq!(
            rate_pack,
            &[
                ("routing_byte_rate", U64),
                ("routing_service_rate", U64),
                ("exit_byte_rate", U64),
                ("exit_service_rate", U64),
            ]
        );
        let scan_interval: &[(&str, CoupledParamsDataTypes)] =
            (&CoupledParamsInner::ScanIntervals(None)).into();
        assert_eq!(
            scan_interval,
            &[
                ("pending_payable_scan_interval", U64),
                ("payable_scan_interval", U64),
                ("receivable_scan_interval", U64),
            ]
        );
        let payment_curves: &[(&str, CoupledParamsDataTypes)] =
            (&CoupledParamsInner::PaymentCurves(None)).into();
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
    fn parse_rate_pack_works() {
        let rate_pack_str = "8|9|11|13";

        let result = CoupledParams::parse_rate_pack(rate_pack_str).unwrap();

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
    fn parse_scan_intervals_works() {
        let scan_intervals_str = "110|115|113";

        let result = CoupledParams::parse_scan_intervals(scan_intervals_str).unwrap();

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
    fn parse_payment_curves_works() {
        let payment_curves_str = "10020|5000010|100|120|20000|18000";

        let result = CoupledParams::parse_payment_curves(payment_curves_str).unwrap();

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
}
