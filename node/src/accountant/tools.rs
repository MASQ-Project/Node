use crate::sub_lib::accountant::PaymentThresholds;
use std::any::Any;

//TODO the data types should change with GH-497 (including signed => unsigned)
pub trait PayableExceedThresholdTools {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool;
    fn is_innocent_balance(&self, balance: i64, limit: i64) -> bool;
    fn calculate_payout_threshold(&self, payment_thresholds: PaymentThresholds, x: u64) -> f64;
    as_any_dcl!();
}

#[derive(Default)]
pub struct PayableExceedThresholdToolsReal {
    pub payment_thresholds: PaymentThresholds,
}

impl PayableExceedThresholdTools for PayableExceedThresholdToolsReal {
    fn is_innocent_age(&self, age: u64, limit: u64) -> bool {
        age <= limit
    }

    fn is_innocent_balance(&self, balance: i64, limit: i64) -> bool {
        balance <= limit
    }

    fn calculate_payout_threshold(&self, payment_thresholds: PaymentThresholds, x: u64) -> f64 {
        let m = -((payment_thresholds.debt_threshold_gwei as f64
            - payment_thresholds.permanent_debt_allowed_gwei as f64)
            / (payment_thresholds.threshold_interval_sec as f64
                - payment_thresholds.maturity_threshold_sec as f64));
        let b = payment_thresholds.debt_threshold_gwei as f64
            - m * payment_thresholds.maturity_threshold_sec as f64;
        m * x as f64 + b
    }
    as_any_impl!();
}

impl PayableExceedThresholdToolsReal {
    pub fn new(payment_thresholds: PaymentThresholds) -> Self {
        Self { payment_thresholds }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::accountant::DEFAULT_PAYMENT_THRESHOLDS;

    #[test]
    fn payable_thresholds_real_can_be_constructed_properly() {
        let payment_thresholds = DEFAULT_PAYMENT_THRESHOLDS.clone();
        let payable_exceed_threshold_tools_real =
            PayableExceedThresholdToolsReal::new(payment_thresholds);

        assert_eq!(
            payable_exceed_threshold_tools_real.payment_thresholds,
            payment_thresholds
        )
    }
}
