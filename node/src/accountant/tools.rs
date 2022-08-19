use crate::accountant::payable_dao::PayableAccount;
use crate::accountant::scanners::scanners::PayableScanner;
use crate::sub_lib::accountant::PaymentThresholds;
use itertools::Itertools;
use std::ops::Add;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

//for debugging only
pub(crate) fn investigate_debt_extremes(all_non_pending_payables: &[PayableAccount]) -> String {
    if all_non_pending_payables.is_empty() {
        "Payable scan found no debts".to_string()
    } else {
        struct PayableInfo {
            balance: i64,
            age: Duration,
        }
        let now = SystemTime::now();
        let init = (
            PayableInfo {
                balance: 0,
                age: Duration::ZERO,
            },
            PayableInfo {
                balance: 0,
                age: Duration::ZERO,
            },
        );
        let (biggest, oldest) = all_non_pending_payables.iter().fold(init, |sofar, p| {
            let (mut biggest, mut oldest) = sofar;
            let p_age = now
                .duration_since(p.last_paid_timestamp)
                .expect("Payable time is corrupt");
            {
                //look at a test if not understandable
                let check_age_parameter_if_the_first_is_the_same =
                    || -> bool { p.balance == biggest.balance && p_age > biggest.age };

                if p.balance > biggest.balance || check_age_parameter_if_the_first_is_the_same() {
                    biggest = PayableInfo {
                        balance: p.balance,
                        age: p_age,
                    }
                }

                let check_balance_parameter_if_the_first_is_the_same =
                    || -> bool { p_age == oldest.age && p.balance > oldest.balance };

                if p_age > oldest.age || check_balance_parameter_if_the_first_is_the_same() {
                    oldest = PayableInfo {
                        balance: p.balance,
                        age: p_age,
                    }
                }
            }
            (biggest, oldest)
        });
        format!("Payable scan found {} debts; the biggest is {} owed for {}sec, the oldest is {} owed for {}sec",
                all_non_pending_payables.len(), biggest.balance, biggest.age.as_secs(),
                oldest.balance, oldest.age.as_secs())
    }
}

pub(crate) fn should_pay(
    payable: &PayableAccount,
    payment_thresholds: Rc<PaymentThresholds>,
) -> bool {
    payable_exceeded_threshold(payable, payment_thresholds).is_some()
}

fn payable_exceeded_threshold(
    payable: &PayableAccount,
    payment_thresholds: Rc<PaymentThresholds>,
) -> Option<u64> {
    // TODO: This calculation should be done in the database, if possible
    let time_since_last_paid = SystemTime::now()
        .duration_since(payable.last_paid_timestamp)
        .expect("Internal error")
        .as_secs();

    if is_innocent_age(
        time_since_last_paid,
        payment_thresholds.maturity_threshold_sec as u64,
    ) {
        return None;
    }

    if is_innocent_balance(
        payable.balance,
        payment_thresholds.permanent_debt_allowed_gwei,
    ) {
        return None;
    }

    let threshold = calculate_payout_threshold(time_since_last_paid, payment_thresholds);
    if payable.balance as f64 > threshold {
        Some(threshold as u64)
    } else {
        None
    }
}

pub(crate) fn payables_debug_summary(
    qualified_payables: &[PayableAccount],
    payment_thresholds: Rc<PaymentThresholds>,
) -> String {
    let now = SystemTime::now();
    let list = qualified_payables
        .iter()
        .map(|payable| {
            let p_age = now
                .duration_since(payable.last_paid_timestamp)
                .expect("Payable time is corrupt");
            let threshold = payable_exceeded_threshold(payable, payment_thresholds.clone())
                .expect("Threshold suddenly changed!");
            format!(
                "{} owed for {}sec exceeds threshold: {}; creditor: {}",
                payable.balance,
                p_age.as_secs(),
                threshold,
                payable.wallet
            )
        })
        .join("\n");
    String::from("Paying qualified debts:\n").add(&list)
}

fn is_innocent_age(age: u64, limit: u64) -> bool {
    age <= limit
}

fn is_innocent_balance(balance: i64, limit: i64) -> bool {
    balance <= limit
}

fn calculate_payout_threshold(x: u64, payment_thresholds: Rc<PaymentThresholds>) -> f64 {
    let m = -((payment_thresholds.debt_threshold_gwei as f64
        - payment_thresholds.permanent_debt_allowed_gwei as f64)
        / (payment_thresholds.threshold_interval_sec as f64
            - payment_thresholds.maturity_threshold_sec as f64));
    let b = payment_thresholds.debt_threshold_gwei as f64
        - m * payment_thresholds.maturity_threshold_sec as f64;
    m * x as f64 + b
}

#[cfg(test)]
mod tests {
    use crate::accountant::payable_dao::PayableAccount;
    use crate::accountant::tools::payables_debug_summary;
    use crate::bootstrapper::BootstrapperConfig;
    use crate::database::dao_utils::{from_time_t, to_time_t};
    use crate::sub_lib::accountant::PaymentThresholds;
    use crate::test_utils::make_wallet;
    use crate::test_utils::unshared_test_utils::make_populated_accountant_config_with_defaults;
    use std::rc::Rc;
    use std::time::SystemTime;

    #[test]
    fn payables_debug_summary_prints_pretty_summary() {
        let now = to_time_t(SystemTime::now());
        let payment_thresholds = PaymentThresholds {
            threshold_interval_sec: 2_592_000,
            debt_threshold_gwei: 1_000_000_000,
            payment_grace_period_sec: 86_400,
            maturity_threshold_sec: 86_400,
            permanent_debt_allowed_gwei: 10_000_000,
            unban_below_gwei: 10_000_000,
        };
        let payment_thresholds_rc = Rc::new(payment_thresholds.clone());
        let qualified_payables = &[
            PayableAccount {
                wallet: make_wallet("wallet0"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1000,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1234,
                ),
                pending_payable_opt: None,
            },
            PayableAccount {
                wallet: make_wallet("wallet1"),
                balance: payment_thresholds.permanent_debt_allowed_gwei + 1,
                last_paid_timestamp: from_time_t(
                    now - payment_thresholds.threshold_interval_sec - 1,
                ),
                pending_payable_opt: None,
            },
        ];

        let result = payables_debug_summary(qualified_payables, payment_thresholds_rc);

        assert_eq!(result,
                   "Paying qualified debts:\n\
                   10001000 owed for 2593234sec exceeds threshold: 9512428; creditor: 0x0000000000000000000000000077616c6c657430\n\
                   10000001 owed for 2592001sec exceeds threshold: 9999604; creditor: 0x0000000000000000000000000077616c6c657431"
        )
    }
}
