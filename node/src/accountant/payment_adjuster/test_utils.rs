// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::payment_adjuster::inner::PaymentAdjusterInnerReal;
use crate::accountant::payment_adjuster::PaymentAdjusterReal;
use crate::test_utils::make_wallet;
use itertools::Either;
use lazy_static::lazy_static;
use masq_lib::constants::MASQ_TOTAL_SUPPLY;
use masq_lib::logger::Logger;
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref MAX_POSSIBLE_MASQ_BALANCE_IN_MINOR: u128 =
        MASQ_TOTAL_SUPPLY as u128 * 10_u128.pow(18);
    pub static ref ONE_MONTH_LONG_DEBT_SEC: u64 = 30 * 24 * 60 * 60;
}

pub fn make_initialized_subject(
    now: SystemTime,
    cw_masq_balance_opt: Option<u128>,
    logger_opt: Option<Logger>,
) -> PaymentAdjusterReal {
    PaymentAdjusterReal {
        inner: Box::new(PaymentAdjusterInnerReal::new(
            now,
            None,
            cw_masq_balance_opt.unwrap_or(0),
        )),
        logger: logger_opt.unwrap_or(Logger::new("test")),
    }
}

pub fn get_extreme_accounts(
    months_of_debt_matrix_and_balance_setup: Either<(Vec<usize>, u128), Vec<(usize, u128)>>,
    now: SystemTime,
) -> Vec<PayableAccount> {
    let seed: Vec<(usize, u128)> = match months_of_debt_matrix_and_balance_setup {
        Either::Left((vec, const_balance)) => vec
            .into_iter()
            .map(|months| (months, const_balance))
            .collect(),
        Either::Right(vec_of_pairs) => vec_of_pairs,
    };
    seed.into_iter()
        .enumerate()
        .map(|(idx, (number_of_months, balance_wei))| PayableAccount {
            wallet: make_wallet(&format!("blah{}", idx)),
            balance_wei,
            last_paid_timestamp: now
                .checked_sub(Duration::from_secs(
                    number_of_months as u64 * (*ONE_MONTH_LONG_DEBT_SEC),
                ))
                .unwrap(),
            pending_payable_opt: None,
        })
        .collect()
}
