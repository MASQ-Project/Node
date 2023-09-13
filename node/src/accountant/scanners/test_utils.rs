// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::mid_scan_msg_handling::payable_scanner::ProtectedPayables;
use crate::accountant::scanners::PayableScanner;

pub fn protect_payables_in_test(payables: Vec<PayableAccount>) -> ProtectedPayables {
    PayableScanner::protect_payables_shared(payables)
}
