// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use masq_lib::type_obfuscation::Obfuscated;
use crate::accountant::database_access_objects::payable_dao::PayableAccount;
use crate::accountant::scanners::PayableScanner;

pub fn protect_payables_in_test(payables: Vec<PayableAccount>) -> Obfuscated {
    Obfuscated::obfuscate_data(payables)
}
