// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

#![cfg(test)]

use masq_lib::type_obfuscation::Obfuscated;
use crate::accountant::QualifiedPayableAccount;

pub fn protect_payables_in_test(payables: Vec<QualifiedPayableAccount>) -> Obfuscated {
    Obfuscated::obfuscate_vector(payables)
}
