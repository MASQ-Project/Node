// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payment_adjuster::PaymentAdjuster;
use crate::accountant::scanners::{PayableScanner, Scanner};
use actix::Message;
use std::marker::PhantomData;

// a super type of the scanner that can hold methods for handling special situations that occur between
// the scan begins and it ends; such occasion is meant for reception of some data that has
// to be processed before the scanner proceeds to the final stage of its cycle where the end message,
// to be shipped to Accountant eventually, will be formed
pub trait ScannerWithMidProcedures<BeginMessage, EndMessage, Provider>:
    Scanner<BeginMessage, EndMessage> + MidScanProceduresProvider<Provider>
where
    BeginMessage: Message,
    EndMessage: Message,
{
}

pub trait MidScanProceduresProvider<T> {
    fn mid_scan_procedures(&self) -> &T;
}
