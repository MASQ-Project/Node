// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::payable_dao::Payment;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::DaoFactoryReal;
use std::time::SystemTime;

#[derive(Debug)]
pub enum PendingPaymentDaoError {
    InsertionFailed(String),
}

pub struct PendingPaymentRecord {
    pub payable_account_rowid: u16,
    pub balance_decrease: u64,
    pub timestamp_of_payment_order: SystemTime,
}

impl PendingPaymentRecord {
    pub fn new(payment: &Payment, rowid: u16) -> Self {
        Self {
            payable_account_rowid: rowid,
            balance_decrease: payment.amount,
            timestamp_of_payment_order: payment.timestamp,
        }
    }
}

pub trait PendingPaymentsDao {
    fn read_backup_record(&self, id: u16) -> Result<PendingPaymentRecord, PendingPaymentDaoError>;
    fn insert_backup_record(
        &self,
        payment: PendingPaymentRecord,
    ) -> Result<(), PendingPaymentDaoError>;
    fn delete_backup_record(&self, id: u16) -> Result<(), PendingPaymentDaoError>;
}

impl PendingPaymentsDao for PendingPaymentsDaoReal {
    fn read_backup_record(&self, id: u16) -> Result<PendingPaymentRecord, PendingPaymentDaoError> {
        todo!()
    }

    fn insert_backup_record(
        &self,
        payment: PendingPaymentRecord,
    ) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }

    fn delete_backup_record(&self, id: u16) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }
}

pub trait PendingPaymentsDaoFactory {
    fn make(&self) -> Box<dyn PendingPaymentsDao>;
}

impl PendingPaymentsDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PendingPaymentsDao> {
        unimplemented!() // Box::new(RecoverDaoReal::new(self.make_connection()))
    }
}

#[derive(Debug)]
pub struct PendingPaymentsDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}
