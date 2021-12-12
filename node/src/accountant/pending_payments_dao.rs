// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::jackass_unsigned_to_signed;
use crate::blockchain::blockchain_bridge::PendingPaymentBackup;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::{to_time_t, DaoFactoryReal};
use rusqlite::types::Value::Null;
use rusqlite::ToSql;

#[derive(Debug)]
pub enum PendingPaymentDaoError {
    InsertionFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    FailMark(String),
    RecordDeletion(String),
}

pub trait PendingPaymentsDao {
    fn read_backup_record(&self, id: u16) -> Result<PendingPaymentBackup, PendingPaymentDaoError>;
    fn insert_backup_record(
        &self,
        payment: PendingPaymentBackup,
    ) -> Result<(), PendingPaymentDaoError>;
    fn delete_backup_record(&self, id: u16) -> Result<(), PendingPaymentDaoError>;
    fn mark_failure(&self, id: u16) -> Result<(), PendingPaymentDaoError>;
}

impl PendingPaymentsDao for PendingPaymentsDaoReal {
    fn read_backup_record(&self, id: u16) -> Result<PendingPaymentBackup, PendingPaymentDaoError> {
        todo!()
    }

    fn insert_backup_record(
        &self,
        payment: PendingPaymentBackup,
    ) -> Result<(), PendingPaymentDaoError> {
        let signed_amount = jackass_unsigned_to_signed(payment.amount)
            .map_err(|e| PendingPaymentDaoError::SignConversionError(e))?;
        let mut stm = self.conn.prepare("insert into pending_payments (payable_rowid, amount, payment_timestamp, process_error) values (?,?,?,?)").expect("Internal error");
        let params: &[&dyn ToSql] = &[
            &payment.rowid,
            &signed_amount,
            &to_time_t(payment.payment_timestamp),
            &Null,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn delete_backup_record(&self, id: u16) -> Result<(), PendingPaymentDaoError> {
        let mut stm = self
            .conn
            .prepare("delete from pending_payments where payable_rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&id]) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn mark_failure(&self, id: u16) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }
}

pub trait PendingPaymentsDaoFactory {
    fn make(&self) -> Box<dyn PendingPaymentsDao>;
}

impl PendingPaymentsDaoFactory for DaoFactoryReal {
    fn make(&self) -> Box<dyn PendingPaymentsDao> {
        Box::new(PendingPaymentsDaoReal::new(self.make_connection()))
    }
}

#[derive(Debug)]
pub struct PendingPaymentsDaoReal {
    conn: Box<dyn ConnectionWrapper>,
}

impl PendingPaymentsDaoReal {
    pub fn new(conn: Box<dyn ConnectionWrapper>) -> Self {
        Self { conn }
    }
}
