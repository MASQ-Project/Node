// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::accountant::jackass_unsigned_to_signed;
use crate::blockchain::blockchain_bridge::PaymentBackupRecord;
use crate::database::connection_wrapper::ConnectionWrapper;
use crate::database::dao_utils::DaoFactoryReal;
use rusqlite::types::Value::Null;
use rusqlite::ToSql;
use web3::types::H256;

#[derive(Debug)]
pub enum PendingPaymentDaoError {
    InsertionFailed(String),
    SignConversionError(u64),
    RecordCannotBeRead,
    FailMark(String),
    RecordDeletion(String),
}

pub trait PendingPaymentsDao {
    fn read_backup_record(&self, id: u64) -> Result<PaymentBackupRecord, PendingPaymentDaoError>; //TODO maybe will be discarded
    fn return_all_active_backup_records(
        &self,
    ) -> Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError>;
    fn initiate_backup_record(&self, amount: u64) -> Result<u64, PendingPaymentDaoError>;
    fn complete_backup_record(
        &self,
        id: u64,
        transaction_hash: H256,
    ) -> Result<(), PendingPaymentDaoError>;
    fn delete_backup_record(&self, id: u64) -> Result<(), PendingPaymentDaoError>;
    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError>;
}

impl PendingPaymentsDao for PendingPaymentsDaoReal {
    fn read_backup_record(&self, id: u64) -> Result<PaymentBackupRecord, PendingPaymentDaoError> {
        todo!()
    }

    fn return_all_active_backup_records(
        &self,
    ) -> Result<Vec<PaymentBackupRecord>, PendingPaymentDaoError> {
        todo!()
    }

    fn initiate_backup_record(&self, amount: u64) -> Result<u64, PendingPaymentDaoError> {
        let signed_amount = jackass_unsigned_to_signed(amount)
            .map_err(|e| PendingPaymentDaoError::SignConversionError(e))?;
        let mut stm = self.conn.prepare("insert into pending_payments (payable_rowid, amount, payment_timestamp, process_error) values (?,?,?,?)").expect("Internal error");
        let params: &[&dyn ToSql] = &[
            &Null, //to let it increment automatically by SQLite
            &signed_amount,
            &Null,
            &Null,
        ];
        match stm.execute(params) {
            Ok(1) => Ok(unimplemented!()),
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn complete_backup_record(
        &self,
        id: u64,
        transaction_hash: H256,
    ) -> Result<(), PendingPaymentDaoError> {
        todo!()
    }

    fn delete_backup_record(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
        let signed_id = jackass_unsigned_to_signed(id)
            .expect("SQLite counts up to i64::MAX; should never happen");
        let mut stm = self
            .conn
            .prepare("delete from pending_payments where payable_rowid = ?")
            .expect("Internal error");
        match stm.execute(&[&signed_id]) {
            Ok(1) => Ok(()),
            Ok(x) => unimplemented!(),
            Err(e) => unimplemented!(),
        }
    }

    fn mark_failure(&self, id: u64) -> Result<(), PendingPaymentDaoError> {
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
