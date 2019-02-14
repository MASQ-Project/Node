use rusqlite::Connection;
use std::fmt::Debug;
use std::time::SystemTime;
use sub_lib::wallet::Wallet;

pub struct Account {
    pub wallet_address: Wallet,
    pub balance: i64,
    pub last_paid_timestamp: SystemTime,
    pub pending_payment_transaction: Option<String>,
}

pub trait PayableDao: Debug {
    fn more_money_owed(&self, wallet_address: &Wallet, amount: u64);

    fn payment_sent(&self, wallet_address: &Wallet, pending_payment_transaction: &str);

    fn payment_confirmed(
        &self,
        wallet_address: &Wallet,
        amount: u64,
        confirmation_noticed_timestamp: &SystemTime,
    );
}

#[derive(Debug)]
pub struct PayableDaoReal {}

impl PayableDao for PayableDaoReal {
    fn more_money_owed(&self, _wallet_address: &Wallet, _amount: u64) {
        unimplemented!()
    }

    fn payment_sent(&self, _wallet_address: &Wallet, _pending_payment_transaction: &str) {
        unimplemented!()
    }

    fn payment_confirmed(
        &self,
        _wallet_address: &Wallet,
        _amount: u64,
        _confirmation_noticed_timestamp: &SystemTime,
    ) {
        unimplemented!()
    }
}

impl PayableDaoReal {
    pub fn new(_conn: Connection) -> PayableDaoReal {
        PayableDaoReal {}
    }
}
