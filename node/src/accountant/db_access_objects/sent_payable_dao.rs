use std::collections::HashMap;
use std::time::SystemTime;
use ethereum_types::H256;
use web3::types::Address;
use crate::accountant::{checked_conversion, comma_joined_stringifiable};
use crate::accountant::db_access_objects::pending_payable_dao::PendingPayableDaoError;
use crate::accountant::db_access_objects::utils::to_time_t;
use crate::accountant::db_big_integer::big_int_divider::BigIntDivider;
use crate::blockchain::blockchain_interface::blockchain_interface_web3::lower_level_interface_web3::TxStatus;
use crate::database::rusqlite_wrappers::ConnectionWrapper;

#[derive(Debug, PartialEq, Eq)]
pub enum SentPayableDaoError {
    InsertionFailed(String),
    // UpdateFailed(String),
    // SignConversionError(u64),
    // RecordCannotBeRead,
    // RecordDeletion(String),
    // ErrorMarkFailed(String),
}

type TxIdentifiers = HashMap<H256, Option<u64>>;

pub struct Tx {
    // GH-608: Perhaps TxReceipt could be a similar structure to be used
    hash: H256,
    receiver_address: Address,
    amount: u128,
    timestamp: SystemTime,
    gas_price_wei: u64,
    nonce: u32,
}

pub struct StatusChange {
    new_status: TxStatus,
}

pub trait SentPayableDao {
    // Note that the order of the returned results is not guaranteed
    fn get_tx_identifiers(&self, hashes: &[H256]) -> TxIdentifiers;
    fn retrieve_pending_txs(&self) -> Vec<Tx>;
    fn retrieve_txs_to_retry(&self) -> Vec<Tx>;
    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError>;
    fn delete_records(&self, ids: &[u64]) -> Result<(), SentPayableDaoError>;
    fn change_statuses(&self, ids: &[StatusChange]) -> Result<(), SentPayableDaoError>;
}

#[derive(Debug)]
pub struct SentPayableDaoReal<'a> {
    conn: Box<dyn ConnectionWrapper + 'a>,
}

impl<'a> SentPayableDaoReal<'a> {
    pub fn new(conn: Box<dyn ConnectionWrapper + 'a>) -> Self {
        // TODO: GH-608: You'll need to write a mock to test this, do that wisely
        Self { conn }
    }

    fn generate_sql_values_for_insertion(txs: &[Tx]) -> String {
        comma_joined_stringifiable(txs, |tx| {
            let amount_checked = checked_conversion::<u128, i128>(tx.amount);
            let (high_bytes, low_bytes) = BigIntDivider::deconstruct(amount_checked);
            format!(
                "('{:?}', '{:?}', {}, {}, {}, {}, {}, 'Pending', 0)",
                tx.hash,
                tx.receiver_address,
                high_bytes,
                low_bytes,
                to_time_t(tx.timestamp),
                tx.gas_price_wei,
                tx.nonce,
            )
        })
    }
}

impl SentPayableDao for SentPayableDaoReal<'_> {
    fn get_tx_identifiers(&self, hashes: &[H256]) -> TxIdentifiers {
        todo!()
    }

    fn retrieve_pending_txs(&self) -> Vec<Tx> {
        todo!()
    }

    fn retrieve_txs_to_retry(&self) -> Vec<Tx> {
        todo!()
    }

    fn insert_new_records(&self, txs: Vec<Tx>) -> Result<(), SentPayableDaoError> {
        let sql = format!(
            "insert into sent_payable (\
            tx_hash, receiver_address, amount_high_b, amount_low_b, \
            timestamp, gas_price_wei, nonce, status, retried\
            ) values {}",
            Self::generate_sql_values_for_insertion(&txs)
        );

        match self.conn.prepare(&sql).expect("Internal error").execute([]) {
            Ok(x) if x == txs.len() => Ok(()),
            Ok(x) => panic!("expected {} changed rows but got {}", txs.len(), x),
            Err(e) => Err(SentPayableDaoError::InsertionFailed(e.to_string())),
        }
    }

    fn delete_records(&self, ids: &[u64]) -> Result<(), SentPayableDaoError> {
        todo!()
    }

    fn change_statuses(&self, ids: &[StatusChange]) -> Result<(), SentPayableDaoError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::accountant::db_access_objects::sent_payable_dao::{
        SentPayableDao, SentPayableDaoError, SentPayableDaoReal, Tx,
    };
    use crate::database::db_initializer::{
        DbInitializationConfig, DbInitializer, DbInitializerReal, DATABASE_FILE,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::database::test_utils::ConnectionWrapperMock;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, OpenFlags};
    use std::time::SystemTime;

    fn make_tx() -> Tx {
        Tx {
            hash: Default::default(),
            receiver_address: Default::default(),
            amount: 0,
            timestamp: SystemTime::now(),
            gas_price_wei: 0,
            nonce: 0,
        }
    }

    #[test]
    fn insert_new_records_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "insert_new_records_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let tx = make_tx();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        let result = subject.insert_new_records(vec![tx]);

        let row_count: i64 = {
            let mut stmt = subject
                .conn
                .prepare("SELECT COUNT(*) FROM sent_payable")
                .unwrap();
            stmt.query_row([], |row| row.get(0)).unwrap()
        };
        assert_eq!(result, Ok(()));
        assert_eq!(row_count, 1);
        // TODO: GH-608: Add more assertions to verify the inserted data after retrieve functions are implemented
    }

    #[test]
    #[should_panic(expected = "expected 1 changed rows but got 0")]
    fn insert_new_records_can_panic() {
        let setup_conn = Connection::open_in_memory().unwrap();
        // Inject a deliberately failing statement into the mocked connection.
        let failing_stmt = {
            setup_conn
                .execute("create table example (id integer)", [])
                .unwrap();
            setup_conn.prepare("select id from example").unwrap()
        };
        let wrapped_conn = ConnectionWrapperMock::default().prepare_result(Ok(failing_stmt));
        let tx = make_tx();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let _ = subject.insert_new_records(vec![tx]);
    }

    #[test]
    fn insert_new_records_can_throw_error() {
        let home_dir = ensure_node_home_directory_exists(
            "sent_payable_dao",
            "insert_new_records_can_throw_error",
        );
        {
            DbInitializerReal::default()
                .initialize(&home_dir, DbInitializationConfig::test_default())
                .unwrap();
        }
        let read_only_conn = Connection::open_with_flags(
            home_dir.join(DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let wrapped_conn = ConnectionWrapperReal::new(read_only_conn);
        let tx = make_tx();
        let subject = SentPayableDaoReal::new(Box::new(wrapped_conn));

        let result = subject.insert_new_records(vec![tx]);

        assert_eq!(
            result,
            Err(SentPayableDaoError::InsertionFailed(
                "attempt to write a readonly database".to_string()
            ))
        )
    }

    #[test]
    fn get_tx_identifiers_works() {
        let home_dir =
            ensure_node_home_directory_exists("sent_payable_dao", "get_tx_identifiers_works");
        let wrapped_conn = DbInitializerReal::default()
            .initialize(&home_dir, DbInitializationConfig::test_default())
            .unwrap();
        let subject = SentPayableDaoReal::new(wrapped_conn);

        todo!("first you'll have to write tests for the insertion method");
    }
}
