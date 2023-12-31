// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::database::db_initializer::ExternalData;
use crate::database::db_migrations::db_migrator::{DatabaseMigration, DbMigratorReal};
use crate::database::rusqlite_wrappers::{ConnectionWrapper, TransactionSafeWrapper};
use masq_lib::constants::CURRENT_SCHEMA_VERSION;
use masq_lib::logger::Logger;
use masq_lib::utils::{to_string, ExpectValue};
use rusqlite::{Error, ToSql};
use std::fmt::{Display, Formatter};

pub trait DBMigDeclarator {
    fn db_password(&self) -> Option<String>;
    fn transaction(&self) -> &TransactionSafeWrapper;
    fn execute_upon_transaction<'a>(
        &self,
        sql_statements: &[&'a dyn StatementObject],
    ) -> rusqlite::Result<()>;
    fn external_parameters(&self) -> &ExternalData;
    fn logger(&self) -> &Logger;
}

pub trait DBMigrationUtilities {
    fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()>;

    fn commit(&mut self) -> Result<(), String>;

    fn make_mig_declarator<'a>(
        &'a self,
        external: &'a ExternalData,
        logger: &'a Logger,
    ) -> Box<dyn DBMigDeclarator + 'a>;

    fn too_high_schema_panics(&self, obsolete_schema: usize);
}

pub struct DBMigrationUtilitiesReal<'a> {
    root_transaction: Option<TransactionSafeWrapper<'a>>,
    db_migrator_configuration: DBMigratorInnerConfiguration,
}

impl<'a> DBMigrationUtilitiesReal<'a> {
    pub fn new<'b: 'a>(
        conn: &'b mut dyn ConnectionWrapper,
        db_migrator_configuration: DBMigratorInnerConfiguration,
    ) -> rusqlite::Result<Self> {
        Ok(Self {
            root_transaction: Some(conn.transaction()?),
            db_migrator_configuration,
        })
    }

    fn root_transaction_ref(&self) -> &TransactionSafeWrapper {
        self.root_transaction.as_ref().expectv("root transaction")
    }
}

impl<'a> DBMigrationUtilities for DBMigrationUtilitiesReal<'a> {
    fn update_schema_version(&self, update_to: usize) -> rusqlite::Result<()> {
        DbMigratorReal::update_schema_version(
            self.db_migrator_configuration
                .db_configuration_table
                .as_str(),
            self.root_transaction_ref(),
            update_to,
        )
    }

    fn commit(&mut self) -> Result<(), String> {
        self.root_transaction
            .take()
            .expectv("owned root transaction")
            .commit()
            .map_err(to_string)
    }

    fn make_mig_declarator<'b>(
        &'b self,
        external: &'b ExternalData,
        logger: &'b Logger,
    ) -> Box<dyn DBMigDeclarator + 'b> {
        Box::new(DBMigDeclaratorReal::new(
            self.root_transaction_ref(),
            external,
            logger,
        ))
    }

    fn too_high_schema_panics(&self, obsolete_schema: usize) {
        if obsolete_schema > self.db_migrator_configuration.current_schema_version {
            panic!(
                "Database claims to be more advanced ({}) than the version {} which is the latest \
             version this Node knows about.",
                obsolete_schema, CURRENT_SCHEMA_VERSION
            )
        }
    }
}

struct DBMigDeclaratorReal<'a> {
    root_transaction_ref: &'a TransactionSafeWrapper<'a>,
    external: &'a ExternalData,
    logger: &'a Logger,
}

impl<'a> DBMigDeclaratorReal<'a> {
    fn new(
        root_transaction_ref: &'a TransactionSafeWrapper,
        external: &'a ExternalData,
        logger: &'a Logger,
    ) -> Self {
        Self {
            root_transaction_ref,
            external,
            logger,
        }
    }
}

impl DBMigDeclarator for DBMigDeclaratorReal<'_> {
    fn db_password(&self) -> Option<String> {
        self.external.db_password_opt.clone()
    }

    fn transaction(&self) -> &TransactionSafeWrapper {
        self.root_transaction_ref
    }

    fn execute_upon_transaction<'a>(
        &self,
        sql_statements: &[&dyn StatementObject],
    ) -> rusqlite::Result<()> {
        let transaction = self.root_transaction_ref;
        sql_statements.iter().fold(Ok(()), |so_far, stm| {
            if so_far.is_ok() {
                match stm.execute(transaction) {
                    Ok(_) => Ok(()),
                    Err(e) if e == Error::ExecuteReturnedResults =>
                        panic!("Statements returning values should be avoided with execute_upon_transaction, caused by: {}",stm),
                    Err(e) => Err(e),
                }
            } else {
                so_far
            }
        })
    }

    fn external_parameters(&self) -> &ExternalData {
        self.external
    }

    fn logger(&self) -> &Logger {
        self.logger
    }
}

pub trait StatementObject: Display {
    fn execute(&self, transaction: &TransactionSafeWrapper) -> rusqlite::Result<()>;
}

impl StatementObject for &str {
    fn execute(&self, transaction: &TransactionSafeWrapper) -> rusqlite::Result<()> {
        transaction.execute(self, &[]).map(|_| ())
    }
}

impl StatementObject for String {
    fn execute(&self, transaction: &TransactionSafeWrapper) -> rusqlite::Result<()> {
        self.as_str().execute(transaction)
    }
}

pub struct StatementWithRusqliteParams {
    pub sql_stm: String,
    pub params: Vec<Box<dyn ToSql>>,
}

impl StatementObject for StatementWithRusqliteParams {
    fn execute(&self, transaction: &TransactionSafeWrapper) -> rusqlite::Result<()> {
        transaction
            .execute(
                &self.sql_stm,
                &self
                    .params
                    .iter()
                    .map(|param| param.as_ref())
                    .collect::<Vec<&dyn ToSql>>(),
            )
            .map(|_| ())
    }
}

impl Display for StatementWithRusqliteParams {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sql_stm)
    }
}

pub struct DBMigratorInnerConfiguration {
    pub db_configuration_table: String,
    pub current_schema_version: usize,
}

impl DBMigratorInnerConfiguration {
    pub fn new() -> Self {
        DBMigratorInnerConfiguration {
            db_configuration_table: "config".to_string(),
            current_schema_version: CURRENT_SCHEMA_VERSION,
        }
    }
}

impl Default for DBMigratorInnerConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct InterimMigrationPlaceholder(usize);

impl DatabaseMigration for InterimMigrationPlaceholder {
    fn migrate<'a>(
        &self,
        _mig_declaration_utilities: Box<dyn DBMigDeclarator + 'a>,
    ) -> rusqlite::Result<()> {
        Ok(())
    }

    fn old_version(&self) -> usize {
        self.0 - 1
    }
}

#[cfg(test)]
mod tests {
    use crate::database::db_migrations::migrator_utils::{
        DBMigrationUtilities, DBMigrationUtilitiesReal, DBMigratorInnerConfiguration,
        StatementObject, StatementWithRusqliteParams,
    };
    use crate::database::rusqlite_wrappers::ConnectionWrapperReal;
    use crate::test_utils::database_utils::make_external_data;
    use masq_lib::logger::Logger;
    use masq_lib::test_utils::utils::ensure_node_home_directory_exists;
    use rusqlite::{Connection, Error, OptionalExtension, ToSql};

    #[test]
    fn statement_with_rusqlite_params_can_display_its_stm() {
        let subject = StatementWithRusqliteParams {
            sql_stm: "insert into table2 (column) values (?)".to_string(),
            params: vec![Box::new(12345)],
        };

        let stm = subject.to_string();

        assert_eq!(stm, "insert into table2 (column) values (?)".to_string())
    }

    #[test]
    fn db_password_works() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "db_password_works");
        let db_path = dir_path.join("test_database.db");
        let mut connection_wrapper =
            ConnectionWrapperReal::new(Connection::open(&db_path).unwrap());
        let utils = DBMigrationUtilitiesReal::new(
            &mut connection_wrapper,
            DBMigratorInnerConfiguration {
                db_configuration_table: "irrelevant".to_string(),
                current_schema_version: 0,
            },
        )
        .unwrap();
        let mut external_parameters = make_external_data();
        external_parameters.db_password_opt = Some("booga".to_string());
        let logger = Logger::new("test_logger");
        let subject = utils.make_mig_declarator(&external_parameters, &logger);

        let result = subject.db_password();

        assert_eq!(result, Some("booga".to_string()));
    }

    #[test]
    fn transaction_works() {
        let dir_path = ensure_node_home_directory_exists("db_migrations", "transaction_works");
        let db_path = dir_path.join("test_database.db");
        let mut connection_wrapper =
            ConnectionWrapperReal::new(Connection::open(&db_path).unwrap());
        let utils = DBMigrationUtilitiesReal::new(
            &mut connection_wrapper,
            DBMigratorInnerConfiguration {
                db_configuration_table: "irrelevant".to_string(),
                current_schema_version: 0,
            },
        )
        .unwrap();
        let external_parameters = make_external_data();
        let logger = Logger::new("test_logger");
        let subject = utils.make_mig_declarator(&external_parameters, &logger);

        let result = subject.transaction();

        result
            .execute("CREATE TABLE IF NOT EXISTS test (column TEXT)", &[])
            .unwrap();
        // no panic? Test passes!
    }

    #[test]
    fn execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled(
    ) {
        let dir_path = ensure_node_home_directory_exists("db_migrations","execute_upon_transaction_returns_the_first_error_encountered_and_the_transaction_is_canceled");
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE test (
            name TEXT,
            count integer
        )",
                [],
            )
            .unwrap();
        let correct_statement_1 = "INSERT INTO test (name,count) VALUES ('mushrooms',270)";
        let erroneous_statement_1 =
            "INSERT INTO botanic_garden (name, count) VALUES (sunflowers, 100)";
        let erroneous_statement_2 = "INSERT INTO milky_way (star) VALUES (just_discovered)";
        let set_of_sql_statements: &[&dyn StatementObject] = &[
            &correct_statement_1,
            &erroneous_statement_1,
            &erroneous_statement_2,
        ];
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration::new();
        let external_parameters = make_external_data();
        let subject = DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap();

        let result = subject
            .make_mig_declarator(&external_parameters, &Logger::new("test logger"))
            .execute_upon_transaction(set_of_sql_statements);

        assert_eq!(
            result.unwrap_err().to_string(),
            "no such table: botanic_garden"
        );
        let connection = Connection::open(&db_path).unwrap();
        //when an error occurs, the underlying transaction gets rolled back, and we cannot see any changes to the database
        let assertion: Option<(String, String)> = connection
            .query_row("SELECT count FROM test WHERE name='mushrooms'", [], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .optional()
            .unwrap();
        assert!(assertion.is_none()) //means no result for this query
    }

    #[test]
    #[should_panic(
        expected = "Statements returning values should be avoided with execute_upon_transaction, caused by: SELECT * FROM botanic_garden"
    )]
    fn execute_upon_transaction_panics_because_statement_returns() {
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "execute_upon_transaction_panics_because_statement_returns",
        );
        let db_path = dir_path.join("test_database.db");
        let connection = Connection::open(&db_path).unwrap();
        connection
            .execute(
                "CREATE TABLE botanic_garden (
            name TEXT,
            count integer
        )",
                [],
            )
            .unwrap();
        let statement_1 = "INSERT INTO botanic_garden (name,count) VALUES ('sun_flowers', 100)";
        let statement_2 = "SELECT * FROM botanic_garden"; //this statement returns data
        let set_of_sql_statements: &[&dyn StatementObject] = &[&statement_1, &statement_2];
        let mut connection_wrapper = ConnectionWrapperReal::new(connection);
        let config = DBMigratorInnerConfiguration::new();
        let external_parameters = make_external_data();
        let subject = DBMigrationUtilitiesReal::new(&mut connection_wrapper, config).unwrap();

        let _ = subject
            .make_mig_declarator(&external_parameters, &Logger::new("test logger"))
            .execute_upon_transaction(set_of_sql_statements);
    }

    #[test]
    fn execute_upon_transaction_handles_also_error_from_stm_with_params() {
        let dir_path = ensure_node_home_directory_exists(
            "db_migrations",
            "execute_upon_transaction_handles_also_error_from_stm_with_params",
        );
        let db_path = dir_path.join("test_database.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE botanic_garden (
                        name TEXT,
                        count integer
                    )",
            [],
        )
        .unwrap();
        let statement_1_simple =
            "INSERT INTO botanic_garden (name,count) VALUES ('sun_flowers', 100)";
        let statement_2_good = StatementWithRusqliteParams {
            sql_stm: "update botanic_garden set count = 111 where name = 'sun_flowers'".to_string(),
            params: {
                let params: Vec<Box<dyn ToSql>> = vec![];
                params
            },
        };
        let statement_3_bad = StatementWithRusqliteParams {
            sql_stm: "select name, count from foo".to_string(),
            params: vec![Box::new("another_whatever")],
        };
        //we expect not to get down to this statement, the error from statement_3 immediately terminates the circuit
        let statement_4_demonstrative = StatementWithRusqliteParams {
            sql_stm: "select name, count from bar".to_string(),
            params: vec![Box::new("also_whatever")],
        };
        let set_of_sql_statements: &[&dyn StatementObject] = &[
            &statement_1_simple,
            &statement_2_good,
            &statement_3_bad,
            &statement_4_demonstrative,
        ];
        let mut conn_wrapper = ConnectionWrapperReal::new(conn);
        let config = DBMigratorInnerConfiguration::new();
        let external_params = make_external_data();
        let subject = DBMigrationUtilitiesReal::new(&mut conn_wrapper, config).unwrap();

        let result = subject
            .make_mig_declarator(&external_params, &Logger::new("test logger"))
            .execute_upon_transaction(set_of_sql_statements);

        match result {
            Err(Error::SqliteFailure(_, err_msg_opt)) => {
                assert_eq!(err_msg_opt, Some("no such table: foo".to_string()))
            }
            x => panic!("we expected SqliteFailure(..) but got: {:?}", x),
        }
        let assert_conn = Connection::open(&db_path).unwrap();
        let assertion: Option<(String, i64)> = assert_conn
            .query_row("SELECT * FROM botanic_garden", [], |row| {
                Ok((row.get(0).unwrap(), row.get(1).unwrap()))
            })
            .optional()
            .unwrap();
        assert_eq!(assertion, None)
        //the table remained empty because an error causes the whole transaction to abort
    }
}
