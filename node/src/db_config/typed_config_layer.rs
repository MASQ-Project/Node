// Copyright (c) 2019-2020, MASQ (https://masq.ai). All rights reserved.

use crate::db_config::secure_config_layer::{SecureConfigLayer, SecureConfigLayerError};
use crate::sub_lib::cryptde::PlainData;
use rustc_hex::{FromHex, ToHex};
use crate::database::connection_wrapper::TransactionWrapper;

#[derive(Debug, PartialEq)]
pub enum TypedConfigLayerError {
    NotPresent,
    TypeError,
    PasswordError,
    TransactionError,
    DatabaseError(String),
}

impl From<SecureConfigLayerError> for TypedConfigLayerError {
    fn from(input: SecureConfigLayerError) -> Self {
        match input {
            SecureConfigLayerError::NotPresent => TypedConfigLayerError::NotPresent,
            SecureConfigLayerError::PasswordError => TypedConfigLayerError::PasswordError,
            SecureConfigLayerError::TransactionError => TypedConfigLayerError::TransactionError,
            SecureConfigLayerError::DatabaseError(msg) => TypedConfigLayerError::DatabaseError(msg),
        }
    }
}

pub trait TypedConfigLayer {
    fn get_u64(&self, name: &str, db_password_opt: Option<&str>) -> Result<Option<u64>, TypedConfigLayerError>;
    fn get_bytes(&self, name: &str, db_password_opt: Option<&str>) -> Result<Option<PlainData>, TypedConfigLayerError>;
    fn set_u64(&self, name: &str, value: Option<u64>, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
    fn set_bytes(&self, name: &str, value: Option<&PlainData>, db_password_opt: Option<&str>) -> Result<(), TypedConfigLayerError>;
}

struct TypedConfigLayerReal {
    scl: Box<dyn SecureConfigLayer>,
}

impl TypedConfigLayer for TypedConfigLayerReal {
    fn check_password(&self, db_password_opt: Option<&str>) -> Result<bool, TypedConfigLayerError> {
        Ok(self.scl.check_password(db_password_opt)?)
    }

    fn change_password(
        &mut self,
        old_password_opt: Option<&str>,
        new_password: &str,
    ) -> Result<(), TypedConfigLayerError> {
        Ok(self.scl.change_password(old_password_opt, new_password)?)
    }

    fn get_all(
        &self,
        db_password_opt: Option<&str>,
    ) -> Result<Vec<(String, Option<String>)>, TypedConfigLayerError> {
        Ok(self.scl.get_all(db_password_opt)?)
    }

    fn get_string(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<String>, TypedConfigLayerError> {
        Ok(self.scl.get(name, db_password_opt)?)
    }

    fn get_u64(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<u64>, TypedConfigLayerError> {
        match self.scl.get (name, db_password_opt)? {
            Some (string) => match string.parse::<u64>() {
                Ok(number) => Ok(Some(number)),
                Err(_) => Err(TypedConfigLayerError::TypeError),
            },
            None => Ok(None),
        }
    }

    fn get_bytes(
        &self,
        name: &str,
        db_password_opt: Option<&str>,
    ) -> Result<Option<PlainData>, TypedConfigLayerError> {
        match self.scl.get (name, db_password_opt)? {
            Some (string) => match string.from_hex::<Vec<u8>>() {
                Ok(bytes) => Ok (Some (PlainData::from (bytes))),
                Err(_) => Err (TypedConfigLayerError::TypeError),
            },
            None => Ok (None),
        }
    }

    fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a> {
        self.scl.transaction()
    }

    fn set_string(
        &self,
        name: &str,
        value_opt: Option<&str>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        Ok(self.scl.set (name, value_opt, db_password_opt)?)
    }

    fn set_u64(
        &self,
        name: &str,
        value_opt: Option<u64>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        match value_opt {
            Some (number) => Ok (self.scl.set (name, Some (&format!("{}", number)), db_password_opt)?),
            None => Ok(self.scl.set (name, None, db_password_opt)?),
        }
    }

    fn set_bytes(
        &self,
        name: &str,
        value_opt: Option<&PlainData>,
        db_password_opt: Option<&str>,
    ) -> Result<(), TypedConfigLayerError> {
        match value_opt {
            Some (bytes) => Ok (self.scl.set (name, Some (&bytes.as_slice().to_hex::<String>()), db_password_opt)?),
            None => Ok(self.scl.set (name, None, db_password_opt)?),
        }
    }
}

impl TypedConfigLayerReal {
    pub fn new(dao: Box<dyn SecureConfigLayer>) -> Self {
        Self {
            scl: dao,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_lib::cryptde::PlainData;
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use crate::db_config::mocks::TransactionWrapperMock;
    use crate::db_config::secure_config_layer::SCLActor;
    use rustc_hex::ToHex;
    use crate::database::connection_wrapper::TransactionWrapper;

    struct SecureConfigLayerMock {
        check_password_params: Arc<Mutex<Vec<Option<String>>>>,
        check_password_results: RefCell<Vec<Result<bool, SecureConfigLayerError>>>,
        change_password_params: Arc<Mutex<Vec<(Option<String>, String)>>>,
        change_password_results: RefCell<Vec<Result<(), SecureConfigLayerError>>>,
        get_all_params: Arc<Mutex<Vec<Option<String>>>>,
        get_all_results: RefCell<Vec<Result<Vec<(String, Option<String>)>, SecureConfigLayerError>>>,
        get_params: Arc<Mutex<Vec<(String, Option<String>)>>>,
        get_results: RefCell<Vec<Result<Option<String>, SecureConfigLayerError>>>,
        transaction_results: RefCell<Vec<TransactionWrapperMock>>,
        set_params: Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>,
        set_results: RefCell<Vec<Result<(), SecureConfigLayerError>>>,
    }

    impl SecureConfigLayer for SecureConfigLayerMock {
        fn check_password(
            &self,
            db_password_opt: Option<&str>,
        ) -> Result<bool, SecureConfigLayerError> {
            self.check_password_params.lock().unwrap().push (db_password_opt.map (|x| x.to_string()));
            self.check_password_results.borrow_mut().remove(0)
        }

        fn change_password(
            &mut self,
            old_password_opt: Option<&str>,
            new_password: &str,
        ) -> Result<(), SecureConfigLayerError> {
            self.change_password_params.lock().unwrap().push ((old_password_opt.map (|x| x.to_string()), new_password.to_string()));
            self.change_password_results.borrow_mut().remove(0)
        }

        fn get_all(
            &self,
            db_password_opt: Option<&str>,
        ) -> Result<Vec<(String, Option<String>)>, SecureConfigLayerError> {
            self.get_all_params.lock().unwrap().push (db_password_opt.map (|x| x.to_string()));
            self.get_all_results.borrow_mut().remove(0)
        }

        fn get(
            &self,
            name: &str,
            db_password_opt: Option<&str>,
        ) -> Result<Option<String>, SecureConfigLayerError> {
            self.get_params.lock().unwrap().push ((name.to_string(), db_password_opt.map (|x| x.to_string())));
            self.get_results.borrow_mut().remove(0)
        }

        fn transaction<'a>(&'a mut self) -> Box<dyn TransactionWrapper<'a> + 'a> {
            Box::new(self.transaction_results.borrow_mut().remove(0))
        }

        fn set(
            &self,
            name: &str,
            value_opt: Option<&str>,
            db_password_opt: Option<&str>,
        ) -> Result<(), SecureConfigLayerError> {
            self.set_params.lock().unwrap().push ((name.to_string(), value_opt.map (|x| x.to_string()), db_password_opt.map (|x| x.to_string())));
            self.set_results.borrow_mut().remove(0)
        }

        fn set_informed(
            &self,
            name: &str,
            value: Option<&str>,
            db_password_opt: Option<&str>,
            act: Box<dyn SCLActor>
        ) -> Result<(), SecureConfigLayerError> {
            unimplemented!()
        }
    }

    impl SecureConfigLayerMock {
        fn new() -> Self {
            Self {
                check_password_params: Arc::new(Mutex::new(vec![])),
                check_password_results: RefCell::new(vec![]),
                change_password_params: Arc::new(Mutex::new(vec![])),
                change_password_results: RefCell::new(vec![]),
                get_all_params: Arc::new(Mutex::new(vec![])),
                get_all_results: RefCell::new(vec![]),
                get_params: Arc::new(Mutex::new(vec![])),
                get_results: RefCell::new(vec![]),
                transaction_results: RefCell::new(vec![]),
                set_params: Arc::new(Mutex::new(vec![])),
                set_results: RefCell::new(vec![]),
            }
        }

        fn check_password_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            self.check_password_params = params.clone();
            self
        }

        fn check_password_result(self, result: Result<bool, SecureConfigLayerError>) -> Self {
            self.check_password_results.borrow_mut().push (result);
            self
        }

        fn change_password_params(
            mut self,
            params: &Arc<Mutex<Vec<(Option<String>, String)>>>,
        ) -> Self {
            self.change_password_params = params.clone();
            self
        }

        fn change_password_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            self.change_password_results.borrow_mut().push (result);
            self
        }

        fn get_all_params(mut self, params: &Arc<Mutex<Vec<Option<String>>>>) -> Self {
            self.get_all_params = params.clone();
            self
        }

        fn get_all_result(
            self,
            result: Result<Vec<(String, Option<String>)>, SecureConfigLayerError>,
        ) -> Self {
            self.get_all_results.borrow_mut().push (result);
            self
        }

        fn get_params(mut self, params: &Arc<Mutex<Vec<(String, Option<String>)>>>) -> Self {
            self.get_params = params.clone();
            self
        }

        fn get_result(self, result: Result<Option<String>, SecureConfigLayerError>) -> Self {
            self.get_results.borrow_mut().push (result);
            self
        }

        fn transaction_result(self, result: TransactionWrapperMock) -> Self {
            self.transaction_results.borrow_mut().push (result);
            self
        }

        fn set_params(
            mut self,
            params: &Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>,
        ) -> Self {
            self.set_params = params.clone();
            self
        }

        fn set_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            self.set_results.borrow_mut().push (result);
            self
        }

        fn set_informed_params(
            self,
            params: &Arc<Mutex<Vec<(String, Option<String>, Option<String>, Box<dyn SCLActor>)>>>,
        ) -> Self {
            unimplemented!()
        }

        fn set_informed_result(self, result: Result<(), SecureConfigLayerError>) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn typed_config_layer_error_from_secure_config_layer_error() {
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::NotPresent),
            TypedConfigLayerError::NotPresent
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::PasswordError),
            TypedConfigLayerError::PasswordError
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::TransactionError),
            TypedConfigLayerError::TransactionError
        );
        assert_eq!(
            TypedConfigLayerError::from(SecureConfigLayerError::DatabaseError("booga".to_string())),
            TypedConfigLayerError::DatabaseError("booga".to_string())
        );
    }

    #[test]
    fn check_password_passes_through() {
        let check_password_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .check_password_params(&check_password_params_arc)
            .check_password_result(Ok(true));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.check_password(Some("password"));

        assert_eq!(result, Ok(true));
        let check_password_params = check_password_params_arc.lock().unwrap();
        assert_eq!(
            *check_password_params,
            vec![Some("password".to_string())]
        )
    }

    #[test]
    fn change_password_passes_through() {
        let change_password_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .change_password_params(&change_password_params_arc)
            .change_password_result(Err(SecureConfigLayerError::TransactionError));
        let mut subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.change_password(None, "password");

        assert_eq!(result, Err(TypedConfigLayerError::TransactionError));
        let change_password_params = change_password_params_arc.lock().unwrap();
        assert_eq!(
            *change_password_params,
            vec![(None, "password".to_string())]
        )
    }

    #[test]
    fn get_all_passes_through() {
        let get_all_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_all_params(&get_all_params_arc)
            .get_all_result(Err(SecureConfigLayerError::PasswordError));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_all(Some ("password"));

        assert_eq!(result, Err(TypedConfigLayerError::PasswordError));
        let get_all_params = get_all_params_arc.lock().unwrap();
        assert_eq!(
            *get_all_params,
            vec![Some ("password".to_string())]
        )
    }

    #[test]
    fn get_string_passes_through_to_get() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(Some ("booga".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_string("parameter_name", Some("password"));

        assert_eq!(result, Ok(Some("booga".to_string())));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![("parameter_name".to_string(), Some("password".to_string()))]
        )
    }

    #[test]
    fn get_u64_handles_present_good_value() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(Some ("1234".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_u64("parameter_name", Some("password"));

        assert_eq! (result, Ok(Some (1234)));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(*get_params, vec![("parameter_name".to_string(), Some ("password".to_string()))])
    }

    #[test]
    fn get_u64_handles_present_bad_value() {
        let scl = SecureConfigLayerMock::new()
            .get_result(Ok(Some ("booga".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_u64("parameter_name", Some("password"));

        assert_eq! (result, Err(TypedConfigLayerError::TypeError));
    }

    #[test]
    fn get_u64_handles_absent_value() {
        let scl = SecureConfigLayerMock::new()
            .get_result(Ok(None));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_u64("parameter_name", Some("password"));

        assert_eq! (result, Ok(None));
    }

    #[test]
    fn get_bytes_handles_present_good_value() {
        let get_params_arc = Arc::new(Mutex::new(vec![]));
        let value = PlainData::new (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let value_string: String = value.as_slice().to_hex();
        let scl = SecureConfigLayerMock::new()
            .get_params(&get_params_arc)
            .get_result(Ok(Some (value_string)));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_bytes("parameter_name", Some("password"));

        assert_eq!(result, Ok(Some(value)));
        let get_params = get_params_arc.lock().unwrap();
        assert_eq!(
            *get_params,
            vec![("parameter_name".to_string(), Some("password".to_string()))]
        )
    }

    #[test]
    fn get_bytes_handles_present_bad_value() {
        let scl = SecureConfigLayerMock::new()
            .get_result(Ok(Some ("I am not a valid hexadecimal string".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_bytes("parameter_name", Some("password"));

        assert_eq!(result, Err(TypedConfigLayerError::TypeError));
    }

    #[test]
    fn get_bytes_handles_absent_value() {
        let scl = SecureConfigLayerMock::new()
            .get_result(Ok(None));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.get_bytes("parameter_name", Some("password"));

        assert_eq! (result, Ok(None));
    }

    #[test]
    fn transaction_passes_through() {
        let transaction = TransactionWrapperMock::new();
        let committed_arc = transaction.committed_arc();
        let scl = SecureConfigLayerMock::new()
            .transaction_result(transaction);
        let mut subject = TypedConfigLayerReal::new(Box::new(scl));

        let mut result = subject.transaction();

        {
            let committed = committed_arc.lock().unwrap();
            assert_eq! (*committed, None);
        }
        result.commit();
        {
            let committed = committed_arc.lock().unwrap();
            assert_eq! (*committed, Some(true));
        }
    }

    #[test]
    fn set_string_passes_through_to_set() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.set_string("parameter_name", Some ("value"), Some("password"));

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("parameter_name".to_string(), Some ("value".to_string()), Some("password".to_string()))]
        )
    }

    #[test]
    fn set_u64_handles_present_value() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .set_params(&set_params_arc)
            .set_result(Err(SecureConfigLayerError::TransactionError));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.set_u64("parameter_name", Some (1234), Some("password"));

        assert_eq!(result, Err(TypedConfigLayerError::TransactionError));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("parameter_name".to_string(), Some ("1234".to_string()), Some("password".to_string()))]
        )
    }

    #[test]
    fn set_u64_handles_absent_value() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .set_params(&set_params_arc)
            .set_result(Err(SecureConfigLayerError::DatabaseError ("booga".to_string())));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.set_u64("parameter_name", None, Some("password"));

        assert_eq!(result, Err(TypedConfigLayerError::DatabaseError ("booga".to_string())));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("parameter_name".to_string(), None, Some("password".to_string()))]
        )
    }

    #[test]
    fn set_bytes_handles_present_value() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let bytes = PlainData::new (&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let bytes_hex: String = bytes.as_slice().to_hex();
        let scl = SecureConfigLayerMock::new()
            .set_params(&set_params_arc)
            .set_result(Ok(()));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.set_bytes("parameter_name", Some (&bytes), Some("password"));

        assert_eq!(result, Ok(()));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("parameter_name".to_string(), Some (bytes_hex), Some("password".to_string()))]
        )
    }

    #[test]
    fn set_bytes_handles_absent_value() {
        let set_params_arc = Arc::new(Mutex::new(vec![]));
        let scl = SecureConfigLayerMock::new()
            .set_params(&set_params_arc)
            .set_result(Err(SecureConfigLayerError::NotPresent));
        let subject = TypedConfigLayerReal::new(Box::new(scl));

        let result = subject.set_bytes("parameter_name", None, Some("password"));

        assert_eq!(result, Err(TypedConfigLayerError::NotPresent));
        let set_params = set_params_arc.lock().unwrap();
        assert_eq!(
            *set_params,
            vec![("parameter_name".to_string(), None, Some("password".to_string()))]
        )
    }
}
