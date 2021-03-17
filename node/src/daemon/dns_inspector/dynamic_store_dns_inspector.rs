// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.
#![cfg(target_os = "macos")]
use crate::daemon::dns_inspector::dns_inspector::DnsInspector;
use regex::Regex;
use std::collections::HashMap;

use crate::daemon::dns_inspector::DnsInspectionError;
use core_foundation::array::CFArray;
use core_foundation::base::FromVoid;
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::CFPropertyList;
use core_foundation::string::CFString;
use std::net::IpAddr;
use std::str::FromStr;
use system_configuration::dynamic_store::SCDynamicStore;
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

const PRIMARY_SERVICE: &str = "PrimaryService";
const SERVER_ADDRESSES: &str = "ServerAddresses";
const SERVER_ADDRESSES_BAK: &str = "ServerAddressesBak";

pub struct DynamicStoreDnsInspector {
    store: Box<dyn StoreWrapper>,
}

impl DnsInspector for DynamicStoreDnsInspector {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError> {
        let (_, dns_info) = self.get_dns_info()?;
        let active_addresses = match dns_info.get(SERVER_ADDRESSES) {
            None => return Err(DnsInspectionError::NotConnected),
            Some(sa) => sa,
        };
        let ip_vec: Vec<IpAddr> = active_addresses
            .iter()
            .flat_map(|ip_str| IpAddr::from_str(ip_str))
            .collect();
        Ok(ip_vec)
    }
}

impl Default for DynamicStoreDnsInspector {
    fn default() -> Self {
        Self {
            store: Box::new(StoreWrapperReal::new("MASQNode")),
        }
    }
}

impl DynamicStoreDnsInspector {
    pub fn new() -> Self {
        Default::default()
    }

    fn get_dns_info(&self) -> Result<(String, HashMap<String, Vec<String>>), DnsInspectionError> {
        let ipv4_map = match self
            .store
            .get_dictionary_string_cfpl("State:/Network/Global/IPv4")
        {
            Some(m) => m,
            None => {
                return Err(DnsInspectionError::NotConnected);
            }
        };
        let primary_service_cfpl = match ipv4_map.get(PRIMARY_SERVICE) {
            Some(ps) => ps,
            None => {
                return Err(DnsInspectionError::NotConnected);
            }
        };
        let primary_service = match self.store.cfpl_to_string(&primary_service_cfpl) {
            Ok(s) => s,
            Err(_) => {
                return Err(DnsInspectionError::ConfigValueTypeError(
                    "State:/Network/Global/IPv4/PrimaryService".to_string(),
                ))
            }
        };
        let dns_base_path = format!("State:/Network/Service/{}/DNS", primary_service);
        let dns_map = match self.store.get_dictionary_string_cfpl(&dns_base_path[..]) {
            Some(m) => m,
            None => return Err(DnsInspectionError::NotConnected),
        };
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        match self.get_server_addresses(&dns_map, &dns_base_path, &SERVER_ADDRESSES) {
            Err(e) => return Err(e),
            Ok(None) => (),
            Ok(Some(sa)) => {
                result.insert(String::from(SERVER_ADDRESSES), sa);
            }
        }
        if let Ok(Some(sa)) =
            self.get_server_addresses(&dns_map, &dns_base_path, SERVER_ADDRESSES_BAK)
        {
            result.insert(String::from(SERVER_ADDRESSES_BAK), sa);
        }
        Ok((dns_base_path, result))
    }

    fn get_server_addresses(
        &self,
        dns_map: &HashMap<String, CFPropertyList>,
        dns_base_path: &str,
        dns_leaf: &str,
    ) -> Result<Option<Vec<String>>, DnsInspectionError> {
        let server_addresses_cfpl = match dns_map.get(dns_leaf) {
            Some(sa) => sa,
            None => return Ok(None),
        };
        let server_address_cfpls = match self.store.cfpl_to_vec(&server_addresses_cfpl) {
            Ok(sa) => sa,
            Err(_) => {
                return Err(DnsInspectionError::ConfigValueTypeError(format!(
                    "{}/{}",
                    dns_base_path, dns_leaf
                )));
            }
        };
        if server_address_cfpls.is_empty() {
            return Ok(Some(vec![]));
        }
        let server_address_opts: Vec<Option<String>> = server_address_cfpls
            .into_iter()
            .map(
                |server_address_cfpl| match self.store.cfpl_to_string(&server_address_cfpl) {
                    Ok(sa) => Some(sa),
                    Err(_) => None,
                },
            )
            .collect();
        if server_address_opts.contains(&None) {
            return Err(DnsInspectionError::ConfigValueTypeError(format!(
                "{}/{}",
                dns_base_path, dns_leaf
            )));
        }
        Ok(Some(
            server_address_opts
                .into_iter()
                .map(|opt| opt.expect("Internal error"))
                .collect(),
        ))
    }
}

pub trait StoreWrapper {
    fn get_dictionary_string_cfpl(&self, path: &str) -> Option<HashMap<String, CFPropertyList>>;
    fn set_dictionary_string_cfpl(
        &self,
        path: &str,
        dictionary: HashMap<String, CFPropertyList>,
    ) -> bool;

    fn cfpl_to_vec(&self, cfpl: &CFPropertyList) -> Result<Vec<CFPropertyList>, String>;
    fn cfpl_to_string(&self, cfpl: &CFPropertyList) -> Result<String, String>;
}

pub struct StoreWrapperReal {
    store: SCDynamicStore,
}

impl StoreWrapper for StoreWrapperReal {
    fn get_dictionary_string_cfpl(&self, path: &str) -> Option<HashMap<String, CFPropertyList>> {
        let cf_dictionary_opt = self
            .store
            .get(path)
            .and_then(CFPropertyList::downcast_into::<CFDictionary>);
        if let Some(cfd) = cf_dictionary_opt {
            let cf_dictionary: CFDictionary = cfd;
            let (keys, values) = cf_dictionary.get_keys_and_values();
            let keys_and_values: Vec<(*const libc::c_void, *const libc::c_void)> =
                keys.into_iter().zip(values).collect();
            Some(
                keys_and_values
                    .into_iter()
                    .map(|key_and_value| {
                        let (cf_key, cf_value) = key_and_value;
                        let key = unsafe { CFString::from_void(cf_key).to_string() };
                        (key, unsafe {
                            CFPropertyList::wrap_under_get_rule(cf_value)
                        })
                    })
                    .collect(),
            )
        } else {
            None
        }
    }

    fn set_dictionary_string_cfpl(
        &self,
        path: &str,
        dictionary: HashMap<String, CFPropertyList>,
    ) -> bool {
        let pairs: Vec<(CFString, CFArray)> = dictionary
            .into_iter()
            .flat_map(|(key, cfpl_value)| {
                match CFPropertyList::downcast_into::<CFArray>(cfpl_value) {
                    Some(v) => Some((CFString::from(&key[..]), v)),
                    None => None,
                }
            })
            .collect();
        let dictionary_cfpl = CFDictionary::from_CFType_pairs(pairs.as_slice());
        self.store.set(path, dictionary_cfpl.into_untyped())
    }

    fn cfpl_to_vec(&self, cfpl: &CFPropertyList) -> Result<Vec<CFPropertyList>, String> {
        match CFPropertyList::downcast_into::<CFArray>(cfpl.clone()) {
            Some(cf_array) => {
                let values = cf_array.get_all_values();
                Ok(values
                    .into_iter()
                    .map(|cf_value| unsafe { CFPropertyList::wrap_under_get_rule(cf_value) })
                    .collect())
            }
            None => Err(format!(
                "cfpl_to_vec must be called on a CFArray, not a {}",
                StoreWrapperReal::type_name(cfpl)
            )),
        }
    }

    fn cfpl_to_string(&self, cfpl: &CFPropertyList) -> Result<String, String> {
        match CFPropertyList::downcast_into::<CFString>(cfpl.clone()) {
            Some(cf_string) => Ok(cf_string.to_string()),
            None => Err(format!(
                "cfpl_to_string must be called on a CFString, not a {}",
                StoreWrapperReal::type_name(cfpl)
            )),
        }
    }
}

impl StoreWrapperReal {
    pub fn new(name: &str) -> StoreWrapperReal {
        StoreWrapperReal {
            store: SCDynamicStoreBuilder::new(name).build(),
        }
    }

    pub fn type_name(cfpl: &CFPropertyList) -> String {
        let regex = Regex::new("^\"<(.*?) ").expect("Bad regex");
        match regex.captures(&format!("{:?}", cfpl.as_CFType())[..]) {
            Some(captures) => match captures.get(1) {
                Some(m) => m.as_str().to_string(),
                None => "Unrecognized".to_string(),
            },
            None => "Unrecognized".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::propertylist::CFPropertyListSubClass;
    use core_foundation::string::CFString;
    use std::cell::RefCell;
    use std::sync::Arc;
    use std::sync::Mutex;

    struct StoreWrapperMock {
        get_dictionary_string_cfpl_parameters: Arc<Mutex<Vec<String>>>,
        get_dictionary_string_cfpl_results: RefCell<Vec<Option<HashMap<String, CFPropertyList>>>>,
        set_dictionary_string_cfpl_parameters:
            Arc<Mutex<Vec<(String, HashMap<String, CFPropertyList>)>>>,
        set_dictionary_string_cfpl_results: RefCell<Vec<bool>>,
        cfpl_to_string_parameters: Arc<Mutex<Vec<CFPropertyList>>>,
        cfpl_to_string_results: RefCell<Vec<Result<String, String>>>,
        cfpl_to_vec_parameters: Arc<Mutex<Vec<CFPropertyList>>>,
        cfpl_to_vec_results: RefCell<Vec<Result<Vec<CFPropertyList>, String>>>,
    }

    impl StoreWrapper for StoreWrapperMock {
        fn get_dictionary_string_cfpl(
            &self,
            path: &str,
        ) -> Option<HashMap<String, CFPropertyList>> {
            self.get_dictionary_string_cfpl_parameters
                .lock()
                .unwrap()
                .push(String::from(path));
            self.get_dictionary_string_cfpl_results
                .borrow_mut()
                .remove(0)
        }

        fn set_dictionary_string_cfpl(
            &self,
            path: &str,
            dictionary: HashMap<String, CFPropertyList>,
        ) -> bool {
            self.set_dictionary_string_cfpl_parameters
                .lock()
                .unwrap()
                .push((String::from(path), dictionary.clone()));
            self.set_dictionary_string_cfpl_results
                .borrow_mut()
                .remove(0)
        }

        fn cfpl_to_vec(&self, cfpl: &CFPropertyList) -> Result<Vec<CFPropertyList>, String> {
            self.cfpl_to_vec_parameters
                .lock()
                .unwrap()
                .push(cfpl.clone());
            self.cfpl_to_vec_results.borrow_mut().remove(0)
        }

        fn cfpl_to_string(&self, cfpl: &CFPropertyList) -> Result<String, String> {
            self.cfpl_to_string_parameters
                .lock()
                .unwrap()
                .push(cfpl.clone());
            self.cfpl_to_string_results.borrow_mut().remove(0)
        }
    }

    impl StoreWrapperMock {
        pub fn new() -> StoreWrapperMock {
            StoreWrapperMock {
                get_dictionary_string_cfpl_parameters: Arc::new(Mutex::new(vec![])),
                get_dictionary_string_cfpl_results: RefCell::new(vec![]),
                set_dictionary_string_cfpl_parameters: Arc::new(Mutex::new(vec![])),
                set_dictionary_string_cfpl_results: RefCell::new(vec![]),
                cfpl_to_string_parameters: Arc::new(Mutex::new(vec![])),
                cfpl_to_string_results: RefCell::new(vec![]),
                cfpl_to_vec_parameters: Arc::new(Mutex::new(vec![])),
                cfpl_to_vec_results: RefCell::new(vec![]),
            }
        }

        pub fn get_dictionary_string_cfpl_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<String>>>,
        ) -> StoreWrapperMock {
            self.get_dictionary_string_cfpl_parameters = parameters.clone();
            self
        }

        pub fn get_dictionary_string_cfpl_result(
            self,
            result: Option<HashMap<String, CFPropertyList>>,
        ) -> StoreWrapperMock {
            self.get_dictionary_string_cfpl_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn set_dictionary_string_cfpl_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(String, HashMap<String, CFPropertyList>)>>>,
        ) -> StoreWrapperMock {
            self.set_dictionary_string_cfpl_parameters = parameters.clone();
            self
        }

        pub fn set_dictionary_string_cfpl_result(self, result: bool) -> StoreWrapperMock {
            self.set_dictionary_string_cfpl_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn cfpl_to_string_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<CFPropertyList>>>,
        ) -> StoreWrapperMock {
            self.cfpl_to_string_parameters = parameters.clone();
            self
        }

        pub fn cfpl_to_string_result(self, result: Result<String, String>) -> StoreWrapperMock {
            self.cfpl_to_string_results.borrow_mut().push(result);
            self
        }

        pub fn cfpl_to_vec_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<CFPropertyList>>>,
        ) -> StoreWrapperMock {
            self.cfpl_to_vec_parameters = parameters.clone();
            self
        }

        pub fn cfpl_to_vec_result(
            self,
            result: Result<Vec<CFPropertyList>, String>,
        ) -> StoreWrapperMock {
            self.cfpl_to_vec_results.borrow_mut().push(result);
            self
        }
    }

    #[test]
    fn cfpl_to_vec_when_not_a_cf_array_should_result_in_error() {
        let subject = StoreWrapperReal::new("unit-test");
        let item = CFBoolean::true_value().to_CFPropertyList();

        let result = subject.cfpl_to_vec(&item).err().unwrap();

        assert_eq!(
            result,
            String::from("cfpl_to_vec must be called on a CFArray, not a CFBoolean")
        );
    }

    #[test]
    fn cfpl_to_string_when_not_a_cf_string_should_result_in_error() {
        let subject = StoreWrapperReal::new("unit-test");
        let item = CFBoolean::true_value().to_CFPropertyList();

        let result = subject.cfpl_to_string(&item).err().unwrap();

        assert_eq!(
            result,
            String::from("cfpl_to_string must be called on a CFString, not a CFBoolean")
        );
    }

    #[test]
    fn inspect_complains_if_root_path_doesnt_exist() {
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn inspect_complains_if_primary_service_doesnt_exist() {
        let ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(Some(ipv4_map));
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn inspect_complains_if_primary_service_is_not_a_string() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFBoolean::true_value().to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Err(String::from("not a string")));
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(
            result,
            Err(DnsInspectionError::ConfigValueTypeError(
                "State:/Network/Global/IPv4/PrimaryService".to_string()
            ))
        );
    }

    #[test]
    fn inspect_complains_if_dns_path_does_not_exist() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn inspect_complains_if_dns_path_has_no_server_addresses() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map));
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn inspect_complains_if_dns_settings_are_not_in_an_array() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let bad_cfpl = CFBoolean::from(true).to_CFPropertyList();
        server_addresses_map.insert(String::from(SERVER_ADDRESSES), bad_cfpl.clone());
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Err(String::from("boolean, not array")));
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(
            result,
            Err(DnsInspectionError::ConfigValueTypeError(String::from(
                "State:/Network/Service/booga/DNS/ServerAddresses"
            )))
        );
    }

    #[test]
    fn inspect_complains_if_dns_settings_are_not_an_array_of_strings() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let bad_server_addresses = &[CFBoolean::from(true)];
        let server_addresses_cfpl = CFArray::from_CFTypes(bad_server_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            server_addresses_cfpl.clone(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Err(String::from("Not a string")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![CFBoolean::from(true).to_CFPropertyList()]));
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect();

        assert_eq!(
            result,
            Err(DnsInspectionError::ConfigValueTypeError(String::from(
                "State:/Network/Service/booga/DNS/ServerAddresses"
            )))
        );
    }

    #[test]
    fn inspect_works_if_everything_is_copacetic() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        let primary_service_cfpl = CFString::from_static_string("booga").to_CFPropertyList();
        ipv4_map.insert(String::from(PRIMARY_SERVICE), primary_service_cfpl);
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let server_addresses = &[
            CFString::from_static_string("1.2.3.4"),
            CFString::from_static_string("5.6.7.8"),
        ];
        let server_addresses_cfpl = CFArray::from_CFTypes(server_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            server_addresses_cfpl.clone(),
        );
        let get_dictionary_string_cfpl_parameters: Arc<Mutex<Vec<String>>> =
            Arc::new(Mutex::new(vec![]));
        let set_dictionary_string_cfpl_parameters_arc = Arc::new(Mutex::new(vec![]));
        let cfpl_to_string_parameters = Arc::new(Mutex::new(vec![]));
        let cfpl_to_vec_parameters = Arc::new(Mutex::new(vec![]));
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_parameters(&get_dictionary_string_cfpl_parameters)
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_parameters(&cfpl_to_string_parameters)
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Ok(String::from("1.2.3.4")))
            .cfpl_to_string_result(Ok(String::from("5.6.7.8")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_parameters(&cfpl_to_vec_parameters)
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("1.2.3.4").to_CFPropertyList(),
                CFString::from_static_string("5.6.7.8").to_CFPropertyList(),
            ]))
            .set_dictionary_string_cfpl_parameters(&set_dictionary_string_cfpl_parameters_arc)
            .set_dictionary_string_cfpl_result(true);
        let mut subject = DynamicStoreDnsInspector::new();
        subject.store = Box::new(store);

        let result = subject.inspect().unwrap();

        assert_eq!(
            result,
            vec![
                IpAddr::from_str("1.2.3.4").unwrap(),
                IpAddr::from_str("5.6.7.8").unwrap(),
            ]
        );
    }
}
