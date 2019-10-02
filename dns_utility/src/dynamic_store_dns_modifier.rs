// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
#![cfg(target_os = "macos")]
use crate::dns_modifier::DnsModifier;
use libc;
use regex::Regex;
use std::collections::HashMap;
use std::iter::FromIterator;

use core_foundation::array::CFArray;
use core_foundation::base::FromVoid;
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::CFPropertyList;
use core_foundation::propertylist::CFPropertyListSubClass;
use core_foundation::string::CFString;
use std::io::Write;
use system_configuration::dynamic_store::SCDynamicStore;
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

const PRIMARY_SERVICE: &str = "PrimaryService";
const SERVER_ADDRESSES: &str = "ServerAddresses";
const SERVER_ADDRESSES_BAK: &str = "ServerAddressesBak";

pub struct DynamicStoreDnsModifier {
    store: Box<dyn StoreWrapper>,
}

impl DnsModifier for DynamicStoreDnsModifier {
    fn type_name(&self) -> &'static str {
        "DynamicStoreDnsModifier"
    }

    fn subvert(&self) -> Result<(), String> {
        let (dns_base_path, dns_info) = self.get_dns_info(true)?;
        let result = match self.subvert_contents(dns_info) {
            Err(e) => return Err(e),
            Ok(None) => return Ok(()),
            Ok(Some(c)) => c,
        };
        self.set_dns_info(dns_base_path, result)
    }

    fn revert(&self) -> Result<(), String> {
        let (dns_base_path, dns_info) = self.get_dns_info(true)?;
        let result = match self.revert_contents(dns_info) {
            Err(e) => return Err(e),
            Ok(None) => return Ok(()),
            Ok(Some(c)) => c,
        };
        self.set_dns_info(dns_base_path, result)
    }

    fn inspect(&self, stdout: &mut (dyn Write + Send)) -> Result<(), String> {
        let (_, dns_info) = self.get_dns_info(false)?;
        let active_addresses = match dns_info.get(SERVER_ADDRESSES) {
            None => return Err(String::from("This system has no DNS settings")),
            Some(sa) => sa,
        };
        let output = active_addresses.join("\n");
        writeln!(stdout, "{}", output).expect("write is broken");
        Ok(())
    }
}

impl Default for DynamicStoreDnsModifier {
    fn default() -> Self {
        Self {
            store: Box::new(StoreWrapperReal::new("MASQNode")),
        }
    }
}

impl DynamicStoreDnsModifier {
    pub fn new() -> Self {
        Default::default()
    }

    fn get_dns_info(
        &self,
        for_write: bool,
    ) -> Result<(String, HashMap<String, Vec<String>>), String> {
        let ipv4_map = match self
            .store
            .get_dictionary_string_cfpl("State:/Network/Global/IPv4")
        {
            Some(m) => m,
            None => {
                return Err(DynamicStoreDnsModifier::process_msg(
                    "Dynamic-Store path State:/Network/Global/IPv4 not found",
                    for_write,
                ));
            }
        };
        let primary_service_cfpl = match ipv4_map.get(PRIMARY_SERVICE) {
            Some(ps) => ps,
            None => {
                return Err(DynamicStoreDnsModifier::process_msg(
                    "Dynamic-Store path State:/Network/Global/IPv4/PrimaryService not found",
                    for_write,
                ));
            }
        };
        let primary_service =
            match self.store.cfpl_to_string(&primary_service_cfpl) {
                Ok(s) => s,
                Err(_) => return Err(DynamicStoreDnsModifier::process_msg(
                    "Dynamic-Store path State:/Network/Global/IPv4/PrimaryService is not a string",
                    for_write,
                )),
            };
        let dns_base_path = format!("State:/Network/Service/{}/DNS", primary_service);
        let dns_map = match self.store.get_dictionary_string_cfpl(&dns_base_path[..]) {
            Some(m) => m,
            None => {
                return Err(DynamicStoreDnsModifier::process_msg(
                    "This system has no DNS settings",
                    for_write,
                ));
            }
        };
        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        match self.get_server_addresses(&dns_map, &dns_base_path, &SERVER_ADDRESSES, for_write) {
            Err(e) => return Err(e),
            Ok(None) => (),
            Ok(Some(sa)) => {
                result.insert(String::from(SERVER_ADDRESSES), sa);
            }
        }
        if let Ok(Some(sa)) =
            self.get_server_addresses(&dns_map, &dns_base_path, SERVER_ADDRESSES_BAK, for_write)
        {
            result.insert(String::from(SERVER_ADDRESSES_BAK), sa);
        }
        Ok((dns_base_path, result))
    }

    fn process_msg(msg: &str, for_write: bool) -> String {
        if for_write {
            format!("{}; DNS settings cannot be modified", msg)
        } else {
            msg.to_string()
        }
    }

    fn set_dns_info(
        &self,
        dns_base_path: String,
        dns_info: HashMap<String, Vec<String>>,
    ) -> Result<(), String> {
        let keys_and_values: Vec<(String, CFPropertyList)> = dns_info
            .into_iter()
            .map(|(key, value)| {
                let cfvalues: Vec<CFString> = value
                    .into_iter()
                    .map(|address| CFString::from(&address[..]))
                    .collect();
                (
                    key,
                    CFArray::from_CFTypes(cfvalues.as_slice())
                        .to_untyped()
                        .to_CFPropertyList(),
                )
            })
            .collect();

        if self.store.set_dictionary_string_cfpl(
            &dns_base_path[..],
            HashMap::from_iter(keys_and_values.into_iter()),
        ) {
            Ok(())
        } else {
            Err(String::from(
                "Error changing DNS settings. Are you sure you ran me with sudo?",
            ))
        }
    }

    fn subvert_contents(
        &self,
        contents: HashMap<String, Vec<String>>,
    ) -> Result<Option<HashMap<String, Vec<String>>>, String> {
        let (active_addresses, first_address) = match self.get_active_addresses_and_first(&contents)
        {
            Err(e) => return Err(e),
            Ok(p) => p,
        };
        if first_address == "127.0.0.1" {
            return Ok(None);
        }
        if active_addresses.contains(&String::from("127.0.0.1")) {
            return Err(String::from(
                "This system's DNS settings don't make sense; aborting",
            ));
        }
        let mut result = HashMap::new();
        result.insert(
            String::from(SERVER_ADDRESSES),
            vec![String::from("127.0.0.1")],
        );
        result.insert(String::from(SERVER_ADDRESSES_BAK), active_addresses.clone());
        Ok(Some(result))
    }

    fn revert_contents(
        &self,
        contents: HashMap<String, Vec<String>>,
    ) -> Result<Option<HashMap<String, Vec<String>>>, String> {
        let (_, first_address) = match self.get_active_addresses_and_first(&contents) {
            Err(e) => return Err(e),
            Ok(p) => p,
        };
        if first_address != "127.0.0.1" {
            return Ok(None);
        }
        let backup_addresses = match contents.get(SERVER_ADDRESSES_BAK) {
            None => {
                return Err(String::from(
                    "This system has no backed-up DNS settings to restore; aborting",
                ));
            }
            Some(sa) => sa,
        };
        Ok(Some(HashMap::from_iter(vec![(
            String::from(SERVER_ADDRESSES),
            backup_addresses.clone(),
        )])))
    }

    fn get_active_addresses_and_first(
        &self,
        contents: &HashMap<String, Vec<String>>,
    ) -> Result<(Vec<String>, String), String> {
        let active_addresses = match contents.get(SERVER_ADDRESSES) {
            None => {
                return Err(String::from(
                    "This system has no DNS settings to modify; aborting",
                ));
            }
            Some(sa) => sa,
        };
        let first_address = match active_addresses.first () {
            None => return Err(String::from("This system does not appear to be connected to a network; DNS settings cannot be modified")),
            Some (fa) => fa,
        };
        Ok((active_addresses.clone(), first_address.clone()))
    }

    fn get_server_addresses(
        &self,
        dns_map: &HashMap<String, CFPropertyList>,
        dns_base_path: &str,
        dns_leaf: &str,
        for_write: bool,
    ) -> Result<Option<Vec<String>>, String> {
        let server_addresses_cfpl = match dns_map.get(dns_leaf) {
            Some(sa) => sa,
            None => return Ok(None),
        };
        let server_address_cfpls = match self.store.cfpl_to_vec(&server_addresses_cfpl) {
            Ok(sa) => sa,
            Err(_) => {
                return Err(DynamicStoreDnsModifier::process_msg(
                    format!(
                        "Dynamic-Store path {}/{} is not an array",
                        dns_base_path, dns_leaf
                    )
                    .as_str(),
                    for_write,
                ));
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
            return Err(DynamicStoreDnsModifier::process_msg(
                format!(
                    "Dynamic-Store path {}/{} is not an array of strings",
                    dns_base_path, dns_leaf
                )
                .as_str(),
                for_write,
            ));
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
    use crate::fake_stream_holder::FakeStreamHolder;
    use crate::utils::get_parameters_from;
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
    fn subvert_complains_if_root_path_doesnt_exist() {
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Global/IPv4 not found; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_primary_service_doesnt_exist() {
        let ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(Some(ipv4_map));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Global/IPv4/PrimaryService not found; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_primary_service_is_not_a_string() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from("PrimaryService"),
            CFBoolean::true_value().to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Err(String::from("not a string")));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Global/IPv4/PrimaryService is not a string; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_dns_path_does_not_exist() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(
            result,
            Err(String::from(
                "This system has no DNS settings; DNS settings cannot be modified"
            ))
        );
    }

    #[test]
    fn subvert_complains_if_dns_path_has_no_server_addresses() {
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(
            result,
            Err(String::from(
                "This system has no DNS settings to modify; aborting"
            ))
        );
    }

    #[test]
    fn subvert_complains_if_dns_settings_are_not_in_an_array() {
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Service/booga/DNS/ServerAddresses is not an array; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_dns_settings_are_empty() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let server_addresses: &[CFString; 0] = &[];
        let server_addresses_cfpl = CFArray::from_CFTypes(server_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            server_addresses_cfpl.clone(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![]));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("This system does not appear to be connected to a network; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_dns_settings_are_not_an_array_of_strings() {
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Service/booga/DNS/ServerAddresses is not an array of strings; DNS settings cannot be modified")));
    }

    #[test]
    fn subvert_complains_if_settings_dont_make_sense() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let server_addresses = &[
            CFString::from_static_string("8.8.8.8"),
            CFString::from_static_string("127.0.0.1"),
        ];
        let server_addresses_cfpl = CFArray::from_CFTypes(server_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            server_addresses_cfpl.clone(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Ok(String::from("8.8.8.8")))
            .cfpl_to_string_result(Ok(String::from("127.0.0.1")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("8.8.8.8").to_CFPropertyList(),
                CFString::from_static_string("127.0.0.1").to_CFPropertyList(),
            ]));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(
            result,
            Err(String::from(
                "This system's DNS settings don't make sense; aborting"
            ))
        );
    }

    #[test]
    fn subvert_backs_off_if_dns_is_already_subverted() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let server_addresses = &[
            CFString::from_static_string("127.0.0.1"),
            CFString::from_static_string("8.8.8.8"),
        ];
        let server_addresses_cfpl = CFArray::from_CFTypes(server_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            server_addresses_cfpl.clone(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Ok(String::from("127.0.0.1")))
            .cfpl_to_string_result(Ok(String::from("8.8.8.8")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("127.0.0.1").to_CFPropertyList(),
                CFString::from_static_string("8.8.8.8").to_CFPropertyList(),
            ]));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn subvert_works_if_everything_is_copacetic() {
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(result, Ok(()));
        assert_eq!(
            get_parameters_from(get_dictionary_string_cfpl_parameters),
            vec!(
                String::from("State:/Network/Global/IPv4"),
                String::from("State:/Network/Service/booga/DNS"),
            )
        );
        let cfpl_to_string_parameter_strings = get_parameters_from(cfpl_to_string_parameters);
        assert!(cfpl_to_string_parameter_strings[0]
            .eq(&CFString::from_static_string("booga").to_CFPropertyList()));
        assert!(cfpl_to_string_parameter_strings[1]
            .eq(&CFString::from_static_string("1.2.3.4").to_CFPropertyList()));
        assert!(cfpl_to_string_parameter_strings[2]
            .eq(&CFString::from_static_string("5.6.7.8").to_CFPropertyList()));
        assert_eq!(cfpl_to_string_parameter_strings.len(), 3);
        assert!(get_parameters_from(cfpl_to_vec_parameters).eq(&vec!(server_addresses_cfpl)));
        let new_server_addresses =
            CFArray::from_CFTypes(&[CFString::from_static_string("127.0.0.1")]);
        let new_backup_server_addresses = CFArray::from_CFTypes(&[
            CFString::from_static_string("1.2.3.4"),
            CFString::from_static_string("5.6.7.8"),
        ]);
        let set_dictionary_string_cfpl_parameters =
            get_parameters_from(set_dictionary_string_cfpl_parameters_arc);
        let &(ref path, ref actual_dnss) = set_dictionary_string_cfpl_parameters
            .first()
            .expect("Method not called");
        assert_eq!(*path, String::from("State:/Network/Service/booga/DNS"));
        compare_cfpls(
            actual_dnss.get(SERVER_ADDRESSES).unwrap(),
            &new_server_addresses.to_untyped().to_CFPropertyList(),
        );
        compare_cfpls(
            actual_dnss.get(SERVER_ADDRESSES_BAK).unwrap(),
            &new_backup_server_addresses.to_untyped().to_CFPropertyList(),
        );
    }

    #[test]
    fn subvert_complains_if_write_fails() {
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
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Ok(String::from("1.2.3.4")))
            .cfpl_to_string_result(Ok(String::from("5.6.7.8")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("1.2.3.4").to_CFPropertyList(),
                CFString::from_static_string("5.6.7.8").to_CFPropertyList(),
            ]))
            .set_dictionary_string_cfpl_result(false);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.subvert();

        assert_eq!(
            result,
            Err(String::from(
                "Error changing DNS settings. Are you sure you ran me with sudo?"
            ))
        );
    }

    #[test]
    fn revert_complains_if_there_is_no_backup() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let dns_map: HashMap<String, CFPropertyList> = HashMap::from_iter(
            vec![(
                String::from(SERVER_ADDRESSES),
                CFArray::from_CFTypes(&[CFString::from_static_string("127.0.0.1")])
                    .to_untyped()
                    .to_CFPropertyList(),
            )]
            .into_iter(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(Some(dns_map))
            .cfpl_to_vec_result(Ok(vec![CFArray::from_CFTypes(&[
                CFString::from_static_string("127.0.0.1"),
            ])
            .to_untyped()
            .to_CFPropertyList()]))
            .cfpl_to_string_result(Ok(String::from("127.0.0.1")));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.revert();

        assert_eq!(
            result,
            Err(String::from(
                "This system has no backed-up DNS settings to restore; aborting"
            ))
        );
    }

    #[test]
    fn revert_backs_off_if_settings_are_already_reverted() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let dns_map: HashMap<String, CFPropertyList> = HashMap::from_iter(
            vec![(
                String::from(SERVER_ADDRESSES),
                CFArray::from_CFTypes(&[CFString::from_static_string("1.2.3.4")])
                    .to_untyped()
                    .to_CFPropertyList(),
            )]
            .into_iter(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(Some(dns_map))
            .cfpl_to_vec_result(Ok(vec![CFArray::from_CFTypes(&[
                CFString::from_static_string("1.2.3.4"),
            ])
            .to_untyped()
            .to_CFPropertyList()]))
            .cfpl_to_string_result(Ok(String::from("1.2.3.4")));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.revert();

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn revert_works_if_everything_is_copacetic() {
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        let primary_service_cfpl = CFString::from_static_string("booga").to_CFPropertyList();
        ipv4_map.insert(String::from(PRIMARY_SERVICE), primary_service_cfpl);
        let mut server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        let active_addresses = &[CFString::from_static_string("127.0.0.1")];
        let active_addresses_cfpl = CFArray::from_CFTypes(active_addresses)
            .to_untyped()
            .to_CFPropertyList();
        let backup_addresses = &[
            CFString::from_static_string("1.2.3.4"),
            CFString::from_static_string("5.6.7.8"),
        ];
        let backup_addresses_cfpl = CFArray::from_CFTypes(backup_addresses)
            .to_untyped()
            .to_CFPropertyList();
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            active_addresses_cfpl.clone(),
        );
        server_addresses_map.insert(
            String::from(SERVER_ADDRESSES_BAK),
            backup_addresses_cfpl.clone(),
        );
        let mut reverted_server_addresses_map: HashMap<String, CFPropertyList> = HashMap::new();
        reverted_server_addresses_map.insert(
            String::from(SERVER_ADDRESSES),
            backup_addresses_cfpl.clone(),
        );
        let set_dictionary_string_cfpl_parameters_arc = Arc::new(Mutex::new(vec![(
            String::from("State:/Network/Service/booga/DNS"),
            reverted_server_addresses_map.clone(),
        )]));
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .cfpl_to_string_result(Ok(String::from("127.0.0.1")))
            .cfpl_to_string_result(Ok(String::from("1.2.3.4")))
            .cfpl_to_string_result(Ok(String::from("5.6.7.8")))
            .get_dictionary_string_cfpl_result(Some(server_addresses_map))
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("127.0.0.1").to_CFPropertyList()
            ]))
            .cfpl_to_vec_result(Ok(vec![
                CFString::from_static_string("1.2.3.4").to_CFPropertyList(),
                CFString::from_static_string("5.6.7.8").to_CFPropertyList(),
            ]))
            .set_dictionary_string_cfpl_parameters(&set_dictionary_string_cfpl_parameters_arc)
            .get_dictionary_string_cfpl_result(Some(reverted_server_addresses_map))
            .set_dictionary_string_cfpl_result(true);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.revert();

        assert_eq!(result, Ok(()));
        let new_server_addresses = CFArray::from_CFTypes(&[
            CFString::from_static_string("1.2.3.4"),
            CFString::from_static_string("5.6.7.8"),
        ]);
        let set_dictionary_string_cfpl_parameters =
            get_parameters_from(set_dictionary_string_cfpl_parameters_arc);
        let &(ref path, ref actual_dnss) = set_dictionary_string_cfpl_parameters
            .first()
            .expect("Method not called");
        assert_eq!(*path, String::from("State:/Network/Service/booga/DNS"));
        assert!(!actual_dnss.contains_key(SERVER_ADDRESSES_BAK));
        compare_cfpls(
            actual_dnss.get(SERVER_ADDRESSES).unwrap(),
            &new_server_addresses.to_untyped().to_CFPropertyList(),
        );
    }

    #[test]
    fn inspect_complains_if_root_path_doesnt_exist() {
        let mut stream_holder = FakeStreamHolder::new();
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result,
            Err(String::from(
                "Dynamic-Store path State:/Network/Global/IPv4 not found"
            ))
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_primary_service_doesnt_exist() {
        let mut stream_holder = FakeStreamHolder::new();
        let ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        let store = StoreWrapperMock::new().get_dictionary_string_cfpl_result(Some(ipv4_map));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result,
            Err(String::from(
                "Dynamic-Store path State:/Network/Global/IPv4/PrimaryService not found"
            ))
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_primary_service_is_not_a_string() {
        let mut stream_holder = FakeStreamHolder::new();
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFBoolean::true_value().to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Err(String::from("not a string")));
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result,
            Err(String::from(
                "Dynamic-Store path State:/Network/Global/IPv4/PrimaryService is not a string"
            ))
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_dns_path_does_not_exist() {
        let mut stream_holder = FakeStreamHolder::new();
        let mut ipv4_map: HashMap<String, CFPropertyList> = HashMap::new();
        ipv4_map.insert(
            String::from(PRIMARY_SERVICE),
            CFString::new("booga").to_CFPropertyList(),
        );
        let store = StoreWrapperMock::new()
            .get_dictionary_string_cfpl_result(Some(ipv4_map))
            .cfpl_to_string_result(Ok(String::from("booga")))
            .get_dictionary_string_cfpl_result(None);
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result, Err(String::from("This system has no DNS settings")));
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_dns_path_has_no_server_addresses() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result, Err(String::from("This system has no DNS settings")));
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_dns_settings_are_not_in_an_array() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Service/booga/DNS/ServerAddresses is not an array")));
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_dns_settings_are_not_an_array_of_strings() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq! (result, Err (String::from ("Dynamic-Store path State:/Network/Service/booga/DNS/ServerAddresses is not an array of strings")));
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_works_if_everything_is_copacetic() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = DynamicStoreDnsModifier::new();
        subject.store = Box::new(store);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            stream_holder.stdout.get_string(),
            String::from("1.2.3.4\n5.6.7.8\n")
        );
        assert_eq!(result.is_ok(), true);
    }

    fn compare_cfpls(a: &CFPropertyList, b: &CFPropertyList) {
        if !a.eq(b) {
            println!("The following two CFPropertyLists were not equal:");
            a.show();
            b.show();
            panic!();
        }
    }
}
