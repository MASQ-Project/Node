// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use dns_modifier::DnsModifier;

#[cfg (windows)]
use winreg::RegKey;
#[cfg (windows)]
use winreg::enums::*;

#[cfg (not (windows))]
const KEY_ALL_ACCESS: u32 = 1234;

const NOT_FOUND: i32 = 2;
const PERMISSION_DENIED: i32 = 5;

pub struct WinRegDnsModifier {
    hive: Box<RegKeyTrait>,
}

impl DnsModifier for WinRegDnsModifier {
    fn type_name (&self) -> &'static str {
        "WinRegDnsModifier"
    }

    fn subvert(&self) -> Result<(), String> {
        let interfaces = self.find_interfaces_to_subvert ()?;
        let begin_overhang: Vec<Box<RegKeyTrait>> = vec! ();
        let begin_error_opt: Option<String> = None;
        let (overhang, error_opt) = interfaces.into_iter ()
            .fold ((begin_overhang, begin_error_opt), |(overhang, error_opt), interface| {
                if error_opt.is_some () {
                    (overhang, error_opt)
                }
                else {
                    match self.subvert_interface (&interface) {
                        Ok (_) => (plus (overhang, interface), error_opt),
                        Err (msg) => (plus (overhang, interface), Some (msg))
                    }
                }
            });
        match error_opt {
            Some (msg) => {
                overhang.into_iter ().for_each (|interface| {self.roll_back_subvert (&interface)});
                Err (msg)
            },
            None => Ok (())
        }
    }

    fn revert(&self) -> Result<(), String> {
        let interfaces = self.find_interfaces_to_revert ()?;
        let begin_overhang: Vec<Box<RegKeyTrait>> = vec! ();
        let begin_error_opt: Option<String> = None;
        let (overhang, error_opt) = interfaces.into_iter ()
            .fold ((begin_overhang, begin_error_opt), |(overhang, error_opt), interface| {
                if error_opt.is_some () {
                    (overhang, error_opt)
                }
                else {
                    match self.revert_interface (&interface) {
                        Ok (_) => (plus (overhang, interface), error_opt),
                        Err (msg) => (plus (overhang, interface), Some (msg))
                    }
                }
            });
        match error_opt {
            Some (msg) => {
                overhang.into_iter ().for_each (|interface| {self.roll_back_revert (&interface)});
                Err (msg)
            },
            None => Ok (())
        }
    }
}

impl WinRegDnsModifier {
    #[cfg (windows)]
    pub fn new () -> WinRegDnsModifier {
        WinRegDnsModifier {
            hive: Box::new (RegKeyReal::new (RegKey::predef (HKEY_LOCAL_MACHINE))),
        }
    }

    #[cfg (not (windows))]
    pub fn new () -> WinRegDnsModifier {
        WinRegDnsModifier {
            hive: Box::new (RegKeyReal{}),
        }
    }

    fn find_interfaces_to_subvert(&self) -> Result<Vec<Box<RegKeyTrait>>, String> {
        let interface_key = self.handle_reg_error(self.hive.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", KEY_ALL_ACCESS))?;
        let gateway_interfaces: Vec<Box<RegKeyTrait>> = interface_key.enum_keys ().into_iter ()
            .flat_map (|k| {k})
            .flat_map (| interface_name | {
                interface_key.open_subkey_with_flags (&interface_name[..], KEY_ALL_ACCESS)
            })
            .filter (| interface | {
                WinRegDnsModifier::get_default_gateway (interface).is_some ()
                && interface.get_value ("NameServer").is_ok ()
            })
            .collect ();
        if gateway_interfaces.is_empty() { return Err(String::from("This system has no accessible network interfaces configured with default gateways and DNS servers")) }
        let distinct_gateway_ips: HashSet<String> = gateway_interfaces.iter ()
            .flat_map (|interface| {
                WinRegDnsModifier::get_default_gateway (interface)
            })
            .collect ();
        if distinct_gateway_ips.len () > 1 {
            return Err (String::from (format! ("This system has {} active network interfaces configured with {} different default gateways. Manual configuration required.",
                gateway_interfaces.len (), distinct_gateway_ips.len ())))
        }
        Ok (gateway_interfaces)
    }

    fn find_interfaces_to_revert(&self) -> Result<Vec<Box<RegKeyTrait>>, String> {
        let interface_key = self.handle_reg_error(self.hive.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", KEY_ALL_ACCESS))?;
        let revertible_interfaces = interface_key.enum_keys ().into_iter ()
            .flat_map (|k| {k})
            .flat_map (| interface_name | {
                interface_key.open_subkey_with_flags (&interface_name[..], KEY_ALL_ACCESS)
            })
            .filter (|interface| {
                interface.get_value ("NameServerBak").is_ok ()
            })
            .collect ();
        Ok (revertible_interfaces)
    }

    fn subvert_interface(&self, interface: &Box<RegKeyTrait>) -> Result <(), String> {
        let name_servers = interface.get_value ("NameServer").expect ("Interface became unsubvertible. Check your DNS settings manually.");
        if WinRegDnsModifier::is_subverted(&name_servers) {return Ok (())}
        if WinRegDnsModifier::makes_no_sense(&name_servers) { return Err(String::from("This system's DNS settings don't make sense; aborting")) }
        self.handle_reg_error (interface.set_value("NameServerBak", name_servers.as_str()))?;
        self.handle_reg_error (interface.set_value("NameServer", "127.0.0.1"))
    }

    fn roll_back_subvert(&self, interface: &Box<RegKeyTrait>) {
        let old_nameservers = match interface.get_value ("NameServerBak") {
            Err (_) => return, // Not yet backed up; no rollback necessary
            Ok (s) => s,
        };
        interface.delete_value ("NameServerBak").expect ("Can't delete NameServerBak to roll back subversion. Check your DNS settings manually.");
        if !WinRegDnsModifier::is_subverted (&interface.get_value ("NameServer").expect ("Can't get NameServer value to roll back subversion. Check your DNS settings manually.")) {return}
        interface.set_value ("NameServer", &old_nameservers).expect ("Can't reset NameServer to roll back subversion. Check your DNS settings manually.");
    }

    fn revert_interface(&self, interface: &Box<RegKeyTrait>) -> Result<(), String> {
        let old_name_servers = interface.get_value ("NameServerBak").expect ("Interface became unrevertible. Check your DNS settings manually.");

        match interface.get_value ("NameServer") {
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => (), // don't create new NameServer if none exists
            _ => { // but it's okay to overwrite an existing NameServer
                match interface.set_value("NameServer", old_name_servers.as_str ()) {
                    Ok (_) => (),
                    Err(e) => return self.handle_reg_error (Err (e)),
                };
            },
        };

        self.handle_reg_error(interface.delete_value("NameServerBak"))
    }

    fn roll_back_revert(&self, interface: &Box<RegKeyTrait>) {
        let old_nameservers = match interface.get_value ("NameServer") {
            Err (_) => return, // No NameServer; no rollback necessary
            Ok (s) => s,
        };
        if WinRegDnsModifier::is_subverted (&old_nameservers) {return}
        interface.set_value ("NameServerBak", &old_nameservers).expect ("Can't set NameServerBak to roll back reversion. Check your DNS settings manually.");
        interface.set_value ("NameServer", "127.0.0.1").expect ("Can't reset NameServer to roll back reversion. Check your DNS settings manually.");
    }

    fn handle_reg_error<T> (&self, result: io::Result<T>) -> Result<T, String> {
        match result {
            Ok(retval) => Ok(retval),
            Err(ref e) if e.raw_os_error() == Some(PERMISSION_DENIED) => return Err(String::from("You must have administrative privilege to modify your DNS settings")),
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => return Err(String::from("Registry contains no DNS information to modify")),
            Err(ref e) => return Err(format!("Unexpected error: {:?}", e)),
        }
    }

    fn is_subverted(name_servers: &String) -> bool {
        name_servers == "127.0.0.1" || name_servers.starts_with ("127.0.0.1,")
    }

    fn makes_no_sense (name_servers: &String) -> bool {
        name_servers.split(",").collect::<Vec<&str>>().contains(&"127.0.0.1")
    }

    fn get_default_gateway (interface: &Box<RegKeyTrait>) -> Option<String> {
        let string_opt = match (interface.get_value ("DefaultGateway"), interface.get_value ("DhcpDefaultGateway")) {
            (Ok(_), Ok(ddg)) => Some (ddg),
            (Ok(dg), Err(_)) => Some (dg),
            (Err(_), Ok(ddg)) => Some (ddg),
            (Err (_), Err (_)) => None
        };
        match string_opt {
            Some (ref s) if s.is_empty () => None,
            Some (s) => Some (s),
            None => None
        }
    }
}

fn plus<T> (mut source: Vec<T>, item: T) -> Vec<T> {
    let mut result = vec! ();
    result.append (&mut source);
    result.push (item);
    result
}

trait RegKeyTrait: Debug {
    fn enum_keys (&self) -> Vec<io::Result<String>>;
    fn open_subkey_with_flags (&self, path: &str, perms: u32) -> io::Result<Box<RegKeyTrait>>;
    fn get_value (&self, path: &str) -> io::Result<String>;
    fn set_value (&self, path: &str, value: &str) -> io::Result<()>;
    fn delete_value (&self, path: &str) -> io::Result<()>;
}

#[cfg (windows)]
#[derive (Debug)]
struct RegKeyReal {
    delegate: RegKey
}

#[cfg (not (windows))]
#[derive (Debug)]
struct RegKeyReal {}

#[cfg (windows)]
impl RegKeyTrait for RegKeyReal {
    fn enum_keys(&self) -> Vec<io::Result<String>> {
        self.delegate.enum_keys ().map (|x| {x}).collect ()
    }

    fn open_subkey_with_flags (&self, path: &str, perms: u32) -> io::Result<Box<RegKeyTrait>> {
        match self.delegate.open_subkey_with_flags (path, perms) {
            Ok (delegate) => Ok (Box::new (RegKeyReal { delegate: delegate})),
            Err (e) => Err (e)
        }
    }

    fn get_value (&self, name: &str) -> io::Result<String> {
        self.delegate.get_value (name)
    }

    fn set_value(&self, name: &str, value: &str) -> io::Result<()> {
        self.delegate.set_value (name, &String::from (value))
    }

    fn delete_value(&self, name: &str) -> io::Result<()> {
        self.delegate.delete_value (name)
    }
}

#[cfg (not (windows))]
impl RegKeyTrait for RegKeyReal {
    fn enum_keys(&self) -> Vec<io::Result<String>> {unimplemented! ()}
    fn open_subkey_with_flags (&self, _path: &str, _perms: u32) -> io::Result<Box<RegKeyTrait>> {unimplemented! ()}
    fn get_value (&self, _name: &str) -> io::Result<String> {unimplemented! ()}
    fn set_value(&self, _name: &str, _value: &str) -> io::Result<()> {unimplemented! ()}
    fn delete_value(&self, _name: &str) -> io::Result<()> {unimplemented! ()}
}

#[cfg (windows)]
impl RegKeyReal {
    pub fn new (delegate: RegKey) -> RegKeyReal {
        RegKeyReal {
            delegate
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;
    use std::io::Error;
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::sync::Arc;
    use utils::get_parameters_from;
    use std::collections::HashMap;

    #[derive (Debug)]
    struct RegKeyMock {
        enum_keys_results: RefCell<Vec<Vec<io::Result<String>>>>,
        open_subkey_with_flags_parameters: Arc<Mutex<Vec<(String, u32)>>>,
        open_subkey_with_flags_results: RefCell<Vec<io::Result<Box<RegKeyTrait>>>>,
        get_value_parameters: Arc<Mutex<Vec<String>>>,
        get_value_results: RefCell<HashMap<String, Vec<io::Result<String>>>>,
        set_value_parameters: Arc<Mutex<Vec<(String, String)>>>,
        set_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
        delete_value_parameters: Arc<Mutex<Vec<String>>>,
        delete_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
    }

    impl RegKeyTrait for RegKeyMock {
        fn enum_keys (&self) -> Vec<io::Result<String>> {
            self.enum_keys_results.borrow_mut ().remove (0)
        }

        fn open_subkey_with_flags (&self, path: &str, perms: u32) -> io::Result<Box<RegKeyTrait>> {
            self.open_subkey_with_flags_parameters.lock ().unwrap ().push ((String::from (path), perms));
            self.open_subkey_with_flags_results.borrow_mut ().remove (0)
        }

        fn get_value (&self, path: &str) -> io::Result<String> {
            self.get_value_parameters.lock ().unwrap ().push (String::from (path));
            self.get_result (&self.get_value_results, "get_value", path)
        }

        fn set_value (&self, path: &str, value: &str) -> io::Result<()> {
            self.set_value_parameters.lock ().unwrap ().push ((String::from (path), String::from (value)));
            self.get_result (&self.set_value_results, "set_value", path)
        }

        fn delete_value (&self, path: &str) -> io::Result<()> {
            self.delete_value_parameters.lock ().unwrap ().push (String::from (path));
            self.get_result (&self.delete_value_results, "delete_value", path)
        }
    }

    impl RegKeyMock {
        pub fn new() -> RegKeyMock {
            RegKeyMock {
                enum_keys_results: RefCell::new(vec!()),
                open_subkey_with_flags_parameters: Arc::new(Mutex::new(vec!())),
                open_subkey_with_flags_results: RefCell::new(vec!()),
                get_value_parameters: Arc::new(Mutex::new(vec!())),
                get_value_results: RefCell::new(HashMap::new()),
                set_value_parameters: Arc::new(Mutex::new(vec!())),
                set_value_results: RefCell::new(HashMap::new()),
                delete_value_parameters: Arc::new(Mutex::new(vec!())),
                delete_value_results: RefCell::new(HashMap::new()),
            }
        }

        pub fn enum_keys_result(self, result: Vec<io::Result<&str>>) -> RegKeyMock {
            self.enum_keys_results.borrow_mut().push(result.into_iter().map(|item| match item {
                Err(e) => Err(e),
                Ok(slice) => Ok(String::from(slice)),
            }).collect());
            self
        }

        pub fn open_subkey_with_flags_parameters(mut self, parameters: &Arc<Mutex<Vec<(String, u32)>>>) -> RegKeyMock {
            self.open_subkey_with_flags_parameters = parameters.clone();
            self
        }

        pub fn open_subkey_with_flags_result(self, result: io::Result<Box<RegKeyTrait>>) -> RegKeyMock {
            self.open_subkey_with_flags_results.borrow_mut().push(result);
            self
        }

        pub fn get_value_parameters(mut self, parameters: &Arc<Mutex<Vec<String>>>) -> RegKeyMock {
            self.get_value_parameters = parameters.clone();
            self
        }

        pub fn get_value_result(self, name: &str, result: io::Result<String>) -> RegKeyMock {
            self.prepare_result(&self.get_value_results, name, result);
            self
        }

        pub fn set_value_parameters(mut self, parameters: &Arc<Mutex<Vec<(String, String)>>>) -> RegKeyMock {
            self.set_value_parameters = parameters.clone();
            self
        }

        pub fn set_value_result(self, name: &str, result: io::Result<()>) -> RegKeyMock {
            self.prepare_result(&self.set_value_results, name, result);
            self
        }

        pub fn delete_value_parameters(mut self, parameters: &Arc<Mutex<Vec<String>>>) -> RegKeyMock {
            self.delete_value_parameters = parameters.clone();
            self
        }

        pub fn delete_value_result(self, name: &str, result: io::Result<()>) -> RegKeyMock {
            self.prepare_result(&self.delete_value_results, name, result);
            self
        }

        fn prepare_result<T>(&self, results: &RefCell<HashMap<String, Vec<io::Result<T>>>>, name: &str, result: io::Result<T>) {
            let mut results_map = results.borrow_mut();
            let vec_exists = {
                results_map.contains_key(name)
            };
            if vec_exists {
                let mut results_opt = results_map.get_mut(&String::from(name));
                let results_ref = results_opt.as_mut().unwrap();
                results_ref.push(result);
            } else {
                let results = vec!(result);
                results_map.insert(String::from(name), results);
            }
        }

        fn get_result<T: Clone + Debug>(&self, results: &RefCell<HashMap<String, Vec<io::Result<T>>>>, method: &str, name: &str) -> io::Result<T> {
            let mut results_map = results.borrow_mut();
            let results_opt = results_map.get_mut(&String::from(name));
            let results_ref = results_opt.expect(format!("No results prepared for {} ({})", method, name).as_str());
            if results_ref.len() > 1 {
                self.get_result_mutable (results_ref)
            }
            else {
                self.get_result_immutable (results_ref, method, name)
            }
        }

        fn get_result_immutable<T: Clone + Debug> (&self, results: &Vec<io::Result<T>>, method: &str, name: &str) -> io::Result<T> {
            if results.len () == 0 {panic! ("No results prepared for {} ({})", method, name)};
            let result_ref = results.first ().unwrap ();
            match result_ref {
                &Ok (ref s) => Ok (s.clone ()),
                &Err (ref e) if e.raw_os_error().is_some () => Err (Error::from_raw_os_error(e.raw_os_error ().unwrap ())),
                &Err (ref e) => Err (Error::from (e.kind ())),
            }
        }

        fn get_result_mutable<T: Clone + Debug> (&self, results: &mut Vec<io::Result<T>>) -> io::Result<T> {
            results.remove (0)
        }
    }

    #[test]
    fn is_already_subverted_says_no_if_substratum_dns_appears_too_late () {
        let result = WinRegDnsModifier::is_subverted(&String::from ("1.1.1.1,127.0.0.1"));

        assert_eq! (result, false)
    }

    #[test]
    fn is_already_subverted_says_no_if_first_dns_is_only_substratum_like() {
        let result = WinRegDnsModifier::is_subverted(&String::from("127.0.0.11"));

        assert_eq!(result, false)
    }

    #[test]
    fn is_already_subverted_says_yes_if_first_dns_is_substratum() {
        let result = WinRegDnsModifier::is_subverted(&String::from("127.0.0.1,1.1.1.1"));

        assert_eq!(result, true)
    }

    #[test]
    fn get_default_gateway_sees_dhcp_if_both_are_specified () {
        // Many people think this is incorrect behavior, but it seems to be the way Win7+ does things.
        let interface: Box<RegKeyTrait> = Box::new (RegKeyMock::new ()
            .get_value_result("DefaultGateway", Ok (String::from ("DefaultGateway")))
            .get_value_result("DhcpDefaultGateway", Ok (String::from ("DhcpDefaultGateway"))));

        let result = WinRegDnsModifier::get_default_gateway (&interface);

        assert_eq! (result, Some (String::from ("DhcpDefaultGateway")))
    }

    #[test]
    fn get_default_gateway_sees_naked_default_if_it_is_the_only_one_specified () {
        let interface: Box<RegKeyTrait> = Box::new (RegKeyMock::new ()
            .get_value_result("DefaultGateway", Ok (String::from ("DefaultGateway")))
            .get_value_result("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND))));

        let result = WinRegDnsModifier::get_default_gateway (&interface);

        assert_eq! (result, Some (String::from ("DefaultGateway")))
    }

    #[test]
    fn get_default_gateway_sees_dhcp_default_if_it_is_the_only_one_specified () {
        let interface: Box<RegKeyTrait> = Box::new (RegKeyMock::new ()
            .get_value_result("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok (String::from ("DhcpDefaultGateway"))));

        let result = WinRegDnsModifier::get_default_gateway (&interface);

        assert_eq! (result, Some (String::from ("DhcpDefaultGateway")))
    }

    #[test]
    fn get_default_gateway_sees_nothing_if_nothing_is_specified () {
        let interface: Box<RegKeyTrait> = Box::new (RegKeyMock::new ()
            .get_value_result("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND))));

        let result = WinRegDnsModifier::get_default_gateway (&interface);

        assert_eq! (result, None)
    }

    #[test]
    fn instance_knows_its_type_name () {
        let subject = WinRegDnsModifier::new ();

        let result = subject.type_name ();

        assert_eq! (result, "WinRegDnsModifier");
    }

    #[test]
    fn subvert_complains_if_permission_is_denied () {
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Err (Error::from_raw_os_error(PERMISSION_DENIED)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("You must have administrative privilege to modify your DNS settings"))
    }

    #[test]
    fn subvert_complains_if_no_interfaces_key_exists () {
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Err (Error::from_raw_os_error(NOT_FOUND)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("Registry contains no DNS information to modify"))
    }

    #[test]
    fn subvert_complains_about_unexpected_os_error () {
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Err (Error::from_raw_os_error(3)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        let string_err = result.err ().unwrap ();
        assert_eq! (string_err.starts_with ("Unexpected error: "), true, "{}", &string_err);
        assert_eq! (string_err.contains ("code: 3"), true, "{}", &string_err);
    }

    #[test]
    fn subvert_complains_if_no_interfaces_have_default_gateway_or_dhcp_default_gateway_values () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error( NOT_FOUND)));
        let another_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_interface"), Ok ("another_interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (one_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("This system has no accessible network interfaces configured with default gateways and DNS servers"));
    }

    #[test]
    fn subvert_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok (String::new ()))
            .get_value_result ("DhcpDefaultGateway", Ok (String::new ()));
        let another_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok (String::new ()))
            .get_value_result ("DhcpDefaultGateway", Ok (String::new ()));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_interface"), Ok ("another_interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (one_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("This system has no accessible network interfaces configured with default gateways and DNS servers"));
    }

    #[test]
    fn subvert_complains_if_interfaces_have_different_gateway_values() {
        let one_interface = RegKeyMock::new ()
            .get_value_result ("DefaultGateway", Ok(String::from("Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8")));
        let another_interface = RegKeyMock::new ()
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Ok(String::from("DHCP Gateway IP")))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8")));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_interface"), Ok ("another_interface")))
            .open_subkey_with_flags_result(Ok (Box::new (one_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("This system has 2 active network interfaces configured with 2 different default gateways. Manual configuration required."));
    }

    #[test]
    fn subvert_complains_if_dns_settings_dont_make_sense () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway",Ok(String::from("Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer",Ok (String::from ("8.8.8.8,127.0.0.1")))
            .get_value_result ("NameServerBak", Err (Error::from_raw_os_error (NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("This system's DNS settings don't make sense; aborting")));
    }

    #[test]
    fn subvert_backs_off_if_dns_is_already_subverted () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok(String::from("Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
    }

    #[test]
    fn subvert_complains_if_name_server_key_exists_and_is_not_writable () {
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .set_value_parameters (&set_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok(String::from("Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Ok (String::from ("Not Substratum")))
            .get_value_result ("NameServerBak", Ok (String::from ("Not Substratum")))
            .set_value_result ("NameServerBak", Ok (()))
            .set_value_result ("NameServer", Err (Error::from_raw_os_error(PERMISSION_DENIED)))
            .delete_value_result ("NameServerBak", Ok (()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
        assert_eq! (get_parameters_from (delete_value_parameters_arc), vec! (
            String::from ("NameServerBak"),
        ));
    }

    #[test]
    fn subvert_backs_out_successes_if_there_is_a_failure_setting_nameserver () {
        let one_active_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_active_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_active_interface = RegKeyMock::new ()
            .set_value_parameters (&one_active_set_value_parameters_arc)
            .delete_value_parameters (&one_active_delete_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok(String::from("Common Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8,8.8.8.9"))) // identify as subvertible
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8,8.8.8.9"))) // retrieve for backup
            .set_value_result ("NameServerBak", Ok (()))
            .get_value_result ("NameServerBak", Ok (String::from ("8.8.8.8,8.8.8.9")))
            .set_value_result ("NameServer", Ok (()))
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1"))) // identify as needing backout
            .delete_value_result ("NameServerBak", Ok (()));
        let another_active_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_active_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_active_interface = RegKeyMock::new ()
            .set_value_parameters (&another_active_set_value_parameters_arc)
            .delete_value_parameters (&another_active_delete_value_parameters_arc)
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Ok(String::from("Common Gateway IP")))
            .get_value_result ("NameServer", Ok (String::from ("9.9.9.9")))
            .set_value_result ("NameServerBak", Ok (()))
            .get_value_result ("NameServerBak", Ok (String::from ("9.9.9.9")))
            .set_value_result ("NameServer", Err (Error::from_raw_os_error(PERMISSION_DENIED)))
            .delete_value_result ("NameServerBak", Ok (()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_active_interface"), Ok ("another_active_interface")))
            .open_subkey_with_flags_result(Ok (Box::new (one_active_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_active_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
        assert_eq! (get_parameters_from (one_active_set_value_parameters_arc), vec! (
            (String::from ("NameServerBak"), String::from ("8.8.8.8,8.8.8.9")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
            (String::from ("NameServer"), String::from ("8.8.8.8,8.8.8.9")),
        ));
        assert_eq! (get_parameters_from (one_active_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak"),
        ));
        assert_eq! (get_parameters_from (another_active_set_value_parameters_arc), vec! (
            (String::from ("NameServerBak"), String::from ("9.9.9.9")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
        assert_eq! (get_parameters_from (another_active_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak"),
        ));
    }

    #[test]
    fn subvert_works_if_everything_is_copasetic () {
        let one_active_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_active_interface = RegKeyMock::new ()
            .set_value_parameters (&one_active_set_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok(String::from("Common Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8,8.8.8.9")))
            .set_value_result ("NameServerBak", Ok (()))
            .set_value_result ("NameServer", Ok (()));
        let another_active_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_active_interface = RegKeyMock::new ()
            .set_value_parameters (&another_active_set_value_parameters_arc)
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Ok(String::from("Common Gateway IP")))
            .get_value_result ("NameServer", Ok (String::from ("9.9.9.9")))
            .set_value_result ("NameServerBak", Ok (()))
            .set_value_result ("NameServer", Ok (()));
        let inactive_interface = RegKeyMock::new ()
            .get_value_result ("DefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_active_interface"), Ok ("another_active_interface"), Ok ("inactive_interface")))
            .open_subkey_with_flags_result(Ok (Box::new (one_active_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_active_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (inactive_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (one_active_set_value_parameters_arc), vec! (
            (String::from ("NameServerBak"), String::from ("8.8.8.8,8.8.8.9")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
        assert_eq! (get_parameters_from (another_active_set_value_parameters_arc), vec! (
            (String::from ("NameServerBak"), String::from ("9.9.9.9")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
    }

    #[test]
    fn subvert_fails_if_no_nameserver_value_exists() {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .get_value_result ("DefaultGateway", Ok(String::from("Gateway IP")))
            .get_value_result ("DhcpDefaultGateway", Err (Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result ("NameServer", Err (Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("This system has no accessible network interfaces configured with default gateways and DNS servers")));
    }

    #[test]
    fn revert_complains_if_backup_exists_and_backup_value_is_not_deletable () {
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .set_value_parameters (&set_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result ("NameServerBak", Ok(String::from("8.8.8.8")))
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8")))
            .set_value_result ("NameServer", Ok (()))
            .set_value_result ("NameServerBak", Ok (()))
            .delete_value_result ("NameServerBak", Err (Error::from_raw_os_error(PERMISSION_DENIED)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
        assert_eq! (get_parameters_from (set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("8.8.8.8")),
            (String::from ("NameServerBak"), String::from ("8.8.8.8")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
    }

    #[test]
    fn revert_complains_if_backup_exists_and_active_value_is_not_writable () {
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .set_value_parameters (&set_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result ("NameServerBak", Ok(String::from("Backed up IP")))
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .delete_value_result ("NameServerBak", Ok (()))
            .set_value_result ("NameServer", Err (Error::from_raw_os_error(PERMISSION_DENIED)))
            .set_value_result ("NameServerBak", Ok (()));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
        assert_eq! (get_parameters_from (set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("Backed up IP")),
        ));
    }

    #[test]
    fn revert_backs_out_successes_if_there_are_failures () {
        let one_subverted_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_subverted_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_subverted_interface = RegKeyMock::new ()
            .set_value_parameters (&one_subverted_set_value_parameters_arc)
            .delete_value_parameters (&one_subverted_delete_value_parameters_arc)
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .get_value_result ("NameServerBak", Ok (String::from ("8.8.8.8")))
            .delete_value_result ("NameServerBak", Ok (()))
            .set_value_result ("NameServer", Ok (()))
            .get_value_result ("NameServer", Ok (String::from ("8.8.8.8")))
            .set_value_result ("NameServerBak", Ok (()));
        let another_subverted_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_subverted_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_subverted_interface = RegKeyMock::new ()
            .set_value_parameters (&another_subverted_set_value_parameters_arc)
            .delete_value_parameters (&another_subverted_delete_value_parameters_arc)
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .get_value_result ("NameServerBak", Ok (String::from ("9.9.9.9")))
            .set_value_result ("NameServer", Ok (()))
            .get_value_result ("NameServer", Ok (String::from ("9.9.9.9")))
            .delete_value_result ("NameServerBak", Err (Error::from_raw_os_error(PERMISSION_DENIED)))
            .set_value_result ("NameServerBak", Ok (()));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_subverted_interface"), Ok ("another_subverted_interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (one_subverted_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_subverted_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
        assert_eq! (get_parameters_from (one_subverted_set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("8.8.8.8")),
            (String::from ("NameServerBak"), String::from ("8.8.8.8")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
        assert_eq! (get_parameters_from (one_subverted_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak"),
        ));
        assert_eq! (get_parameters_from (another_subverted_set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("9.9.9.9")),
            (String::from ("NameServerBak"), String::from ("9.9.9.9")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
        assert_eq! (get_parameters_from (another_subverted_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak")
        ));
    }

    #[test]
    fn revert_works_if_everything_is_copasetic () {
        let one_subverted_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_subverted_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_subverted_interface = RegKeyMock::new ()
            .set_value_parameters (&one_subverted_set_value_parameters_arc)
            .delete_value_parameters (&one_subverted_delete_value_parameters_arc)
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .get_value_result ("NameServerBak", Ok (String::from ("8.8.8.8")))
            .set_value_result ("NameServer", Ok (()))
            .delete_value_result ("NameServerBak", Ok (()));
        let another_subverted_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_subverted_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let another_subverted_interface = RegKeyMock::new ()
            .set_value_parameters (&another_subverted_set_value_parameters_arc)
            .delete_value_parameters (&another_subverted_delete_value_parameters_arc)
            .get_value_result ("NameServer", Ok (String::from ("127.0.0.1")))
            .get_value_result ("NameServerBak", Ok (String::from ("9.9.9.9")))
            .set_value_result ("NameServer", Ok (()))
            .delete_value_result ("NameServerBak", Ok (()));
        let unsubverted_set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let unsubverted_delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let unsubverted_interface = RegKeyMock::new ()
            .set_value_parameters (&unsubverted_set_value_parameters_arc)
            .delete_value_parameters (&unsubverted_delete_value_parameters_arc)
            .get_value_result ("NameServer", Ok (String::from ("10.10.10.10")))
            .get_value_result ("NameServerBak", Err (Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("one_subverted_interface"), Ok ("another_subverted_interface"), Ok ("unsubverted_interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (one_subverted_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (another_subverted_interface)))
            .open_subkey_with_flags_result(Ok (Box::new (unsubverted_interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (one_subverted_set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("8.8.8.8"))
        ));
        assert_eq! (get_parameters_from (one_subverted_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak")
        ));
        assert_eq! (get_parameters_from (another_subverted_set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("9.9.9.9"))
        ));
        assert_eq! (get_parameters_from (another_subverted_delete_value_parameters_arc), vec! (
            String::from ("NameServerBak")
        ));
        assert_eq! (get_parameters_from (unsubverted_set_value_parameters_arc).len (), 0);
        assert_eq! (get_parameters_from (unsubverted_delete_value_parameters_arc).len (), 0);
    }

    #[test]
    fn revert_succeeds_with_no_work_if_no_subverted_nic_is_found () {
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result ("NameServerBak", Err (Error::from_raw_os_error(NOT_FOUND)));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (delete_value_parameters_arc).len (), 0);
    }

    #[test]
    fn revert_succeeds_after_deleting_name_server_bak_if_no_name_server_is_found () {
        let set_value_parameters = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .set_value_parameters (&set_value_parameters)
            .delete_value_parameters (&delete_value_parameters)
            .get_value_result ("NameServerBak", Ok (String::from ("8.8.8.8")))
            .get_value_result ("NameServer", Err (Error::from_raw_os_error(NOT_FOUND)))
            .delete_value_result ("NameServerBak", Ok (()));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.revert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (delete_value_parameters), vec! (
            String::from ("NameServerBak")
        ));
    }
}
