// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use dns_modifier::DnsModifier;
use std::fmt::Debug;
use std::io;

#[cfg (windows)]
use winreg::RegKey;
#[cfg (windows)]
use winreg::enums::*;

#[cfg (not (windows))]
const KEY_ALL_ACCESS: u32 = 1234;

pub struct WinRegDnsModifier {
    hive: Box<RegKeyTrait>,
}

impl DnsModifier for WinRegDnsModifier {
    fn type_name (&self) -> &'static str {
        "WinRegDnsModifier"
    }

    fn subvert(&self) -> Result<(), String> {
        let interface = self.find_interface_to_modify()?;
        match interface.get_value ("NameServer") {
            Err (_) => self.subvert_nonexistent (interface),
            Ok (name_servers) => self.subvert_existing (interface, name_servers)
        }
    }

    fn revert(&self) -> Result<(), String> {
        let interface = self.find_interface_to_modify ()?;
        match interface.get_value ("NameServer") {
            Err (_) => Ok (()),
            Ok (name_servers) => {
                if !WinRegDnsModifier::is_subverted (&name_servers) {return Ok (())}
                match interface.get_value ("NameServerBak") {
                    Err (_) => self.revert_without_backup (interface),
                    Ok (old_name_servers) => self.revert_with_backup (interface, old_name_servers)
                }
            }
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

    fn find_interface_to_modify(&self) -> Result<Box<RegKeyTrait>, String> {
        let interfaces = self.handle_reg_error(self.hive.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", KEY_ALL_ACCESS))?;
        let mut gateway_interfaces: Vec<Box<RegKeyTrait>> = interfaces.enum_keys ().iter ()
            .flat_map (|k| {k})
            .flat_map (| interface_name | {
                interfaces.open_subkey_with_flags (&interface_name[..], KEY_ALL_ACCESS)
            })
            .filter (| interface | {
                let default_gateway_spec = WinRegDnsModifier::is_value_specified (interface.get_value ("DefaultGateway"));
                let dhcp_default_gateway_spec = WinRegDnsModifier::is_value_specified (interface.get_value ("DhcpDefaultGateway"));
                default_gateway_spec || dhcp_default_gateway_spec
            })
            .collect ();
        if gateway_interfaces.is_empty() { return Err(String::from("This system has no accessible network interfaces configured with default gateways")) }
        if gateway_interfaces.len () > 1 { return Err(String::from("This system has multiple network interfaces configured with default gateways")) }
        Ok (gateway_interfaces.remove (0))
    }

    fn subvert_nonexistent (&self, interface: Box<RegKeyTrait>) -> Result<(), String> {
        self.handle_reg_error (interface.set_value ("NameServer", "127.0.0.1"))?;
        Ok (())
    }

    fn subvert_existing (&self, interface: Box<RegKeyTrait>, name_servers: String) -> Result <(), String> {
        if WinRegDnsModifier::is_subverted(&name_servers) {return Ok (())}
        if WinRegDnsModifier::makes_no_sense(&name_servers) { return Err(String::from("This system's DNS settings don't make sense; aborting")) }
        self.handle_reg_error (interface.set_value("NameServerBak", name_servers.as_str()))?;
        interface.set_value("NameServer", "127.0.0.1").expect ("Inconsistency in the Registry (2)");
        Ok (())
    }

    fn revert_without_backup (&self, interface: Box<RegKeyTrait>) -> Result<(), String> {
        self.handle_reg_error (interface.delete_value ("NameServer"))?;
        Ok (())
    }

    fn revert_with_backup (&self, interface: Box<RegKeyTrait>, old_name_servers: String) -> Result<(), String> {
        self.handle_reg_error (interface.set_value("NameServer", old_name_servers.as_str()))?;
        interface.delete_value("NameServerBak").expect ("Inconsistency in the Registry (3)");
        Ok (())
    }

    fn handle_reg_error<T> (&self, result: io::Result<T>) -> Result<T, String> {
        match result {
            Ok(retval) => Ok(retval),
            Err(ref e) if e.raw_os_error() == Some(5) => return Err(String::from("You must have administrative privilege to modify your DNS settings")),
            Err(ref e) if e.raw_os_error() == Some(2) => return Err(String::from("Registry contains no DNS information to modify")),
            Err(ref e) => return Err(format!("Unexpected error: {:?}", e)),
        }
    }

    fn is_value_specified (result: io::Result<String>) -> bool {
        match &result {
            &Err (_) => false,
            &Ok (ref s) if s.is_empty () => false,
            &Ok (_) => true,
        }
    }

    fn is_subverted(name_servers: &String) -> bool {
        name_servers == "127.0.0.1" || name_servers.starts_with ("127.0.0.1,")
    }

    fn makes_no_sense (name_servers: &String) -> bool {
        name_servers.split(",").collect::<Vec<&str>>().contains(&"127.0.0.1")
    }
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

    #[derive (Debug)]
    struct RegKeyMock {
        enum_keys_results: RefCell<Vec<Vec<io::Result<String>>>>,
        open_subkey_with_flags_parameters: Arc<Mutex<Vec<(String, u32)>>>,
        open_subkey_with_flags_results: RefCell<Vec<io::Result<Box<RegKeyTrait>>>>,
        get_value_parameters: Arc<Mutex<Vec<String>>>,
        get_value_results: RefCell<Vec<io::Result<String>>>,
        set_value_parameters: Arc<Mutex<Vec<(String, String)>>>,
        set_value_results: RefCell<Vec<io::Result<()>>>,
        delete_value_parameters: Arc<Mutex<Vec<String>>>,
        delete_value_results: RefCell<Vec<io::Result<()>>>,
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
            self.get_value_results.borrow_mut ().remove (0)
        }

        fn set_value (&self, path: &str, value: &str) -> io::Result<()> {
            self.set_value_parameters.lock ().unwrap ().push ((String::from (path), String::from (value)));
            self.set_value_results.borrow_mut ().remove (0)
        }

        fn delete_value (&self, path: &str) -> io::Result<()> {
            self.delete_value_parameters.lock ().unwrap ().push (String::from (path));
            self.delete_value_results.borrow_mut ().remove (0)
        }
    }

    impl RegKeyMock {
        pub fn new () -> RegKeyMock {
            RegKeyMock {
                enum_keys_results: RefCell::new (vec! ()),
                open_subkey_with_flags_parameters: Arc::new (Mutex::new (vec! ())),
                open_subkey_with_flags_results: RefCell::new (vec! ()),
                get_value_parameters: Arc::new (Mutex::new (vec! ())),
                get_value_results: RefCell::new (vec! ()),
                set_value_parameters: Arc::new (Mutex::new (vec! ())),
                set_value_results: RefCell::new (vec! ()),
                delete_value_parameters: Arc::new (Mutex::new (vec! ())),
                delete_value_results: RefCell::new (vec! ()),
            }
        }

        pub fn enum_keys_result (self, result: Vec<io::Result<&str>>) -> RegKeyMock {
            self.enum_keys_results.borrow_mut ().push (result.into_iter ().map (|item| match item {
                Err(e) => Err(e),
                Ok(slice) => Ok(String::from (slice)),
            }).collect());
            self
        }

        pub fn open_subkey_with_flags_parameters(mut self, parameters: &Arc<Mutex<Vec<(String, u32)>>>) -> RegKeyMock {
            self.open_subkey_with_flags_parameters = parameters.clone ();
            self
        }

        pub fn open_subkey_with_flags_result(self, result: io::Result<Box<RegKeyTrait>>) -> RegKeyMock {
            self.open_subkey_with_flags_results.borrow_mut ().push (result);
            self
        }

        pub fn get_value_parameters (mut self, parameters: &Arc<Mutex<Vec<String>>>) -> RegKeyMock {
            self.get_value_parameters = parameters.clone ();
            self
        }

        pub fn get_value_result (self, result: io::Result<String>) -> RegKeyMock {
            self.get_value_results.borrow_mut ().push (result);
            self
        }

        pub fn set_value_parameters (mut self, parameters: &Arc<Mutex<Vec<(String, String)>>>) -> RegKeyMock {
            self.set_value_parameters = parameters.clone ();
            self
        }

        pub fn set_value_result (self, result: io::Result<()>) -> RegKeyMock {
            self.set_value_results.borrow_mut ().push (result);
            self
        }

        pub fn delete_value_parameters (mut self, parameters: &Arc<Mutex<Vec<String>>>) -> RegKeyMock {
            self.delete_value_parameters = parameters.clone ();
            self
        }

        pub fn delete_value_result (self, result: io::Result<()>) -> RegKeyMock {
            self.delete_value_results.borrow_mut ().push (result);
            self
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
    fn instance_knows_its_type_name () {
        let subject = WinRegDnsModifier::new ();

        let result = subject.type_name ();

        assert_eq! (result, "WinRegDnsModifier");
    }

    #[test]
    fn subvert_complains_if_permission_is_denied () {
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Err (Error::from_raw_os_error(5)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result.err ().unwrap (), String::from ("You must have administrative privilege to modify your DNS settings"))
    }

    #[test]
    fn subvert_complains_if_no_interfaces_key_exists () {
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_result(Err (Error::from_raw_os_error(2)));
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
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Err (Error::from_raw_os_error(2)));
        let another_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Err (Error::from_raw_os_error(2)));
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

        assert_eq! (result.err ().unwrap (), String::from ("This system has no accessible network interfaces configured with default gateways"));
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("one_interface"), KEY_ALL_ACCESS),
             (String::from ("another_interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
        ));
    }

    #[test]
    fn subvert_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok (String::new ()))
            .get_value_result (Ok (String::new ()));
        let another_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok (String::new ()))
            .get_value_result (Ok (String::new ()));
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

        assert_eq! (result.err ().unwrap (), String::from ("This system has no accessible network interfaces configured with default gateways"));
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("one_interface"), KEY_ALL_ACCESS),
            (String::from ("another_interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
        ));
    }

    #[test]
    fn subvert_complains_if_too_many_interfaces_have_default_gateway_or_dhcp_gateway_values() {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let one_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)));
        let another_interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok(String::from("DHCP Gateway IP")));
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

        assert_eq! (result.err ().unwrap (), String::from ("This system has multiple network interfaces configured with default gateways"));
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("one_interface"), KEY_ALL_ACCESS),
            (String::from ("another_interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
        ));
    }

    #[test]
    fn subvert_complains_if_dns_settings_dont_make_sense () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("8.8.8.8,127.0.0.1")));
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
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
    }

    #[test]
    fn subvert_backs_off_if_dns_is_already_subverted () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("127.0.0.1")));
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
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
    }

    #[test]
    fn subvert_complains_if_key_exists_and_is_not_writable () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("Not Substratum")))
            .set_value_result (Err (Error::from_raw_os_error(5)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive_open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_parameters (&hive_open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
    }

    #[test]
    fn subvert_complains_if_key_does_not_exist_and_is_not_writable () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .set_value_result (Err (Error::from_raw_os_error(5)));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive_open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_parameters (&hive_open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Err (String::from ("You must have administrative privilege to modify your DNS settings")));
    }

    #[test]
    fn subvert_works_if_everything_is_copacetic () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("Not Substratum")))
            .set_value_result (Ok (()))
            .set_value_result (Ok (()));
        let open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interfaces = RegKeyMock::new ()
            .enum_keys_result (vec! (Ok ("interface")))
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interface)));
        let hive_open_subkey_with_flags_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let hive = RegKeyMock::new ()
            .open_subkey_with_flags_parameters (&hive_open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok (Box::new (interfaces)));
        let mut subject = WinRegDnsModifier::new ();
        subject.hive = Box::new (hive);

        let result = subject.subvert ();

        assert_eq! (result, Ok (()));
        assert_eq! (get_parameters_from (hive_open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
        assert_eq! (get_parameters_from (set_value_parameters_arc), vec! (
            (String::from ("NameServerBak"), String::from ("Not Substratum")),
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
    }

    #[test]
    fn subvert_works_if_no_nameserver_value_exists () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .set_value_result (Ok (()));
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
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
        assert_eq! (get_parameters_from (set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("127.0.0.1")),
        ));
    }

    #[test]
    fn revert_backs_off_if_dns_is_not_subverted_and_there_is_no_name_server_value () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Err (Error::from_raw_os_error(2)));
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
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
    }

    #[test]
    fn revert_backs_off_if_dns_is_not_subverted_but_there_is_a_name_server_value () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("1.1.1.1,8.8.8.8")));
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
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer")
        ));
    }

    #[test]
    fn revert_complains_if_backup_exists_and_value_is_not_writable () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("127.0.0.1")))
            .get_value_result (Ok (String::from ("8.8.8.8")))
            .set_value_result (Err (Error::from_raw_os_error(5)));
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
    }

    #[test]
    fn revert_complains_if_backup_does_not_exist_and_value_is_not_writable () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("127.0.0.1")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .delete_value_result (Err (Error::from_raw_os_error(5)));
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
    }

    #[test]
    fn revert_works_if_everything_is_copa_fricking_cetic () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let set_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .set_value_parameters (&set_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("127.0.0.1")))
            .get_value_result (Ok (String::from ("8.8.8.8")))
            .set_value_result (Ok (()))
            .delete_value_result (Ok (()));
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
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer"),
            String::from ("NameServerBak"),
        ));
        assert_eq! (get_parameters_from (set_value_parameters_arc), vec! (
            (String::from ("NameServer"), String::from ("8.8.8.8"))
        ));
        assert_eq! (get_parameters_from (delete_value_parameters_arc), vec! (
            String::from ("NameServerBak")
        ));
    }

    #[test]
    fn revert_works_if_no_backup_exists () {
        let get_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let delete_value_parameters_arc = Arc::new (Mutex::new (vec! ()));
        let interface = RegKeyMock::new ()
            .get_value_parameters (&get_value_parameters_arc)
            .delete_value_parameters (&delete_value_parameters_arc)
            .get_value_result (Ok(String::from("Gateway IP")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .get_value_result (Ok (String::from ("127.0.0.1")))
            .get_value_result (Err (Error::from_raw_os_error(2)))
            .delete_value_result (Ok (()));
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
        assert_eq! (get_parameters_from (open_subkey_with_flags_parameters_arc), vec! (
            (String::from ("interface"), KEY_ALL_ACCESS),
        ));
        assert_eq! (get_parameters_from (get_value_parameters_arc), vec! (
            String::from ("DefaultGateway"),
            String::from ("DhcpDefaultGateway"),
            String::from ("NameServer"),
            String::from ("NameServerBak"),
        ));
        assert_eq! (get_parameters_from (delete_value_parameters_arc), vec! (
            String::from ("NameServer")
        ));
    }

    fn get_parameters_from<T> (parameters_arc: Arc<Mutex<Vec<T>>>) -> Vec<T> where T: Clone {
        let parameters_guard = parameters_arc.lock ().unwrap ();
        let parameters_ref: &Vec<T> = parameters_guard.as_ref ();
        parameters_ref.clone ()
    }
}
