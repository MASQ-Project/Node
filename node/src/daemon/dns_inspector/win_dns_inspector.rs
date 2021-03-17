// Copyright (c) 2019-2021, MASQ (https://masq.ai). All rights reserved.

use crate::daemon::dns_inspector::dns_inspector::DnsInspector;
use crate::daemon::dns_inspector::DnsInspectionError;
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use winreg::enums::*;
use winreg::RegKey;

const NOT_FOUND: i32 = 2;

pub struct WinDnsInspector {
    hive: Box<dyn RegKeyTrait>,
}

impl DnsInspector for WinDnsInspector {
    fn inspect(&self) -> Result<Vec<IpAddr>, DnsInspectionError> {
        let interfaces = self.find_interfaces_to_inspect()?;
        let dns_server_list_csv = self.find_dns_server_list(interfaces)?;
        let ip_vec: Vec<_> = dns_server_list_csv
            .split(',')
            .flat_map(|ip_str| IpAddr::from_str(&ip_str))
            .collect();
        Ok(ip_vec)
    }
}

impl Default for WinDnsInspector {
    fn default() -> Self {
        WinDnsInspector {
            hive: Box::new(RegKeyReal::new(
                RegKey::predef(HKEY_LOCAL_MACHINE),
                "HKEY_LOCAL_MACHINE",
            )),
        }
    }
}

impl WinDnsInspector {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Default::default()
    }

    pub fn find_interfaces_to_inspect(
        &self,
    ) -> Result<Vec<Box<dyn RegKeyTrait>>, DnsInspectionError> {
        self.find_interfaces(KEY_READ)
    }

    fn find_interfaces(
        &self,
        access_required: u32,
    ) -> Result<Vec<Box<dyn RegKeyTrait>>, DnsInspectionError> {
        let interface_key = self.handle_reg_error(self.hive.open_subkey_with_flags(
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
            access_required,
        ))?;
        let gateway_interfaces: Vec<Box<dyn RegKeyTrait>> = interface_key
            .enum_keys()
            .into_iter()
            .flatten()
            .flat_map(|interface_name| {
                interface_key.open_subkey_with_flags(&interface_name[..], access_required)
            })
            .filter(|interface| {
                WinDnsInspector::get_default_gateway(interface.as_ref()).is_some()
                    && interface.get_value("NameServer").is_ok()
            })
            .collect();
        if gateway_interfaces.is_empty() {
            return Err(DnsInspectionError::NotConnected);
        }
        let distinct_gateway_ips: HashSet<String> = gateway_interfaces
            .iter()
            .flat_map(|interface| WinDnsInspector::get_default_gateway(interface.as_ref()))
            .collect();
        if distinct_gateway_ips.len() > 1 {
            Err(DnsInspectionError::ConflictingEntries(
                gateway_interfaces.len(),
                distinct_gateway_ips.len(),
            ))
        } else {
            Ok(gateway_interfaces)
        }
    }

    pub fn find_dns_server_list(
        &self,
        interfaces: Vec<Box<dyn RegKeyTrait>>,
    ) -> Result<String, DnsInspectionError> {
        let interfaces_len = interfaces.len();
        let list_result_vec: Vec<Result<String, DnsInspectionError>> = interfaces
            .into_iter()
            .map(|interface| self.find_dns_servers_for_interface(interface))
            .collect();
        let mut errors: Vec<DnsInspectionError> = list_result_vec
            .iter()
            .flat_map(|result_ref| match *result_ref {
                Err(ref e) => Some(e.clone()),
                Ok(_) => None,
            })
            .collect();
        if !errors.is_empty() {
            return Err(errors.remove(0));
        }
        let list_set: HashSet<String> = list_result_vec
            .into_iter()
            .flat_map(|result| match result {
                Err(_e) => None,
                Ok(list) => Some(list),
            })
            .collect();
        if list_set.len() > 1 {
            Err(DnsInspectionError::ConflictingEntries(
                interfaces_len,
                list_set.len(),
            ))
        } else {
            let list_vec = list_set.into_iter().collect::<Vec<String>>();
            Ok(list_vec[0].clone())
        }
    }

    fn find_dns_servers_for_interface(
        &self,
        interface: Box<dyn RegKeyTrait>,
    ) -> Result<String, DnsInspectionError> {
        match (
            interface.get_value("DhcpNameServer"),
            interface.get_value("NameServer"),
        ) {
            (Err(_), Err(_)) => Err(DnsInspectionError::NotConnected),
            (Err(_), Ok(ref permanent)) if permanent == &String::new() => {
                Err(DnsInspectionError::NotConnected)
            }
            (Ok(ref dhcp), Err(_)) => Ok(dhcp.clone()),
            (Ok(ref dhcp), Ok(ref permanent)) if permanent == &String::new() => Ok(dhcp.clone()),
            (_, Ok(permanent)) => Ok(permanent),
        }
    }

    fn handle_reg_error<T>(&self, result: io::Result<T>) -> Result<T, DnsInspectionError> {
        match result {
            Ok(retval) => Ok(retval),
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => {
                Err(DnsInspectionError::RegistryQueryOsError(
                    "Registry contains no DNS information to display".to_string(),
                ))
            }
            Err(ref e) => Err(DnsInspectionError::RegistryQueryOsError(format!(
                "Unexpected error: {:?}",
                e
            ))),
        }
    }

    fn get_default_gateway(interface: &dyn RegKeyTrait) -> Option<String> {
        let string_opt = match (
            interface.get_value("DefaultGateway"),
            interface.get_value("DhcpDefaultGateway"),
        ) {
            (Ok(_), Ok(ddg)) => Some(ddg),
            (Ok(dg), Err(_)) => Some(dg),
            (Err(_), Ok(ddg)) => Some(ddg),
            (Err(_), Err(_)) => None,
        };
        match string_opt {
            Some(ref s) if s.is_empty() => None,
            Some(s) => Some(s),
            None => None,
        }
    }
}

pub trait RegKeyTrait: Debug {
    fn path(&self) -> &str;
    fn enum_keys(&self) -> Vec<io::Result<String>>;
    fn open_subkey_with_flags(&self, path: &str, perms: u32) -> io::Result<Box<dyn RegKeyTrait>>;
    fn get_value(&self, path: &str) -> io::Result<String>;
    fn set_value(&self, path: &str, value: &str) -> io::Result<()>;
    fn delete_value(&self, path: &str) -> io::Result<()>;
}

#[derive(Debug)]
struct RegKeyReal {
    delegate: RegKey,
    path: String,
}

impl RegKeyTrait for RegKeyReal {
    fn path(&self) -> &str {
        &self.path
    }

    fn enum_keys(&self) -> Vec<io::Result<String>> {
        self.delegate.enum_keys().collect()
    }

    fn open_subkey_with_flags(&self, path: &str, perms: u32) -> io::Result<Box<dyn RegKeyTrait>> {
        match self.delegate.open_subkey_with_flags(path, perms) {
            Ok(delegate) => Ok(Box::new(RegKeyReal {
                delegate,
                path: path.to_string(),
            })),
            Err(e) => Err(e),
        }
    }

    fn get_value(&self, name: &str) -> io::Result<String> {
        self.delegate.get_value(name)
    }

    fn set_value(&self, name: &str, value: &str) -> io::Result<()> {
        self.delegate.set_value(name, &value.to_string())
    }

    fn delete_value(&self, name: &str) -> io::Result<()> {
        self.delegate.delete_value(name)
    }
}

impl RegKeyReal {
    pub fn new(delegate: RegKey, path: &str) -> RegKeyReal {
        RegKeyReal {
            delegate,
            path: path.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::dns_inspector::DnsInspectionError;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Error;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn get_default_gateway_sees_dhcp_if_both_are_specified() {
        // Many people think this is incorrect behavior, but it seems to be the way Win7+ does things.
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Ok("DefaultGateway".to_string()))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsInspector::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DhcpDefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_naked_default_if_it_is_the_only_one_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Ok("DefaultGateway".to_string()))
                .get_value_result(
                    "DhcpDefaultGateway",
                    Err(Error::from_raw_os_error(NOT_FOUND)),
                ),
        );

        let result = WinDnsInspector::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_dhcp_default_if_it_is_the_only_one_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsInspector::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DhcpDefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_nothing_if_nothing_is_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result(
                    "DhcpDefaultGateway",
                    Err(Error::from_raw_os_error(NOT_FOUND)),
                ),
        );

        let result = WinDnsInspector::get_default_gateway(interface.as_ref());

        assert_eq!(result, None)
    }

    #[test]
    fn find_dns_servers_for_interface_handles_all_info_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_name_server_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from DHCP".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_dhcp_name_server_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result(
                    "NameServer",
                    Ok("name server list from permanent".to_string()),
                )
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from permanent".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_both_dhcp_and_nameserver() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result(
                    "NameServer",
                    Ok("name server list from permanent".to_string()),
                )
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from permanent".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_nameserver_blank_and_dhcp_nameserver_present() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Ok("".to_string()))
                .get_value_result(
                    "DhcpNameServer",
                    Ok("name server list from DHCP".to_string()),
                ),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Ok("name server list from DHCP".to_string()));
    }

    #[test]
    fn find_dns_servers_for_interface_handles_nameserver_blank_and_dhcp_nameserver_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Ok("".to_string()))
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsInspector::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(result, Err(DnsInspectionError::NotConnected));
    }

    #[test]
    fn inspect_complains_if_no_interfaces_key_exists() {
        let stream_holder = FakeStreamHolder::new();
        let hive = RegKeyMock::default()
            .open_subkey_with_flags_result(Err(Error::from_raw_os_error(NOT_FOUND)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(
            result.err().unwrap(),
            DnsInspectionError::RegistryQueryOsError(
                "Registry contains no DNS information to display".to_string()
            )
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_about_unexpected_os_error() {
        let hive =
            RegKeyMock::default().open_subkey_with_flags_result(Err(Error::from_raw_os_error(3)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        let error = result.err().unwrap();

        assert_eq!(
            error,DnsInspectionError::RegistryQueryOsError(r#"Unexpected error: Os { code: 3, kind: NotFound, message: "The system cannot find the path specified." }"#.to_string()),
            "{:?}",
            &error
        );
    }

    #[test]
    fn inspect_complains_if_no_interfaces_have_default_gateway_or_dhcp_default_gateway_values() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), DnsInspectionError::NotConnected);
    }

    #[test]
    fn inspect_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values()
    {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(result.err().unwrap(), DnsInspectionError::NotConnected);
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_gateway_values() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("DHCP Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let last_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("DHCP Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_interface"),
                Ok("another_interface"),
                Ok("last_interface"),
            ])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(last_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(
            result.err().unwrap(),
            DnsInspectionError::ConflictingEntries(3, 2)
        );
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_dns_server_lists() {
        let one_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("1.2.3.4".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("2.3.4.5,6.7.8.9".to_string()))
            .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND)));
        let another_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("1.2.3.4".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("3.4.5.6,7.8.9.0".to_string()))
            .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND)));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(
            result.err().unwrap(),
            DnsInspectionError::ConflictingEntries(2, 2)
        );
    }

    #[test]
    fn inspect_works_if_everything_is_fine() {
        let one_active_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("DhcpNameServer", Ok("goober".to_string()));
        let another_active_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("DhcpNameServer", Ok("ignored".to_string()));
        let inactive_interface = RegKeyMock::default()
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_active_interface"),
                Ok("another_active_interface"),
                Ok("inactive_interface"),
            ])
            .open_subkey_with_flags_result(Ok(Box::new(one_active_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_active_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(inactive_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsInspector::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect();

        assert_eq!(
            result.unwrap(),
            vec![
                IpAddr::from_str("8.8.8.8").unwrap(),
                IpAddr::from_str("8.8.8.9").unwrap()
            ]
        );
    }

    #[derive(Debug, Default)]
    struct RegKeyMock {
        path: String,
        enum_keys_results: RefCell<Vec<Vec<io::Result<String>>>>,
        open_subkey_with_flags_parameters: Arc<Mutex<Vec<(String, u32)>>>,
        open_subkey_with_flags_results: RefCell<Vec<io::Result<Box<dyn RegKeyTrait>>>>,
        get_value_parameters: Arc<Mutex<Vec<String>>>,
        get_value_results: RefCell<HashMap<String, Vec<io::Result<String>>>>,
        set_value_parameters: Arc<Mutex<Vec<(String, String)>>>,
        set_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
        delete_value_parameters: Arc<Mutex<Vec<String>>>,
        delete_value_results: RefCell<HashMap<String, Vec<io::Result<()>>>>,
    }

    impl RegKeyTrait for RegKeyMock {
        fn path(&self) -> &str {
            &self.path
        }

        fn enum_keys(&self) -> Vec<io::Result<String>> {
            self.enum_keys_results.borrow_mut().remove(0)
        }

        fn open_subkey_with_flags(
            &self,
            path: &str,
            perms: u32,
        ) -> io::Result<Box<dyn RegKeyTrait>> {
            self.open_subkey_with_flags_parameters
                .lock()
                .unwrap()
                .push((String::from(path), perms));
            self.open_subkey_with_flags_results.borrow_mut().remove(0)
        }

        fn get_value(&self, path: &str) -> io::Result<String> {
            self.get_value_parameters
                .lock()
                .unwrap()
                .push(String::from(path));
            self.get_result(&self.get_value_results, "get_value", path)
        }

        fn set_value(&self, path: &str, value: &str) -> io::Result<()> {
            self.set_value_parameters
                .lock()
                .unwrap()
                .push((String::from(path), String::from(value)));
            self.get_result(&self.set_value_results, "set_value", path)
        }

        fn delete_value(&self, path: &str) -> io::Result<()> {
            self.delete_value_parameters
                .lock()
                .unwrap()
                .push(String::from(path));
            self.get_result(&self.delete_value_results, "delete_value", path)
        }
    }

    impl RegKeyMock {
        pub fn enum_keys_result(self, result: Vec<io::Result<&str>>) -> RegKeyMock {
            self.enum_keys_results.borrow_mut().push(
                result
                    .into_iter()
                    .map(|item| match item {
                        Err(e) => Err(e),
                        Ok(slice) => Ok(String::from(slice)),
                    })
                    .collect(),
            );
            self
        }

        pub fn open_subkey_with_flags_result(
            self,
            result: io::Result<Box<dyn RegKeyTrait>>,
        ) -> RegKeyMock {
            self.open_subkey_with_flags_results
                .borrow_mut()
                .push(result);
            self
        }

        pub fn get_value_result(self, name: &str, result: io::Result<String>) -> RegKeyMock {
            self.prepare_result(&self.get_value_results, name, result);
            self
        }

        fn prepare_result<T>(
            &self,
            results: &RefCell<HashMap<String, Vec<io::Result<T>>>>,
            name: &str,
            result: io::Result<T>,
        ) {
            let mut results_map = results.borrow_mut();
            let vec_exists = { results_map.contains_key(name) };
            if vec_exists {
                let mut results_opt = results_map.get_mut(name);
                let results_ref = results_opt.as_mut().unwrap();
                results_ref.push(result);
            } else {
                let results = vec![result];
                results_map.insert(String::from(name), results);
            }
        }

        fn get_result<T: Clone + Debug>(
            &self,
            results: &RefCell<HashMap<String, Vec<io::Result<T>>>>,
            method: &str,
            name: &str,
        ) -> io::Result<T> {
            let mut results_map = results.borrow_mut();
            let results_opt = results_map.get_mut(name);
            let results_ref = results_opt
                .expect(format!("No results prepared for {} ({})", method, name).as_str());
            if results_ref.len() > 1 {
                self.get_result_mutable(results_ref)
            } else {
                self.get_result_immutable(results_ref, method, name)
            }
        }

        fn get_result_immutable<T: Clone + Debug>(
            &self,
            results: &Vec<io::Result<T>>,
            method: &str,
            name: &str,
        ) -> io::Result<T> {
            if results.len() == 0 {
                panic!("No results prepared for {} ({})", method, name)
            };
            let result_ref = results.first().unwrap();
            match result_ref {
                &Ok(ref s) => Ok(s.clone()),
                &Err(ref e) if e.raw_os_error().is_some() => {
                    Err(Error::from_raw_os_error(e.raw_os_error().unwrap()))
                }
                &Err(ref e) => Err(Error::from(e.kind())),
            }
        }

        fn get_result_mutable<T: Clone + Debug>(
            &self,
            results: &mut Vec<io::Result<T>>,
        ) -> io::Result<T> {
            results.remove(0)
        }
    }
}
