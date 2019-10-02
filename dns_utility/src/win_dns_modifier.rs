// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

use crate::dns_modifier::DnsModifier;
use crate::ipconfig_wrapper::{IpconfigWrapper, IpconfigWrapperReal};
use crate::netsh::{Netsh, NetshCommand, NetshError};
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use winreg::enums::*;
use winreg::RegKey;

const NOT_FOUND: i32 = 2;
const PERMISSION_DENIED: i32 = 5;
const PERMISSION_DENIED_STR: &str = "Permission denied";

pub struct WinDnsModifier {
    hive: Box<dyn RegKeyTrait>,
    ipconfig: Box<dyn IpconfigWrapper>,
    netsh: Box<dyn Netsh>,
}

impl DnsModifier for WinDnsModifier {
    fn type_name(&self) -> &'static str {
        "WinDnsModifier"
    }

    fn subvert(&self) -> Result<(), String> {
        let interfaces = self.find_interfaces_to_subvert()?;
        let begin_overhang: Vec<Box<dyn RegKeyTrait>> = vec![];
        let begin_error_opt: Option<String> = None;
        let (subverted_so_far, error_opt) = interfaces.into_iter().fold(
            (begin_overhang, begin_error_opt),
            |(so_far, error_opt), interface| {
                if error_opt.is_some() {
                    (so_far, error_opt)
                } else {
                    match self.subvert_interface(interface.as_ref()) {
                        Ok(_) => (plus(so_far, interface), error_opt),
                        Err(msg) => (plus(so_far, interface), Some(msg)),
                    }
                }
            },
        );
        match error_opt {
            Some(msg) => {
                subverted_so_far
                    .into_iter()
                    .for_each(|interface| self.roll_back_subvert(interface.as_ref()));
                Err(msg)
            }
            None => Ok(()),
        }
    }

    fn revert(&self) -> Result<(), String> {
        let interfaces = self.find_interfaces_to_revert()?;
        let begin_overhang: Vec<Box<dyn RegKeyTrait>> = vec![];
        let begin_error_opt: Option<String> = None;
        let (overhang, error_opt) = interfaces.into_iter().fold(
            (begin_overhang, begin_error_opt),
            |(overhang, error_opt), interface| {
                if error_opt.is_some() {
                    (overhang, error_opt)
                } else {
                    match self.revert_interface(interface.as_ref()) {
                        Ok(_) => (plus(overhang, interface), error_opt),
                        Err(msg) => (plus(overhang, interface), Some(msg)),
                    }
                }
            },
        );
        match error_opt {
            Some(msg) => {
                overhang
                    .into_iter()
                    .for_each(|interface| self.roll_back_revert(interface.as_ref()));
                Err(msg)
            }
            None => Ok(()),
        }
    }

    fn inspect(&self, stdout: &mut (dyn io::Write + Send)) -> Result<(), String> {
        let interfaces = self.find_interfaces_to_inspect()?;
        let dns_server_list_csv = self.find_dns_server_list(interfaces)?;
        let dns_server_list = dns_server_list_csv.split(',');
        let output = dns_server_list.fold(String::new(), |so_far, dns_server| {
            format!("{}{}\n", so_far, dns_server)
        });
        write!(stdout, "{}", output).expect("write is broken");
        Ok(())
    }
}

impl Default for WinDnsModifier {
    fn default() -> Self {
        WinDnsModifier {
            hive: Box::new(RegKeyReal::new(
                RegKey::predef(HKEY_LOCAL_MACHINE),
                "HKEY_LOCAL_MACHINE",
            )),
            ipconfig: Box::new(IpconfigWrapperReal {}),
            netsh: Box::new(NetshCommand {}),
        }
    }
}

impl WinDnsModifier {
    pub fn new() -> Self {
        Default::default()
    }

    fn find_interfaces_to_subvert(&self) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        self.find_interfaces(KEY_ALL_ACCESS)
    }

    fn find_interfaces_to_revert(&self) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        let interface_key = self.handle_reg_error(
            false,
            self.hive.open_subkey_with_flags(
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                KEY_ALL_ACCESS,
            ),
        )?;
        let revertible_interfaces = interface_key
            .enum_keys()
            .into_iter()
            .flat_map(|k| k)
            .flat_map(|interface_name| {
                interface_key.open_subkey_with_flags(&interface_name[..], KEY_ALL_ACCESS)
            })
            .filter(|interface| interface.get_value("NameServerBak").is_ok())
            .collect();
        Ok(revertible_interfaces)
    }

    pub fn find_interfaces_to_inspect(&self) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        self.find_interfaces(KEY_READ)
    }

    fn find_interfaces(&self, access_required: u32) -> Result<Vec<Box<dyn RegKeyTrait>>, String> {
        let interface_key = self.handle_reg_error(
            access_required == KEY_READ,
            self.hive.open_subkey_with_flags(
                "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                access_required,
            ),
        )?;
        let gateway_interfaces: Vec<Box<dyn RegKeyTrait>> = interface_key
            .enum_keys()
            .into_iter()
            .flat_map(|k| k)
            .flat_map(|interface_name| {
                interface_key.open_subkey_with_flags(&interface_name[..], access_required)
            })
            .filter(|interface| {
                WinDnsModifier::get_default_gateway(interface.as_ref()).is_some()
                    && interface.get_value("NameServer").is_ok()
            })
            .collect();
        if gateway_interfaces.is_empty() {
            return Err("This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
        }
        let distinct_gateway_ips: HashSet<String> = gateway_interfaces
            .iter()
            .flat_map(|interface| WinDnsModifier::get_default_gateway(interface.as_ref()))
            .collect();
        if distinct_gateway_ips.len() > 1 {
            let msg = match access_required {
                code if code == KEY_ALL_ACCESS => "Manual configuration required.",
                code if code == KEY_READ => "Cannot summarize DNS settings.",
                _ => "",
            };
            Err (format! ("This system has {} active network interfaces configured with {} different default gateways. {}",
                gateway_interfaces.len (), distinct_gateway_ips.len (), msg))
        } else {
            Ok(gateway_interfaces)
        }
    }

    pub fn find_dns_server_list(
        &self,
        interfaces: Vec<Box<dyn RegKeyTrait>>,
    ) -> Result<String, String> {
        let interfaces_len = interfaces.len();
        let list_result_vec: Vec<Result<String, String>> = interfaces
            .into_iter()
            .map(|interface| self.find_dns_servers_for_interface(interface))
            .collect();
        let errors: Vec<String> = list_result_vec
            .iter()
            .flat_map(|result_ref| match *result_ref {
                Err(ref e) => Some(e.clone()),
                Ok(_) => None,
            })
            .collect();
        if !errors.is_empty() {
            return Err(errors.join(", "));
        }
        let list_set: HashSet<String> = list_result_vec
            .into_iter()
            .flat_map(|result| match result {
                Err(e) => panic!("Error magically appeared: {}", e),
                Ok(list) => Some(list),
            })
            .collect();
        if list_set.len() > 1 {
            Err (format! ("This system has {} active network interfaces configured with {} different DNS server lists. Cannot summarize DNS settings.", interfaces_len, list_set.len ()))
        } else {
            let list_vec = list_set.into_iter().collect::<Vec<String>>();
            Ok(list_vec[0].clone())
        }
    }

    fn find_dns_servers_for_interface(
        &self,
        interface: Box<dyn RegKeyTrait>,
    ) -> Result<String, String> {
        match (
            interface.get_value("DhcpNameServer"),
            interface.get_value("NameServer"),
        ) {
            (Err(_), Err(_)) => Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string(),
            ),
            (Err(_), Ok(ref permanent)) if permanent == &String::new() => Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string(),
            ),
            (Ok(ref dhcp), Err(_)) => Ok(dhcp.clone()),
            (Ok(ref dhcp), Ok(ref permanent)) if permanent == &String::new() => Ok(dhcp.clone()),
            (_, Ok(permanent)) => Ok(permanent),
        }
    }

    fn subvert_interface(&self, interface: &dyn RegKeyTrait) -> Result<(), String> {
        let name_servers = interface
            .get_value("NameServer")
            .expect("Interface became unsubvertible. Check your DNS settings manually.");
        if WinDnsModifier::is_subverted(&name_servers) {
            return Ok(());
        }
        if WinDnsModifier::makes_no_sense(&name_servers) {
            return Err(String::from(
                "This system's DNS settings don't make sense; aborting",
            ));
        }
        self.handle_reg_error(
            false,
            interface.set_value("NameServerBak", name_servers.as_str()),
        )?;

        self.set_nameservers(interface, "127.0.0.1").map_err(|e| {
            if e == PERMISSION_DENIED_STR {
                "You must have administrative privilege to modify your DNS settings".to_string()
            } else {
                format!("Unexpected error: {}", e)
            }
        })
    }

    fn set_nameservers(
        &self,
        interface: &dyn RegKeyTrait,
        nameservers: &str,
    ) -> Result<(), String> {
        if let Some(friendly_name) = self.find_adapter_friendly_name(interface) {
            match self.netsh.set_nameserver(&friendly_name, nameservers) {
                Ok(()) => Ok(()),
                Err(NetshError::IOError(ref e)) if e.raw_os_error() == Some(PERMISSION_DENIED) => {
                    Err(PERMISSION_DENIED_STR.to_string())
                }
                Err(NetshError::IOError(ref e)) => Err(e.to_string()),
                Err(e) => Err(format!("{:?}", e)),
            }
        } else {
            Err(format!(
                "Could not find adapter name for interface: {}",
                interface.path()
            ))
        }
    }

    fn find_adapter_friendly_name(&self, interface: &dyn RegKeyTrait) -> Option<String> {
        if let Ok(adapters) = self.ipconfig.get_adapters() {
            adapters
                .into_iter()
                .find(|adapter| {
                    adapter.adapter_name().to_lowercase() == interface.path().to_lowercase()
                })
                .map(|adapter| adapter.friendly_name().to_string())
        } else {
            None
        }
    }

    fn roll_back_subvert(&self, interface: &dyn RegKeyTrait) {
        let old_nameservers = match interface.get_value("NameServerBak") {
            Err(_) => return, // Not yet backed up; no rollback necessary
            Ok(s) => s,
        };
        interface.delete_value("NameServerBak").expect(
            "Can't delete NameServerBak to roll back subversion. Check your DNS settings manually.",
        );

        if WinDnsModifier::is_subverted(&interface.get_value("NameServer").expect(
            "Can't get NameServer value to roll back subversion. Check your DNS settings manually.",
        )) {
            self.set_nameservers(interface, &old_nameservers).expect(
                "Can't reset NameServer to roll back subversion. Check your DNS settings manually.",
            )
        }
    }

    fn revert_interface(&self, interface: &dyn RegKeyTrait) -> Result<(), String> {
        let old_name_servers = interface
            .get_value("NameServerBak")
            .expect("Interface became unrevertible. Check your DNS settings manually.");

        match interface.get_value("NameServer") {
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => (), // don't create new NameServer if none exists
            _ => {
                // but it's okay to overwrite an existing NameServer
                match self.set_nameservers(interface, old_name_servers.as_str()) {
                    Ok(()) => (),
                    Err(ref e) if e == PERMISSION_DENIED_STR => {
                        return Err(String::from(
                            "You must have administrative privilege to modify your DNS settings",
                        ))
                    }
                    Err(e) => return Err(format!("Unexpected error: {}", e)),
                }
            }
        };

        self.handle_reg_error(false, interface.delete_value("NameServerBak"))
    }

    fn roll_back_revert(&self, interface: &dyn RegKeyTrait) {
        let old_nameservers = match interface.get_value("NameServer") {
            Err(_) => return, // No NameServer; no rollback necessary
            Ok(s) => s,
        };
        if WinDnsModifier::is_subverted(&old_nameservers) {
            return;
        }
        interface
            .set_value("NameServerBak", &old_nameservers)
            .expect(
                "Can't set NameServerBak to roll back reversion. Check your DNS settings manually.",
            );

        self.set_nameservers(interface, "127.0.0.1").expect(
            "Can't reset NameServer to roll back reversion. Check your DNS settings manually.",
        );
    }

    fn handle_reg_error<T>(&self, read_only: bool, result: io::Result<T>) -> Result<T, String> {
        match result {
            Ok(retval) => Ok(retval),
            Err(ref e) if e.raw_os_error() == Some(PERMISSION_DENIED) => Err(String::from(
                "You must have administrative privilege to modify your DNS settings",
            )),
            Err(ref e) if e.raw_os_error() == Some(NOT_FOUND) => Err(format!(
                "Registry contains no DNS information {}",
                if read_only { "to display" } else { "to modify" }
            )),
            Err(ref e) => Err(format!("Unexpected error: {:?}", e)),
        }
    }

    fn is_subverted(name_servers: &str) -> bool {
        name_servers == "127.0.0.1" || name_servers.starts_with("127.0.0.1,")
    }

    fn makes_no_sense(name_servers: &str) -> bool {
        name_servers.split(',').any(|ip| ip == "127.0.0.1")
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

pub fn plus<T>(mut source: Vec<T>, item: T) -> Vec<T> {
    let mut result = vec![];
    result.append(&mut source);
    result.push(item);
    result
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
        self.delegate.enum_keys().map(|x| x).collect()
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
    use crate::adapter_wrapper::test_utils::AdapterWrapperStub;
    use crate::adapter_wrapper::AdapterWrapper;
    use crate::fake_stream_holder::FakeStreamHolder;
    use crate::ipconfig_wrapper::test_utils::IpconfigWrapperMock;
    use crate::netsh::tests_utils::NetshMock;
    use crate::utils::get_parameters_from;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io::Error;
    use std::sync::Arc;
    use std::sync::Mutex;

    #[test]
    fn is_subverted_says_no_if_masq_dns_appears_too_late() {
        let result = WinDnsModifier::is_subverted(&"1.1.1.1,127.0.0.1".to_string());

        assert_eq!(result, false)
    }

    #[test]
    fn is_subverted_says_no_if_first_dns_is_only_masq_like() {
        let result = WinDnsModifier::is_subverted(&"127.0.0.11".to_string());

        assert_eq!(result, false)
    }

    #[test]
    fn is_subverted_says_yes_if_first_dns_is_masq() {
        let result = WinDnsModifier::is_subverted(&"127.0.0.1,1.1.1.1".to_string());

        assert_eq!(result, true)
    }

    #[test]
    fn get_default_gateway_sees_dhcp_if_both_are_specified() {
        // Many people think this is incorrect behavior, but it seems to be the way Win7+ does things.
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Ok("DefaultGateway".to_string()))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

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

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, Some("DefaultGateway".to_string()))
    }

    #[test]
    fn get_default_gateway_sees_dhcp_default_if_it_is_the_only_one_specified() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpDefaultGateway", Ok("DhcpDefaultGateway".to_string())),
        );

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

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

        let result = WinDnsModifier::get_default_gateway(interface.as_ref());

        assert_eq!(result, None)
    }

    #[test]
    fn windnsmodifier_knows_its_type_name() {
        let subject = WinDnsModifier::default();

        let result = subject.type_name();

        assert_eq!(result, "WinDnsModifier");
    }

    #[test]
    fn find_dns_servers_for_interface_handles_all_info_missing() {
        let interface: Box<dyn RegKeyTrait> = Box::new(
            RegKeyMock::default()
                .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
                .get_value_result("DhcpNameServer", Err(Error::from_raw_os_error(NOT_FOUND))),
        );
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(
            result,
            Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string()
            )
        );
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
        let subject = WinDnsModifier::new();

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
        let subject = WinDnsModifier::new();

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
        let subject = WinDnsModifier::new();

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
        let subject = WinDnsModifier::new();

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
        let subject = WinDnsModifier::new();

        let result = subject.find_dns_servers_for_interface(interface);

        assert_eq!(
            result,
            Err(
                "Interface has neither NameServer nor DhcpNameServer; probably not connected"
                    .to_string()
            )
        );
    }

    #[test]
    fn set_nameservers_complains_if_it_cant_find_the_adapter_friendly_name() {
        let mut subject = WinDnsModifier::new();
        let ipconfig =
            IpconfigWrapperMock::new().get_adapters_result(Err(Error::from_raw_os_error(3).into()));
        subject.ipconfig = Box::new(ipconfig);
        let interface = RegKeyMock::new("the_interface");

        let result = subject.set_nameservers(&interface, "nevermind");

        assert_eq!(
            result,
            Err("Could not find adapter name for interface: the_interface".to_string())
        );
    }

    #[test]
    fn subvert_complains_if_permission_is_denied() {
        let hive = RegKeyMock::default()
            .open_subkey_with_flags_result(Err(Error::from_raw_os_error(PERMISSION_DENIED)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            "You must have administrative privilege to modify your DNS settings".to_string()
        )
    }

    #[test]
    fn subvert_complains_if_no_interfaces_key_exists() {
        let hive = RegKeyMock::default()
            .open_subkey_with_flags_result(Err(Error::from_raw_os_error(NOT_FOUND)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            "Registry contains no DNS information to modify".to_string()
        )
    }

    #[test]
    fn subvert_complains_about_unexpected_os_error_from_registry() {
        let hive =
            RegKeyMock::default().open_subkey_with_flags_result(Err(Error::from_raw_os_error(3)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        let string_err = result.err().unwrap();
        assert!(
            string_err.starts_with("Unexpected error: "),
            "actual: {}",
            &string_err
        );
        assert!(string_err.contains("code: 3"), "actual: {}", &string_err);
    }

    #[test]
    fn subvert_complains_about_unexpected_os_error_from_netsh() {
        let mut subject = WinDnsModifier::default();
        let interface = RegKeyMock::new("interface")
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()))
            .set_value_result("NameServerBak", Ok(()));
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        subject.ipconfig = Box::new(ipconfig);
        let netsh = NetshMock::new()
            .set_nameserver_result(Err(NetshError::IOError(Error::from_raw_os_error(3))));
        subject.netsh = Box::new(netsh);

        let result = subject.subvert_interface(&interface);

        let string_err = result.err().unwrap();
        assert!(
            string_err.starts_with("Unexpected error: "),
            "actual: {}",
            &string_err
        );
        assert!(string_err.contains("os error 3"), "actual: {}", &string_err);
    }

    #[test]
    #[should_panic(
        expected = "Can't reset NameServer to roll back subversion. Check your DNS settings manually."
    )]
    fn roll_back_subvert_panics_when_set_nameserver_fails() {
        let mut subject = WinDnsModifier::new();
        let interface = RegKeyMock::new("interface")
            .delete_value_result("NameServerBak", Ok(()))
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Ok("fine".to_string()));

        let netsh = NetshMock::new().set_nameserver_result(Err(NetshError::IOError(
            Error::from_raw_os_error(PERMISSION_DENIED),
        )));
        subject.netsh = Box::new(netsh);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(build_adapter_stubs(&[(interface.path(), "Ethernet")]));
        subject.ipconfig = Box::new(ipconfig);

        subject.roll_back_subvert(&interface)
    }

    #[test]
    fn subvert_complains_if_no_interfaces_have_default_gateway_or_dhcp_default_gateway_values() {
        let get_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let another_interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            );
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
    }

    #[test]
    fn subvert_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values()
    {
        let get_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let another_interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok(String::new()))
            .get_value_result("DhcpDefaultGateway", Ok(String::new()));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
    }

    #[test]
    fn subvert_complains_if_interfaces_have_different_gateway_values() {
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
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("one_interface"), Ok("another_interface")])
            .open_subkey_with_flags_result(Ok(Box::new(one_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(result.err().unwrap(), "This system has 2 active network interfaces configured with 2 different default gateways. Manual configuration required.".to_string());
    }

    #[test]
    fn subvert_complains_if_dns_settings_dont_make_sense() {
        let get_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8,127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Err(Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        subject.ipconfig = Box::new(ipconfig);

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
        let get_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let ipconfig = IpconfigWrapperMock::new();
        subject.ipconfig = Box::new(
            ipconfig.get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())])),
        );

        let result = subject.subvert();

        assert_eq!(result, Ok(()));
        assert_eq!(
            get_parameters_from(open_subkey_with_flags_parameters_arc),
            vec!(("interface".to_string(), KEY_ALL_ACCESS),)
        );
    }

    #[test]
    fn subvert_complains_if_name_server_key_exists_and_is_not_writable() {
        let set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::new("interface")
            .set_value_parameters(&set_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("Not MASQ".to_string()))
            .set_value_result("NameServerBak", Ok(()))
            .delete_value_parameters(&delete_value_parameters_arc)
            .get_value_result("NameServerBak", Ok("Not MASQ".to_string()))
            .delete_value_result("NameServerBak", Ok(()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        let netsh = NetshMock::new().set_nameserver_result(Err(NetshError::IOError(
            Error::from_raw_os_error(PERMISSION_DENIED),
        )));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        subject.ipconfig = Box::new(ipconfig);
        subject.netsh = Box::new(netsh);

        let result = subject.subvert();

        assert_eq!(
            result.err().expect("result was not an error"),
            "You must have administrative privilege to modify your DNS settings"
        );
        assert_eq!(
            get_parameters_from(delete_value_parameters_arc),
            vec!("NameServerBak".to_string(),)
        );
    }

    #[test]
    fn subvert_backs_out_successes_if_there_is_a_failure_setting_nameserver() {
        let one_active_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_active_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_active_interface = RegKeyMock::new("one_active_interface")
            .set_value_parameters(&one_active_set_value_parameters_arc)
            .delete_value_parameters(&one_active_delete_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string())) // identify as subvertible
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string())) // retrieve for backup
            .set_value_result("NameServerBak", Ok(()))
            .get_value_result("NameServerBak", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("NameServer", Ok("127.0.0.1".to_string())) // identify as needing backout
            .delete_value_result("NameServerBak", Ok(()));
        let another_active_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_active_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_active_interface = RegKeyMock::new("another_active_interface")
            .set_value_parameters(&another_active_set_value_parameters_arc)
            .delete_value_parameters(&another_active_delete_value_parameters_arc)
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("9.9.9.9".to_string()))
            .set_value_result("NameServerBak", Ok(()))
            .get_value_result("NameServerBak", Ok("9.9.9.9".to_string()))
            .delete_value_result("NameServerBak", Ok(()));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_active_interface"),
                Ok("another_active_interface"),
            ])
            .open_subkey_with_flags_result(Ok(Box::new(one_active_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_active_interface)));

        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let netsh = NetshMock::new()
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Err(NetshError::IOError(Error::from_raw_os_error(
                PERMISSION_DENIED,
            ))))
            .set_nameserver_result(Ok(()));
        let set_nameserver_params = netsh.set_nameserver_parameters.clone();
        subject.netsh = Box::new(netsh);
        let ipconfig = IpconfigWrapperMock::new();
        subject.ipconfig = Box::new(
            ipconfig
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_active_interface", "Ethernet"),
                    ("another_active_interface", "Othernet"),
                ]))
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_active_interface", "Ethernet"),
                    ("another_active_interface", "Othernet"),
                ]))
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_active_interface", "Ethernet"),
                    ("another_active_interface", "Othernet"),
                ])),
        );

        let result = subject.subvert();

        assert_eq!(
            result.err().expect("result was not an error"),
            "You must have administrative privilege to modify your DNS settings"
        );
        assert_eq!(
            get_parameters_from(one_active_set_value_parameters_arc),
            vec!(("NameServerBak".to_string(), "8.8.8.8,8.8.8.9".to_string()),)
        );
        assert_eq!(
            get_parameters_from(one_active_delete_value_parameters_arc),
            vec!("NameServerBak".to_string(),)
        );
        assert_eq!(
            get_parameters_from(another_active_set_value_parameters_arc),
            vec!(("NameServerBak".to_string(), "9.9.9.9".to_string()),)
        );
        assert_eq!(
            get_parameters_from(another_active_delete_value_parameters_arc),
            vec!("NameServerBak".to_string(),)
        );
        assert_eq!(
            get_parameters_from(set_nameserver_params),
            vec![
                ("Ethernet".to_string(), "127.0.0.1".to_string()),
                ("Othernet".to_string(), "127.0.0.1".to_string()),
                ("Ethernet".to_string(), "8.8.8.8,8.8.8.9".to_string()),
            ]
        );
    }

    #[test]
    fn subvert_works_if_everything_is_fine() {
        let one_active_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_active_interface = RegKeyMock::new("one_active_interface")
            .get_value_result("DefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Ok("8.8.8.8,8.8.8.9".to_string()))
            .get_value_result("DhcpIPAddress", Ok("192.168.1.234".to_string()))
            .set_value_parameters(&one_active_set_value_parameters_arc)
            .set_value_result("NameServerBak", Ok(()));
        let another_active_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_active_interface = RegKeyMock::new("another_active_interface")
            .get_value_result("DefaultGateway", Err(Error::from_raw_os_error(NOT_FOUND)))
            .get_value_result("DhcpDefaultGateway", Ok("Common Gateway IP".to_string()))
            .get_value_result("NameServer", Ok("9.9.9.9".to_string()))
            .get_value_result("DhcpIPAddress", Ok("192.168.1.246".to_string()))
            .set_value_parameters(&another_active_set_value_parameters_arc)
            .set_value_result("NameServerBak", Ok(()));
        let inactive_interface = RegKeyMock::new("inactive_interface")
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
        let netsh = NetshMock::new()
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()));
        let netsh_params_arc = netsh.set_nameserver_parameters.clone();
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        subject.netsh = Box::new(netsh);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(build_adapter_stubs(&[
                ("one_active_interface", "One Ethernet"),
                ("another_active_interface", "Another Ethernet"),
            ]))
            .get_adapters_result(build_adapter_stubs(&[
                ("one_active_interface", "One Ethernet"),
                ("another_active_interface", "Another Ethernet"),
            ]));
        subject.ipconfig = Box::new(ipconfig);

        let result = subject.subvert();

        assert_eq!(result, Ok(()));
        assert_eq!(
            get_parameters_from(one_active_set_value_parameters_arc),
            vec![("NameServerBak".to_string(), "8.8.8.8,8.8.8.9".to_string())]
        );
        assert_eq!(
            get_parameters_from(another_active_set_value_parameters_arc),
            vec![("NameServerBak".to_string(), "9.9.9.9".to_string())]
        );

        assert_eq!(
            get_parameters_from(netsh_params_arc),
            vec![
                ("One Ethernet".to_string(), "127.0.0.1".to_string()),
                ("Another Ethernet".to_string(), "127.0.0.1".to_string())
            ]
        );
    }

    #[test]
    fn subvert_fails_if_no_nameserver_value_exists() {
        let get_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::default()
            .get_value_parameters(&get_value_parameters_arc)
            .set_value_parameters(&set_value_parameters_arc)
            .get_value_result("DefaultGateway", Ok("Gateway IP".to_string()))
            .get_value_result(
                "DhcpDefaultGateway",
                Err(Error::from_raw_os_error(NOT_FOUND)),
            )
            .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.subvert();

        assert_eq!(result, Err("This system has no accessible network interfaces configured with default gateways and DNS servers".to_string()));
    }

    #[test]
    fn revert_complains_if_backup_exists_and_backup_value_is_not_deletable() {
        let set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let set_nameserver_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::new("interface")
            .set_value_parameters(&set_value_parameters_arc)
            .delete_value_parameters(&delete_value_parameters_arc)
            .get_value_result("NameServerBak", Ok("8.8.8.8".to_string()))
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()))
            .set_value_result("NameServerBak", Ok(()))
            .delete_value_result(
                "NameServerBak",
                Err(Error::from_raw_os_error(PERMISSION_DENIED)),
            );
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]))
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        subject.ipconfig = Box::new(ipconfig);
        let mut netsh = NetshMock::new()
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()));
        netsh.set_nameserver_parameters = set_nameserver_parameters_arc.clone();
        subject.netsh = Box::new(netsh);

        let result = subject.revert();

        assert_eq!(
            result,
            Err(String::from(
                "You must have administrative privilege to modify your DNS settings"
            ))
        );
        assert_eq!(
            get_parameters_from(set_value_parameters_arc),
            vec!(("NameServerBak".to_string(), "8.8.8.8".to_string()),)
        );
        assert_eq!(
            get_parameters_from(set_nameserver_parameters_arc),
            vec![
                ("Ethernet".to_string(), "8.8.8.8".to_string()),
                ("Ethernet".to_string(), "127.0.0.1".to_string()),
            ]
        )
    }

    #[test]
    fn revert_complains_if_backup_exists_and_active_value_is_not_writable() {
        let set_nameserver_parameters_arc = Arc::new(Mutex::new(vec![]));
        let delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::new("interface")
            .delete_value_parameters(&delete_value_parameters_arc)
            .get_value_result("NameServerBak", Ok("Backed up IP".to_string()))
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .delete_value_result("NameServerBak", Ok(()))
            .set_value_result("NameServerBak", Ok(()));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        subject.ipconfig = Box::new(ipconfig);
        let mut netsh = NetshMock::new().set_nameserver_result(Err(NetshError::IOError(
            Error::from_raw_os_error(PERMISSION_DENIED),
        )));
        netsh.set_nameserver_parameters = set_nameserver_parameters_arc.clone();
        subject.netsh = Box::new(netsh);

        let result = subject.revert();

        assert_eq!(
            result,
            Err(String::from(
                "You must have administrative privilege to modify your DNS settings"
            ))
        );
        assert_eq!(
            get_parameters_from(set_nameserver_parameters_arc),
            vec![("Ethernet".to_string(), "Backed up IP".to_string())]
        );
    }

    #[test]
    fn revert_backs_out_successes_if_there_are_failures() {
        let one_subverted_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_subverted_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let set_nameserver_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_subverted_interface = RegKeyMock::new("one_subverted_interface")
            .set_value_parameters(&one_subverted_set_value_parameters_arc)
            .delete_value_parameters(&one_subverted_delete_value_parameters_arc)
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Ok("8.8.8.8".to_string()))
            .delete_value_result("NameServerBak", Ok(()))
            .get_value_result("NameServer", Ok("8.8.8.8".to_string()))
            .set_value_result("NameServerBak", Ok(()));
        let another_subverted_set_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_subverted_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_subverted_interface = RegKeyMock::new("another_subverted_interface")
            .set_value_parameters(&another_subverted_set_value_parameters_arc)
            .delete_value_parameters(&another_subverted_delete_value_parameters_arc)
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Ok("9.9.9.9".to_string()))
            .get_value_result("NameServer", Ok("9.9.9.9".to_string()))
            .delete_value_result(
                "NameServerBak",
                Err(Error::from_raw_os_error(PERMISSION_DENIED)),
            )
            .set_value_result("NameServerBak", Ok(()));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_subverted_interface"),
                Ok("another_subverted_interface"),
            ])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(one_subverted_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_subverted_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]))
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]))
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]))
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]));
        subject.ipconfig = Box::new(ipconfig);
        let mut netsh = NetshMock::new()
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()));
        netsh.set_nameserver_parameters = set_nameserver_parameters_arc.clone();
        subject.netsh = Box::new(netsh);

        let result = subject.revert();

        assert_eq!(
            result,
            Err(String::from(
                "You must have administrative privilege to modify your DNS settings"
            ))
        );
        assert_eq!(
            get_parameters_from(one_subverted_set_value_parameters_arc),
            vec!(("NameServerBak".to_string(), "8.8.8.8".to_string()),)
        );
        assert_eq!(
            get_parameters_from(one_subverted_delete_value_parameters_arc),
            vec!("NameServerBak".to_string(),)
        );
        assert_eq!(
            get_parameters_from(another_subverted_set_value_parameters_arc),
            vec!(("NameServerBak".to_string(), "9.9.9.9".to_string()),)
        );
        assert_eq!(
            get_parameters_from(another_subverted_delete_value_parameters_arc),
            vec!("NameServerBak".to_string())
        );
        assert_eq!(
            get_parameters_from(set_nameserver_parameters_arc),
            vec![
                ("Ethernet".to_string(), "8.8.8.8".to_string()),
                ("WiFi".to_string(), "9.9.9.9".to_string()),
                ("Ethernet".to_string(), "127.0.0.1".to_string()),
                ("WiFi".to_string(), "127.0.0.1".to_string()),
            ]
        )
    }

    #[test]
    fn revert_works_if_everything_is_fine() {
        let one_subverted_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let set_nameserver_parameters_arc = Arc::new(Mutex::new(vec![]));
        let one_subverted_interface = RegKeyMock::new("one_subverted_interface")
            .delete_value_parameters(&one_subverted_delete_value_parameters_arc)
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Ok("8.8.8.8".to_string()))
            .delete_value_result("NameServerBak", Ok(()));
        let another_subverted_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let another_subverted_interface = RegKeyMock::new("another_subverted_interface")
            .delete_value_parameters(&another_subverted_delete_value_parameters_arc)
            .get_value_result("NameServer", Ok("127.0.0.1".to_string()))
            .get_value_result("NameServerBak", Ok("9.9.9.9".to_string()))
            .set_value_result("NameServer", Ok(()))
            .delete_value_result("NameServerBak", Ok(()));
        let unsubverted_delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let unsubverted_interface = RegKeyMock::new("unsubverted_interface")
            .delete_value_parameters(&unsubverted_delete_value_parameters_arc)
            .get_value_result("NameServer", Ok("10.10.10.10".to_string()))
            .get_value_result("NameServerBak", Err(Error::from_raw_os_error(NOT_FOUND)));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![
                Ok("one_subverted_interface"),
                Ok("another_subverted_interface"),
                Ok("unsubverted_interface"),
            ])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(one_subverted_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(another_subverted_interface)))
            .open_subkey_with_flags_result(Ok(Box::new(unsubverted_interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]))
            .get_adapters_result(build_adapter_stubs(&[
                ("one_subverted_interface", "Ethernet"),
                ("another_subverted_interface", "WiFi"),
            ]));
        subject.ipconfig = Box::new(ipconfig);
        let mut netsh = NetshMock::new()
            .set_nameserver_result(Ok(()))
            .set_nameserver_result(Ok(()));
        netsh.set_nameserver_parameters = set_nameserver_parameters_arc.clone();
        subject.netsh = Box::new(netsh);

        let result = subject.revert();

        assert_eq!(result, Ok(()));
        assert_eq!(
            get_parameters_from(set_nameserver_parameters_arc),
            vec![
                ("Ethernet".to_string(), "8.8.8.8".to_string()),
                ("WiFi".to_string(), "9.9.9.9".to_string())
            ]
        );
        assert_eq!(
            get_parameters_from(one_subverted_delete_value_parameters_arc),
            vec!("NameServerBak".to_string())
        );
        assert_eq!(
            get_parameters_from(another_subverted_delete_value_parameters_arc),
            vec!("NameServerBak".to_string())
        );
        assert_eq!(
            get_parameters_from(unsubverted_delete_value_parameters_arc).len(),
            0
        );
    }

    #[test]
    fn revert_succeeds_with_no_work_if_no_subverted_nic_is_found() {
        let delete_value_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::default()
            .delete_value_parameters(&delete_value_parameters_arc)
            .get_value_result("NameServerBak", Err(Error::from_raw_os_error(NOT_FOUND)));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.revert();

        assert_eq!(result, Ok(()));
        assert_eq!(get_parameters_from(delete_value_parameters_arc).len(), 0);
    }

    #[test]
    fn revert_succeeds_after_deleting_name_server_bak_if_no_name_server_is_found() {
        let set_value_parameters = Arc::new(Mutex::new(vec![]));
        let delete_value_parameters = Arc::new(Mutex::new(vec![]));
        let interface = RegKeyMock::default()
            .set_value_parameters(&set_value_parameters)
            .delete_value_parameters(&delete_value_parameters)
            .get_value_result("NameServerBak", Ok("8.8.8.8".to_string()))
            .get_value_result("NameServer", Err(Error::from_raw_os_error(NOT_FOUND)))
            .delete_value_result("NameServerBak", Ok(()));
        let open_subkey_with_flags_parameters_arc = Arc::new(Mutex::new(vec![]));
        let interfaces = RegKeyMock::default()
            .enum_keys_result(vec![Ok("interface")])
            .open_subkey_with_flags_parameters(&open_subkey_with_flags_parameters_arc)
            .open_subkey_with_flags_result(Ok(Box::new(interface)));
        let hive = RegKeyMock::default().open_subkey_with_flags_result(Ok(Box::new(interfaces)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.revert();

        assert_eq!(result, Ok(()));
        assert_eq!(
            get_parameters_from(delete_value_parameters),
            vec!("NameServerBak".to_string())
        );
    }

    #[test]
    fn revert_complains_about_unexpected_os_error_from_netsh() {
        let mut subject = WinDnsModifier::default();
        let interface = RegKeyMock::new("interface")
            .get_value_result("NameServerBak", Ok("8.8.8.8".to_string()))
            .get_value_result("NameServer", Ok("OverwriteMe".to_string()));
        let ipconfig = IpconfigWrapperMock::new()
            .get_adapters_result(Ok(vec![Box::new(AdapterWrapperStub::default())]));
        subject.ipconfig = Box::new(ipconfig);
        let netsh = NetshMock::new()
            .set_nameserver_result(Err(NetshError::IOError(Error::from_raw_os_error(3))));
        subject.netsh = Box::new(netsh);

        let result = subject.revert_interface(&interface);

        let string_err = result.err().unwrap();
        assert!(
            string_err.starts_with("Unexpected error: "),
            "actual: {}",
            &string_err
        );
        assert!(string_err.contains("os error 3"), "actual: {}", &string_err);
    }

    #[test]
    fn inspect_complains_if_no_interfaces_key_exists() {
        let mut stream_holder = FakeStreamHolder::new();
        let hive = RegKeyMock::default()
            .open_subkey_with_flags_result(Err(Error::from_raw_os_error(NOT_FOUND)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result.err().unwrap(),
            "Registry contains no DNS information to display".to_string()
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_about_unexpected_os_error() {
        let mut stream_holder = FakeStreamHolder::new();
        let hive =
            RegKeyMock::default().open_subkey_with_flags_result(Err(Error::from_raw_os_error(3)));
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect(stream_holder.streams().stdout);

        let string_err = result.err().unwrap();
        assert_eq!(
            string_err.starts_with("Unexpected error: "),
            true,
            "{}",
            &string_err
        );
        assert_eq!(string_err.contains("code: 3"), true, "{}", &string_err);
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_no_interfaces_have_default_gateway_or_dhcp_default_gateway_values() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_blank_default_gateway_and_dhcp_default_gateway_values()
    {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result.err().unwrap(), "This system has no accessible network interfaces configured with default gateways and DNS servers".to_string());
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_gateway_values() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result.err().unwrap(), "This system has 3 active network interfaces configured with 2 different default gateways. Cannot summarize DNS settings.".to_string());
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_interfaces_have_different_dns_server_lists() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let ipconfig = IpconfigWrapperMock::new();
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        subject.ipconfig = Box::new(
            ipconfig
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_interface", "Ethernet"),
                    ("another_interface", "Wifi"),
                ]))
                .get_adapters_result(build_adapter_stubs(&[
                    ("one_interface", "Ethernet"),
                    ("another_interface", "Wifi"),
                ])),
        );

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result.err().unwrap(), "This system has 2 active network interfaces configured with 2 different DNS server lists. Cannot summarize DNS settings.".to_string());
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_works_if_everything_is_fine() {
        let mut stream_holder = FakeStreamHolder::new();
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
        let mut subject = WinDnsModifier::default();
        subject.hive = Box::new(hive);
        let ipconfig = IpconfigWrapperMock::new();
        subject.ipconfig = Box::new(ipconfig.get_adapters_result(build_adapter_stubs(&[
            ("one_active_interface", "Ethernet"),
            ("another_active_interface", "Wifi"),
        ])));

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(result, Ok(()));
        assert_eq!(
            stream_holder.stdout.get_string(),
            "8.8.8.8\n8.8.8.9\n".to_string()
        );
    }

    fn build_adapter_stubs(
        names: &[(&str, &str)],
    ) -> Result<Vec<Box<dyn AdapterWrapper>>, ipconfig::error::Error> {
        Ok(names
            .iter()
            .map(|(adapter_name, friendly_name)| {
                Box::new(AdapterWrapperStub {
                    adapter_name: adapter_name.to_string(),
                    friendly_name: friendly_name.to_string(),
                }) as Box<dyn AdapterWrapper>
            })
            .collect())
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
        pub fn new(path: &str) -> RegKeyMock {
            RegKeyMock {
                path: path.to_string(),
                enum_keys_results: RefCell::new(vec![]),
                open_subkey_with_flags_parameters: Arc::new(Mutex::new(vec![])),
                open_subkey_with_flags_results: RefCell::new(vec![]),
                get_value_parameters: Arc::new(Mutex::new(vec![])),
                get_value_results: RefCell::new(HashMap::new()),
                set_value_parameters: Arc::new(Mutex::new(vec![])),
                set_value_results: RefCell::new(HashMap::new()),
                delete_value_parameters: Arc::new(Mutex::new(vec![])),
                delete_value_results: RefCell::new(HashMap::new()),
            }
        }

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

        pub fn open_subkey_with_flags_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(String, u32)>>>,
        ) -> RegKeyMock {
            self.open_subkey_with_flags_parameters = parameters.clone();
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

        pub fn get_value_parameters(mut self, parameters: &Arc<Mutex<Vec<String>>>) -> RegKeyMock {
            self.get_value_parameters = parameters.clone();
            self
        }

        pub fn get_value_result(self, name: &str, result: io::Result<String>) -> RegKeyMock {
            self.prepare_result(&self.get_value_results, name, result);
            self
        }

        pub fn set_value_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<(String, String)>>>,
        ) -> RegKeyMock {
            self.set_value_parameters = parameters.clone();
            self
        }

        pub fn set_value_result(self, name: &str, result: io::Result<()>) -> RegKeyMock {
            self.prepare_result(&self.set_value_results, name, result);
            self
        }

        pub fn delete_value_parameters(
            mut self,
            parameters: &Arc<Mutex<Vec<String>>>,
        ) -> RegKeyMock {
            self.delete_value_parameters = parameters.clone();
            self
        }

        pub fn delete_value_result(self, name: &str, result: io::Result<()>) -> RegKeyMock {
            self.prepare_result(&self.delete_value_results, name, result);
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
