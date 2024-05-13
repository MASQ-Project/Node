// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
#![cfg(target_os = "linux")]
use crate::dns_modifier::DnsModifier;
use regex::Regex;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::ops::Add;
use std::path::Path;
use std::path::PathBuf;

pub struct ResolvConfDnsModifier {
    root: PathBuf,
}

impl DnsModifier for ResolvConfDnsModifier {
    fn type_name(&self) -> &'static str {
        "ResolvConfDnsModifier"
    }

    #[allow(unused_mut)]
    fn subvert(&self) -> Result<(), String> {
        let (mut file, contents_before) = self.open_resolv_conf(true)?;
        let contents_after = self.subvert_contents(contents_before)?;
        self.replace_contents(file, contents_after)
    }

    #[allow(unused_mut)]
    fn revert(&self) -> Result<(), String> {
        let (mut file, contents_before) = self.open_resolv_conf(true)?;
        let contents_after = self.revert_contents(contents_before)?;
        self.replace_contents(file, contents_after)
    }

    #[allow(unused_mut)]
    fn inspect(&self, stdout: &mut (dyn io::Write + Send)) -> Result<(), String> {
        let (_, contents) = self.open_resolv_conf(false)?;
        self.inspect_contents(contents, stdout)
    }
}

impl Default for ResolvConfDnsModifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvConfDnsModifier {
    pub fn new() -> ResolvConfDnsModifier {
        ResolvConfDnsModifier {
            root: PathBuf::from("/"),
        }
    }

    fn open_resolv_conf(&self, for_write: bool) -> Result<(File, String), String> {
        let mut open_options = OpenOptions::new();
        open_options.read(true);
        open_options.write(for_write);
        open_options.create(false);
        let path = Path::new(&self.root)
            .join(Path::new("etc"))
            .join(Path::new("resolv.conf"));
        let mut file = match open_options.open(path.clone()) {
            Ok(f) => f,
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                return Err(ResolvConfDnsModifier::process_msg(
                    "/etc/resolv.conf was not found",
                    for_write,
                ));
            }
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied => {
                let suffix = if for_write { " and writable" } else { "" };
                let msg = format!("/etc/resolv.conf is not readable{}", suffix);
                return Err(ResolvConfDnsModifier::process_msg(msg.as_str(), for_write));
            }
            Err(ref e) if e.raw_os_error() == Some(21) => {
                return Err(ResolvConfDnsModifier::process_msg(
                    "/etc/resolv.conf is a directory",
                    for_write,
                ));
            }
            Err(e) => return Err(format!("Unexpected error opening {:?}: {}", path, e)),
        };
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return Err(ResolvConfDnsModifier::process_msg(
                "/etc/resolv.conf is not a UTF-8 text file",
                for_write,
            ));
        }
        Ok((file, contents))
    }

    fn process_msg(msg: &str, for_write: bool) -> String {
        if for_write {
            format!("{} and could not be modified", msg)
        } else {
            msg.to_string()
        }
    }

    fn subvert_contents(&self, contents_before: String) -> Result<String, String> {
        let active_nameservers = self.active_nameservers(&contents_before[..]);
        self.check_disconnected(&active_nameservers)?;
        if self.check_already_subverted(&active_nameservers) {
            return Ok(contents_before);
        }
        self.check_for_nonsense(&active_nameservers)?;
        let mut contents_after = contents_before.clone();
        let mut existing_nameservers = self.existing_nameservers(&contents_before[..]);
        existing_nameservers.reverse();
        existing_nameservers.iter().for_each(|tuple_ref| {
            let start = tuple_ref.1;
            contents_after.insert(start, '#');
        });
        contents_after.push_str("\nnameserver 127.0.0.1\n");
        Ok(contents_after)
    }

    fn revert_contents(&self, contents_before: String) -> Result<String, String> {
        let mut contents_after = contents_before.clone();
        let (begin, length) = match self.find_masq_nameserver(&contents_after[..])? {
            Some(t) => t,
            None => return Ok(contents_before),
        };
        contents_after = ResolvConfDnsModifier::remove_span(contents_after, begin, length);
        let mut existing_nameservers = self.existing_nameservers(&contents_after[..]);
        if existing_nameservers.is_empty() {
            return Err(String::from(
                "There do not appear to be any DNS settings to revert to",
            ));
        }
        existing_nameservers.reverse();
        existing_nameservers.iter().for_each(|tuple_ref| {
            let start = tuple_ref.1;
            contents_after.remove(start);
        });
        Ok(contents_after)
    }

    fn inspect_contents(
        &self,
        contents: String,
        stdout: &mut (dyn Write + Send),
    ) -> Result<(), String> {
        let active_nameservers = self.active_nameservers(&contents[..]);
        self.check_disconnected(&active_nameservers)?;
        let output_list = active_nameservers
            .into_iter()
            .map(|pair| self.nameserver_line_to_ip(pair.0))
            .fold(String::new(), |so_far, ip_address| {
                format!("{}{}\n", so_far, ip_address)
            });
        write!(stdout, "{}", output_list).expect("stdout doesn't work");
        Ok(())
    }

    pub fn nameserver_line_to_ip(&self, nameserver_line: String) -> String {
        let regex = Regex::new(r"^\s*nameserver\s+([^\s#]*)").expect("Regex syntax error");
        let captures = regex
            .captures(nameserver_line.as_str())
            .unwrap_or_else(|| panic!("Badly formatted nameserver line: {}", nameserver_line));
        String::from(
            captures
                .get(1)
                .expect("Regex had no capture group")
                .as_str(),
        )
    }

    pub fn active_nameservers(&self, contents: &str) -> Vec<(String, usize)> {
        let regex = Regex::new(r"(^|\n)\s*(nameserver\s+[^\s]*)").expect("Regex syntax error");
        let capture_matches = regex.captures_iter(contents);
        capture_matches
            .map(|captures| {
                let capture = captures.get(2).expect("Inconsistent regex code");
                (String::from(capture.as_str()), capture.start())
            })
            .collect()
    }

    pub fn existing_nameservers(&self, contents: &str) -> Vec<(String, usize)> {
        let regex = Regex::new(r"(^|\n)\s*(#?\s*nameserver\s+[^\s]*)").expect("Regex syntax error");
        let capture_matches = regex.captures_iter(contents);
        capture_matches
            .map(|captures| {
                let capture = captures.get(2).expect("Inconsistent regex code");
                (String::from(capture.as_str()), capture.start())
            })
            .collect()
    }

    pub fn is_masq_ip(nameserver_entry: &str) -> bool {
        let syntax_regex = Regex::new(r"nameserver\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*(#|$)")
            .expect("Regex syntax error");
        if !syntax_regex.is_match(nameserver_entry) {
            return false;
        }
        let masq_regex =
            Regex::new(r"nameserver\s+127\.0\.0\.1([#\s]|$)").expect("Regex syntax error");
        masq_regex.is_match(nameserver_entry)
    }

    fn find_masq_nameserver(&self, contents: &str) -> Result<Option<(usize, usize)>, String> {
        // TODO: Should probably use active_nameservers()
        let regex =
            Regex::new(r"(^|\n)\s*(nameserver\s+127\.0\.0\.1\n?)").expect("Regex syntax error");
        let capture_matches = regex.captures_iter(contents);
        let mut results: Vec<(usize, usize)> = capture_matches
            .map(|captures| {
                let capture = captures.get(2).expect("Inconsistent regex code");
                (capture.start(), capture.as_str().len())
            })
            .collect();
        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(results.remove(0))),
            _ => Err(String::from(
                "This system's DNS settings don't make sense; aborting",
            )),
        }
    }

    #[allow(unused_mut)]
    fn replace_contents(&self, mut file: File, contents: String) -> Result<(), String> {
        match self.replace_contents_system(file, contents) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("/etc/resolv.conf could not be modified: {:?}", e)),
        }
    }

    fn replace_contents_system(&self, mut file: File, contents: String) -> io::Result<()> {
        let _ = file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        let _ = file.write(contents.as_bytes())?;
        Ok(())
    }

    fn check_disconnected(&self, active_nameservers: &[(String, usize)]) -> Result<(), String> {
        if active_nameservers.is_empty() {
            Err(String::from(
                "This system does not appear to be connected to a network",
            ))
        } else {
            Ok(())
        }
    }

    fn check_already_subverted(&self, active_nameservers: &[(String, usize)]) -> bool {
        let first_active_nameserver = active_nameservers
            .first()
            .expect("Internal error")
            .0
            .clone();
        ResolvConfDnsModifier::is_masq_ip(&first_active_nameserver)
    }

    fn check_for_nonsense(&self, active_nameservers: &[(String, usize)]) -> Result<(), String> {
        if active_nameservers
            .iter()
            .any(|tuple| ResolvConfDnsModifier::is_masq_ip(&tuple.0))
        {
            Err(String::from(
                "This system's DNS settings don't make sense; aborting",
            ))
        } else {
            Ok(())
        }
    }

    fn remove_span(s: String, begin: usize, length: usize) -> String {
        let prefix = &s[..begin];
        let suffix = &s[(begin + length)..];
        let result = String::from(prefix);
        result.add(suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use masq_lib::test_utils::fake_stream_holder::FakeStreamHolder;
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[should_panic(expected = "Badly formatted nameserver line: booga-booga")]
    fn nameserver_line_to_ip_panics_when_given_badly_formatted_nameserver_line() {
        let nameserver_line = "booga-booga".to_string();
        let subject = ResolvConfDnsModifier::new();

        subject.nameserver_line_to_ip(nameserver_line);
    }

    #[test]
    fn nameserver_line_to_ip_handles_line_with_leading_whitespace_and_comment() {
        let nameserver_line =
            "  \t  \tnameserver  \t  \t booga-booga  \t\t  # comment #".to_string();
        let subject = ResolvConfDnsModifier::new();

        let result = subject.nameserver_line_to_ip(nameserver_line);

        assert_eq!(result, "booga-booga".to_string());
    }

    #[test]
    fn nameserver_line_to_ip_handles_line_with_minimum_whitespace_and_no_comment() {
        let nameserver_line = "nameserver booga-booga".to_string();
        let subject = ResolvConfDnsModifier::new();

        let result = subject.nameserver_line_to_ip(nameserver_line);

        assert_eq!(result, "booga-booga".to_string());
    }

    #[test]
    fn active_nameservers_are_properly_detected_in_trimmed_file() {
        let contents =
            "nameserver beginning\n#nameserver commented\n# nameserver commented2\n nameserver preceded_by_space\nnameserver followed_by_space \nnameserver with more than two words\n ## nameserver double_comment\nnameserver ending";
        let subject = ResolvConfDnsModifier::new();

        let result = subject.active_nameservers(contents);

        assert_eq!(
            result,
            vec!(
                (String::from("nameserver beginning"), 0),
                (String::from("nameserver preceded_by_space"), 68),
                (String::from("nameserver followed_by_space"), 97),
                (String::from("nameserver with"), 127),
                (String::from("nameserver ending"), 193)
            )
        );
    }

    #[test]
    fn active_nameservers_are_properly_detected_in_untrimmed_file() {
        let contents =
            "#leading comment\nnameserver beginning\nnameserver ending\n#trailing comment";
        let subject = ResolvConfDnsModifier::new();

        let result = subject.active_nameservers(contents);

        assert_eq!(
            result,
            vec!(
                (String::from("nameserver beginning"), 17),
                (String::from("nameserver ending"), 38)
            )
        );
    }

    #[test]
    fn existing_nameservers_are_properly_detected_in_trimmed_file() {
        let contents =
            "#nameserver beginning\n#nameserver commented\n# nameserver commented2\n #nameserver preceded_by_space\nnameserver followed_by_space \nnameserver with more than two words\n##nameserver double_comment\nnameserver ending";
        let subject = ResolvConfDnsModifier::new();

        let result = subject.existing_nameservers(contents);

        assert_eq!(
            result,
            vec!(
                (String::from("#nameserver beginning"), 0),
                (String::from("#nameserver commented"), 22),
                (String::from("# nameserver commented2"), 44),
                (String::from("#nameserver preceded_by_space"), 69),
                (String::from("nameserver followed_by_space"), 99),
                (String::from("nameserver with"), 129),
                (String::from("nameserver ending"), 193)
            )
        );
    }

    #[test]
    fn existing_nameservers_are_properly_detected_in_untrimmed_file() {
        let contents =
            "#leading comment\n#nameserver beginning\nnameserver ending\n#trailing comment";
        let subject = ResolvConfDnsModifier::new();

        let result = subject.existing_nameservers(contents);

        assert_eq!(
            result,
            vec!(
                (String::from("#nameserver beginning"), 17),
                (String::from("nameserver ending"), 39)
            )
        );
    }

    #[test]
    fn is_masq_ip_detects_masq_dns_with_nothing_following() {
        let nameserver_entry = "nameserver 127.0.0.1";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, true);
    }

    #[test]
    fn is_masq_ip_detects_masq_dns_with_whitespace_following() {
        let nameserver_entry = "nameserver 127.0.0.1 #comment";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, true);
    }

    #[test]
    fn is_masq_ip_detects_masq_dns_with_hashmark_following() {
        let nameserver_entry = "nameserver 127.0.0.1#comment";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, true);
    }

    #[test]
    fn is_masq_ip_detects_absence_of_masq_dns_with_valid_ip() {
        let nameserver_entry = "nameserver 127.0.0.12";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, false);
    }

    #[test]
    fn is_masq_ip_detects_absence_of_masq_dns_with_valid_ip_and_whitespace() {
        let nameserver_entry = "nameserver 127.0.0.12 #comment";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, false);
    }

    #[test]
    fn is_masq_ip_detects_absence_of_masq_dns_with_valid_ip_and_hashmark() {
        let nameserver_entry = "nameserver 127.0.0.12#comment";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, false);
    }

    #[test]
    fn is_masq_ip_detects_absence_of_masq_dns_with_invalid_ip() {
        let nameserver_entry = "nameserver 127.0.0.1A";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, false);
    }

    #[test]
    fn is_masq_ip_detects_absence_of_masq_dns_with_invalid_comment() {
        let nameserver_entry = "nameserver 127.0.0.1 A";

        let result = ResolvConfDnsModifier::is_masq_ip(nameserver_entry);

        assert_eq!(result, false);
    }

    #[test]
    fn replace_contents_translates_system_errors() {
        let root = make_root("replace_contents_translates_system_errors");
        {
            let file = make_resolv_conf(&root, "original original original");
            let mut permissions = file.metadata().unwrap().permissions();
            permissions.set_mode(0o555);
            file.set_permissions(permissions).unwrap();
        }
        let file = File::open(root.join(Path::new("etc")).join(Path::new("resolv.conf"))).unwrap();
        let subject = ResolvConfDnsModifier::new();

        let result = subject.replace_contents(file, String::from("modified modified modified"));
        let result_err = result.err().unwrap();

        assert_eq!(
            result_err.starts_with("/etc/resolv.conf could not be modified: "),
            true,
            "{}",
            &result_err
        );
        assert_eq!(
            result_err.contains("\"Invalid argument\""),
            true,
            "{}",
            &result_err
        );
    }

    #[test]
    fn instance_knows_its_type_name() {
        let subject = ResolvConfDnsModifier::new();

        let result = subject.type_name();

        assert_eq!(result, "ResolvConfDnsModifier");
    }

    #[test]
    fn subvert_complains_if_resolv_conf_does_not_exist() {
        let root = make_root("subvert_complains_if_resolv_conf_does_not_exist");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf was not found and could not be modified")
        )
    }

    #[test]
    fn subvert_complains_if_resolv_conf_exists_but_is_a_directory() {
        let root = make_root("subvert_complains_if_resolv_conf_exists_but_is_a_directory");
        fs::create_dir_all(
            Path::new(&root)
                .join(Path::new("etc"))
                .join(Path::new("resolv.conf")),
        )
        .unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is a directory and could not be modified")
        )
    }

    #[test]
    fn subvert_complains_if_resolv_conf_exists_but_is_not_readable() {
        let root = make_root("subvert_complains_if_resolv_conf_exists_but_is_not_readable");
        let file = make_resolv_conf(&root, "");
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_mode(0o333);
        file.set_permissions(permissions.clone()).unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        permissions.set_mode(0o777);
        file.set_permissions(permissions).unwrap();
        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not readable and writable and could not be modified")
        )
    }

    #[test]
    fn subvert_complains_if_resolv_conf_exists_but_is_not_writable() {
        let root = make_root("subvert_complains_if_resolv_conf_exists_but_is_not_writable");
        let file = make_resolv_conf(&root, "");
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_mode(0o555);
        file.set_permissions(permissions).unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not readable and writable and could not be modified")
        )
    }

    #[test]
    fn subvert_complains_if_resolv_conf_is_not_utf_8() {
        let root = make_root("subvert_complains_if_resolv_conf_is_not_utf_8");
        let mut file = make_resolv_conf(&root, "");
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write(&[192, 193]).unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not a UTF-8 text file and could not be modified")
        )
    }

    #[test]
    fn subvert_backs_off_if_dns_is_already_subverted() {
        let root = make_root("subvert_backs_off_if_dns_is_already_subverted");
        make_resolv_conf(&root, "nameserver 127.0.0.1\nnameserver 8.8.8.8\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root.clone();

        let result = subject.subvert();

        let contents = get_resolv_conf(&root);
        assert_eq!(
            contents,
            String::from("nameserver 127.0.0.1\nnameserver 8.8.8.8\n")
        );
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn subvert_complains_if_dns_settings_dont_make_sense() {
        let root = make_root("subvert_complains_if_dns_settings_dont_make_sense");
        make_resolv_conf(&root, "nameserver 8.8.8.8\nnameserver 127.0.0.1\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("This system's DNS settings don't make sense; aborting")
        )
    }

    #[test]
    fn subvert_complains_if_there_is_no_preexisting_nameserver_directive() {
        let root = make_root("subvert_complains_if_there_is_no_preexisting_nameserver_directive");
        make_resolv_conf(&root, "");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.subvert();

        assert_eq!(
            result.err().unwrap(),
            String::from("This system does not appear to be connected to a network")
        )
    }

    #[test]
    fn subvert_works_if_everything_is_copacetic() {
        let root = make_root("subvert_works_if_everything_is_copacetic");
        make_resolv_conf (&root, "#comment\n# nameserver 1.1.1.1\nnameserver 127.0.0.111#comment\nnameserver 8.8.8.8\nunrecognized directive\nnameserver 9.9.9.9");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root.clone();

        let result = subject.subvert();

        let contents = get_resolv_conf(&root);
        assert_eq! (contents, String::from (
            "#comment\n## nameserver 1.1.1.1\n#nameserver 127.0.0.111#comment\n#nameserver 8.8.8.8\nunrecognized directive\n#nameserver 9.9.9.9\nnameserver 127.0.0.1\n"
        ));
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn revert_backs_off_if_dns_is_not_subverted() {
        let root = make_root("revert_backs_off_if_dns_is_not_subverted");
        make_resolv_conf(&root, "#nameserver 127.0.0.1\nnameserver 8.8.8.8\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root.clone();

        let result = subject.revert();

        let contents = get_resolv_conf(&root);
        assert_eq!(
            contents,
            String::from("#nameserver 127.0.0.1\nnameserver 8.8.8.8\n")
        );
        assert_eq!(result.is_ok(), true, "{:?}", result);
    }

    #[test]
    fn revert_complains_if_there_is_no_single_masq_nameserver_directive() {
        let root = make_root("revert_complains_if_there_is_no_single_masq_nameserver_directive");
        make_resolv_conf(
            &root,
            "nameserver 127.0.0.1\n#nameserver 8.8.8.8\nnameserver 127.0.0.1\n",
        );
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.revert();

        assert_eq!(
            result.err().unwrap(),
            String::from("This system's DNS settings don't make sense; aborting")
        )
    }

    #[test]
    fn revert_complains_if_there_is_no_single_commented_non_masq_nameserver_directive() {
        let root = make_root(
            "revert_complains_if_there_is_no_single_commented_non_masq_nameserver_directive",
        );
        make_resolv_conf(&root, "nameserver 127.0.0.1\n## nameserver 8.8.8.8\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.revert();

        assert_eq!(
            result.err().unwrap(),
            String::from("There do not appear to be any DNS settings to revert to")
        )
    }

    #[test]
    fn revert_works_if_everything_is_copacetic() {
        let root = make_root("revert_works_if_everything_is_copacetic");
        make_resolv_conf (&root, "#comment\n## nameserver 1.1.1.1\n#nameserver 8.8.8.8\n#nameserver 9.9.9.9\nnameserver 127.0.0.1\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root.clone();

        let result = subject.revert();

        let contents = get_resolv_conf(&root);
        assert_eq!(
            contents,
            String::from(
                "#comment\n## nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n"
            )
        );
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn inspect_complains_if_resolv_conf_does_not_exist() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_complains_if_resolv_conf_does_not_exist");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf was not found")
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_resolv_conf_exists_but_is_a_directory() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_complains_if_resolv_conf_exists_but_is_a_directory");
        fs::create_dir_all(
            Path::new(&root)
                .join(Path::new("etc"))
                .join(Path::new("resolv.conf")),
        )
        .unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not a UTF-8 text file")
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_resolv_conf_exists_but_is_not_readable() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_complains_if_resolv_conf_exists_but_is_not_readable");
        let file = make_resolv_conf(&root, "");
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_mode(0o333);
        file.set_permissions(permissions.clone()).unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.inspect(stream_holder.streams().stdout);

        permissions.set_mode(0o777);
        file.set_permissions(permissions).unwrap();
        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not readable")
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_resolv_conf_is_not_utf_8() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_complains_if_resolv_conf_is_not_utf_8");
        let mut file = make_resolv_conf(&root, "");
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write(&[192, 193]).unwrap();
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result.err().unwrap(),
            String::from("/etc/resolv.conf is not a UTF-8 text file")
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_complains_if_there_is_no_preexisting_nameserver_directive() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_complains_if_there_is_no_preexisting_nameserver_directive");
        make_resolv_conf(&root, "");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root;

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            result.err().unwrap(),
            String::from("This system does not appear to be connected to a network")
        );
        assert_eq!(stream_holder.stdout.get_string(), String::new());
    }

    #[test]
    fn inspect_works_if_everything_is_copacetic() {
        let mut stream_holder = FakeStreamHolder::new();
        let root = make_root("inspect_works_if_everything_is_copacetic");
        make_resolv_conf (&root, "#comment\n## nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n#nameserver 127.0.0.1\n");
        let mut subject = ResolvConfDnsModifier::new();
        subject.root = root.clone();

        let result = subject.inspect(stream_holder.streams().stdout);

        assert_eq!(
            stream_holder.stdout.get_string(),
            String::from("8.8.8.8\n9.9.9.9\n")
        );
        assert_eq!(result.is_ok(), true);
    }

    fn make_root(test_name: &str) -> PathBuf {
        let cur_dir = env::current_dir().unwrap();
        let generated_dir = cur_dir.join(Path::new("generated"));
        let suite_dir = generated_dir.join(Path::new("ResolvConfDnsModifier"));
        let base_dir = suite_dir.join(Path::new(test_name));
        let _ = fs::remove_dir_all(base_dir.clone()); // don't care if it doesn't exist
        fs::create_dir_all(base_dir.clone()).unwrap();
        base_dir
    }

    fn make_resolv_conf(root: &PathBuf, file_contents: &str) -> File {
        let path = Path::new(root).join(Path::new("etc"));
        fs::create_dir_all(path.clone()).unwrap();
        let mut file = File::create(path.join(Path::new("resolv.conf"))).unwrap();
        write!(file, "{}", file_contents).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file
    }

    fn get_resolv_conf(root: &PathBuf) -> String {
        let path = Path::new(root)
            .join(Path::new("etc"))
            .join(Path::new("resolv.conf"));
        let mut file = File::open(path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents
    }
}
