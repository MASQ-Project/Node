// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
extern crate sub_lib;
extern crate dns_utility_lib;

mod utils;

use std::fs::File;
use std::io;
use std::io::Read;
use std::path::Path;
use utils::TestCommand;

#[cfg (unix)]
use dns_utility_lib::resolv_conf_dns_modifier::ResolvConfDnsModifier;

#[test]
#[cfg (unix)]
fn resolv_conf_subvert_and_revert_integration () {
    let contents = match get_file_contents ("/etc/resolv.conf") {
        Ok (c) => c,
        Err (_) => {println! ("---INTEGRATION TEST CANNOT YET RUN IN THIS ENVIRONMENT---"); return}
    };
    let active_nameservers: Vec<String> = ResolvConfDnsModifier::new ().active_nameservers (contents.as_str ()).iter ()
        .map (|entry| entry.0.clone ()).collect ();
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), false, "Already contains '\\n#nameserver 127.0.0.1':\n{}", contents);

    let mut subvert_command = TestCommand::start ("dns_utility", vec! ("subvert"));
    let exit_status = subvert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", subvert_command.output ());

    let contents = get_file_contents ("/etc/resolv.conf").unwrap ();
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), true, "Doesn't contain '\\n#nameserver 127.0.0.1':\n{}", contents);
    active_nameservers.iter ().for_each (|entry| {
        assert_eq! (contents.contains (&format! ("\n#{}", entry)[..]), true, "Doesn't contain '\\n#{}':\n{}", entry, contents)
    });

    let mut revert_command = TestCommand::start ("dns_utility", vec! ("revert"));
    let exit_status = revert_command.wait ();
    assert_eq! (exit_status, Some (0), "{}", revert_command.output ());

    let contents = get_file_contents ("/etc/resolv.conf").unwrap ();
    assert_eq! (contents.contains ("\nnameserver 127.0.0.1"), false, "Still contains '\\n#nameserver 127.0.0.1':\n{}", contents);
    active_nameservers.iter ().for_each (|entry| {
        assert_eq! (contents.contains (&format! ("\n{}", entry)[..]), true, "Doesn't contain '\\n{}':\n{}", entry, contents)
    });
}

fn get_file_contents (filename: &str) -> io::Result<String> {
    let mut file = File::open (Path::new (filename))?;
    let mut contents = String::new ();
    file.read_to_string (&mut contents).unwrap ();
    Ok (contents)
}
