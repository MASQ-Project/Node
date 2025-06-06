// Copyright (c) 2024, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use ip_country_lib::ip_country::ip_country;
use ip_country_lib::ip_country::DBIPParserFactoryReal;
use std::env;
use std::io;
use std::process;

pub fn main() {
    process::exit(ip_country(
        env::args().collect(),
        &mut io::stdin(),
        &mut io::stdout(),
        &mut io::stderr(),
        &DBIPParserFactoryReal {},
    ))
}
