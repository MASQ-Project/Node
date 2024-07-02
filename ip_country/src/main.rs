use ip_country_lib::ip_country::ip_country;
use std::env;
use std::io;
use std::process;

pub fn main() {
    process::exit(ip_country(
        env::args().collect(),
        &mut io::stdin(),
        &mut io::stdout(),
        &mut io::stderr(),
    ))
}
