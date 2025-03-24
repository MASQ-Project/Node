
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

use lazy_static::lazy_static;
use crate::country_block_stream::Country;
use crate::countries::Countries;

lazy_static! {
    pub static ref COUNTRIES: Countries = Countries::new(vec![
        Country::new(0, "ZZ", "Sentinel"),
        Country::new(1, "AB", "First Country"),
        Country::new(2, "CD", "Second Country"),
    ]);
}

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    todo!("Generate with ip_country/main.rs");
}

pub fn ipv4_country_block_count() -> usize {
    todo!("Generate with ip_country/main.rs")
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    todo!("Generate with ip_country/main.rs");
}

pub fn ipv6_country_block_count() -> usize {
    todo!("Generate with ip_country/main.rs")
}
