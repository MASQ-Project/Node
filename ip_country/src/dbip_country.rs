
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

use std::collections::HashMap;
use lazy_static::lazy_static;
use crate::country_block_stream::Country;

lazy_static! {
    pub static ref COUNTRIES: Vec<Country> = vec![
        todo!("Generate with ip_country/main.rs")
    ];
    pub static ref INDEX_BY_ISO3166: HashMap<String, usize> = COUNTRIES
        .iter()
        .map(|country| (country.iso3166.clone(), country.index))
        .collect::<HashMap<String, usize>>();
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
