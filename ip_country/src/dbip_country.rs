
// GENERATED CODE: REGENERATE, DO NOT MODIFY!

use lazy_static::lazy_static;
use crate::countries::Countries;

lazy_static! {
    pub static ref COUNTRIES: Countries = Countries::new(vec![
        ("ZZ", "Sentinel"),
        ("AD", "Andorra"),
        ("AO", "Angola"),
        ("AS", "American Samoa"),
    ]);
}

pub fn ipv4_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x8098000300801003, 0x18081B0020981C04, 0xB428C00158440E83, 0x00076162030DC320,
        ],
        256
    )
}

pub fn ipv4_country_block_count() -> usize {
    6
}

pub fn ipv6_country_data() -> (Vec<u64>, usize) {
    (
        vec![
            0x3000040000400007, 0x00C0001400020000, 0x4400047000000700, 0x0160002300034000,
            0x800470007C000D40, 0x200163808002B800, 0x1F000398006A000C, 0x004F8008E0010A00,
            0x0AA0014200263800, 0x0018A002F0005980, 0x028080C006B800CE, 0x0000000000001BE0,
        ],
        737
    )
}

pub fn ipv6_country_block_count() -> usize {
    6
}
