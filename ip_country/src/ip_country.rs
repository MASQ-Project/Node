use std::io;
use masq_lib::test_utils::fake_stream_holder::ByteArrayWriter;
use crate::bit_queue::BitQueue;
use crate::country_block_stream::CountryBlock;

pub fn ip_country(
    args: Vec<String>,
    stdin: &mut dyn io::Read,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write
) -> i32 {
    let mut bit_queue = BitQueue::new();
    let mut line_number = 0usize;
    let mut csvRdr = csv::Reader::from_reader(stdin);
    let errors = csvRdr.records()
        .map(|string_record_result| {
            match string_record_result {
                Ok(string_record) => CountryBlock::try_from(string_record),
                Err(e) => Err(format!("{:?}", e))
            }
        })
        .flat_map(|country_block_result| {
            line_number += 1;
            match country_block_result {
                Ok(country_block) => {
                    country_block.serialize_to(&mut bit_queue);
                    None
                },
                Err(e) => Some(format!("Line {}: {}", line_number, e)), // TODO no test for this line yet
            }
        })
        .collect::<Vec<String>>();
    generate_rust_code (bit_queue, stdout);
    if (errors.is_empty()) {
        return 0
    }
    else {
        todo!("Write errors to stderr and return error code");
    }
}

fn generate_rust_code(mut bit_queue: BitQueue, output: &mut dyn io::Write) {
    todo!()
}

#[cfg(test)]
mod tests {
    use masq_lib::test_utils::fake_stream_holder::{ByteArrayReader, ByteArrayWriter};
    use super::*;

    static TEST_DATA: &str =
"0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.15.255,CN
1.0.16.0,1.0.31.255,JP
1.0.32.0,1.0.63.255,CN
1.0.64.0,1.0.127.255,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
";
    
    /*
IPv4
For each block:
    Two bits: number of elements since the last block that have changed, minus one
    For each changed element:
        Two bits giving the index of the changed element
        Eight bits giving the value of the changed element
    Nine bits giving the index of the country code in crate::countries::COUNTRIES

000.000.000.000, 000.255.255.255, ZZ
001.000.000.000, 001.000.000.255, AU
001.000.001.000, 001.000.003.255, CN
001.000.004.000, 001.000.007.255, AU
001.000.008.000, 001.000.015.255, CN
001.000.016.000, 001.000.031.255, JP
001.000.032.000, 001.000.063.255, CN
001.000.064.000, 001.000.127.255, JP
001.000.128.000, 001.000.255.255, TH
001.001.000.000, 001.001.000.255, CN
001.001.001.000, ?              , ZZ

11 00 00000000 01 00000000 10 00000000 11 00000000 000000000
00 00 00000001 000001110
00 10 00000001 000101110
00 10 00000100 000001110
00 10 00001000 000101110
00 10 00010000 001110001
00 10 00100000 000101110
00 10 01000000 001110001
00 10 10000000 011011101
01 01 00000001 10 00000000 0000011|10
00 10 00000001 000000000
-------------------------------------------------------------------------------------
C0040200C00000020E201171020388205C42071220171201C4A01BA8030003880400

     */
    
    #[test]
    fn high_level_test() {
        let mut stdin = ByteArrayReader::new(TEST_DATA.as_bytes());
        let mut stdout = ByteArrayWriter::new();
        let mut stderr = ByteArrayWriter::new();
        
        let result = ip_country(vec![], &mut stdin, &mut stdout, &mut stderr);
        
        assert_eq!(result, 0);
        let stdout_string = String::from_utf8(stdout.get_bytes()).unwrap();
        let stderr_string = String::from_utf8(stderr.get_bytes()).unwrap();
        assert_eq!(stdout_string,
"
// GENERATED CODE: DO NOT MODIFY!
use lazy_static::lazy_static;

lazy_static! {
    static ref IP_COUNTRY_DATA: Vec<u8> = vec![
        0xC0, 0x04, 0x02, 0x00, 0xC0, 0x00, 0x00, 0x02, 0x0E, 0x20,
        0x11, 0x71, 0x02, 0x03, 0x88, 0x20, 0x5C, 0x42, 0x07, 0x12,
        0x20, 0x17, 0x12, 0x01, 0xC4, 0xA0, 0x1B, 0xA8, 0x03, 0x00,
        0x03, 0x88, 0x04, 0x00,
    ];
}
".to_string()
        );
        assert_eq!(stderr_string, "".to_string());
    }
}
