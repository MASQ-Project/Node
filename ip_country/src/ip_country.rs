use std::io;
use crate::bit_queue::BitQueue;
use crate::country_block_stream::CountryBlock;
use crate::country_block_serde::CountryBlockSerializer;

pub fn ip_country(
    args: Vec<String>,
    stdin: &mut dyn io::Read,
    stdout: &mut dyn io::Write,
    stderr: &mut dyn io::Write
) -> i32 {
    let mut serializer = CountryBlockSerializer::new();
    let mut line_number = 0usize;
    let mut csv_rdr = csv::Reader::from_reader(stdin);
    let errors = csv_rdr.records()
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
                    serializer.add(country_block);
                    None
                },
                Err(e) => Some(format!("Line {}: {}", line_number, e)), // TODO no test for this line yet
            }
        })
        .collect::<Vec<String>>();
    let (ipv4_bit_queue, ipv6_bit_queue) = serializer.finish();
    generate_rust_code (ipv4_bit_queue, ipv6_bit_queue, stdout);
    if errors.is_empty() {
        return 0
    }
    else {
        todo!("Write errors to stderr and return error code");
    }
}

fn generate_rust_code(mut ipv4_bit_queue: BitQueue, ipv6_bit_queue: BitQueue, output: &mut dyn io::Write) {
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

pub fn ipv4_country_data(): (Vec<u64>, usize) {
    (
        vec![
            0xC0040200C0000002, 0x0E20117102038820, 0x5C42071220171201, 0xC4A01BA803000388,
            0x0000000000000400,
        ],
        272
    )
}

pub fn ipv6_country_data(): Vec<u8> {
    vec![
    ]
}
".to_string()
        );
        assert_eq!(stderr_string, "".to_string());
    }
}
