use crate::bit_queue::BitQueue;
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};
use crate::country_block_stream::CountryBlock;
use std::io;
use crate::ip_country::DBIPParser;
use std::cmp::min;
use std::any::Any;

pub struct CSVParser {}

impl DBIPParser for CSVParser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn parse(
        &self,
        stdin: &mut dyn io::Read,
        errors: &mut Vec<String>,
    ) -> (FinalBitQueue, FinalBitQueue, Option<Vec<(String, String)>>) {
        let mut csv_rdr = csv::Reader::from_reader(stdin);
        let mut serializer = CountryBlockSerializer::new();
        let mut local_errors = csv_rdr
            .records()
            .map(|string_record_result| match string_record_result {
                Ok(string_record) => CountryBlock::try_from(string_record),
                Err(e) => Err(format!("CSV format error: {:?}", e)),
            })
            .enumerate()
            .flat_map(|(idx, country_block_result)| match country_block_result {
                Ok(country_block) => {
                    serializer.add(country_block);
                    None
                }
                Err(e) => Some(format!("Line {}: {}", idx + 1, e)),
            })
            .collect::<Vec<String>>();
        let (final_ipv4, final_ipv6) = serializer.finish();
        errors.extend(local_errors);
        (final_ipv4, final_ipv6, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use test_utilities::byte_array_reader_writer::{ByteArrayReader, ByteArrayWriter};

    static PROPER_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.4.0,1.0.7.255,AU
1.0.8.0,1.0.15.255,CN
1.0.16.0,1.0.31.255,JP
1.0.32.0,1.0.63.255,CN
1.0.64.0,1.0.127.255,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    static BAD_TEST_DATA: &str = "0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
1.0.1.0,1.0.3.255,CN
1.0.7.255,AU
1.0.8.0,1.0.15.255
1.0.16.0,1.0.31.255,JP,
BOOGA,BOOGA,BOOGA
1.0.63.255,1.0.32.0,CN
1.0.64.0,1.0.64.0,JP
1.0.128.0,1.0.255.255,TH
1.1.0.0,1.1.0.255,CN
0:0:0:0:0:0:0:0,0:255:255:255:0:0:0:0,ZZ
1:0:0:0:0:0:0:0,1:0:0:255:0:0:0:0,AU
1:0:1:0:0:0:0:0,1:0:3:255:0:0:0:0,CN
1:0:4:0:0:0:0:0,1:0:7:255:0:0:0:0,AU
1:0:8:0:0:0:0:0,1:0:15:255:0:0:0:0,CN
1:0:16:0:0:0:0:0,1:0:31:255:0:0:0:0,JP
BOOGA,BOOGA,BOOGA
1:0:32:0:0:0:0:0,1:0:63:255:0:0:0:0,CN
1:0:64:0:0:0:0:0,1:0:127:255:0:0:0:0,JP
1:0:128:0:0:0:0:0,1:0:255:255:0:0:0:0,TH
1:1:0:0:0:0:0:0,1:1:0:255:0:0:0:0,CN
";

    #[test]
    fn happy_path_test() {
        let mut stdin = ByteArrayReader::new(PROPER_TEST_DATA.as_bytes());
        let mut errors = vec![];
        let subject = CSVParser{};

        let (ipv4_bit_queue, ipv6_bit_queue, countries_opt) =
            subject.parse(&mut stdin, &mut errors);

        let expected_errors: Vec<String> = vec![];
        assert_eq!(errors, expected_errors);
        assert_eq!(ipv4_bit_queue.bit_queue.len(), 271);
        assert_eq!(ipv4_bit_queue.block_count, 11);
        let ipv4_compressed: Vec<u64> = ipv4_bit_queue.into();
        assert_eq!(
            ipv4_compressed,
            vec![
                0x0080000300801003, 0x82201C0902E01807, 0x28102E208388840B, 0x605C0100AB76020E,
                0x0000000000000000
            ]
        );
        assert_eq!(ipv6_bit_queue.bit_queue.len(), 1513);
        assert_eq!(ipv6_bit_queue.block_count, 20);
        let ipv6_compressed: Vec<u64> = ipv6_bit_queue.into();
        assert_eq!(
            ipv6_compressed,
            vec![
                0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
                0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
                0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
                0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
                0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
                0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
            ]
        );
    }

    #[test]
    fn sad_path_test() {
        let mut stdin = ByteArrayReader::new(BAD_TEST_DATA.as_bytes());
        let mut errors = vec![];
        let subject = CSVParser{};

        let (ipv4_bit_queue, ipv6_bit_queue, countries_opt) =
            subject.parse(&mut stdin, &mut errors);

        assert_eq!(ipv4_bit_queue.bit_queue.len(), 239);
        assert_eq!(ipv4_bit_queue.block_count, 9);
        let ipv4_compressed: Vec<u64> = ipv4_bit_queue.into();
        assert_eq!(
            ipv4_compressed,
            vec![
                0x0080000300801003, 0x5020000902E01807, 0xAB74038090000E1C, 0x00000000605C0100
            ]
        );
        assert_eq!(ipv6_bit_queue.bit_queue.len(), 1513);
        assert_eq!(ipv6_bit_queue.block_count, 20);
        let ipv6_compressed: Vec<u64> = ipv6_bit_queue.into();
        assert_eq!(
            ipv6_compressed,
            vec![
                0x3000040000400007, 0x00C0001400020000, 0xA80954B000000700, 0x4000000F0255604A,
                0x0300004000040004, 0xE04AAC8380003800, 0x00018000A4000001, 0x2AB0003485C0001C,
                0x0600089000000781, 0xC001D20700007000, 0x00424000001E04AA, 0x15485C0001C00018,
                0xC90000007812AB00, 0x2388000700006002, 0x000001E04AAC00C5, 0xC0001C0001801924,
                0x0007812AB0063485, 0x0070000600C89000, 0x1E04AAC049D23880, 0xC000180942400000,
                0x12AB025549BA0001, 0x0040002580000078, 0xAC8B800038000300, 0x000000000001E04A,
            ]
        );
        assert_eq!(errors, vec![
            "Line 3: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 67, line: 4, record: 3 }), expected_len: 3, len: 2 })",
            "Line 4: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 80, line: 5, record: 4 }), expected_len: 3, len: 2 })",
            "Line 5: CSV format error: Error(UnequalLengths { pos: Some(Position { byte: 99, line: 6, record: 5 }), expected_len: 3, len: 4 })",
            "Line 6: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'",
            "Line 7: Ending address 1.0.32.0 is less than starting address 1.0.63.255",
            "Line 17: Invalid (AddrParseError(Ip)) IP address in CSV record: 'BOOGA'",
        ]);
    }

    impl Into<Vec<u64>> for FinalBitQueue {
        fn into(mut self) -> Vec<u64> {
            let mut result = vec![];
            while(!self.bit_queue.is_empty()) {
                let bits = self.bit_queue.take_bits(min(64, self.bit_queue.len())).unwrap();
                result.push(bits);
            }
            result
        }
    }
}
