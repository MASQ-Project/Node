use crate::countries::Countries;
use crate::country_block_serde::{CountryBlockSerializer, FinalBitQueue};
use crate::country_block_stream::{CountryBlock, IpRange};
use crate::ip_country::DBIPParser;
use csv::{StringRecord, StringRecordIter};
use lazy_static::lazy_static;
use std::any::Any;
use std::fmt::Display;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

lazy_static! {
    static ref HARD_CODED_COUNTRIES: Countries = Countries::new(
        vec![
            ("ZZ", "Sentinel"),
            ("AF", "Afghanistan"),
            ("AX", "Aland Islands"),
            ("AL", "Albania"),
            ("DZ", "Algeria"),
            ("AS", "American Samoa"),
            ("AD", "Andorra"),
            ("AO", "Angola"),
            ("AI", "Anguilla"),
            ("AQ", "Antarctica"),
            ("AG", "Antigua and Barbuda"),
            ("AR", "Argentina"),
            ("AM", "Armenia"),
            ("AW", "Aruba"),
            ("AU", "Australia"),
            ("AT", "Austria"),
            ("AZ", "Azerbaijan"),
            ("BS", "Bahamas"),
            ("BH", "Bahrain"),
            ("BD", "Bangladesh"),
            ("BB", "Barbados"),
            ("BY", "Belarus"),
            ("BE", "Belgium"),
            ("BZ", "Belize"),
            ("BJ", "Benin"),
            ("BM", "Bermuda"),
            ("BT", "Bhutan"),
            ("BO", "Bolivia"),
            ("BQ", "Bonaire, Sint Eustatius, Saba"),
            ("BA", "Bosnia, Herzegovina"),
            ("BW", "Botswana"),
            ("BV", "Bouvet Island"),
            ("BR", "Brazil"),
            ("IO", "British Indian Ocean Territory"),
            ("BN", "Brunei Darussalam"),
            ("BG", "Bulgaria"),
            ("BF", "Burkina Faso"),
            ("BI", "Burundi"),
            ("CV", "Cabo Verde"),
            ("KH", "Cambodia"),
            ("CM", "Cameroon"),
            ("CA", "Canada"),
            ("KY", "Cayman Islands"),
            ("CF", "Central African Republic"),
            ("TD", "Chad"),
            ("CL", "Chile"),
            ("CN", "China"),
            ("CX", "Christmas Island"),
            ("CC", "Cocos Islands"),
            ("CO", "Colombia"),
            ("KM", "Comoros"),
            ("CD", "Democratic Republic of Congo"),
            ("CG", "Congo"),
            ("CK", "Cook Islands"),
            ("CR", "Costa Rica"),
            ("CI", "Ivory Coast"),
            ("HR", "Croatia"),
            ("CU", "Cuba"),
            ("CW", "Curacao"),
            ("CY", "Cyprus"),
            ("CZ", "Czechia"),
            ("DK", "Denmark"),
            ("DJ", "Djibouti"),
            ("DM", "Dominica"),
            ("DO", "Dominican Republic"),
            ("EC", "Ecuador"),
            ("EG", "Egypt"),
            ("SV", "El Salvador"),
            ("GQ", "Equatorial Guinea"),
            ("ER", "Eritrea"),
            ("EE", "Estonia"),
            ("SZ", "Eswatini"),
            ("ET", "Ethiopia"),
            ("FK", "Falkland Islands"),
            ("FO", "Faroe Islands"),
            ("FJ", "Fiji"),
            ("FI", "Finland"),
            ("FR", "France"),
            ("GF", "French Guiana"),
            ("PF", "French Polynesia"),
            ("TF", "French Southern Territories"),
            ("GA", "Gabon"),
            ("GM", "Gambia"),
            ("GE", "Georgia"),
            ("DE", "Germany"),
            ("GH", "Ghana"),
            ("GI", "Gibraltar"),
            ("GR", "Greece"),
            ("GL", "Greenland"),
            ("GD", "Grenada"),
            ("GP", "Guadeloupe"),
            ("GU", "Guam"),
            ("GT", "Guatemala"),
            ("GG", "Guernsey"),
            ("GN", "Guinea"),
            ("GW", "Guinea-Bissau"),
            ("GY", "Guyana"),
            ("HT", "Haiti"),
            ("HM", "Heard Island and McDonald Islands"),
            ("VA", "Holy See"),
            ("HN", "Honduras"),
            ("HK", "Hong Kong"),
            ("HU", "Hungary"),
            ("IS", "Iceland"),
            ("IN", "India"),
            ("ID", "Indonesia"),
            ("IR", "Iran"),
            ("IQ", "Iraq"),
            ("IE", "Ireland"),
            ("IM", "Isle of Man"),
            ("IL", "Israel"),
            ("IT", "Italy"),
            ("JM", "Jamaica"),
            ("JP", "Japan"),
            ("JE", "Jersey"),
            ("JO", "Jordan"),
            ("KZ", "Kazakhstan"),
            ("KE", "Kenya"),
            ("KI", "Kiribati"),
            ("KP", "North Korea"),
            ("KR", "South Korea"),
            ("KW", "Kuwait"),
            ("KG", "Kyrgyzstan"),
            ("LA", "Lao People's Democratic Republic"),
            ("LV", "Latvia"),
            ("LB", "Lebanon"),
            ("LS", "Lesotho"),
            ("LR", "Liberia"),
            ("LY", "Libya"),
            ("LI", "Liechtenstein"),
            ("LT", "Lithuania"),
            ("LU", "Luxembourg"),
            ("MO", "Macao"),
            ("MG", "Madagascar"),
            ("MW", "Malawi"),
            ("MY", "Malaysia"),
            ("MV", "Maldives"),
            ("ML", "Mali"),
            ("MT", "Malta"),
            ("MH", "Harshall Islands"),
            ("MQ", "Martinique"),
            ("MR", "Mauritania"),
            ("MU", "Mauritius"),
            ("YT", "Mayotte"),
            ("MX", "Mexico"),
            ("FM", "Micronesia"),
            ("MD", "Moldova"),
            ("MC", "Monaco"),
            ("MN", "Mongolia"),
            ("ME", "Montenegro"),
            ("MS", "Montserrat"),
            ("MA", "Morocco"),
            ("MZ", "Mozambique"),
            ("MM", "Myanmar"),
            ("NA", "Namibia"),
            ("NR", "Nauru"),
            ("NP", "Nepal"),
            ("NL", "Netherlands"),
            ("NC", "New Caledonia"),
            ("NZ", "New Zealand"),
            ("NI", "Nicaragua"),
            ("NE", "Niger"),
            ("NG", "Nigeria"),
            ("NU", "Niue"),
            ("NF", "Norfolk Island"),
            ("MK", "North Macedonia"),
            ("MP", "Morthern Mariana Islands"),
            ("NO", "Norway"),
            ("OM", "Oman"),
            ("PK", "Pakistan"),
            ("PW", "Palau"),
            ("PS", "Palestine"),
            ("PA", "Panama"),
            ("PG", "Papua New Guinea"),
            ("PY", "Paraguay"),
            ("PE", "Peru"),
            ("PH", "Phillipines"),
            ("PN", "Pitcairn"),
            ("PL", "Poland"),
            ("PT", "Portugal"),
            ("PR", "Puerto Rico"),
            ("QA", "Qatar"),
            ("RE", "Reunion"),
            ("RO", "Romanian"),
            ("RU", "Russian Federation"),
            ("RW", "Rwanda"),
            ("BL", "Saint Barthelemy"),
            ("SH", "Saint Helena, Ascension Island, Tristan da Cunha"),
            ("KN", "Saint Kitts and Nevis"),
            ("LC", "Saint Lucia"),
            ("MF", "Saint Martin"),
            ("PM", "Saint Pierre and Miquelon"),
            ("VC", "Saint Vincent and the Grenadines"),
            ("WS", "Samoa"),
            ("SM", "San Marino"),
            ("ST", "Sao Tome and Principe"),
            ("SA", "Saudi Arabia"),
            ("SN", "Senegal"),
            ("RS", "Serbia"),
            ("SC", "Seychelles"),
            ("SL", "Sierra Leone"),
            ("SG", "Singapore"),
            ("SX", "Sint Maarten"),
            ("SK", "Slovakia"),
            ("SI", "Slovenia"),
            ("SB", "Solomon Islands"),
            ("SO", "Somalia"),
            ("ZA", "South Africa"),
            ("GS", "South Georgia and the South Sandwich Islands"),
            ("SS", "South Sudan"),
            ("ES", "Spain"),
            ("LK", "Sri Lanka"),
            ("SD", "Sudan"),
            ("SR", "Suriname"),
            ("SJ", "Svalbard and Jan Mayen"),
            ("SE", "Sweden"),
            ("CH", "Switzerland"),
            ("SY", "Syrian Arab Republic"),
            ("TW", "Taiwan"),
            ("TJ", "Tajikistan"),
            ("TZ", "Tanzania"),
            ("TH", "Thailand"),
            ("TL", "Timor-Leste"),
            ("TG", "Togo"),
            ("TK", "Tokelau"),
            ("TO", "Tonga"),
            ("TT", "Trinidad and Tobago"),
            ("TN", "Tunisia"),
            ("TR", "Turkiye"),
            ("TM", "Turkmenistan"),
            ("TC", "Turks and Caicos Islands"),
            ("TV", "Tuvalu"),
            ("UG", "Uganda"),
            ("UA", "Ukraine"),
            ("AE", "United Arab Emirates"),
            ("GB", "United Kingdom"),
            ("UM", "United States Minor Outlying Islands"),
            ("US", "United States"),
            ("UY", "Uruguay"),
            ("UZ", "Uzbekistan"),
            ("VU", "Vanuatu"),
            ("VE", "Venezuela"),
            ("VN", "Vietnam"),
            ("VG", "British Virgin Islands"),
            ("VI", "US Virgin Islands"),
            ("WF", "Wallis and Futuna"),
            ("EH", "Western Sahara"),
            ("YE", "Yemen"),
            ("ZM", "Zambia"),
            ("ZW", "Zimbabwe"),
            ("XK", "Kosovo"),
        ]
        .into_iter()
        .map(|(iso3166, name)| (iso3166.to_string(), name.to_string()))
        .collect::<Vec<(String, String)>>()
    );
}

pub struct CSVParser {}

impl DBIPParser for CSVParser {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn parse(
        &self,
        stdin: &mut dyn io::Read,
        errors: &mut Vec<String>,
    ) -> (FinalBitQueue, FinalBitQueue, Countries) {
        let mut csv_rdr = csv::Reader::from_reader(stdin);
        let mut serializer = CountryBlockSerializer::new();
        let local_errors = csv_rdr
            .records()
            .map(|string_record_result| match string_record_result {
                Ok(string_record) => {
                    let countries: &Countries = &HARD_CODED_COUNTRIES;
                    CountryBlock::try_from((countries, string_record))
                }
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
        (final_ipv4, final_ipv6, HARD_CODED_COUNTRIES.clone())
    }
}

impl TryFrom<(&Countries, StringRecord)> for CountryBlock {
    type Error = String;

    fn try_from(
        (countries, string_record): (&Countries, StringRecord),
    ) -> Result<CountryBlock, String> {
        let mut iter = string_record.iter();
        let start_ip = ip_addr_from_iter(&mut iter)?;
        let end_ip = ip_addr_from_iter(&mut iter)?;
        let iso3166 = match iter.next() {
            None => return Err("CSV line contains no ISO 3166 country code".to_string()),
            Some(s) => s,
        };
        if iter.next().is_some() {
            return Err(format!(
                "CSV line should contain 3 elements, but contains {}",
                string_record.len()
            ));
        };
        validate_ip_range(start_ip, end_ip)?;
        let country = countries.country_from_code(iso3166)?;
        let country_block = match (start_ip, end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) => CountryBlock {
                ip_range: IpRange::V4(start, end),
                country: country.clone(),
            },
            (IpAddr::V6(start), IpAddr::V6(end)) => CountryBlock {
                ip_range: IpRange::V6(start, end),
                country: country.clone(),
            },
            (start, end) => panic!(
                "Start and end addresses must be of the same type, not {} and {}",
                start, end
            ),
        };
        Ok(country_block)
    }
}

fn ip_addr_from_iter(iter: &mut StringRecordIter) -> Result<IpAddr, String> {
    let ip_string = match iter.next() {
        None => return Err("Missing IP address in CSV record".to_string()),
        Some(s) => s,
    };
    let ip_addr = match IpAddr::from_str(ip_string) {
        Err(e) => {
            return Err(format!(
                "Invalid ({:?}) IP address in CSV record: '{}'",
                e, ip_string
            ))
        }
        Ok(ip) => ip,
    };
    Ok(ip_addr)
}

fn validate_ips_are_sequential<SingleIntegerIPRep, IP>(start: IP, end: IP) -> Result<(), String>
where
    SingleIntegerIPRep: From<IP> + PartialOrd,
    IP: Display + Copy,
{
    if SingleIntegerIPRep::from(start) > SingleIntegerIPRep::from(end) {
        Err(format!(
            "Ending address {} is less than starting address {}",
            end, start
        ))
    } else {
        Ok(())
    }
}

fn validate_ip_range(start_ip: IpAddr, end_ip: IpAddr) -> Result<(), String> {
    match (start_ip, end_ip) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            validate_ips_are_sequential::<u32, Ipv4Addr>(start_v4, end_v4)
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            validate_ips_are_sequential::<u128, Ipv6Addr>(start_v6, end_v6)
        }
        (s, e) => Err(format!(
            "Beginning address {} and ending address {} must be the same IP address version",
            s, e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::country_block_stream::Country;
    use std::cmp::min;
    use test_utilities::byte_array_reader_writer::ByteArrayReader;

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
        let subject = CSVParser {};

        let (ipv4_bit_queue, ipv6_bit_queue, countries) = subject.parse(&mut stdin, &mut errors);

        let expected_errors: Vec<String> = vec![];
        assert_eq!(errors, expected_errors);
        assert_eq!(countries, HARD_CODED_COUNTRIES.clone());
        assert_eq!(ipv4_bit_queue.bit_queue.len(), 271);
        assert_eq!(ipv4_bit_queue.block_count, 11);
        let ipv4_compressed: Vec<u64> = ipv4_bit_queue.into();
        assert_eq!(
            ipv4_compressed,
            vec![
                9259400846767034371,
                153151013337962502,
                5192703286562554892,
                6944551727792783886,
                0
            ]
        );
        assert_eq!(ipv6_bit_queue.bit_queue.len(), 1513);
        assert_eq!(ipv6_bit_queue.block_count, 20);
        let ipv6_compressed: Vec<u64> = ipv6_bit_queue.into();
        assert_eq!(
            ipv6_compressed,
            vec![
                3458768911871246343,
                54043281427922944,
                12108302188053268224,
                4611686082891046986,
                216173056991952900,
                16161919892486895616,
                422215216529409,
                3075958771080495132,
                432354978795882369,
                13835570455618023424,
                18647717209048234,
                1533581226265280536,
                14483576403638004480,
                2562548218038607874,
                2062837088453,
                30786350749988,
                2112345178780806,
                31525223174541312,
                2163041463893637376,
                13835084483327426560,
                1345171479032233985,
                18014559570755704,
                12433312672202621696,
                122954
            ]
        );
    }

    #[test]
    fn sad_path_test() {
        let mut stdin = ByteArrayReader::new(BAD_TEST_DATA.as_bytes());
        let mut errors = vec![];
        let subject = CSVParser {};

        let (ipv4_bit_queue, ipv6_bit_queue, countries) = subject.parse(&mut stdin, &mut errors);

        assert_eq!(countries, HARD_CODED_COUNTRIES.clone());
        assert_eq!(ipv4_bit_queue.bit_queue.len(), 239);
        assert_eq!(ipv4_bit_queue.block_count, 9);
        let ipv4_compressed: Vec<u64> = ipv4_bit_queue.into();
        assert_eq!(
            ipv4_compressed,
            vec![
                9259400846767034371,
                10385300779421407238,
                12351125828770205212,
                1616904448
            ]
        );
        assert_eq!(ipv6_bit_queue.bit_queue.len(), 1513);
        assert_eq!(ipv6_bit_queue.block_count, 20);
        let ipv6_compressed: Vec<u64> = ipv6_bit_queue.into();
        assert_eq!(
            ipv6_compressed,
            vec![
                3458768911871246343,
                54043281427922944,
                12108302188053268224,
                4611686082891046986,
                216173056991952900,
                16161919892486895616,
                422215216529409,
                3075958771080495132,
                432354978795882369,
                13835570455618023424,
                18647717209048234,
                1533581226265280536,
                14483576403638004480,
                2562548218038607874,
                2062837088453,
                30786350749988,
                2112345178780806,
                31525223174541312,
                2163041463893637376,
                13835084483327426560,
                1345171479032233985,
                18014559570755704,
                12433312672202621696,
                122954
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

    fn test_countries() -> Countries {
        Countries::old_new(vec![
            Country::new(0, "ZZ", "Sentinel"),
            Country::new(1, "AS", "American Samoa"),
            Country::new(2, "VN", "Vietnam"),
        ])
    }

    #[test]
    fn try_from_fails_for_missing_iso3166() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err("CSV line contains no ISO 3166 country code".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_too_many_elements() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "US", "extra"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err("CSV line should contain 3 elements, but contains 4".to_string())
        );
    }

    #[test]
    fn try_from_works_for_ipv4() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "AS"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Ok(CountryBlock {
                ip_range: IpRange::V4(
                    Ipv4Addr::from_str("1.2.3.4").unwrap(),
                    Ipv4Addr::from_str("5.6.7.8").unwrap()
                ),
                country: test_countries().country_from_code("AS").unwrap().clone(),
            })
        );
    }

    #[test]
    fn try_from_works_for_ipv6() {
        let string_record = StringRecord::from(vec![
            "1234:2345:3456:4567:5678:6789:789A:89AB",
            "4321:5432:6543:7654:8765:9876:A987:BA98",
            "VN",
        ]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Ok(CountryBlock {
                ip_range: IpRange::V6(
                    Ipv6Addr::from_str("1234:2345:3456:4567:5678:6789:789A:89AB").unwrap(),
                    Ipv6Addr::from_str("4321:5432:6543:7654:8765:9876:A987:BA98").unwrap()
                ),
                country: test_countries().country_from_code("VN").unwrap().clone(),
            })
        );
    }

    #[test]
    fn try_from_fails_for_bad_ip_syntax() {
        let string_record = StringRecord::from(vec!["Ooga", "Booga", "AS"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err("Invalid (AddrParseError(Ip)) IP address in CSV record: 'Ooga'".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_missing_start_ip() {
        let strings: Vec<&str> = vec![];
        let string_record = StringRecord::from(strings);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(result, Err("Missing IP address in CSV record".to_string()));
    }

    #[test]
    fn try_from_fails_for_missing_end_ip() {
        let string_record = StringRecord::from(vec!["1.2.3.4"]);

        let result = CountryBlock::try_from((&test_countries(), string_record))
            .err()
            .unwrap();

        assert_eq!(result, "Missing IP address in CSV record".to_string());
    }

    #[test]
    fn try_from_fails_for_reversed_ipv4_addresses() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "1.2.3.3", "ZZ"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err("Ending address 1.2.3.3 is less than starting address 1.2.3.4".to_string())
        );
    }

    #[test]
    fn try_from_fails_for_reversed_ipv6_addresses() {
        let string_record = StringRecord::from(vec!["1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:7", "ZZ"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err(
                "Ending address 1:2:3:4:5:6:7:7 is less than starting address 1:2:3:4:5:6:7:8"
                    .to_string()
            )
        );
    }

    #[test]
    fn try_from_fails_for_mixed_ip_types() {
        let string_record_46 = StringRecord::from(vec!["4.3.2.1", "1:2:3:4:5:6:7:8", "ZZ"]);
        let string_record_64 = StringRecord::from(vec!["1:2:3:4:5:6:7:8", "4.3.2.1", "ZZ"]);

        let result_46 = CountryBlock::try_from((&test_countries(), string_record_46));
        let result_64 = CountryBlock::try_from((&test_countries(), string_record_64));

        assert_eq!(result_46, Err("Beginning address 4.3.2.1 and ending address 1:2:3:4:5:6:7:8 must be the same IP address version".to_string()));
        assert_eq!(result_64, Err("Beginning address 1:2:3:4:5:6:7:8 and ending address 4.3.2.1 must be the same IP address version".to_string()));
    }

    #[test]
    fn try_from_fails_for_unrecognized_iso3166() {
        let string_record = StringRecord::from(vec!["1.2.3.4", "5.6.7.8", "XY"]);

        let result = CountryBlock::try_from((&test_countries(), string_record));

        assert_eq!(
            result,
            Err("'XY' is not a valid ISO3166 country code".to_string())
        );
    }

    impl Into<Vec<u64>> for FinalBitQueue {
        fn into(mut self) -> Vec<u64> {
            let mut result = vec![];
            while !self.bit_queue.is_empty() {
                let bits = self
                    .bit_queue
                    .take_bits(min(64, self.bit_queue.len()))
                    .unwrap();
                result.push(bits);
            }
            result
        }
    }
}
