use std::collections::HashMap;
use lazy_static::lazy_static;
use crate::country_block_stream::Country;

lazy_static! {
    pub static ref COUNTRIES: Vec<Country> = vec![
        Country::new(0, "ZZ", "Sentinel"),
        Country::new(1, "AF", "Afghanistan"),
        Country::new(2, "AX", "Aland Islands"),
        Country::new(3, "AL", "Albania"),
        Country::new(4, "DZ", "Algeria"),
        Country::new(5, "AS", "American Samoa"),
        Country::new(6, "AD", "Andorra"),
        Country::new(7, "AO", "Angola"),
        Country::new(8, "AI", "Anguilla"),
        Country::new(9, "AQ", "Antarctica"),
        Country::new(10, "AG", "Antigua and Barbuda"),
        Country::new(11, "AR", "Argentina"),
        Country::new(12, "AM", "Armenia"),
        Country::new(13, "AW", "Aruba"),
        Country::new(14, "AU", "Australia"),
        Country::new(15, "AT", "Austria"),
        Country::new(16, "AZ", "Azerbaijan"),
        Country::new(17, "BS", "Bahamas"),
        Country::new(18, "BH", "Bahrain"),
        Country::new(19, "BD", "Bangladesh"),
        Country::new(20, "BB", "Barbados"),
        Country::new(21, "BY", "Belarus"),
        Country::new(22, "BE", "Belgium"),
        Country::new(23, "BZ", "Belize"),
        Country::new(24, "BJ", "Benin"),
        Country::new(25, "BM", "Bermuda"),
        Country::new(26, "BT", "Bhutan"),
        Country::new(27, "BO", "Bolivia"),
        Country::new(28, "BQ", "Bonaire, Sint Eustatius, Saba"),
        Country::new(29, "BA", "Bosnia, Herzegovina"),
        Country::new(30, "BW", "Botswana"),
        Country::new(31, "BV", "Bouvet Island"),
        Country::new(32, "BR", "Brazil"),
        Country::new(33, "IO", "British Indian Ocean Territory"),
        Country::new(34, "BN", "Brunei Darussalam"),
        Country::new(35, "BG", "Bulgaria"),
        Country::new(36, "BF", "Burkina Faso"),
        Country::new(37, "BI", "Burundi"),
        Country::new(38, "CV", "Cabo Verde"),
        Country::new(39, "KH", "Cambodia"),
        Country::new(40, "CM", "Cameroon"),
        Country::new(41, "CA", "Canada"),
        Country::new(42, "KY", "Cayman Islands"),
        Country::new(43, "CF", "Central African Republic"),
        Country::new(44, "TD", "Chad"),
        Country::new(45, "CL", "Chile"),
        Country::new(46, "CN", "China"),
        Country::new(47, "CX", "Christmas Island"),
        Country::new(48, "CC", "Cocos Islands"),
        Country::new(49, "CO", "Colombia"),
        Country::new(50, "KM", "Comoros"),
        Country::new(51, "CD", "Democratic Republic of Congo"),
        Country::new(52, "CG", "Congo"),
        Country::new(53, "CK", "Cook Islands"),
        Country::new(54, "CR", "Costa Rica"),
        Country::new(55, "CI", "Ivory Coast"),
        Country::new(56, "HR", "Croatia"),
        Country::new(57, "CU", "Cuba"),
        Country::new(58, "CW", "Curacao"),
        Country::new(59, "CY", "Cyprus"),
        Country::new(60, "CZ", "Czechia"),
        Country::new(61, "DK", "Denmark"),
        Country::new(62, "DJ", "Djibouti"),
        Country::new(63, "DM", "Dominica"),
        Country::new(64, "DO", "Dominican Republic"),
        Country::new(65, "EC", "Ecuador"),
        Country::new(66, "EG", "Egypt"),
        Country::new(67, "SV", "El Salvador"),
        Country::new(68, "GQ", "Equatorial Guinea"),
        Country::new(69, "ER", "Eritrea"),
        Country::new(70, "EE", "Estonia"),
        Country::new(71, "SZ", "Eswatini"),
        Country::new(72, "ET", "Ethiopia"),
        Country::new(73, "FK", "Falkland Islands"),
        Country::new(74, "FO", "Faroe Islands"),
        Country::new(75, "FJ", "Fiji"),
        Country::new(76, "FI", "Finland"),
        Country::new(77, "FR", "France"),
        Country::new(78, "GF", "French Guiana"),
        Country::new(79, "PF", "French Polynesia"),
        Country::new(80, "TF", "French Southern Territories"),
        Country::new(81, "GA", "Gabon"),
        Country::new(82, "GM", "Gambia"),
        Country::new(83, "GE", "Georgia"),
        Country::new(84, "DE", "Germany"),
        Country::new(85, "GH", "Ghana"),
        Country::new(86, "GI", "Gibraltar"),
        Country::new(87, "GR", "Greece"),
        Country::new(88, "GL", "Greenland"),
        Country::new(89, "GD", "Grenada"),
        Country::new(90, "GP", "Guadeloupe"),
        Country::new(91, "GU", "Guam"),
        Country::new(92, "GT", "Guatemala"),
        Country::new(93, "GG", "Guernsey"),
        Country::new(94, "GN", "Guinea"),
        Country::new(95, "GW", "Guinea-Bissau"),
        Country::new(96, "GY", "Guyana"),
        Country::new(97, "HT", "Haiti"),
        Country::new(98, "HM", "Heard Island and McDonald Islands"),
        Country::new(99, "VA", "Holy See"),
        Country::new(100, "HN", "Honduras"),
        Country::new(101, "HK", "Hong Kong"),
        Country::new(102, "HU", "Hungary"),
        Country::new(103, "IS", "Iceland"),
        Country::new(104, "IN", "India"),
        Country::new(105, "ID", "Indonesia"),
        Country::new(106, "IR", "Iran"),
        Country::new(107, "IQ", "Iraq"),
        Country::new(108, "IE", "Ireland"),
        Country::new(109, "IM", "Isle of Man"),
        Country::new(110, "IL", "Israel"),
        Country::new(111, "IT", "Italy"),
        Country::new(112, "JM", "Jamaica"),
        Country::new(113, "JP", "Japan"),
        Country::new(114, "JE", "Jersey"),
        Country::new(115, "JO", "Jordan"),
        Country::new(116, "KZ", "Kazakhstan"),
        Country::new(117, "KE", "Kenya"),
        Country::new(118, "KI", "Kiribati"),
        Country::new(119, "KP", "North Korea"),
        Country::new(120, "KR", "South Korea"),
        Country::new(121, "KW", "Kuwait"),
        Country::new(122, "KG", "Kyrgyzstan"),
        Country::new(123, "LA", "Lao People's Democratic Republic"),
        Country::new(124, "LV", "Latvia"),
        Country::new(125, "LB", "Lebanon"),
        Country::new(126, "LS", "Lesotho"),
        Country::new(127, "LR", "Liberia"),
        Country::new(128, "LY", "Libya"),
        Country::new(129, "LI", "Liechtenstein"),
        Country::new(130, "LT", "Lithuania"),
        Country::new(131, "LU", "Luxembourg"),
        Country::new(132, "MO", "Macao"),
        Country::new(133, "MG", "Madagascar"),
        Country::new(134, "MW", "Malawi"),
        Country::new(135, "MY", "Malaysia"),
        Country::new(136, "MV", "Maldives"),
        Country::new(137, "ML", "Mali"),
        Country::new(138, "MT", "Malta"),
        Country::new(139, "MH", "Harshall Islands"),
        Country::new(140, "MQ", "Martinique"),
        Country::new(141, "MR", "Mauritania"),
        Country::new(142, "MU", "Mauritius"),
        Country::new(143, "YT", "Mayotte"),
        Country::new(144, "MX", "Mexico"),
        Country::new(145, "FM", "Micronesia"),
        Country::new(146, "MD", "Moldova"),
        Country::new(147, "MC", "Monaco"),
        Country::new(148, "MN", "Mongolia"),
        Country::new(149, "ME", "Montenegro"),
        Country::new(150, "MS", "Montserrat"),
        Country::new(151, "MA", "Morocco"),
        Country::new(152, "MZ", "Mozambique"),
        Country::new(153, "MM", "Myanmar"),
        Country::new(154, "NA", "Namibia"),
        Country::new(155, "NR", "Nauru"),
        Country::new(156, "NP", "Nepal"),
        Country::new(157, "NL", "Netherlands"),
        Country::new(158, "NC", "New Caledonia"),
        Country::new(159, "NZ", "New Zealand"),
        Country::new(160, "NI", "Nicaragua"),
        Country::new(161, "NE", "Niger"),
        Country::new(162, "NG", "Nigeria"),
        Country::new(163, "NU", "Niue"),
        Country::new(164, "NF", "Norfolk Island"),
        Country::new(165, "MK", "North Macedonia"),
        Country::new(166, "MP", "Morthern Mariana Islands"),
        Country::new(167, "NO", "Norway"),
        Country::new(168, "OM", "Oman"),
        Country::new(169, "PK", "Pakistan"),
        Country::new(170, "PW", "Palau"),
        Country::new(171, "PS", "Palestine"),
        Country::new(172, "PA", "Panama"),
        Country::new(173, "PG", "Papua New Guinea"),
        Country::new(174, "PY", "Paraguay"),
        Country::new(175, "PE", "Peru"),
        Country::new(176, "PH", "Phillipines"),
        Country::new(177, "PN", "Pitcairn"),
        Country::new(178, "PL", "Poland"),
        Country::new(179, "PT", "Portugal"),
        Country::new(180, "PR", "Puerto Rico"),
        Country::new(181, "QA", "Qatar"),
        Country::new(182, "RE", "Reunion"),
        Country::new(183, "RO", "Romanian"),
        Country::new(184, "RU", "Russian Federation"),
        Country::new(185, "RW", "Rwanda"),
        Country::new(186, "BL", "Saint Barthelemy"),
        Country::new(187, "SH", "Saint Helena, Ascension Island, Tristan da Cunha"),
        Country::new(188, "KN", "Saint Kitts and Nevis"),
        Country::new(189, "LC", "Saint Lucia"),
        Country::new(190, "MF", "Saint Martin"),
        Country::new(191, "PM", "Saint Pierre and Miquelon"),
        Country::new(192, "VC", "Saint Vincent and the Grenadines"),
        Country::new(193, "WS", "Samoa"),
        Country::new(194, "SM", "San Marino"),
        Country::new(195, "ST", "Sao Tome and Principe"),
        Country::new(196, "SA", "Saudi Arabia"),
        Country::new(197, "SN", "Senegal"),
        Country::new(198, "RS", "Serbia"),
        Country::new(199, "SC", "Seychelles"),
        Country::new(200, "SL", "Sierra Leone"),
        Country::new(201, "SG", "Singapore"),
        Country::new(202, "SX", "Sint Maarten"),
        Country::new(203, "SK", "Slovakia"),
        Country::new(204, "SI", "Slovenia"),
        Country::new(205, "SB", "Solomon Islands"),
        Country::new(206, "SO", "Somalia"),
        Country::new(207, "ZA", "South Africa"),
        Country::new(208, "GS", "South Georgia and the South Sandwich Islands"),
        Country::new(209, "SS", "South Sudan"),
        Country::new(210, "ES", "Spain"),
        Country::new(211, "LK", "Sri Lanka"),
        Country::new(212, "SD", "Sudan"),
        Country::new(213, "SR", "Suriname"),
        Country::new(214, "SJ", "Svalbard and Jan Mayen"),
        Country::new(215, "SE", "Sweden"),
        Country::new(216, "CH", "Switzerland"),
        Country::new(217, "SY", "Syrian Arab Republic"),
        Country::new(218, "TW", "Taiwan"),
        Country::new(219, "TJ", "Tajikistan"),
        Country::new(220, "TZ", "Tanzania"),
        Country::new(221, "TH", "Thailand"),
        Country::new(222, "TL", "Timor-Leste"),
        Country::new(223, "TG", "Togo"),
        Country::new(224, "TK", "Tokelau"),
        Country::new(225, "TO", "Tonga"),
        Country::new(226, "TT", "Trinidad and Tobago"),
        Country::new(227, "TN", "Tunisia"),
        Country::new(228, "TR", "Turkiye"),
        Country::new(229, "TM", "Turkmenistan"),
        Country::new(230, "TC", "Turks and Caicos Islands"),
        Country::new(231, "TV", "Tuvalu"),
        Country::new(232, "UG", "Uganda"),
        Country::new(233, "UA", "Ukraine"),
        Country::new(234, "AE", "United Arab Emirates"),
        Country::new(235, "GB", "United Kingdom"),
        Country::new(236, "UM", "United States Minor Outlying Islands"),
        Country::new(237, "US", "United States"),
        Country::new(238, "UY", "Uruguay"),
        Country::new(239, "UZ", "Uzbekistan"),
        Country::new(240, "VU", "Vanuatu"),
        Country::new(241, "VE", "Venezuela"),
        Country::new(242, "VN", "Vietnam"),
        Country::new(243, "VG", "British Virgin Islands"),
        Country::new(244, "VI", "US Virgin Islands"),
        Country::new(245, "WF", "Wallis and Futuna"),
        Country::new(246, "EH", "Western Sahara"),
        Country::new(247, "YE", "Yemen"),
        Country::new(248, "ZM", "Zambia"),
        Country::new(249, "ZW", "Zimbabwe"),
    ];
    
    pub static ref INDEX_BY_ISO3166: HashMap<String, usize> = COUNTRIES
        .iter()
        .map(|country| (country.iso3166.clone(), country.index))
        .collect::<HashMap<String, usize>>();
}

impl TryFrom<&str> for Country {
    type Error = String;

    fn try_from(iso3166: &str) -> Result<Self, Self::Error> {
        let index = match INDEX_BY_ISO3166.get(&iso3166.to_ascii_uppercase()) {
            None => return Err(format!("'{}' is not a valid ISO3166 country code", iso3166)),
            Some(index) => *index,
        };
        Ok(Country::try_from(index).expect(&format!("Data error: ISO3166 {} maps to index {}, but there is no such Country", iso3166, index)))
    }
}

impl From<usize> for Country {
    fn from(index: usize) -> Self {
        match COUNTRIES.get(index) {
            None => panic!("There are only {} Countries; no Country is at index {}", COUNTRIES.len(), index),
            Some(country) => country.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::countries::COUNTRIES;
    use crate::country_block_stream::Country;

    #[test]
    fn countries_are_properly_ordered() {
        COUNTRIES.iter()
            .enumerate()
            .for_each(|(index, country)| 
                assert_eq!(
                    country.index, 
                    index, 
                    "Index for {} should have been {} but was {}", 
                    country.name, 
                    index,
                    country.index
                )
            );
    }

    #[test]
    fn string_length_check() {
        COUNTRIES.iter()
            .for_each(|country| {
                assert_eq!(country.iso3166.len(), 2);
                assert_eq!(
                    country.name.len() > 0, true,
                    "Blank country name for {} at index {}",
                    country.iso3166, country.index
                );
            })
    }

    #[test]
    fn try_from_str_happy_path() {

        let result = Country::try_from("IL");

        assert_eq!(result, Ok(COUNTRIES.get(110).unwrap().clone()));
    }

    #[test]
    fn try_from_str_wrong_case() {

        let result = Country::try_from("il");

        assert_eq!(result, Ok(COUNTRIES.get(110).unwrap().clone()));
    }

    #[test]
    fn try_from_str_bad_iso3166() {

        let result = Country::try_from("Booga");

        assert_eq!(result, Err("'Booga' is not a valid ISO3166 country code".to_string()));
    }

    #[test]
    fn from_index_happy_path() {

        let result = Country::from(110usize);

        assert_eq!(result, COUNTRIES.get(110).unwrap().clone());
    }

    #[test]
    #[should_panic(expected = "There are only 250 Countries; no Country is at index 4096")]
    fn try_from_index_bad_index() {

        let _ = Country::from(4096usize);
    }
}