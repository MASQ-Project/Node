use std::collections::HashMap;
use lazy_static::lazy_static;
use crate::country_block_stream::Country;

lazy_static! {
    pub static ref COUNTRIES: Vec<Country> = vec![
        Country::new(0, "ZZ", "Sentinel", true),
        Country::new(1, "AF", "Afghanistan", false),
        Country::new(2, "AX", "Aland Islands", true),
        Country::new(3, "AL", "Albania", true),
        Country::new(4, "DZ", "Algeria", true),
        Country::new(5, "AS", "American Samoa", true),
        Country::new(6, "AD", "Andorra", true),
        Country::new(7, "AO", "Angola", true),
        Country::new(8, "AI", "Anguilla", true),
        Country::new(9, "AQ", "Antarctica", true),
        Country::new(10, "AG", "Antigua and Barbuda", true),
        Country::new(11, "AR", "Argentina", true),
        Country::new(12, "AM", "Armenia", true),
        Country::new(13, "AW", "Aruba", true),
        Country::new(14, "AU", "Australia", true),
        Country::new(15, "AT", "Austria", true),
        Country::new(16, "AZ", "Azerbaijan", true),
        Country::new(17, "BS", "Bahamas", true),
        Country::new(18, "BH", "Bahrain", true),
        Country::new(19, "BD", "Bangladesh", true),
        Country::new(20, "BB", "Barbados", true),
        Country::new(21, "BY", "Belarus", false),
        Country::new(22, "BE", "Belgium", true),
        Country::new(23, "BZ", "Belize", true),
        Country::new(24, "BJ", "Benin", true),
        Country::new(25, "BM", "Bermuda", true),
        Country::new(26, "BT", "Bhutan", true),
        Country::new(27, "BO", "Bolivia", true),
        Country::new(28, "BQ", "Bonaire, Sint Eustatius, Saba", true),
        Country::new(29, "BA", "Bosnia, Herzegovina", true),
        Country::new(30, "BW", "Botswana", true),
        Country::new(31, "BV", "Bouvet Island", true),
        Country::new(32, "BR", "Brazil", true),
        Country::new(33, "IO", "British Indian Ocean Territory", true),
        Country::new(34, "BN", "Brunei Darussalam", true),
        Country::new(35, "BG", "Bulgaria", true),
        Country::new(36, "BF", "Burkina Faso", true),
        Country::new(37, "BI", "Burundi", true),
        Country::new(38, "CV", "Cabo Verde", true),
        Country::new(39, "KH", "Cambodia", true),
        Country::new(40, "CM", "Cameroon", true),
        Country::new(41, "CA", "Canada", true),
        Country::new(42, "KY", "Cayman Islands", true),
        Country::new(43, "CF", "Central African Republic", true),
        Country::new(44, "TD", "Chad", true),
        Country::new(45, "CL", "Chile", true),
        Country::new(46, "CN", "China", false),
        Country::new(47, "CX", "Christmas Island", true),
        Country::new(48, "CC", "Cocos Islands", true),
        Country::new(49, "CO", "Colombia", true),
        Country::new(50, "KM", "Comoros", true),
        Country::new(51, "CD", "Democratic Republic of Congo", true),
        Country::new(52, "CG", "Congo", true),
        Country::new(53, "CK", "Cook Islands", true),
        Country::new(54, "CR", "Costa Rica", true),
        Country::new(55, "CI", "Ivory Coast", true),
        Country::new(56, "HR", "Croatia", true),
        Country::new(57, "CU", "Cuba", true),
        Country::new(58, "CW", "Curacao", true),
        Country::new(59, "CY", "Cyprus", true),
        Country::new(60, "CZ", "Czechia", true),
        Country::new(61, "DK", "Denmark", true),
        Country::new(62, "DJ", "Djibouti", true),
        Country::new(63, "DM", "Dominica", true),
        Country::new(64, "DO", "Dominican Republic", true),
        Country::new(65, "EC", "Ecuador", true),
        Country::new(66, "EG", "Egypt", true),
        Country::new(67, "SV", "El Salvador", true),
        Country::new(68, "GQ", "Equatorial Guinea", true),
        Country::new(69, "ER", "Eritrea", true),
        Country::new(70, "EE", "Estonia", true),
        Country::new(71, "SZ", "Eswatini", true),
        Country::new(72, "ET", "Ethiopia", true),
        Country::new(73, "FK", "Falkland Islands", true),
        Country::new(74, "FO", "Faroe Islands", true),
        Country::new(75, "FJ", "Fiji", true),
        Country::new(76, "FI", "Finland", true),
        Country::new(77, "FR", "France", true),
        Country::new(78, "GF", "French Guiana", true),
        Country::new(79, "PF", "French Polynesia", true),
        Country::new(80, "TF", "French Southern Territories", true),
        Country::new(81, "GA", "Gabon", true),
        Country::new(82, "GM", "Gambia", true),
        Country::new(83, "GE", "Georgia", true),
        Country::new(84, "DE", "Germany", true),
        Country::new(85, "GH", "Ghana", true),
        Country::new(86, "GI", "Gibraltar", true),
        Country::new(87, "GR", "Greece", true),
        Country::new(88, "GL", "Greenland", true),
        Country::new(89, "GD", "Grenada", true),
        Country::new(90, "GP", "Guadeloupe", true),
        Country::new(91, "GU", "Guam", true),
        Country::new(92, "GT", "Guatemala", true),
        Country::new(93, "GG", "Guernsey", true),
        Country::new(94, "GN", "Guinea", true),
        Country::new(95, "GW", "Guinea-Bissau", true),
        Country::new(96, "GY", "Guyana", true),
        Country::new(97, "HT", "Haiti", true),
        Country::new(98, "HM", "Heard Island and McDonald Islands", true),
        Country::new(99, "VA", "Holy See", true),
        Country::new(100, "HN", "Honduras", true),
        Country::new(101, "HK", "Hong Kong", true),
        Country::new(102, "HU", "Hungary", true),
        Country::new(103, "IS", "Iceland", true),
        Country::new(104, "IN", "India", true),
        Country::new(105, "ID", "Indonesia", true),
        Country::new(106, "IR", "Iran", false),
        Country::new(107, "IQ", "Iraq", false),
        Country::new(108, "IE", "Ireland", true),
        Country::new(109, "IM", "Isle of Man", true),
        Country::new(110, "IL", "Israel", true),
        Country::new(111, "IT", "Italy", true),
        Country::new(112, "JM", "Jamaica", true),
        Country::new(113, "JP", "Japan", true),
        Country::new(114, "JE", "Jersey", true),
        Country::new(115, "JO", "Jordan", true),
        Country::new(116, "KZ", "Kazakhstan", true),
        Country::new(117, "KE", "Kenya", true),
        Country::new(118, "KI", "Kiribati", true),
        Country::new(119, "KP", "North Korea", false),
        Country::new(120, "KR", "South Korea", true),
        Country::new(121, "KW", "Kuwait", true),
        Country::new(122, "KG", "Kyrgyzstan", true),
        Country::new(123, "LA", "Lao People's Democratic Republic", true),
        Country::new(124, "LV", "Latvia", true),
        Country::new(125, "LB", "Lebanon", true),
        Country::new(126, "LS", "Lesotho", true),
        Country::new(127, "LR", "Liberia", true),
        Country::new(128, "LY", "Libya", true),
        Country::new(129, "LI", "Liechtenstein", true),
        Country::new(130, "LT", "Lithuania", true),
        Country::new(131, "LU", "Luxembourg", true),
        Country::new(132, "MO", "Macao", true),
        Country::new(133, "MG", "Madagascar", true),
        Country::new(134, "MW", "Malawi", true),
        Country::new(135, "MY", "Malaysia", true),
        Country::new(136, "MV", "Maldives", true),
        Country::new(137, "ML", "Mali", true),
        Country::new(138, "MT", "Malta", true),
        Country::new(139, "MH", "Harshall Islands", true),
        Country::new(140, "MQ", "Martinique", true),
        Country::new(141, "MR", "Mauritania", true),
        Country::new(142, "MU", "Mauritius", true),
        Country::new(143, "YT", "Mayotte", true),
        Country::new(144, "MX", "Mexico", true),
        Country::new(145, "FM", "Micronesia", true),
        Country::new(146, "MD", "Moldova", true),
        Country::new(147, "MC", "Monaco", true),
        Country::new(148, "MN", "Mongolia", true),
        Country::new(149, "ME", "Montenegro", true),
        Country::new(150, "MS", "Montserrat", true),
        Country::new(151, "MA", "Morocco", true),
        Country::new(152, "MZ", "Mozambique", true),
        Country::new(153, "MM", "Myanmar", true),
        Country::new(154, "NA", "Namibia", true),
        Country::new(155, "NR", "Nauru", true),
        Country::new(156, "NP", "Nepal", true),
        Country::new(157, "NL", "Netherlands", true),
        Country::new(158, "NC", "New Caledonia", true),
        Country::new(159, "NZ", "New Zealand", true),
        Country::new(160, "NI", "Nicaragua", true),
        Country::new(161, "NE", "Niger", true),
        Country::new(162, "NG", "Nigeria", true),
        Country::new(163, "NU", "Niue", true),
        Country::new(164, "NF", "Norfolk Island", true),
        Country::new(165, "MK", "North Macedonia", true),
        Country::new(166, "MP", "Morthern Mariana Islands", true),
        Country::new(167, "NO", "Norway", true),
        Country::new(168, "OM", "Oman", true),
        Country::new(169, "PK", "Pakistan", false),
        Country::new(170, "PW", "Palau", true),
        Country::new(171, "PS", "Palestine", true),
        Country::new(172, "PA", "Panama", true),
        Country::new(173, "PG", "Papua New Guinea", true),
        Country::new(174, "PY", "Paraguay", true),
        Country::new(175, "PE", "Peru", true),
        Country::new(176, "PH", "Phillipines", true),
        Country::new(177, "PN", "Pitcairn", true),
        Country::new(178, "PL", "Poland", true),
        Country::new(179, "PT", "Portugal", true),
        Country::new(180, "PR", "Puerto Rico", true),
        Country::new(181, "QA", "Qatar", true),
        Country::new(182, "RE", "Reunion", true),
        Country::new(183, "RO", "Romanian", true),
        Country::new(184, "RU", "Russian Federation", true),
        Country::new(185, "RW", "Rwanda", true),
        Country::new(186, "BL", "Saint Barthelemy", true),
        Country::new(187, "SH", "Saint Helena, Ascension Island, Tristan da Cunha", true),
        Country::new(188, "KN", "Saint Kitts and Nevis", true),
        Country::new(189, "LC", "Saint Lucia", true),
        Country::new(190, "MF", "Saint Martin", true),
        Country::new(191, "PM", "Saint Pierre and Miquelon", true),
        Country::new(192, "VC", "Saint Vincent and the Grenadines", true),
        Country::new(193, "WS", "Samoa", true),
        Country::new(194, "SM", "San Marino", true),
        Country::new(195, "ST", "Sao Tome and Principe", true),
        Country::new(196, "SA", "Saudi Arabia", false),
        Country::new(197, "SN", "Senegal", true),
        Country::new(198, "RS", "Serbia", true),
        Country::new(199, "SC", "Seychelles", true),
        Country::new(200, "SL", "Sierra Leone", true),
        Country::new(201, "SG", "Singapore", true),
        Country::new(202, "SX", "Sint Maarten", true),
        Country::new(203, "SK", "Slovakia", true),
        Country::new(204, "SI", "Slovenia", true),
        Country::new(205, "SB", "Solomon Islands", true),
        Country::new(206, "SO", "Somalia", true),
        Country::new(207, "ZA", "South Africa", true),
        Country::new(208, "GS", "South Georgia and the South Sandwich Islands", true),
        Country::new(209, "SS", "South Sudan", true),
        Country::new(210, "ES", "Spain", true),
        Country::new(211, "LK", "Sri Lanka", true),
        Country::new(212, "SD", "Sudan", true),
        Country::new(213, "SR", "Suriname", true),
        Country::new(214, "SJ", "Svalbard and Jan Mayen", true),
        Country::new(215, "SE", "Sweden", true),
        Country::new(216, "CH", "Switzerland", true),
        Country::new(217, "SY", "Syrian Arab Republic", true),
        Country::new(218, "TW", "Taiwan", true),
        Country::new(219, "TJ", "Tajikistan", true),
        Country::new(220, "TZ", "Tanzania", true),
        Country::new(221, "TH", "Thailand", true),
        Country::new(222, "TL", "Timor-Leste", true),
        Country::new(223, "TG", "Togo", true),
        Country::new(224, "TK", "Tokelau", true),
        Country::new(225, "TO", "Tonga", true),
        Country::new(226, "TT", "Trinidad and Tobago", true),
        Country::new(227, "TN", "Tunisia", true),
        Country::new(228, "TR", "Turkiye", true),
        Country::new(229, "TM", "Turkmenistan", true),
        Country::new(230, "TC", "Turks and Caicos Islands", true),
        Country::new(231, "TV", "Tuvalu", true),
        Country::new(232, "UG", "Uganda", true),
        Country::new(233, "UA", "Ukraine", true),
        Country::new(234, "AE", "United Arab Emirates", true),
        Country::new(235, "GB", "United Kingdom", true),
        Country::new(236, "UM", "United States Minor Outlying Islands", true),
        Country::new(237, "US", "United States", true),
        Country::new(238, "UY", "Uruguay", true),
        Country::new(239, "UZ", "Uzbekistan", true),
        Country::new(240, "VU", "Vanuatu", true),
        Country::new(241, "VE", "Venezuela", false),
        Country::new(242, "VN", "Vietnam", true),
        Country::new(243, "VG", "British Virgin Islands", true),
        Country::new(244, "VI", "US Virgin Islands", true),
        Country::new(245, "WF", "Wallis and Futuna", true),
        Country::new(246, "EH", "Western Sahara", true),
        Country::new(247, "YE", "Yemen", false),
        Country::new(248, "ZM", "Zambia", true),
        Country::new(249, "ZW", "Zimbabwe", true),
        Country::new(250, "XK", "Kosovo", true),
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
    #[should_panic(expected = "There are only 251 Countries; no Country is at index 4096")]
    fn try_from_index_bad_index() {

        let _ = Country::from(4096usize);
    }
}