// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::net::IpAddr;
use ip_country_lib;
use ip_country_lib::country_finder::country_finder;
use ip_country_lib::dbip_country;

#[derive(Clone, Debug, Default)]
pub struct NodeLocation {
    id: u8,
    locale: String,
    pub(crate) free_world: bool
}

impl PartialEq<Self> for NodeLocation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NodeLocation {}

pub fn get_node_location(ip: Option<IpAddr>) -> Option<NodeLocation> {
    match ip {
        Some(ip_addr) => {
            let country = country_finder(dbip_country::ipv4_country_data, dbip_country::ipv6_country_data, ip_addr).expect("expected IP");
            Some( NodeLocation { id: country.index as u8, locale: country.iso3166.to_string(), free_world: country.free_world } )
        }
        None => None
    }

}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;
    use crate::neighborhood::node_location::{get_node_location, NodeLocation};
    use crate::neighborhood::node_record::NodeRecordMetadata;
    use crate::test_utils::neighborhood_test_utils::make_node_record;

    #[test]
    fn test_node_location() {
        let node_location = get_node_location(Some(IpAddr::V4(Ipv4Addr::new(125, 125, 125, 1)))).unwrap();

        assert_eq!(node_location.locale, "CN");
        assert_eq!(node_location.id, 46);
        assert_eq!(node_location.free_world, false);
    }

    #[test]
    fn construct_node_record_metadata_with_free_world_bit() {
        let metadata = NodeRecordMetadata::new(
            get_node_location(Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))))
        );

        assert_eq!(metadata.node_location.as_ref().unwrap(), &NodeLocation { id: 14, locale: "AU".to_string(), free_world: true });
        assert_eq!(metadata.free_world, metadata.node_location.as_ref().unwrap().free_world);
        assert_eq!(metadata.node_location.as_ref().unwrap().free_world, true);
        assert_eq!(metadata.node_location.as_ref().unwrap().locale, "AU");
        assert_eq!(metadata.node_location.as_ref().unwrap().id, 14);
    }

    #[test]
    fn construct_node_record_for_test() {
        let node_record = make_node_record(1111, true);

        assert_eq!(node_record.metadata.free_world, true);
        assert_eq!(node_record.metadata.node_location, Some(NodeLocation { id: 14, locale: "AU".to_string(), free_world: true }))
    }

    #[test]
    fn construct_node_record_for_test_with_100_high_ips() {
        let vals: Vec<u16> = (0..100).map(|v| v + 1111).collect();

        let timestart = SystemTime::now();
        let mut result_str: String = String::new();
        let expected_str = "1.1.1.1:1111 AU true
1.1.1.2:1112 AU true
1.1.1.3:1113 AU true
1.1.1.4:1114 AU true
1.1.1.5:1115 AU true
1.1.1.6:1116 AU true
1.1.1.7:1117 AU true
1.1.1.8:1118 AU true
1.1.1.9:1119 AU true
1.1.2.0:1120 CN false
1.1.2.1:1121 CN false
1.1.2.2:1122 CN false
1.1.2.3:1123 CN false
1.1.2.4:1124 CN false
1.1.2.5:1125 CN false
1.1.2.6:1126 CN false
1.1.2.7:1127 CN false
1.1.2.8:1128 CN false
1.1.2.9:1129 CN false
1.1.3.0:1130 CN false
1.1.3.1:1131 CN false
1.1.3.2:1132 CN false
1.1.3.3:1133 CN false
1.1.3.4:1134 CN false
1.1.3.5:1135 CN false
1.1.3.6:1136 CN false
1.1.3.7:1137 CN false
1.1.3.8:1138 CN false
1.1.3.9:1139 CN false
1.1.4.0:1140 CN false
1.1.4.1:1141 CN false
1.1.4.2:1142 CN false
1.1.4.3:1143 CN false
1.1.4.4:1144 CN false
1.1.4.5:1145 CN false
1.1.4.6:1146 CN false
1.1.4.7:1147 CN false
1.1.4.8:1148 CN false
1.1.4.9:1149 CN false
1.1.5.0:1150 CN false
1.1.5.1:1151 CN false
1.1.5.2:1152 CN false
1.1.5.3:1153 CN false
1.1.5.4:1154 CN false
1.1.5.5:1155 CN false
1.1.5.6:1156 CN false
1.1.5.7:1157 CN false
1.1.5.8:1158 CN false
1.1.5.9:1159 CN false
1.1.6.0:1160 CN false
1.1.6.1:1161 CN false
1.1.6.2:1162 CN false
1.1.6.3:1163 CN false
1.1.6.4:1164 CN false
1.1.6.5:1165 CN false
1.1.6.6:1166 CN false
1.1.6.7:1167 CN false
1.1.6.8:1168 CN false
1.1.6.9:1169 CN false
1.1.7.0:1170 CN false
1.1.7.1:1171 CN false
1.1.7.2:1172 CN false
1.1.7.3:1173 CN false
1.1.7.4:1174 CN false
1.1.7.5:1175 CN false
1.1.7.6:1176 CN false
1.1.7.7:1177 CN false
1.1.7.8:1178 CN false
1.1.7.9:1179 CN false
1.1.8.0:1180 CN false
1.1.8.1:1181 CN false
1.1.8.2:1182 CN false
1.1.8.3:1183 CN false
1.1.8.4:1184 CN false
1.1.8.5:1185 CN false
1.1.8.6:1186 CN false
1.1.8.7:1187 CN false
1.1.8.8:1188 CN false
1.1.8.9:1189 CN false
1.1.9.0:1190 CN false
1.1.9.1:1191 CN false
1.1.9.2:1192 CN false
1.1.9.3:1193 CN false
1.1.9.4:1194 CN false
1.1.9.5:1195 CN false
1.1.9.6:1196 CN false
1.1.9.7:1197 CN false
1.1.9.8:1198 CN false
1.1.9.9:1199 CN false
1.2.0.0:1200 CN false
1.2.0.1:1201 CN false
1.2.0.2:1202 CN false
1.2.0.3:1203 CN false
1.2.0.4:1204 CN false
1.2.0.5:1205 CN false
1.2.0.6:1206 CN false
1.2.0.7:1207 CN false
1.2.0.8:1208 CN false
1.2.0.9:1209 CN false
1.2.1.0:1210 CN false
".to_string();

        for val in vals {
            let node_record = make_node_record(val, true);
            let fmt_result =
                format!("{} {} {}\n",
                        node_record.metadata.node_addr_opt.unwrap().to_string(),
                        node_record.metadata.node_location.unwrap().locale.to_string(),
                        node_record.metadata.free_world.to_string());
            result_str += fmt_result.as_str();
        }

        let timeend = SystemTime::now();

        assert_eq!(result_str, expected_str);
        assert_eq!(timeend.duration_since(timestart).unwrap().as_secs() < 200, true);
    }

    #[test]
    fn construct_node_record_for_test_with_10_high_ips() {
        let vals: Vec<u16> = (0..10).map(|v| v + 1111).collect();
        let timestart = SystemTime::now();
        let mut result_str: String = String::new();
        let expected_str = "1.1.1.1:1111 AU true
1.1.1.2:1112 AU true
1.1.1.3:1113 AU true
1.1.1.4:1114 AU true
1.1.1.5:1115 AU true
1.1.1.6:1116 AU true
1.1.1.7:1117 AU true
1.1.1.8:1118 AU true
1.1.1.9:1119 AU true
1.1.2.0:1120 CN false
".to_string();

        for val in vals {
            let node_record = make_node_record(val, true);
            let fmt_result =
                format!("{} {} {}\n",
                        node_record.metadata.node_addr_opt.unwrap().to_string(),
                        node_record.metadata.node_location.unwrap().locale.to_string(),
                        node_record.metadata.free_world.to_string());
            result_str += fmt_result.as_str();
        }

        let timeend = SystemTime::now();

        assert_eq!(result_str, expected_str);
        assert_eq!(timeend.duration_since(timestart).unwrap().as_secs() < 20, true);
    }
}
