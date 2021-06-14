use serde_derive::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MappingProtocol {
    Pmp,
    Pcp,
    Igdp,
}

impl From<String> for MappingProtocol {
    fn from(val: String) -> Self {
        match val.as_str() {
            "PCP" => Self::Pcp,
            "PMP" => Self::Pmp,
            "IGDP" => Self::Igdp,
            _ => panic!("something is wrong"),
        }
    }
}

impl Display for MappingProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingProtocol::Pcp => write!(f, "PCP"),
            MappingProtocol::Pmp => write!(f, "PMP"),
            MappingProtocol::Igdp => write!(f, "IGDP"),
        }
    }
}

#[cfg(test)]
mod test_mod {
    use crate::automap_tools::MappingProtocol;

    #[test]
    fn from_string_to_pcp_matches_correctly() {
        let result: MappingProtocol = "PCP".to_string().into();

        assert_eq!(result, MappingProtocol::Pcp)
    }

    #[test]
    fn from_string_to_pmp_matches_correctly() {
        let result: MappingProtocol = "PMP".to_string().into();

        assert_eq!(result, MappingProtocol::Pmp)
    }

    #[test]
    fn from_string_to_igdp_matches_correctly() {
        let result: MappingProtocol = "IGDP".to_string().into();

        assert_eq!(result, MappingProtocol::Igdp)
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn lower_number_should_panic() {
        let _: MappingProtocol = "0".to_string().into();
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn higher_number_should_panic() {
        let _: MappingProtocol = "4".to_string().into();
    }

    #[test]
    fn from_pmp_to_string_matches_correctly() {
        let result = MappingProtocol::Pmp.to_string();

        assert_eq!(result, "PMP".to_string())
    }

    #[test]
    fn from_pcp_to_string_matches_correctly() {
        let result = MappingProtocol::Pcp.to_string();

        assert_eq!(result, "PCP".to_string())
    }

    #[test]
    fn from_igdp_to_string_matches_correctly() {
        let result = MappingProtocol::Igdp.to_string();

        assert_eq!(result, "IGDP".to_string())
    }
}
