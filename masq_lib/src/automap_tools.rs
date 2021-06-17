use serde_derive::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum AutomapProtocol {
    Pmp,
    Pcp,
    Igdp,
}

impl From<String> for AutomapProtocol {
    fn from(val: String) -> Self {
        match val.as_str() {
            "PCP" => Self::Pcp,
            "PMP" => Self::Pmp,
            "IGDP" => Self::Igdp,
            _ => panic!("something is wrong"),
        }
    }
}

impl Display for AutomapProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AutomapProtocol::Pcp => write!(f, "PCP"),
            AutomapProtocol::Pmp => write!(f, "PMP"),
            AutomapProtocol::Igdp => write!(f, "IGDP"),
        }
    }
}

#[cfg(test)]
mod test_mod {
    use crate::automap_tools::AutomapProtocol;

    #[test]
    fn from_string_to_pcp_matches_correctly() {
        let result: AutomapProtocol = "PCP".to_string().into();

        assert_eq!(result, AutomapProtocol::Pcp)
    }

    #[test]
    fn from_string_to_pmp_matches_correctly() {
        let result: AutomapProtocol = "PMP".to_string().into();

        assert_eq!(result, AutomapProtocol::Pmp)
    }

    #[test]
    fn from_string_to_igdp_matches_correctly() {
        let result: AutomapProtocol = "IGDP".to_string().into();

        assert_eq!(result, AutomapProtocol::Igdp)
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn lower_number_should_panic() {
        let _: AutomapProtocol = "0".to_string().into();
    }

    #[test]
    #[should_panic(expected = "something is wrong")]
    fn higher_number_should_panic() {
        let _: AutomapProtocol = "4".to_string().into();
    }

    #[test]
    fn from_pmp_to_string_matches_correctly() {
        let result = AutomapProtocol::Pmp.to_string();

        assert_eq!(result, "PMP".to_string())
    }

    #[test]
    fn from_pcp_to_string_matches_correctly() {
        let result = AutomapProtocol::Pcp.to_string();

        assert_eq!(result, "PCP".to_string())
    }

    #[test]
    fn from_igdp_to_string_matches_correctly() {
        let result = AutomapProtocol::Igdp.to_string();

        assert_eq!(result, "IGDP".to_string())
    }
}
