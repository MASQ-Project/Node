use crate::neighborhood::gossip::AccessibleGossipRecord;
use crate::neighborhood::node_record::NodeRecord;
use crate::sub_lib::cryptde::PublicKey;
use crate::sub_lib::wallet::Wallet;
use lazy_static::lazy_static;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use time::{OffsetDateTime, PrimitiveDateTime};

lazy_static! {
    pub static ref FUDGE_FACTOR: time::Duration = time::Duration::seconds(1);
}

#[derive(Clone, Debug, Eq)]
pub struct Malefactor {
    pub public_key_opt: Option<PublicKey>,
    pub ip_address_opt: Option<IpAddr>,
    pub earning_wallet_opt: Option<Wallet>,
    pub consuming_wallet_opt: Option<Wallet>,
    pub timestamp: PrimitiveDateTime,
    pub reason: String,
}

impl Display for Malefactor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Malefactor{}{}{} detected at {}: {}",
            match &self.public_key_opt {
                Some(pk) => format!(" {}", pk),
                None => "".to_string(),
            },
            match &self.ip_address_opt {
                Some(ip) => format!(" at {}", ip),
                None => "".to_string(),
            },
            match &self.earning_wallet_opt {
                Some(wallet) => format!(" with earning wallet {}", wallet),
                None => "".to_string(),
            } + &match (
                &self.earning_wallet_opt.is_some(),
                &self.consuming_wallet_opt
            ) {
                (true, Some(wallet)) => format!(", consuming wallet {}", wallet),
                (false, Some(wallet)) => format!(" with consuming wallet {}", wallet),
                (_, None) => "".to_string(),
            },
            self.timestamp,
            self.reason
        )
    }
}

impl PartialEq for Malefactor {
    // Logic behind this custom implementation:
    // The only place we will ever compare Malefactors for equality is in tests. In tests,
    // the Malefactor that is generated in the production code and the Malefactor that is used
    // for assertion will frequently be created a few microseconds apart, and therefore their
    // timestamps will not be identical and the equality assertion will fail, even when the two
    // are logically the same. Therefore, this custom implementation will consider two Malefactors
    // equal if their timestamps are within FUDGE_FACTOR of each other and all their other fields are
    // equal.
    fn eq(&self, other: &Self) -> bool {
        let equal = self.public_key_opt == other.public_key_opt
            && self.ip_address_opt == other.ip_address_opt
            && self.earning_wallet_opt == other.earning_wallet_opt
            && self.consuming_wallet_opt == other.consuming_wallet_opt
            && self.reason == other.reason;
        let plus_one_second = self.timestamp.saturating_add(*FUDGE_FACTOR);
        let minus_one_second = self.timestamp.saturating_sub(*FUDGE_FACTOR);
        equal && (other.timestamp >= minus_one_second && other.timestamp <= plus_one_second)
    }
}

impl From<(&NodeRecord, String)> for Malefactor {
    fn from(pair: (&NodeRecord, String)) -> Self {
        let (node_record, reason) = pair;
        Self::new(
            Some(node_record.public_key().clone()),
            node_record
                .metadata
                .node_addr_opt
                .as_ref()
                .map(|na| na.ip_addr()),
            Some(node_record.inner.earning_wallet.clone()),
            None,
            reason,
        )
    }
}

impl From<(&AccessibleGossipRecord, String)> for Malefactor {
    fn from(pair: (&AccessibleGossipRecord, String)) -> Self {
        let (agr, reason) = pair;
        Self::new(
            Some(agr.inner.public_key.clone()),
            agr.node_addr_opt.as_ref().map(|na| na.ip_addr()),
            Some(agr.inner.earning_wallet.clone()),
            None,
            reason,
        )
    }
}

impl Malefactor {
    pub fn new(
        public_key_opt: Option<PublicKey>,
        ip_address_opt: Option<IpAddr>,
        earning_wallet_opt: Option<Wallet>,
        consuming_wallet_opt: Option<Wallet>,
        reason: String,
    ) -> Self {
        if public_key_opt.is_none()
            && ip_address_opt.is_none()
            && earning_wallet_opt.is_none()
            && consuming_wallet_opt.is_none()
        {
            panic!("Malefactor must have at least one identifying attribute");
        }
        Self {
            public_key_opt,
            ip_address_opt,
            earning_wallet_opt,
            consuming_wallet_opt,
            timestamp: Self::timestamp(),
            reason,
        }
    }

    fn timestamp() -> PrimitiveDateTime {
        let odt = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        PrimitiveDateTime::new(odt.date(), odt.time())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[should_panic(expected = "Malefactor must have at least one identifying attribute")]
    #[test]
    fn doesnt_tolerate_all_nones() {
        let _ = Malefactor::new(None, None, None, None, "Bad Smell".to_string());
    }

    #[test]
    fn timestamps_properly() {
        let before = Malefactor::timestamp();

        let malefactor = Malefactor::new(
            Some(PublicKey::from(&b"Booga"[..])),
            None,
            None,
            None,
            "Bad Smell".to_string(),
        );

        let after = Malefactor::timestamp();
        assert!(malefactor.timestamp >= before);
        assert!(malefactor.timestamp <= after);
    }

    #[test]
    fn displays_public_key() {
        let public_key = PublicKey::from(&b"Booga"[..]);
        let malefactor = Malefactor {
            public_key_opt: Some(public_key),
            ip_address_opt: None,
            earning_wallet_opt: None,
            consuming_wallet_opt: None,
            timestamp: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
                time::Time::from_hms(12, 34, 56).unwrap(),
            ),
            reason: "Bad Smell".to_string(),
        };

        let string = format!("{}", malefactor);

        assert_eq!(
            string,
            "Malefactor Qm9vZ2E detected at 2024-06-01 12:34:56.0: Bad Smell".to_string()
        );
    }

    #[test]
    fn displays_ip_address() {
        let ip_address = IpAddr::from_str("12.34.56.78").unwrap();
        let malefactor = Malefactor {
            public_key_opt: None,
            ip_address_opt: Some(ip_address),
            earning_wallet_opt: None,
            consuming_wallet_opt: None,
            timestamp: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
                time::Time::from_hms(12, 34, 56).unwrap(),
            ),
            reason: "Bad Smell".to_string(),
        };

        let string = format!("{}", malefactor);

        assert_eq!(
            string,
            "Malefactor at 12.34.56.78 detected at 2024-06-01 12:34:56.0: Bad Smell".to_string()
        );
    }

    #[test]
    fn displays_earning_wallet() {
        let earning_wallet =
            Wallet::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let malefactor = Malefactor {
            public_key_opt: None,
            ip_address_opt: None,
            earning_wallet_opt: Some(earning_wallet),
            consuming_wallet_opt: None,
            timestamp: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
                time::Time::from_hms(12, 34, 56).unwrap(),
            ),
            reason: "Bad Smell".to_string(),
        };

        let string = format!("{}", malefactor);

        assert_eq!(
            string,
            "Malefactor with earning wallet 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee detected at 2024-06-01 12:34:56.0: Bad Smell".to_string()
        );
    }

    #[test]
    fn displays_consuming_wallet() {
        let consuming_wallet =
            Wallet::from_str("0xcccccccccccccccccccccccccccccccccccccccc").unwrap();
        let malefactor = Malefactor {
            public_key_opt: None,
            ip_address_opt: None,
            earning_wallet_opt: None,
            consuming_wallet_opt: Some(consuming_wallet),
            timestamp: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
                time::Time::from_hms(12, 34, 56).unwrap(),
            ),
            reason: "Bad Smell".to_string(),
        };

        let string = format!("{}", malefactor);

        assert_eq!(
            string,
            "Malefactor with consuming wallet 0xcccccccccccccccccccccccccccccccccccccccc detected at 2024-06-01 12:34:56.0: Bad Smell".to_string()
        );
    }

    #[test]
    fn displays_all_fields() {
        let public_key = PublicKey::from(&b"Booga"[..]);
        let ip_address = IpAddr::from_str("12.34.56.78").unwrap();
        let earning_wallet =
            Wallet::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let consuming_wallet =
            Wallet::from_str("0xcccccccccccccccccccccccccccccccccccccccc").unwrap();
        let malefactor = Malefactor {
            public_key_opt: Some(public_key),
            ip_address_opt: Some(ip_address),
            earning_wallet_opt: Some(earning_wallet),
            consuming_wallet_opt: Some(consuming_wallet),
            timestamp: PrimitiveDateTime::new(
                time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
                time::Time::from_hms(12, 34, 56).unwrap(),
            ),
            reason: "Bad Smell".to_string(),
        };

        let string = format!("{}", malefactor);

        assert_eq!(
            string,
            "Malefactor Qm9vZ2E at 12.34.56.78 with earning wallet 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, consuming wallet 0xcccccccccccccccccccccccccccccccccccccccc detected at 2024-06-01 12:34:56.0: Bad Smell".to_string()
        );
    }

    #[test]
    fn eq_works_for_equal_timestamps() {
        let public_key = PublicKey::from(&b"Booga"[..]);
        let ip_address = IpAddr::from_str("12.34.56.78").unwrap();
        let earning_wallet =
            Wallet::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let consuming_wallet =
            Wallet::from_str("0xcccccccccccccccccccccccccccccccccccccccc").unwrap();
        let timestamp = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
            time::Time::from_hms(12, 34, 56).unwrap(),
        );
        let reason = "Bad Smell".to_string();
        let a = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: reason.clone(),
        };
        let b = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: reason.clone(),
        };
        let c = Malefactor {
            public_key_opt: None,
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: reason.clone(),
        };
        let d = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: None,
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: reason.clone(),
        };
        let e = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: None,
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: reason.clone(),
        };
        let f = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: None,
            timestamp,
            reason: reason.clone(),
        };
        let g = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp,
            reason: "".to_string(),
        };

        assert_eq!(a, a);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
        assert_ne!(a, f);
        assert_ne!(a, g);
    }

    #[test]
    fn eq_says_true_for_timestamps_exactly_one_second_apart() {
        let public_key = PublicKey::from(&b"Booga"[..]);
        let ip_address = IpAddr::from_str("12.34.56.78").unwrap();
        let earning_wallet =
            Wallet::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let consuming_wallet =
            Wallet::from_str("0xcccccccccccccccccccccccccccccccccccccccc").unwrap();
        let timestamp_early = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
            time::Time::from_hms(12, 34, 56).unwrap(),
        );
        let timestamp_late = timestamp_early.saturating_add(FUDGE_FACTOR.clone());
        let reason = "Bad Smell".to_string();
        let a = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp: timestamp_early,
            reason: reason.clone(),
        };
        let b = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp: timestamp_late,
            reason: reason.clone(),
        };

        assert_eq!(a, b);
        assert_eq!(b, a);
    }

    #[test]
    fn eq_says_false_for_timestamps_more_than_one_second_apart() {
        let public_key = PublicKey::from(&b"Booga"[..]);
        let ip_address = IpAddr::from_str("12.34.56.78").unwrap();
        let earning_wallet =
            Wallet::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        let consuming_wallet =
            Wallet::from_str("0xcccccccccccccccccccccccccccccccccccccccc").unwrap();
        let timestamp_early = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2024, time::Month::June, 1).unwrap(),
            time::Time::from_hms(12, 34, 56).unwrap(),
        );
        let timestamp_middle = timestamp_early
            .saturating_add(FUDGE_FACTOR.saturating_add(time::Duration::milliseconds(1)));
        let timestamp_late = timestamp_middle
            .saturating_add(FUDGE_FACTOR.saturating_add(time::Duration::milliseconds(1)));
        let reason = "Bad Smell".to_string();
        let a = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp: timestamp_early,
            reason: reason.clone(),
        };
        let b = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp: timestamp_middle,
            reason: reason.clone(),
        };
        let c = Malefactor {
            public_key_opt: Some(public_key.clone()),
            ip_address_opt: Some(ip_address.clone()),
            earning_wallet_opt: Some(earning_wallet.clone()),
            consuming_wallet_opt: Some(consuming_wallet.clone()),
            timestamp: timestamp_late,
            reason: reason.clone(),
        };

        assert_ne!(a, b);
        assert_ne!(b, a);
        assert_ne!(b, c);
        assert_ne!(c, b);
        assert_ne!(a, c);
        assert_ne!(c, a);
    }
}
