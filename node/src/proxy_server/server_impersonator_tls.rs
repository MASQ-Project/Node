// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::proxy_server::protocol_pack::ServerImpersonator;

pub struct ServerImpersonatorTls {}

impl ServerImpersonator for ServerImpersonatorTls {
    fn route_query_failure_response(&self, _server_name: &str) -> Vec<u8> {
        Vec::from(&TLS_INTERNAL_ERROR_ALERT[..])
    }

    fn dns_resolution_failure_response(&self, _server_name: Option<String>) -> Vec<u8> {
        Vec::from(&TLS_UNRECOGNIZED_NAME_ALERT[..])
    }

    fn consuming_wallet_absent(&self) -> Vec<u8> {
        Vec::from(&TLS_INTERNAL_ERROR_ALERT[..])
    }
}

const TLS_INTERNAL_ERROR_ALERT: [u8; 7] = [
    0x15, // alert
    0x03, 0x03, // TLS 1.2
    0x00, 0x02, // packet length
    0x02, // fatal alert
    0x50, // internal_error alert
];

const TLS_UNRECOGNIZED_NAME_ALERT: [u8; 7] = [
    0x15, // alert
    0x03, 0x03, // TLS 1.2
    0x00, 0x02, // packet length
    0x02, // fatal alert
    0x70, // unrecognized_name alert
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_correct_values() {
        let tls_internal_error_alert_expected: [u8; 7] = [
            0x15, // alert
            0x03, 0x03, // TLS 1.2
            0x00, 0x02, // packet length
            0x02, // fatal alert
            0x50, // internal_error alert
        ];

        let tls_unrecognized_name_alert_expected: [u8; 7] = [
            0x15, // alert
            0x03, 0x03, // TLS 1.2
            0x00, 0x02, // packet length
            0x02, // fatal alert
            0x70, // unrecognized_name alert
        ];

        assert_eq!(TLS_INTERNAL_ERROR_ALERT, tls_internal_error_alert_expected);
        assert_eq!(
            TLS_UNRECOGNIZED_NAME_ALERT,
            tls_unrecognized_name_alert_expected
        );
    }

    #[test]
    fn route_query_failure_response_produces_internal_error_alert() {
        let subject = ServerImpersonatorTls {};

        let result = subject.route_query_failure_response("ignored");

        assert_eq!(Vec::from(&TLS_INTERNAL_ERROR_ALERT[..]), result);
    }

    #[test]
    fn dns_resolution_failure_response_produces_unrecognized_name_alert() {
        let subject = ServerImpersonatorTls {};

        let result = subject.dns_resolution_failure_response(None);

        assert_eq!(Vec::from(&TLS_UNRECOGNIZED_NAME_ALERT[..]), result);
    }

    #[test]
    fn consuming_wallet_absent_produces_internal_error_alert() {
        let subject = ServerImpersonatorTls {};

        let result = subject.consuming_wallet_absent();

        assert_eq!(Vec::from(&TLS_INTERNAL_ERROR_ALERT[..]), result);
    }
}
