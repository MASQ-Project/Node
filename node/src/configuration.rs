// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use crate::discriminator::DiscriminatorFactory;
use crate::http_request_start_finder::HttpRequestDiscriminatorFactory;
use crate::persistent_configuration::{HTTP_PORT, TLS_PORT};
use crate::tls_discriminator_factory::TlsDiscriminatorFactory;
use std::collections::HashMap;

pub struct Configuration {
    pub port_configurations: HashMap<u16, PortConfiguration>,
}

impl Configuration {
    pub fn new() -> Configuration {
        Configuration {
            port_configurations: HashMap::new(),
        }
    }

    pub fn establish(&mut self) {
        self.port_configurations.insert(
            HTTP_PORT,
            PortConfiguration::new(
                vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                false,
            ),
        );
        self.port_configurations.insert(
            TLS_PORT,
            PortConfiguration::new(
                vec![
                    Box::new(TlsDiscriminatorFactory::new()),
                    Box::new(HttpRequestDiscriminatorFactory::new()),
                ],
                false,
            ),
        );
    }
}

#[derive(Clone)]
pub struct PortConfiguration {
    pub discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
    pub is_clandestine: bool,
}

impl PortConfiguration {
    pub fn new(
        discriminator_factories: Vec<Box<dyn DiscriminatorFactory>>,
        is_clandestine: bool,
    ) -> PortConfiguration {
        PortConfiguration {
            discriminator_factories,
            is_clandestine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discriminator::UnmaskedChunk;
    use crate::node_test_utils::NullDiscriminatorFactory;
    use crate::test_utils::test_utils::assert_contains;

    fn all_ports(config: &Configuration) -> Vec<u16> {
        config
            .port_configurations
            .keys()
            .map(|port_ref| *port_ref)
            .collect()
    }

    fn clandestine_ports(config: &Configuration) -> Vec<u16> {
        all_ports(config)
            .into_iter()
            .filter(|port| (*port != HTTP_PORT) && (*port != TLS_PORT))
            .collect()
    }

    #[test]
    fn establish_produces_configuration_for_http_port() {
        let mut subject = Configuration::new();

        subject.establish();

        let mut http_port_configuration = subject.port_configurations.remove(&HTTP_PORT).unwrap();
        assert_eq!(http_port_configuration.discriminator_factories.len(), 1);
        assert!(!http_port_configuration.is_clandestine);
        let http_factory = http_port_configuration.discriminator_factories.remove(0);
        let mut http_discriminator = http_factory.make();
        http_discriminator.add_data("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes());
        let http_chunk = http_discriminator.take_chunk().unwrap();
        assert_eq!(
            http_chunk,
            UnmaskedChunk::new(
                Vec::from("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes()),
                true,
                true,
            )
        );
    }

    #[test]
    fn establish_produces_configuration_for_tls_port() {
        let mut subject = Configuration::new();

        subject.establish();

        let mut tls_port_configuration = subject.port_configurations.remove(&TLS_PORT).unwrap();
        assert_eq!(tls_port_configuration.discriminator_factories.len(), 2);
        assert!(!tls_port_configuration.is_clandestine);
        let tls_factory = tls_port_configuration.discriminator_factories.remove(0);
        let mut tls_discriminator = tls_factory.make();

        tls_discriminator.add_data(&vec![0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03][..]);
        let tls_chunk = tls_discriminator.take_chunk().unwrap();

        assert_eq!(
            tls_chunk,
            UnmaskedChunk::new(
                vec!(0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03),
                true,
                true,
            )
        );
    }

    #[test]
    fn default_port_443_configuration_includes_an_http_discriminator_factory() {
        let mut subject = Configuration::new();

        subject.establish();

        let mut port_443_configuration = subject.port_configurations.remove(&443).unwrap();
        let http_factory = port_443_configuration.discriminator_factories.remove(1);
        let mut http_discriminator = http_factory.make();

        http_discriminator.add_data("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes());
        let http_chunk = http_discriminator.take_chunk().unwrap();
        assert_eq!(
            http_chunk,
            UnmaskedChunk::new(
                Vec::from("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes()),
                true,
                true,
            )
        );
    }

    #[test]
    fn establish_produces_configuration_with_no_clandestine_ports() {
        let mut subject = Configuration::new();

        subject.establish();

        assert_eq!(clandestine_ports(&subject).len(), 0);
    }

    #[test]
    fn all_ports_returns_list_of_all_ports() {
        let mut subject = Configuration::new();
        let factory1 = NullDiscriminatorFactory::new();
        let factory2 = NullDiscriminatorFactory::new();
        let factory3 = NullDiscriminatorFactory::new();
        subject.port_configurations.insert(
            HTTP_PORT,
            PortConfiguration::new(vec![Box::new(factory1), Box::new(factory2)], false),
        );
        subject.port_configurations.insert(
            TLS_PORT,
            PortConfiguration::new(vec![Box::new(factory3)], false),
        );
        subject
            .port_configurations
            .insert(3456, PortConfiguration::new(vec![], true));

        let ports = all_ports(&subject);

        assert_contains(&ports, &HTTP_PORT);
        assert_contains(&ports, &TLS_PORT);
        assert_contains(&ports, &3456);
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn clandestine_ports_returns_only_clandestine_ports() {
        let mut subject = Configuration::new();
        let factory1 = NullDiscriminatorFactory::new();
        let factory2 = NullDiscriminatorFactory::new();
        let factory3 = NullDiscriminatorFactory::new();
        subject.port_configurations.insert(
            HTTP_PORT,
            PortConfiguration::new(vec![Box::new(factory1), Box::new(factory2)], false),
        );
        subject.port_configurations.insert(
            TLS_PORT,
            PortConfiguration::new(vec![Box::new(factory3)], false),
        );
        subject
            .port_configurations
            .insert(3456, PortConfiguration::new(vec![], true));

        let ports = clandestine_ports(&subject);

        assert_eq!(ports.contains(&3456), true);
        assert_eq!(ports.len(), 1);
    }
}
