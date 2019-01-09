// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use discriminator::DiscriminatorFactory;
use http_request_start_finder::HttpRequestDiscriminatorFactory;
use json_discriminator_factory::JsonDiscriminatorFactory;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use sub_lib::parameter_finder::ParameterFinder;
use tls_discriminator_factory::TlsDiscriminatorFactory;

// TODO: This should be subsumed into BootstrapperConfig
pub struct Configuration {
    pub port_configurations: HashMap<u16, PortConfiguration>,
}

impl Configuration {
    pub fn new() -> Configuration {
        Configuration {
            port_configurations: HashMap::new(),
        }
    }

    pub fn establish(&mut self, args: &Vec<String>) {
        self.port_configurations.insert(
            80,
            PortConfiguration::new(
                vec![Box::new(HttpRequestDiscriminatorFactory::new())],
                false,
            ),
        );
        self.port_configurations.insert(
            443,
            PortConfiguration::new(vec![Box::new(TlsDiscriminatorFactory::new())], false),
        );

        let port_count = Configuration::parse_port_count(&ParameterFinder::new(args.clone()));
        for _ in 0..port_count {
            let port = Configuration::find_free_port();
            self.port_configurations.insert(
                port,
                PortConfiguration::new(vec![Box::new(JsonDiscriminatorFactory::new())], true),
            );
        }
    }

    pub fn all_ports(&self) -> Vec<u16> {
        self.port_configurations
            .keys()
            .map(|port_ref| *port_ref)
            .collect()
    }

    pub fn clandestine_ports(&self) -> Vec<u16> {
        self.all_ports()
            .into_iter()
            .filter(|port| (*port != 80) && (*port != 443))
            .collect()
    }

    fn find_free_port() -> u16 {
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .expect("Not enough free ports");
        socket.local_addr().expect("Bind failed").port()
    }

    fn parse_port_count(finder: &ParameterFinder) -> usize {
        let usage = "--port_count <number of clandestine ports to open, default = 0>";
        match finder.find_value_for("--port_count", usage) {
            None => 0,
            Some(ref port_count_str) => match port_count_str.parse::<usize>() {
                Ok(port_count) => port_count,
                Err(_) => panic!(
                    "--port_count <clandestine port count> needs a number, not '{}'",
                    port_count_str
                ),
            },
        }
    }
}

#[derive(Clone)]
pub struct PortConfiguration {
    pub discriminator_factories: Vec<Box<DiscriminatorFactory>>,
    pub is_clandestine: bool,
}

impl PortConfiguration {
    pub fn new(
        discriminator_factories: Vec<Box<DiscriminatorFactory>>,
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
    use discriminator::UnmaskedChunk;
    use node_test_utils::NullDiscriminatorFactory;
    use test_utils::test_utils::assert_contains;

    #[test]
    fn find_free_port_works_ten_times() {
        let sockets: Vec<UdpSocket> = (0u16..10u16)
            .map(|_| {
                let port = Configuration::find_free_port();
                UdpSocket::bind(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port,
                ))
                .expect(&format!("Could not bind free port {}", port))
            })
            .collect();
        for i in 0..10 {
            for j in (i + 1)..10 {
                assert_ne!(
                    sockets[i].local_addr().expect("Bind failed").port(),
                    sockets[j].local_addr().expect("Bind failed").port(),
                    "Port #{} is the same as port #{}: {}!",
                    i,
                    j,
                    sockets[i].local_addr().expect("Bind failed").port()
                );
            }
        }
    }

    #[test]
    fn no_parameters_produces_configuration_for_80() {
        let args = vec![String::from("command")];
        let mut subject = Configuration::new();

        subject.establish(&args);

        let mut port_80_configuration = subject.port_configurations.remove(&80).unwrap();
        assert_eq!(port_80_configuration.discriminator_factories.len(), 1);
        assert!(!port_80_configuration.is_clandestine);
        let http_factory = port_80_configuration.discriminator_factories.remove(0);
        let mut http_discriminator = http_factory.make();
        http_discriminator.add_data("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes());
        let http_chunk = http_discriminator.take_chunk().unwrap();
        assert_eq!(
            http_chunk,
            UnmaskedChunk::new(
                Vec::from("GET http://url.com HTTP/1.1\r\n\r\n".as_bytes()),
                true,
                true
            )
        );
    }

    #[test]
    fn no_parameters_produces_configuration_for_443() {
        let args = vec![String::from("command")];
        let mut subject = Configuration::new();

        subject.establish(&args);

        let mut port_443_configuration = subject.port_configurations.remove(&443).unwrap();
        assert_eq!(port_443_configuration.discriminator_factories.len(), 1);
        assert!(!port_443_configuration.is_clandestine);
        let tls_factory = port_443_configuration.discriminator_factories.remove(0);
        let mut tls_discriminator = tls_factory.make();
        tls_discriminator.add_data(&vec![0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03][..]);
        let tls_chunk = tls_discriminator.take_chunk().unwrap();
        assert_eq!(
            tls_chunk,
            UnmaskedChunk::new(
                vec!(0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03),
                true,
                true
            )
        );
    }

    #[test]
    fn no_parameters_produces_configuration_with_no_high_ports() {
        let args = vec![String::from("command")];
        let mut subject = Configuration::new();

        subject.establish(&args);

        assert_eq!(subject.clandestine_ports().len(), 0);
    }

    #[test]
    fn port_count_produces_configuration_with_proper_number_of_high_ports() {
        let args = vec![
            String::from("command"),
            String::from("--port_count"),
            String::from("5"),
        ];
        let mut subject = Configuration::new();

        subject.establish(&args);

        subject.port_configurations.remove(&80);
        subject.port_configurations.remove(&443);
        assert_eq!(subject.all_ports().len(), 5);
        subject.all_ports().into_iter().for_each(|high_port| {
            let mut high_port_configuration =
                subject.port_configurations.remove(&high_port).unwrap();
            assert_eq!(high_port_configuration.discriminator_factories.len(), 1);
            let json_factory = high_port_configuration.discriminator_factories.remove(0);
            let mut json_discriminator = json_factory.make();
            json_discriminator.add_data(&b"{\"component\": \"NBHD\", \"bodyText\": \"booga\"}"[..]);
            let json_chunk = json_discriminator.take_chunk().unwrap();
            assert_eq!(
                json_chunk,
                UnmaskedChunk::new(b"booga".to_vec(), true, false)
            );
        });
    }

    #[test]
    #[should_panic(expected = "--port_count <clandestine port count> needs a number, not 'booga'")]
    fn parse_port_count_rejects_badly_formatted_port_count() {
        let args = vec![
            String::from("command"),
            String::from("--port_count"),
            String::from("booga"),
        ];
        let finder = ParameterFinder::new(args);

        Configuration::parse_port_count(&finder);
    }

    #[test]
    fn all_ports_returns_list_of_all_ports() {
        let mut subject = Configuration::new();
        let factory1 = NullDiscriminatorFactory::new();
        let factory2 = NullDiscriminatorFactory::new();
        let factory3 = NullDiscriminatorFactory::new();
        subject.port_configurations.insert(
            80,
            PortConfiguration::new(vec![Box::new(factory1), Box::new(factory2)], false),
        );
        subject
            .port_configurations
            .insert(443, PortConfiguration::new(vec![Box::new(factory3)], false));
        subject
            .port_configurations
            .insert(3456, PortConfiguration::new(vec![], true));

        let ports = subject.all_ports();

        assert_contains(&ports, &80);
        assert_contains(&ports, &443);
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
            80,
            PortConfiguration::new(vec![Box::new(factory1), Box::new(factory2)], false),
        );
        subject
            .port_configurations
            .insert(443, PortConfiguration::new(vec![Box::new(factory3)], false));
        subject
            .port_configurations
            .insert(3456, PortConfiguration::new(vec![], true));

        let ports = subject.clandestine_ports();

        assert_eq!(ports.contains(&3456), true);
        assert_eq!(ports.len(), 1);
    }
}
