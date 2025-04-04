use crate::ip_country::DBIPParser;
use std::io;
use std::any::Any;
use std::net::IpAddr;
use maxminddb::{MaxMindDbError, Reader, Within, WithinItem};
use serde::Deserialize;
use crate::country_block_serde::{FinalBitQueue};
use crate::countries::Countries;
use maxminddb::geoip2::City;

pub fn factory<'de>() -> Box<dyn MmdbReaderWrapperFactory<'de>> {
    Box::new(MmdbReaderWrapperFactoryReal::new())
}

pub struct MMDBParser<'de> {
    factory: Box<dyn MmdbReaderWrapperFactory<'de>>,
}

impl DBIPParser for MMDBParser<'static> {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn parse(
        &self,
        _stdin: &mut dyn io::Read,
        _errors: &mut Vec<String>,
    ) -> (FinalBitQueue, FinalBitQueue, Countries) {
        todo!()
    }
}

impl<'de> MMDBParser<'de> {
    pub fn new() -> Self {
        // UNTESTED CODE
        MMDBParser::new_from_factory(factory())
    }

    fn new_from_factory(factory: Box<dyn MmdbReaderWrapperFactory<'de>>) -> MMDBParser<'de> {
        MMDBParser {
            factory,
        }
    }
}

trait WithinWrapper<'de>: Iterator<Item=Result<WithinItem<City<'de>>, MaxMindDbError>> {}

struct WithinWrapperReal<'de> {
    delegate: Within<'de, City<'de>, Vec<u8>>
}

impl<'de> WithinWrapper<'de> for WithinWrapperReal<'de> {}

impl<'de> Iterator for WithinWrapperReal<'de> {
    type Item = Result<WithinItem<City<'de>>, MaxMindDbError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.delegate.next()
    }
}

trait MmdbReaderWrapper<'de> {
    fn within(&'de self, cidr: ipnetwork::IpNetwork) -> 
        Result<Box<dyn WithinWrapper<Item=Result<WithinItem<City<'de>>, MaxMindDbError>> + 'de>, MaxMindDbError>;
}

struct MmdbReaderWrapperReal {
    delegate: Reader<Vec<u8>>
}

impl<'de> MmdbReaderWrapper<'de> for MmdbReaderWrapperReal {
    fn within(&'de self, cidr: ipnetwork::IpNetwork) -> 
        Result<
            Box<dyn WithinWrapper<Item=Result<WithinItem<City<'de>>, MaxMindDbError>> + 'de>,
            MaxMindDbError
        > {
        self.delegate.within(cidr).map (|within| {
            Box::new(WithinWrapperReal { delegate: within })
              as Box<dyn WithinWrapper<Item=Result<WithinItem<City<'de>>, MaxMindDbError>> + 'de>
        })
    }
}

impl<'de> MmdbReaderWrapperReal {
    pub fn from_source(buf: Vec<u8>) -> Result<MmdbReaderWrapperReal, MaxMindDbError> {
        let delegate = Reader::from_source(buf)?;
        Ok(Self { delegate })
    }
}

trait MmdbReaderWrapperFactory<'de> {
    fn make(
        &self,
        buf: Vec<u8>,
    ) -> Result<Box<dyn MmdbReaderWrapper<'de>>, MaxMindDbError>;
}

struct MmdbReaderWrapperFactoryReal {}

impl<'de> MmdbReaderWrapperFactory<'de> for MmdbReaderWrapperFactoryReal {
    fn make(
        &self,
        buf: Vec<u8>,
    ) -> Result<Box<dyn MmdbReaderWrapper<'de>>, MaxMindDbError> {
        Ok(Box::new(MmdbReaderWrapperReal::from_source(buf)?))
    }
}

impl MmdbReaderWrapperFactoryReal {
    pub fn new() -> MmdbReaderWrapperFactoryReal {
        MmdbReaderWrapperFactoryReal {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use ipnetwork::IpNetwork;
    use maxminddb::{MaxMindDbError, Within};
    use maxminddb::geoip2::city::Country;
    use test_utilities::byte_array_reader_writer::ByteArrayReader;
    use crate::ip_country_mmdb::{MmdbReaderWrapper, MmdbReaderWrapperFactory, MmdbReaderWrapperReal};

    struct WithinWrapperMock {
        iter: Box<dyn Iterator<Item=Result<WithinItem<City<'static>>, MaxMindDbError>>>
    }

    impl<'de> WithinWrapper<'de> for WithinWrapperMock {
    }

    impl<'de> Iterator for WithinWrapperMock {
        type Item = Result<WithinItem<City<'de>>, MaxMindDbError>;

        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next()
        }
    }

    impl WithinWrapperMock {
        pub fn new(results: Vec<Result<(IpNetwork, &'static str, &'static str), MaxMindDbError>>) -> Self {
            let items = results.into_iter()
                .map(|result| {
                    result.map(|item| {
                        let (ip_network, iso3166, name) = item;
                        Self::convert((ip_network, iso3166, name))
                    })
                })
                .collect::<Vec<_>>();
            Self { iter: Box::new(items.into_iter()) }
        }

        fn convert(item: (IpNetwork, &'static str, &'static str)) -> WithinItem<City<'static>> {
            let (ip_network, iso3166, name) = item;
            let mut names = BTreeMap::new();
            names.insert("en", name);
            let country = Country {
                geoname_id: None,
                is_in_european_union: None,
                iso_code: Some(iso3166),
                names: Some(names),
            };
            let city = City {
                city: None,
                continent: None,
                country: Some(country),
                location: None,
                postal: None,
                registered_country: None,
                represented_country: None,
                subdivisions: None,
                traits: None,
            };
            WithinItem {
                ip_net: ip_network,
                info: city,
            }
        }
    }

    struct MmdbReaderWrapperMock {
        within_params: Arc<Mutex<Vec<IpNetwork>>>,
        within_results: RefCell<Vec<Result<WithinWrapperMock, MaxMindDbError>>>
    }

    impl<'de> MmdbReaderWrapper<'de> for MmdbReaderWrapperMock {
        fn within(&'de self, cidr: IpNetwork) -> Result<
            Box<dyn WithinWrapper<Item=Result<
                WithinItem<City<'de>>,
                MaxMindDbError
            >> + 'de>,
            MaxMindDbError
        > {
            self.within_params.lock().unwrap().push(cidr);
            let result = self.within_results.borrow_mut().remove(0);
            result.map (|within_wrapper_mock|
                Box::new(within_wrapper_mock)
                    as Box<dyn WithinWrapper<Item=Result<WithinItem<City<'de>>, MaxMindDbError>> + 'de>
            )
        }
    }

    impl MmdbReaderWrapperMock {
        pub fn new() -> MmdbReaderWrapperMock {
            Self{
                within_params: Arc::new(Mutex::new(vec![])),
                within_results: RefCell::new(vec![]),
            }
        }

        pub fn within_params(mut self, params: &Arc<Mutex<Vec<IpNetwork>>>) -> Self {
            self.within_params = params.clone();
            self
        }

        pub fn within_result(mut self, result: Result<WithinWrapperMock, MaxMindDbError>) -> Self {
            self.within_results.borrow_mut().push(result);
            self
        }
    }

    struct MmdbReaderWrapperFactoryMock {
        make_params: Arc<Mutex<Vec<Vec<u8>>>>,
        make_results: RefCell<Vec<Result<MmdbReaderWrapperMock, MaxMindDbError>>>
    }

    impl<'de> MmdbReaderWrapperFactory<'de> for MmdbReaderWrapperFactoryMock {
        fn make(
            &self,
            buf: Vec<u8>,
        ) -> Result<Box<dyn MmdbReaderWrapper<'de>>, MaxMindDbError> {
            self.make_params.lock().unwrap().push(buf);
            self.make_results.borrow_mut().remove(0)
                .map(|x| Box::new(x) as Box<dyn MmdbReaderWrapper<'de>>)
        }
    }

    impl<'de> MmdbReaderWrapperFactoryMock {
        pub fn new() -> Self {
            Self{
                make_params: Arc::new(Mutex::new(vec![])),
                make_results: RefCell::new(vec![]),
            }
        }

        pub fn make_params(mut self, params: &Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
            self.make_params = params.clone();
            self
        }

        pub fn make_result(mut self, result: Result<MmdbReaderWrapperMock, MaxMindDbError>) -> Self {
            self.make_results.borrow_mut().push(result);
            self
        }
    }

    static FAKE_MMDB_DATA: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    /// Iterate over blocks of IP networks in the opened MaxMind DB
    ///
    /// Example:
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use maxminddb::{geoip2, Within};
    ///
    /// let reader = maxminddb::Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap();
    ///
    /// let ip_net = IpNetwork::V6("::/0".parse().unwrap());
    /// let mut iter: Within<geoip2::City, _> = reader.within(ip_net).unwrap();
    /// while let Some(next) = iter.next() {
    ///     let item = next.unwrap();
    ///     println!("ip_net={}, city={:?}", item.ip_net, item.info);
    /// }
    /// ```

    #[test]
    fn happy_path() {
        let within_params_arc = Arc::new(Mutex::new(vec![]));
        let reader = MmdbReaderWrapperMock::new()
            .within_params(&within_params_arc)
            .within_result(Ok(WithinWrapperMock::new(vec![
                Ok((IpNetwork::from_str("1.2.3.0/24").unwrap(), "CZ", "Czech Republic")),
                Ok((IpNetwork::from_str("3.2.1.0/24").unwrap(), "IN", "India")),
            ])))
            .within_result(Ok(WithinWrapperMock::new(vec![
                Ok((IpNetwork::from_str("1::2::3::0/120").unwrap(), "CZ", "Czech Republic")),
                Ok((IpNetwork::from_str("3::2::1::0/120").unwrap(), "IN", "India")),
            ])));
        let make_params_arc = Arc::new(Mutex::new(vec![]));
        let factory = MmdbReaderWrapperFactoryMock::new()
            .make_params(&make_params_arc)
            .make_result(Ok(reader));
        let subject = MMDBParser::new_from_factory(Box::new(factory));
        let mut stdin = ByteArrayReader::new(FAKE_MMDB_DATA);
        let mut errors = vec![];

        let (ipv4_bit_queue, ipv6_bit_queue, countries) =
            subject.parse(&mut stdin, &mut errors);

        let expected_errors: Vec<String> = vec![];
        assert_eq!(errors, expected_errors);
        let make_params = make_params_arc.lock().unwrap();
        assert_eq!(*make_params, vec![FAKE_MMDB_DATA.to_vec()]);
        let within_params = within_params_arc.lock().unwrap();
        assert_eq!(
            *within_params,
            vec![
                IpNetwork::new(IpAddr::from_str("0.0.0.0").unwrap(), 0).unwrap(),
                IpNetwork::new(IpAddr::from_str("::").unwrap(), 0).unwrap(),
            ]
        )
    }
}
