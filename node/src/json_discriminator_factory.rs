// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
use crate::discriminator::Discriminator;
use crate::discriminator::DiscriminatorFactory;
use crate::json_framer::JsonFramer;
use crate::json_masquerader::JsonMasquerader;

#[derive(Debug, Default)]
pub struct JsonDiscriminatorFactory {}

impl DiscriminatorFactory for JsonDiscriminatorFactory {
    fn make(&self) -> Discriminator {
        Discriminator::new(
            Box::new(JsonFramer::new()),
            vec![Box::new(JsonMasquerader::new())],
        )
    }

    fn duplicate(&self) -> Box<dyn DiscriminatorFactory> {
        Box::new(JsonDiscriminatorFactory {})
    }
}

impl JsonDiscriminatorFactory {
    pub fn new() -> JsonDiscriminatorFactory {
        JsonDiscriminatorFactory {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discriminator::UnmaskedChunk;
    use crate::masquerader::Masquerader;

    #[test]
    fn discriminator_factory_duplicate_works() {
        let subject = JsonDiscriminatorFactory::new();

        subject.duplicate();

        // no panic; test passes
    }

    #[test]
    fn factory_makes_discriminator_that_ignores_non_json_data() {
        let data = &b"I am not JSON!"[..];
        let subject = JsonDiscriminatorFactory::new();
        let mut discriminator = subject.make();

        discriminator.add_data(data);
        let result = discriminator.take_chunk();

        assert_eq!(result, None)
    }

    #[test]
    fn factory_makes_discriminator_that_unmasks_json_data() {
        let data = &b"I am contained in JSON!"[..];
        let masquerader = JsonMasquerader::new();
        let json = masquerader.mask(data).unwrap();
        let subject = JsonDiscriminatorFactory::new();
        let mut discriminator = subject.make();

        discriminator.add_data(&json[..]);
        let result = discriminator.take_chunk();

        assert_eq!(result, Some(UnmaskedChunk::new(data.to_vec(), true, false)))
    }
}
