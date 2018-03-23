// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.
use sub_lib::dispatcher::Component;
use masquerader::Masquerader;
use discriminator::UnmaskedChunk;
use masquerader::MasqueradeError;

pub struct NullMasquerader {
    component: Component
}

impl Masquerader for NullMasquerader {
    fn try_unmask(&self, item: &[u8]) -> Option<UnmaskedChunk> {
        Some (UnmaskedChunk::new (Vec::from (item), self.component, true))
    }

    fn mask(&self, _component: Component, _data: &[u8]) -> Result<Vec<u8>, MasqueradeError> {
        unimplemented!()
    }
}

impl NullMasquerader {
    pub fn new (component: Component) -> NullMasquerader {
        NullMasquerader {
            component
        }
    }
}

#[cfg (test)]
mod tests {
    use super::*;

    #[test]
    fn try_unmask_returns_input_data_with_specified_component () {
        let data = "booga".as_bytes ();
        let subject = NullMasquerader::new (Component::Hopper);

        let result = subject.try_unmask (data).unwrap ();

        assert_eq! (result, UnmaskedChunk::new (Vec::from (data), Component::Hopper, true));
    }
}
