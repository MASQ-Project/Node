// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::TypeId;
use std::mem::transmute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Obfuscated {
    type_id: TypeId,
    bytes: Vec<u8>,
}

impl Obfuscated {
    // Although we're asking the compiler for a cast between two types
    // where one is generic and both could possibly be of a different
    // size, which almost applies to an unsupported kind of operation,
    // the compiler stays calm here. The use of vectors at the input as
    // well as output lets us avoid the above depicted situation.
    //
    // If you wish to write an implementation allowing more arbitrary
    // types on your own, instead of helping yourself by a library like
    // 'bytemuck', consider these functions from the std library,
    // 'mem::transmute_copy' or 'mem::forget()', which will renew
    // the compiler's trust for you. However, the true adventure will
    // begin when you are supposed to write code to realign the plain
    // bytes backwards to your desired type...

    pub fn obfuscate_vector<D: 'static>(data: Vec<D>) -> Obfuscated {
        let bytes = unsafe { transmute::<Vec<D>, Vec<u8>>(data) };

        Obfuscated {
            type_id: TypeId::of::<D>(),
            bytes,
        }
    }

    pub fn expose_vector<D: 'static>(self) -> Vec<D> {
        if self.type_id != TypeId::of::<D>() {
            panic!("Forbidden! You're trying to interpret obfuscated data as the wrong type.")
        }

        unsafe { transmute::<Vec<u8>, Vec<D>>(self.bytes) }
    }

    // Proper casting from a non vec structure into a vector of bytes
    // is difficult and ideally requires an involvement of a library
    // like bytemuck.
    // If you think we do need such cast, place other methods in here
    // and don't remove the ones above because:
    //    a) bytemuck will force you to implement its 'Pod' trait which
    //       might imply an (at minimum) ugly implementation for a std
    //       type like a Vec because both the trait and the type have
    //       their definitions situated externally to our project,
    //       therefore you might need to solve it by introducing
    //       a super-trait from our code
    //    b) using our simple 'obfuscate_vector' function will always
    //       be fairly more efficient than if done with help of
    //       the other library
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_works() {
        let data = vec!["I'm fearing of losing my entire identity".to_string()];

        let obfuscated_data = Obfuscated::obfuscate_vector(data.clone());
        let fenix_like_data: Vec<String> = obfuscated_data.expose_vector();

        assert_eq!(data, fenix_like_data)
    }

    #[test]
    #[should_panic(
        expected = "Forbidden! You're trying to interpret obfuscated data as the wrong type."
    )]
    fn obfuscation_attempt_to_reinterpret_to_wrong_type() {
        let data = vec![0_u64];
        let obfuscated_data = Obfuscated::obfuscate_vector(data.clone());
        let _: Vec<u128> = obfuscated_data.expose_vector();
    }
}
