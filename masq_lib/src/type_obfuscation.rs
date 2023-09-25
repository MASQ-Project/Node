// Copyright (c) 2019, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use std::any::TypeId;
use std::mem::transmute;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Obfuscated {
    type_id: TypeId,
    bytes: Vec<u8>,
}

impl Obfuscated {
    // We don't irritate the compiler because of asking for a cast between
    // two types with one being generic where they could possibly be of
    // different sizes. It's an issue in our implementation. The use of
    // vectors at the input as well as output lets us avoid the situation.
    // If you wish to write a more complicated implementation instead of
    // using a library like 'bytemuck' consider functions like
    // 'mem::transmute_copy' or 'mem::forget()' which will help you earn
    // the compiler's trust but then the adventure begins when you are
    // supposed to write the code to realign the plain bytes back to
    // your desired type...

    pub fn obfuscate_vector<D: 'static>(data: Vec<D>) -> Obfuscated {
        let bytes = unsafe { transmute::<Vec<D>, Vec<u8>>(data) };

        Obfuscated {
            type_id: TypeId::of::<D>(),
            bytes,
        }
    }

    pub fn expose_vector<D: 'static>(self) -> Vec<D> {
        if self.type_id != TypeId::of::<D>() {
            panic!("Forbidden! You're trying to interpret obfuscated type A as type B")
        }

        unsafe { transmute::<Vec<u8>, Vec<D>>(self.bytes) }
    }

    // Proper casting from a non vec structure into a vector of bytes
    // is difficult and ideally requires an involvement of a library
    // like bytemuck
    // If you think we do need such cast, place other methods in here
    // and don't remove the ones above because:
    //    a) bytemuck will force you implement its 'Pod' trait which
    //       might implementation for a std type like a Vec (minimally)
    //       ugly because both the trait and the type are defined
    //       externally to our project, therefore you might make it work
    //       via introducing a super-trait defined in our code
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
    #[should_panic(expected = "Forbidden! You're trying to interpret obfuscated type A as type B")]
    fn obfuscation_attempt_to_reinterpret_to_wrong_type() {
        let data = vec![0_u64];
        let obfuscated_data = Obfuscated::obfuscate_vector(data.clone());
        let _: Vec<u128> = obfuscated_data.expose_vector();
    }
}
