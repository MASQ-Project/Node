// Copyright (c) 2019-2021, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.

use crate::sub_lib::wallet::Wallet;
use ethereum_types::{Address, U256};
use ethsign::Signature;
use ethsign_crypto::Keccak256;
use rlp::RlpStream;
use serde_derive::{Deserialize, Serialize};

/// Description of a Transaction, pending or in the chain.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct RawTransaction {
    /// Nonce
    pub nonce: U256,
    /// Recipient (None when contract creation)
    pub to: Option<Address>,
    /// Transfered value
    pub value: U256,
    /// Gas Price
    #[serde(rename = "gasPrice")]
    pub gas_price: U256,
    /// Gas limit
    #[serde(rename = "gasLimit")]
    pub gas_limit: U256,
    /// Input data
    pub data: Vec<u8>,
}

impl RawTransaction {
    /// Signs and returns the RLP-encoded transaction
    pub fn sign(&self, wallet: &Wallet, chain_id: u8) -> Vec<u8> {
        let hash = self.tx_hash(chain_id);
        let sig = ecdsa_sign(&hash, wallet, chain_id);
        let mut tx = RlpStream::new();
        tx.begin_unbounded_list();
        self.encode(&mut tx);
        tx.append(&sig.v);
        tx.append(&sig.r.to_vec());
        tx.append(&sig.s.to_vec());
        tx.finalize_unbounded_list();
        tx.out()
    }

    fn tx_hash(&self, chain_id: u8) -> Vec<u8> {
        let mut hash = RlpStream::new();
        hash.begin_unbounded_list();
        self.encode(&mut hash);
        hash.append(&vec![chain_id]);
        hash.append(&U256::zero());
        hash.append(&U256::zero());
        hash.finalize_unbounded_list();
        hash.out().keccak256().to_vec()
    }

    fn encode(&self, s: &mut RlpStream) {
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        if let Some(ref t) = self.to {
            s.append(t);
        } else {
            s.append(&vec![]);
        }
        s.append(&self.value);
        s.append(&self.data);
    }
}

fn ecdsa_sign(hash: &dyn AsRef<[u8]>, wallet: &Wallet, chain_id: u8) -> Signature {
    match wallet.sign(&hash) {
        Ok(s) => Signature {
            v: s.v + chain_id * 2 + 35,
            r: s.r,
            s: s.s,
        },
        Err(e) => panic!("{:?}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockchain::bip32::Bip32ECKeyPair;
    use ethereum_types::H256;

    #[derive(Deserialize)]
    struct Signing {
        signed: Vec<u8>,
        private_key: H256,
    }

    #[test]
    fn test_signs_transaction_eth() {
        let text_txs_json = String::from(
            r#"[
        [{"nonce": "0x9", "gasPrice": "0x4a817c800", "gasLimit": "0x5208", "to": "0x3535353535353535353535353535353535353535", "value": "0xde0b6b3a7640000", "data": []}, {"private_key": "0x4646464646464646464646464646464646464646464646464646464646464646", "signed": [248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167, 100, 0, 0, 128, 35, 160, 252, 75, 179, 203, 183, 59, 165, 78, 216, 79, 250, 46, 27, 53, 141, 53, 71, 132, 114, 169, 103, 15, 101, 139, 140, 214, 133, 0, 170, 80, 209, 236, 160, 81, 184, 225, 44, 42, 86, 48, 109, 196, 39, 204, 47, 83, 131, 165, 30, 237, 232, 212, 226, 240, 55, 205, 178, 224, 31, 146, 171, 253, 114, 30, 153]}],
        [{"nonce": "0x0", "gasPrice": "0xd55698372431", "gasLimit": "0x1e8480", "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": "0x3b9aca00", "data": []}, {"private_key": "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "signed": [248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159, 200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132, 59, 154, 202, 0, 128, 36, 160, 31, 49, 247, 117, 12, 212, 195, 73, 65, 180, 66, 235, 204, 17, 5, 190, 206, 237, 4, 251, 252, 220, 98, 140, 158, 123, 88, 213, 236, 183, 123, 207, 160, 76, 250, 11, 158, 106, 231, 225, 132, 153, 116, 74, 72, 201, 5, 6, 41, 120, 123, 163, 168, 103, 139, 244, 14, 54, 58, 95, 169, 4, 216, 60, 223]}],
        [{"nonce": "0x00", "gasPrice": "0x09184e72a000", "gasLimit": "0x2710", "to": null, "value": "0x00", "data": [127,116,101,115,116,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,87]}, {"private_key": "0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109", "signed": [248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116, 101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 87, 35, 160, 99, 229, 207, 38, 9, 40, 235, 251, 58, 38, 122, 27, 101, 74, 188, 18, 248, 108, 128, 212, 42, 104, 80, 218, 83, 23, 60, 148, 97, 133, 80, 171, 160, 7, 89, 31, 205, 153, 45, 102, 65, 227, 88, 38, 123, 123, 62, 50, 233, 78, 106, 125, 110, 44, 34, 219, 3, 240, 237, 125, 45, 220, 105, 77, 234]}]
        ]"#,
        );

        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&text_txs_json).unwrap();
        let chain_id = 0u8;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(
                signed.signed,
                tx.sign(
                    &Wallet::from(
                        Bip32ECKeyPair::from_raw_secret(&signed.private_key.0.as_ref()).unwrap()
                    ),
                    chain_id
                )
            );
        }
    }

    #[test]
    fn test_signs_transaction_ropsten() {
        let text_txs_json = String::from(
            r#"[
        [{"nonce": "0x9", "gasPrice": "0x4a817c800", "gasLimit": "0x5208", "to": "0x3535353535353535353535353535353535353535", "value": "0xde0b6b3a7640000", "data": []}, {"private_key": "0x4646464646464646464646464646464646464646464646464646464646464646", "signed": [248, 108, 9, 133, 4, 168, 23, 200, 0, 130, 82, 8, 148, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 136, 13, 224, 182, 179, 167, 100, 0, 0, 128, 41, 160, 8, 220, 80, 201, 100, 41, 178, 35, 151, 227, 210, 85, 27, 41, 27, 82, 217, 176, 64, 92, 205, 10, 195, 169, 66, 91, 213, 199, 124, 52, 3, 192, 160, 94, 220, 102, 179, 128, 78, 150, 78, 230, 117, 10, 10, 32, 108, 241, 50, 19, 148, 198, 6, 147, 110, 175, 70, 157, 72, 31, 216, 193, 229, 151, 115]}],
        [{"nonce": "0x0", "gasPrice": "0xd55698372431", "gasLimit": "0x1e8480", "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", "value": "0x3b9aca00", "data": []}, {"private_key": "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", "signed": [248, 106, 128, 134, 213, 86, 152, 55, 36, 49, 131, 30, 132, 128, 148, 240, 16, 159, 200, 223, 40, 48, 39, 182, 40, 92, 200, 137, 245, 170, 98, 78, 172, 31, 85, 132, 59, 154, 202, 0, 128, 41, 160, 186, 65, 161, 205, 173, 93, 185, 43, 220, 161, 63, 65, 19, 229, 65, 186, 247, 197, 132, 141, 184, 196, 6, 117, 225, 181, 8, 81, 198, 102, 150, 198, 160, 112, 126, 42, 201, 234, 236, 168, 183, 30, 214, 145, 115, 201, 45, 191, 46, 3, 113, 53, 80, 203, 164, 210, 112, 42, 182, 136, 223, 125, 232, 21, 205]}],
        [{"nonce": "0x00", "gasPrice": "0x09184e72a000", "gasLimit": "0x2710", "to": null, "value": "0x00", "data": [127,116,101,115,116,50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,96,0,87]}, {"private_key": "0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109", "signed": [248, 117, 128, 134, 9, 24, 78, 114, 160, 0, 130, 39, 16, 128, 128, 164, 127, 116, 101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 0, 87, 41, 160, 146, 204, 57, 32, 218, 236, 59, 94, 106, 72, 174, 211, 223, 160, 122, 186, 126, 44, 200, 41, 222, 117, 117, 177, 189, 78, 203, 8, 172, 155, 219, 66, 160, 83, 82, 37, 6, 243, 61, 188, 102, 176, 132, 102, 74, 111, 180, 105, 33, 122, 106, 109, 73, 180, 65, 10, 117, 175, 190, 19, 196, 17, 128, 193, 75]}]
        ]"#,
        );

        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&text_txs_json).unwrap();
        let chain_id = 3u8;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(
                signed.signed,
                tx.sign(
                    &Wallet::from(
                        Bip32ECKeyPair::from_raw_secret(&signed.private_key.0.as_ref()).unwrap()
                    ),
                    chain_id
                )
            );
        }
    }

    #[test]
    fn test_transfer_transaction_signing_ropsten() {
        let txt_txs_json = String::from(
            r#"[
            [{"nonce":"0x00","gasPrice":"0x3b9aca00","gasLimit":"0x0f4240","to":"0xcd6C588E005032dd882CD43Bf53a32129BE81302","value":"0x00","data":[169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]}, {"private_key": "0x0fde24c464a9c55a83a164ec8f31888921549da2401a1af3cd79cccf5685421a", "signed": [248, 169, 128, 132, 59, 154, 202, 0, 131, 15, 66, 64, 148, 205, 108, 88, 142, 0, 80, 50, 221, 136, 44, 212, 59, 245, 58, 50, 18, 155, 232, 19, 2, 128, 184, 68, 169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 42, 160, 240, 147, 168, 58, 164, 16, 163, 171, 215, 39, 218, 5, 142, 236, 21, 21, 19, 126, 12, 160, 18, 49, 170, 75, 235, 248, 227, 239, 20, 86, 33, 188, 160, 23, 6, 133, 51, 6, 58, 162, 253, 93, 24, 232, 166, 152, 21, 78, 149, 194, 85, 96, 75, 208, 248, 164, 139, 100, 126, 89, 105, 31, 33, 123, 31]}],
            [{"nonce":"0x00","gasPrice":"0x3b9aca00","gasLimit":"0x2dc6c0","to":"0xcd6C588E005032dd882CD43Bf53a32129BE81302","value":"0x00","data":[169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]}, {"private_key": "0x0fde24c464a9c55a83a164ec8f31888921549da2401a1af3cd79cccf5685421a", "signed": [248, 169, 128, 132, 59, 154, 202, 0, 131, 45, 198, 192, 148, 205, 108, 88, 142, 0, 80, 50, 221, 136, 44, 212, 59, 245, 58, 50, 18, 155, 232, 19, 2, 128, 184, 68, 169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 42, 160, 127, 123, 199, 240, 47, 239, 91, 20, 9, 5, 106, 179, 193, 5, 38, 243, 206, 162, 81, 140, 208, 17, 168, 105, 34, 90, 187, 113, 173, 121, 132, 37, 160, 79, 58, 225, 10, 3, 129, 227, 67, 219, 124, 112, 145, 94, 6, 46, 141, 12, 43, 41, 151, 122, 108, 77, 116, 206, 221, 86, 13, 75, 188, 162, 92]}]
        ]"#,
        );

        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&txt_txs_json).unwrap();
        let chain_id = 3u8;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(
                signed.signed,
                tx.sign(
                    &Wallet::from(
                        Bip32ECKeyPair::from_raw_secret(&signed.private_key.0.as_ref()).unwrap()
                    ),
                    chain_id
                )
            );
        }
    }

    #[test]
    fn test_transfer_transaction_signing_mainnet() {
        let txt_txs_json = String::from(
            r#"[
            [{"nonce":"0x00","gasPrice":"0x04a817c800","gasLimit":"0x0493e0","to":"0x8D75959f1E61EC2571aa72798237101F084DE63a","value":"0x00","data":[169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]}, {"private_key": "0x0fde24c464a9c55a83a164ec8f31888921549da2401a1af3cd79cccf5685421a", "signed": [248, 170, 128, 133, 4, 168, 23, 200, 0, 131, 4, 147, 224, 148, 141, 117, 149, 159, 30, 97, 236, 37, 113, 170, 114, 121, 130, 55, 16, 31, 8, 77, 230, 58, 128, 184, 68, 169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 38, 160, 119, 24, 174, 4, 103, 214, 218, 90, 184, 161, 214, 158, 165, 39, 8, 11, 37, 217, 24, 255, 239, 78, 217, 209, 140, 98, 207, 177, 97, 198, 80, 234, 160, 33, 134, 61, 21, 44, 79, 23, 207, 118, 217, 252, 231, 11, 189, 118, 184, 156, 79, 171, 157, 171, 131, 143, 129, 129, 42, 104, 0, 48, 52, 247, 151]}],
            [{"nonce":"0x00","gasPrice":"0x9502F9000","gasLimit":"0xd431","to":"0x8D75959f1E61EC2571aa72798237101F084DE63a","value":"0x00","data":[169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]}, {"private_key": "0x0fde24c464a9c55a83a164ec8f31888921549da2401a1af3cd79cccf5685421a", "signed": [248, 169, 128, 133, 9, 80, 47, 144, 0, 130, 212, 49, 148, 141, 117, 149, 159, 30, 97, 236, 37, 113, 170, 114, 121, 130, 55, 16, 31, 8, 77, 230, 58, 128, 184, 68, 169, 5, 156, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 251, 134, 113, 219, 131, 0, 141, 56, 44, 46, 110, 166, 127, 163, 119, 55, 140, 12, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 38, 160, 9, 76, 204, 226, 14, 222, 72, 191, 217, 123, 150, 248, 98, 19, 182, 77, 179, 166, 231, 200, 31, 115, 239, 198, 179, 124, 115, 215, 74, 233, 208, 49, 160, 38, 52, 5, 216, 214, 17, 19, 130, 39, 94, 105, 1, 220, 10, 64, 176, 57, 13, 147, 74, 219, 228, 63, 240, 94, 161, 108, 181, 87, 185, 237, 207]}]
        ]"#,
        );

        let txs: Vec<(RawTransaction, Signing)> = serde_json::from_str(&txt_txs_json).unwrap();
        let chain_id = 1u8;
        for (tx, signed) in txs.into_iter() {
            assert_eq!(
                signed.signed,
                tx.sign(
                    &Wallet::from(
                        Bip32ECKeyPair::from_raw_secret(&signed.private_key.0.as_ref()).unwrap()
                    ),
                    chain_id
                )
            );
        }
    }
}
