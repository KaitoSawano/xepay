// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Address derivation for XEPAY using ML-DSA-65 public keys.

use xepay_crypto::sha3_256_hex;

use crate::base58check;
use crate::bech32;
use crate::blockchain;

use super::PUBLIC_KEY_SIZE;

pub fn address_from_public_key(public_key: &[u8]) -> Result<String, String> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "public key must be {} bytes, got {}",
            PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }

    let payload = [public_key, b"addr"].concat();
    let hash_hex = sha3_256_hex(&payload);
    let hash_bytes = hex::decode(&hash_hex).expect("sha3 hex is always valid");
    let hash20 = &hash_bytes[..20];

    let prefix = blockchain::legacy_prefix_byte();
    let mut body = vec![prefix];
    body.extend_from_slice(hash20);

    Ok(base58check::encode(&body))
}

pub fn verify_legacy_address(address: &str) -> bool {
    let payload = match base58check::decode(address) {
        Some(p) => p,
        None => return false,
    };
    if payload.len() != 21 {
        return false;
    }
    let expected_prefix = blockchain::legacy_prefix_byte();
    payload[0] == expected_prefix
}

pub fn address_from_public_key_bech32(public_key: &[u8]) -> Result<String, String> {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return Err(format!(
            "public key must be {} bytes, got {}",
            PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }

    let payload = [public_key, b"addr"].concat();
    let hash_hex = sha3_256_hex(&payload);
    let hash_bytes = hex::decode(&hash_hex).expect("sha3 hex is always valid");
    let hash20 = &hash_bytes[..20];

    let hrp = blockchain::bech32_hrp();
    bech32::encode(hrp, hash20)
}

pub fn verify_bech32_address(address: &str) -> bool {
    let hrp = blockchain::bech32_hrp();
    match bech32::decode(address) {
        Some((decoded_hrp, _data)) => decoded_hrp == hrp,
        None => false,
    }
}
