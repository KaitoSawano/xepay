// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! ML-DSA-65 verification for XEPAY.

use ml_dsa::{MlDsa65, Signature, VerifyingKey, Verifier};

use super::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

/// Verify an ML-DSA-65 signature using only the public key.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_SIZE {
        return false;
    }
    if signature.len() != SIGNATURE_SIZE {
        return false;
    }

    let vk_encoded: [u8; PUBLIC_KEY_SIZE] = match public_key.try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };

    let vk = VerifyingKey::<MlDsa65>::decode(&vk_encoded.into());

    let sig_encoded: [u8; SIGNATURE_SIZE] = match signature.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let sig = match Signature::<MlDsa65>::try_from(&sig_encoded[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(message, &sig).is_ok()
}
