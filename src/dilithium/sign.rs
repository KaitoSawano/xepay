// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! ML-DSA-65 signing for XEPAY.

use ml_dsa::{MlDsa65, SigningKey, Signer};

use super::SECRET_KEY_SIZE;

/// Sign a message with a 32-byte ML-DSA-65 seed.
pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != SECRET_KEY_SIZE {
        return Err(format!(
            "secret key must be {} bytes, got {}",
            SECRET_KEY_SIZE,
            secret_key.len()
        ));
    }

    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| "secret key must be exactly 32 bytes".to_string())?;

    let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
    let signature = sk.sign(message);

    Ok(signature.encode().to_vec())
}
