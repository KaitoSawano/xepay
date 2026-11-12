// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! ML-DSA-65 key pair generation and reconstruction.

use ml_dsa::{Generate, Keypair, MlDsa65, SigningKey};

use super::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};

/// An ML-DSA-65 key pair.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a new key pair using the operating system random number generator.
    pub fn generate() -> Result<Self, String> {
        let sk = SigningKey::<MlDsa65>::generate();
        let vk = sk.verifying_key();

        let secret_key = sk.as_seed().to_vec();
        let public_key = vk.encode().to_vec();

        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(format!(
                "unexpected public key size: got {}, expected {}",
                public_key.len(),
                PUBLIC_KEY_SIZE
            ));
        }
        if secret_key.len() != SECRET_KEY_SIZE {
            return Err(format!(
                "unexpected secret key size: got {}, expected {}",
                secret_key.len(),
                SECRET_KEY_SIZE
            ));
        }

        Ok(KeyPair {
            public_key,
            secret_key,
        })
    }

    /// Reconstruct a key pair from a 32-byte seed.
    pub fn from_secret(secret_bytes: &[u8]) -> Result<Self, String> {
        if secret_bytes.len() != SECRET_KEY_SIZE {
            return Err(format!(
                "secret key must be {} bytes, got {}",
                SECRET_KEY_SIZE,
                secret_bytes.len()
            ));
        }

        let seed: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| "secret key must be exactly 32 bytes".to_string())?;

        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let vk = sk.verifying_key();

        Ok(KeyPair {
            public_key: vk.encode().to_vec(),
            secret_key: secret_bytes.to_vec(),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    pub fn secret_key_hex(&self) -> String {
        hex::encode(&self.secret_key)
    }
}
