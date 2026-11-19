// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Wallet management for XEPAY.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::datadir;
use crate::dilithium::address;
use crate::dilithium::keypair::KeyPair;
use crate::utils::now_millis;
use xepay_crypto::encryption;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEntry {
    pub address: String,
    pub public_key: String,
    pub secret: String,
    pub label: String,
    pub created_at: u128,
    pub encryption_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub entries: Vec<WalletEntry>,
    pub created_at: u128,
    pub encrypted: bool,
    pub salt: String,
    pub nonce: String,
    pub cached_password: Option<String>,
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            entries: Vec::new(),
            created_at: now_millis(),
            encrypted: false,
            salt: String::new(),
            nonce: String::new(),
            cached_password: None,
        }
    }

    pub fn load_default() -> Result<Self, String> {
        let path = datadir::wallet_path();
        Self::load_from(&path)
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&data).map_err(|e| e.to_string())
    }

    pub fn save_default(&self) -> Result<(), String> {
        let path = datadir::wallet_path();
        self.save_to(&path)
    }

    /// Persist the wallet to disk.
    ///
    /// The wallet is always written in encrypted form when a password is
    /// available, either because the wallet is already encrypted or
    /// because the caller decrypted it and kept the password in
    /// `cached_password`. Writing the decrypted form back to disk would
    /// leak every private key in plaintext, which is exactly the bug this
    /// function used to have. A wallet that was never encrypted and has
    /// no cached password is written as-is so that the normal
    /// unencrypted development workflow keeps working.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        if self.encrypted || self.cached_password.is_some() {
            let password = match &self.cached_password {
                Some(p) => p.clone(),
                None => return Err("wallet is encrypted but no password is cached".into()),
            };
            let encrypted = self.to_encrypted(&password)?;
            let data = serde_json::to_string_pretty(&encrypted).map_err(|e| e.to_string())?;
            std::fs::write(path, data).map_err(|e| e.to_string())
        } else {
            let data = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
            std::fs::write(path, data).map_err(|e| e.to_string())
        }
    }

    /// Produce a copy of the wallet whose entries are encrypted with the
    /// given password. If the wallet is already encrypted, the existing
    /// salt and nonce are reused so that re-saving does not change the
    /// on-disk representation of an unchanged wallet.
    fn to_encrypted(&self, password: &str) -> Result<Wallet, String> {
        if self.encrypted {
            return Ok(self.clone());
        }

        let salt = if self.salt.is_empty() {
            crate::utils::random_hex(16)
        } else {
            self.salt.clone()
        };
        let nonce = if self.nonce.is_empty() {
            crate::utils::random_hex(12)
        } else {
            self.nonce.clone()
        };

        let key = encryption::derive_key(password, &salt);
        let nonce_bytes = hex::decode(&nonce).map_err(|e| e.to_string())?;

        let mut encrypted_entries = Vec::new();
        for entry in &self.entries {
            let plaintext = serde_json::to_string(entry).map_err(|e| e.to_string())?;
            let ciphertext = encryption::aes_encrypt(&key, &nonce_bytes, &plaintext)?;
            let enc_entry = WalletEntry {
                address: entry.address.clone(),
                public_key: entry.public_key.clone(),
                secret: ciphertext,
                label: entry.label.clone(),
                created_at: entry.created_at,
                encryption_nonce: nonce.clone(),
            };
            encrypted_entries.push(enc_entry);
        }

        Ok(Wallet {
            entries: encrypted_entries,
            created_at: self.created_at,
            encrypted: true,
            salt,
            nonce,
            cached_password: Some(password.to_string()),
        })
    }

    pub fn add_new_address(&mut self, label: String) -> String {
        let kp = KeyPair::generate().expect("keypair generation failed");
        let addr = address::address_from_public_key(&kp.public_key)
            .expect("address generation failed");

        let entry = WalletEntry {
            address: addr.clone(),
            public_key: kp.public_key_hex(),
            secret: kp.secret_key_hex(),
            label,
            created_at: now_millis(),
            encryption_nonce: String::new(),
        };
        self.entries.push(entry);
        addr
    }

    pub fn get_entry(&self, address: &str) -> Option<&WalletEntry> {
        self.entries.iter().find(|e| e.address == address)
    }

    pub fn get_entry_mut(&mut self, address: &str) -> Option<&mut WalletEntry> {
        self.entries.iter_mut().find(|e| e.address == address)
    }

    pub fn default_address(&self) -> Option<&WalletEntry> {
        self.entries.first()
    }

    pub fn encrypt(&mut self, password: &str) -> Result<(), String> {
        if self.encrypted {
            return Err("wallet is already encrypted".into());
        }

        let salt = crate::utils::random_hex(16);
        let key = encryption::derive_key(password, &salt);
        let nonce = crate::utils::random_hex(12);
        let nonce_bytes = hex::decode(&nonce).map_err(|e| e.to_string())?;

        let mut encrypted_entries = Vec::new();
        for entry in &self.entries {
            let plaintext = serde_json::to_string(entry).map_err(|e| e.to_string())?;
            let ciphertext = encryption::aes_encrypt(&key, &nonce_bytes, &plaintext)?;
            let enc_entry = WalletEntry {
                address: entry.address.clone(),
                public_key: entry.public_key.clone(),
                secret: ciphertext,
                label: entry.label.clone(),
                created_at: entry.created_at,
                encryption_nonce: nonce.clone(),
            };
            encrypted_entries.push(enc_entry);
        }

        self.entries = encrypted_entries;
        self.encrypted = true;
        self.salt = salt;
        self.nonce = nonce;
        self.cached_password = Some(password.to_string());

        Ok(())
    }

    pub fn decrypt(&self, password: &str) -> Result<Wallet, String> {
        if !self.encrypted {
            return Ok(self.clone());
        }

        let key = encryption::derive_key(password, &self.salt);

        let mut decrypted_entries = Vec::new();
        for entry in &self.entries {
            let nonce_bytes = hex::decode(&entry.encryption_nonce).map_err(|e| e.to_string())?;
            let plaintext = encryption::aes_decrypt(&key, &nonce_bytes, &entry.secret)?;
            let dec_entry: WalletEntry =
                serde_json::from_str(&plaintext).map_err(|e| e.to_string())?;
            decrypted_entries.push(dec_entry);
        }

        let w = Wallet {
            entries: decrypted_entries,
            created_at: self.created_at,
            encrypted: false,
            salt: self.salt.clone(),
            nonce: self.nonce.clone(),
            cached_password: Some(password.to_string()),
        };
        Ok(w)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}
