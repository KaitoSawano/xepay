// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Wallet representation and persistence.

use crate::datadir;
use crate::dilithium::{address, keypair::KeyPair};
use crate::utils::now_millis;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletEntry {
    pub address: String,
    pub public_key: String,
    pub secret: String,
    pub label: String,
    pub created_at: u128,
    /// Unique nonce for AES-GCM encryption of this entry's secret.
    /// This prevents nonce reuse across multiple encrypted entries.
    #[serde(default)]
    pub encryption_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub entries: Vec<WalletEntry>,
    pub created_at: u128,
    pub encrypted: bool,
    pub salt: String,
    pub nonce: String, // Legacy field, kept for backward compatibility
    /// Cached password for re-encryption during the current session.
    /// This is never serialized to disk.
    #[serde(skip)]
    pub cached_password: Option<String>,
}

impl Wallet {
    pub fn new() -> Self {
        let mut w = Wallet {
            entries: Vec::new(),
            created_at: now_millis(),
            encrypted: false,
            salt: String::new(),
            nonce: String::new(),
            cached_password: None,
        };
        w.add_new_address("default".to_string());
        w
    }

    pub fn add_new_address(&mut self, label: String) -> String {
        let kp = KeyPair::generate().expect("keypair generation failed");
        let addr =
            address::address_from_public_key(&kp.public_key).expect("address generation failed");

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

    pub fn get_entry(&self, addr: &str) -> Option<&WalletEntry> {
        self.entries.iter().find(|e| e.address == addr)
    }

    pub fn default_address(&self) -> Option<&WalletEntry> {
        self.entries.last()
    }

    pub fn from_secret(secret_hex: &str, label: String) -> Result<WalletEntry, String> {
        let bytes = hex::decode(secret_hex).map_err(|e| e.to_string())?;
        let kp = KeyPair::from_secret(&bytes)?;
        let addr = address::address_from_public_key(&kp.public_key)?;

        Ok(WalletEntry {
            address: addr,
            public_key: kp.public_key_hex(),
            secret: kp.secret_key_hex(),
            label,
            created_at: now_millis(),
            encryption_nonce: String::new(),
        })
    }

    pub fn save_default(&self) -> std::io::Result<()> {
        datadir::ensure_dirs()?;
        self.save(&datadir::as_str(&datadir::wallet_path()))
    }

    pub fn load_default() -> std::io::Result<Self> {
        Self::load(&datadir::as_str(&datadir::wallet_path()))
    }

    pub fn exists_default() -> bool {
        datadir::wallet_path().exists()
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut to_save = self.clone();
        
        // If the wallet was previously encrypted and is currently decrypted in memory,
        // we must re-encrypt it before saving to prevent plaintext secret leakage.
        if !to_save.encrypted && to_save.cached_password.is_some() {
            let pass = to_save.cached_password.clone().unwrap();
            to_save.re_encrypt_internal(&pass)
                .map_err(|e| std::io::Error::other(format!("re-encryption failed: {}", e)))?;
        } else {
            // Ensure the cached password is never serialized to disk.
            to_save.cached_password = None;
        }

        let json = serde_json::to_string_pretty(&to_save).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    pub fn load(path: &str) -> std::io::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let mut w: Wallet = serde_json::from_str(&data).map_err(std::io::Error::other)?;
        w.cached_password = None; // Clear on load
        Ok(w)
    }

    pub fn encrypt(&mut self, password: &str) -> Result<(), String> {
        if self.encrypted {
            return Err("wallet is already encrypted".into());
        }
        if password.is_empty() {
            return Err("password must not be empty".into());
        }

        let salt = crate::utils::random_hex(16);
        let key = xepay_crypto::derive_key(password, &salt);

        for entry in self.entries.iter_mut() {
            // Generate a unique nonce for each entry to prevent nonce reuse.
            let entry_nonce_hex = crate::utils::random_hex(12);
            let nonce = crate::utils::hex_to_bytes(&entry_nonce_hex)?;

            let ciphertext = xepay_crypto::aes_encrypt(&key, &nonce, &entry.secret)?;
            entry.secret = ciphertext;
            entry.encryption_nonce = entry_nonce_hex;
        }

        self.encrypted = true;
        self.salt = salt;
        self.nonce = String::new(); // Clear legacy global nonce
        self.cached_password = Some(password.to_string());

        Ok(())
    }

    fn re_encrypt_internal(&mut self, password: &str) -> Result<(), String> {
        if self.encrypted {
            return Ok(());
        }

        let salt = crate::utils::random_hex(16);
        let key = xepay_crypto::derive_key(password, &salt);

        for entry in self.entries.iter_mut() {
            let entry_nonce_hex = crate::utils::random_hex(12);
            let nonce = crate::utils::hex_to_bytes(&entry_nonce_hex)?;

            let ciphertext = xepay_crypto::aes_encrypt(&key, &nonce, &entry.secret)?;
            entry.secret = ciphertext;
            entry.encryption_nonce = entry_nonce_hex;
        }

        self.encrypted = true;
        self.salt = salt;
        self.nonce = String::new();
        self.cached_password = Some(password.to_string());

        Ok(())
    }

    pub fn decrypt(&self, password: &str) -> Result<Wallet, String> {
        if !self.encrypted {
            return Ok(self.clone());
        }

        let key = xepay_crypto::derive_key(password, &self.salt);
        let mut decrypted = self.clone();

        for entry in decrypted.entries.iter_mut() {
            // Use the per-entry nonce. Fallback to the legacy global nonce
            // for wallets created before this fix.
            let nonce_hex = if entry.encryption_nonce.is_empty() {
                &self.nonce
            } else {
                &entry.encryption_nonce
            };

            let nonce = crate::utils::hex_to_bytes(nonce_hex)?;
            // FIX BUG AP: Validate nonce length to prevent AES-GCM panic.
            if nonce.len() != 12 {
                return Err(format!("invalid nonce length for address {}", entry.address));
            }

            let plaintext = xepay_crypto::aes_decrypt(&key, &nonce, &entry.secret)?;
            entry.secret = plaintext;
        }

        decrypted.encrypted = false;
        decrypted.cached_password = Some(password.to_string());
        Ok(decrypted)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}
