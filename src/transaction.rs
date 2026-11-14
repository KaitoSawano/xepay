// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Account-based transaction model with per-address nonces.

use serde::{Deserialize, Serialize};
use xepay_crypto::sha3_256_hex;

use crate::consensus::rules;
use crate::consensus::spec;
use crate::dilithium::address;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub note: String,
    /// Raw ML-DSA-65 public key (1952 bytes). Stored as bytes, not hex,
    /// so the transaction size is not doubled by hex encoding.
    #[serde(default)]
    pub public_key: Vec<u8>,
    /// Raw ML-DSA-65 signature (3309 bytes). Stored as bytes, not hex.
    #[serde(default)]
    pub signature: Vec<u8>,
    pub output_script: String,
}

impl Transaction {
    pub fn new(from: &str, to: &str, amount: u64, fee: u64, nonce: u64) -> Self {
        Self::new_with_note(from, to, amount, fee, nonce, String::new())
    }

    pub fn new_with_note(
        from: &str,
        to: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
        note: String,
    ) -> Self {
        Self {
            txid: String::new(),
            from: from.into(),
            to: to.into(),
            amount,
            fee,
            nonce,
            note,
            public_key: Vec::new(),
            signature: Vec::new(),
            output_script: String::new(),
        }
        .finalize()
    }

    /// Create a transaction that carries an on-chain message.
    ///
    /// The transaction is a self-send (from == to) with a minimal amount
    /// so that the value is returned to the sender, mirroring the OP_RETURN
    /// convention. The message is stored in the `note` field prefixed with
    /// `[MSG]` followed by a hex-encoded payload.
    pub fn new_message(
        sender: &str,
        fee: u64,
        nonce: u64,
        message: &str,
    ) -> Result<Self, String> {
        if message.is_empty() {
            return Err("message must not be empty".into());
        }
        if message.len() > rules::MAX_MESSAGE_LEN {
            return Err(format!(
                "message exceeds {} bytes",
                rules::MAX_MESSAGE_LEN
            ));
        }

        let hex_payload = hex::encode(message.as_bytes());
        let note = format!("{}{}", rules::MESSAGE_PREFIX, hex_payload);

        if note.len() > rules::MAX_NOTE_LEN {
            return Err("encoded message exceeds note size limit".into());
        }

        Ok(Self::new_with_note(
            sender,
            sender,
            rules::MIN_MESSAGE_AMOUNT,
            fee,
            nonce,
            note,
        ))
    }

    fn finalize(mut self) -> Self {
        self.txid = self.compute_txid();
        self
    }

    pub fn coinbase(note: String) -> Self {
        Self {
            txid: String::new(),
            from: "COINBASE".into(),
            to: "MINER".into(),
            amount: 0,
            fee: 0,
            nonce: 0,
            note,
            public_key: Vec::new(),
            signature: Vec::new(),
            output_script: String::new(),
        }
        .finalize()
    }

    pub fn secret(note: String) -> Self {
        Self {
            txid: String::new(),
            from: "GENESIS".into(),
            to: "XEPC".into(),
            amount: 0,
            fee: 0,
            nonce: 0,
            note,
            public_key: Vec::new(),
            signature: Vec::new(),
            output_script: String::new(),
        }
        .finalize()
    }

    /// Return true if this transaction is an on-chain message.
    pub fn is_message_tx(&self) -> bool {
        self.note.starts_with(rules::MESSAGE_PREFIX)
    }

    /// Decode the message body from a message transaction.
    pub fn extract_message(&self) -> Option<String> {
        if !self.is_message_tx() {
            return None;
        }

        let body = &self.note[rules::MESSAGE_PREFIX.len()..];
        let bytes = hex::decode(body).ok()?;
        String::from_utf8(bytes).ok()
    }

    pub fn compute_txid(&self) -> String {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.from.as_bytes());
        payload.push(0);
        payload.extend_from_slice(self.to.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.amount.to_be_bytes());
        payload.extend_from_slice(&self.fee.to_be_bytes());
        payload.extend_from_slice(&self.nonce.to_be_bytes());
        payload.extend_from_slice(self.note.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.public_key);
        payload.extend_from_slice(&self.signature);
        payload.extend_from_slice(self.output_script.as_bytes());
        sha3_256_hex(&payload)
    }

    pub fn signing_hash(&self) -> String {
        let chain_id = spec::current_network().magic_hex();
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            chain_id,
            self.from,
            self.to,
            self.amount,
            self.fee,
            self.nonce,
            self.note,
        );
        sha3_256_hex(payload.as_bytes())
    }

    pub fn sign(&mut self, secret_hex: &str) -> Result<(), String> {
        use crate::dilithium::{keypair::KeyPair, sign};

        let sk = hex::decode(secret_hex).map_err(|e| e.to_string())?;
        let kp = KeyPair::from_secret(&sk)?;

        self.public_key = kp.public_key.clone();

        let msg = hex::decode(self.signing_hash()).map_err(|e| e.to_string())?;
        let sig = sign::sign(&kp.secret_key, &msg)?;

        self.signature = sig;

        self.txid = self.compute_txid();

        Ok(())
    }

    pub fn verify_signature(&self) -> bool {
        crate::validation::rule_signature(self).is_ok()
    }

    pub fn expected_address(&self) -> Option<String> {
        if self.public_key.is_empty() {
            return None;
        }
        address::address_from_public_key(&self.public_key).ok()
    }

    pub fn is_valid(&self) -> bool {
        self.txid == self.compute_txid()
            && (address::verify_legacy_address(&self.from)
                || address::verify_bech32_address(&self.from))
            && (address::verify_legacy_address(&self.to)
                || address::verify_bech32_address(&self.to))
            && self.from != self.to
            && self.amount > 0
            && self.note.len() <= crate::consensus::rules::MAX_NOTE_LEN
            && self.verify_signature()
            && self
                .expected_address()
                .map(|a| a == self.from)
                .unwrap_or(false)
    }
}
