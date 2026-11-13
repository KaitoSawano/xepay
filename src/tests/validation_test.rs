// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use serial_test::serial;
use std::sync::Mutex;
use xepay::block::Block;
use xepay::blockchain::Blockchain;
use xepay::consensus::rules;
use xepay::dilithium::{address, keypair::KeyPair};
use xepay::transaction::Transaction;
use xepay::validation;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

fn dummy_address() -> String {
    let kp = KeyPair::generate().expect("keypair generation failed");
    address::address_from_public_key(&kp.public_key).expect("address failed")
}

#[test]
#[serial]
fn block_with_wrong_previous_hash_is_rejected() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let prev = chain.chain.last().unwrap().clone();
        let mut b = Block::new(
            prev.index + 1,
            "0".repeat(64),
            50_000_000_000,
            chain.nbits,
            Vec::new(),
        )
        .expect("failed to create block in test");
        b.hash = b.calculate_hash();
        let err = validation::validate_block(&mut chain, &prev, &b);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().code, "E035");
    });
}

#[test]
#[serial]
fn block_with_wrong_index_is_rejected() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let prev = chain.chain.last().unwrap().clone();
        let mut b = Block::new(
            prev.index + 2,
            prev.hash.clone(),
            50_000_000_000,
            chain.nbits,
            Vec::new(),
        )
        .expect("failed to create block in test");
        b.hash = b.calculate_hash();
        let err = validation::validate_block(&mut chain, &prev, &b);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().code, "E036");
    });
}

#[test]
#[serial]
fn transaction_with_zero_amount_is_rejected() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        let from = dummy_address();
        let to = dummy_address();
        let tx = Transaction::new(&from, &to, 0, 0, 0);
        let err = validation::validate_transaction(&chain, &tx);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().code, "E005");
    });
}

#[test]
#[serial]
fn transaction_with_self_send_is_rejected() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        let addr = dummy_address();
        let tx = Transaction::new(&addr, &addr, 1, 0, 0);
        let err = validation::validate_transaction(&chain, &tx);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().code, "E004");
    });
}

#[test]
fn address_format_validation() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let valid_addr = address::address_from_public_key(&kp.public_key).expect("address failed");

    let chain = Blockchain::new();
    assert!(validation::is_valid_address(&valid_addr, &chain));
    assert!(!validation::is_valid_address("XEPC123", &chain));
    assert!(!validation::is_valid_address("not-an-address", &chain));
}

#[test]
fn zero_hash_constant_is_correct() {
    assert_eq!(rules::ZERO_HASH.len(), 64);
    assert!(rules::ZERO_HASH.chars().all(|c| c == '0'));
}

#[test]
fn txid_changes_when_public_key_changes() {
    let mut tx = Transaction::new(&dummy_address(), &dummy_address(), 1, 0, 0);
    let txid1 = tx.txid.clone();
    // Because public_key is now Vec<u8>, we change it to a valid dummy byte array
    tx.public_key = vec![0xaa; 1952]; 
    let txid2 = tx.compute_txid();
    assert_ne!(txid1, txid2);
}
