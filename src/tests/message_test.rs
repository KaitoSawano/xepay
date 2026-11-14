// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use serial_test::serial;
use std::sync::Mutex;
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

#[test]
fn message_tx_detects_and_extracts() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let addr = address::address_from_public_key(&kp.public_key).expect("address failed");
    let msg = "Hello, XEPAY!";
    let mut tx = Transaction::new_message(&addr, 10_000, 0, msg).expect("new_message failed");

    assert!(tx.is_message_tx());
    assert_eq!(tx.extract_message(), Some(msg.to_string()));

    tx.sign(&kp.secret_key_hex()).expect("sign failed");
    assert!(tx.verify_signature());
}

#[test]
fn message_tx_rejects_empty() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let addr = address::address_from_public_key(&kp.public_key).expect("address failed");
    let err = Transaction::new_message(&addr, 10_000, 0, "").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn message_tx_rejects_oversize() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let addr = address::address_from_public_key(&kp.public_key).expect("address failed");
    let long = "A".repeat(rules::MAX_MESSAGE_LEN + 1);
    let err = Transaction::new_message(&addr, 10_000, 0, &long).unwrap_err();
    assert!(err.contains("exceeds"));
}

#[test]
fn self_send_without_prefix_is_rejected() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let addr = address::address_from_public_key(&kp.public_key).expect("address failed");
    let mut tx = Transaction::new_with_note(&addr, &addr, 1, 10_000, 0, "hello".into());
    tx.sign(&kp.secret_key_hex()).expect("sign failed");
    let err = validation::rule_self_send(&tx).unwrap_err();
    assert_eq!(err.code, "E004");
}

#[test]
fn message_tx_with_wrong_amount_is_rejected() {
    let kp = KeyPair::generate().expect("keypair generation failed");
    let addr = address::address_from_public_key(&kp.public_key).expect("address failed");
    let mut tx = Transaction::new_message(&addr, 10_000, 0, "hi").expect("new_message failed");
    tx.amount = 999;
    tx.txid = tx.compute_txid();
    let err = validation::rule_message_format(&tx).unwrap_err();
    assert_eq!(err.code, "E054");
}

#[test]
#[serial]
fn message_tx_apply_returns_amount_to_sender() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();
        let kp = KeyPair::generate().expect("keypair generation failed");
        let addr = address::address_from_public_key(&kp.public_key).expect("address failed");

        let genesis_balance = chain.balance_of("GENESIS");
        assert!(genesis_balance > 0);

        // Fund the sender account via a manual state update.
        let mut acc = chain.state.get_account(&addr).unwrap().unwrap_or(xepay::storage::Account {
            nonce: 0,
            balance: 0,
            immature_rewards: Vec::new(),
            code: Vec::new(),
            storage: std::collections::BTreeMap::new(),
        });
        acc.balance = 1_000_000;
        chain.state.update_account(&addr, &acc).unwrap();

        let balance_before = chain.balance_of(&addr);
        let fee = 10_000;
        let mut tx = Transaction::new_message(&addr, fee, 0, "hello").expect("new_message failed");
        tx.sign(&kp.secret_key_hex()).expect("sign failed");

        chain.apply_transaction(&tx).expect("apply_transaction failed");

        // Sender balance should have decreased only by the fee.
        let balance_after = chain.balance_of(&addr);
        assert_eq!(balance_before - fee, balance_after);
    });
}
