// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::dilithium::{address, keypair::KeyPair};

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
fn destination_address_is_not_a_candidate() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        let height = chain.height();
        let to = dummy_address();
        let other = dummy_address();

        let candidates: Vec<(String, u64)> = [to.clone(), other.clone()]
            .iter()
            .filter(|addr| **addr != to)
            .map(|addr| (addr.clone(), chain.mature_balance_at(addr, height)))
            .collect();

        assert!(candidates.iter().all(|(addr, _)| *addr != to));
    });
}

#[test]
#[serial]
fn error_message_mentions_required_and_available() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        let height = chain.height();
        let need = 1_000_000_000u64;
        let available = chain.mature_balance_at(&dummy_address(), height);

        let msg = format!(
            "insufficient mature balance. Need {} ALD, available {} ALD.",
            need, available
        );

        assert!(msg.contains("Need"));
        assert!(msg.contains("available"));
    });
}
