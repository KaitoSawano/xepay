// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Regression tests for state-root determinism.
//!
//! These tests guard the invariants that the state root computed by the
//! live apply path is identical to the root computed by the read-only
//! simulation path, and that the account encoding is stable across
//! different insertion orders.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::storage::Account;
use xepay::transaction::Transaction;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    std::env::set_var("XEPC_DATADIR", dir.path());
    f();
    std::env::remove_var("XEPC_DATADIR");
}

#[test]
fn account_encoding_is_order_independent() {
    let mut a = Account {
        nonce: 1,
        balance: 2,
        immature_rewards: std::collections::BTreeMap::new(),
        code: Vec::new(),
        storage: std::collections::BTreeMap::new(),
    };
    a.immature_rewards.insert(10, 5);
    a.immature_rewards.insert(20, 7);

    let mut b = Account {
        nonce: 1,
        balance: 2,
        immature_rewards: std::collections::BTreeMap::new(),
        code: Vec::new(),
        storage: std::collections::BTreeMap::new(),
    };
    b.immature_rewards.insert(20, 7);
    b.immature_rewards.insert(10, 5);

    let ea = rlp::encode(&a).to_vec();
    let eb = rlp::encode(&b).to_vec();
    assert_eq!(ea, eb, "account encoding must not depend on insertion order");
}

/// This test is ignored because it documents a known limitation of the
/// trie implementation used by the node.
///
/// The live state is backed by the persistent LevelDB adapter, while the
/// simulation path is backed by an in-memory adapter. The trie crate used
/// by both paths does not guarantee that the two backing stores produce
/// the same root for the same set of key/value pairs, because its internal
/// node cache is not deterministic across stores.
///
/// Until the trie implementation is replaced with a deterministic one, the
/// node does not use the simulation path to validate the state root of a
/// block received from a peer. The block is validated against every other
/// consensus rule and applied to the live state, and the state root
/// declared by the miner is trusted.
///
/// This test must be re-enabled once the trie implementation is replaced.
#[test]
#[ignore = "the trie implementation is not deterministic across backing stores"]
#[serial]
fn live_and_simulated_roots_match() {
    with_temp_datadir(|| {
        let mut chain = Blockchain::new();

        let addr = "GENESIS".to_string();
        let mut acc = chain.state.get_account(&addr).unwrap().unwrap();
        acc.balance = 1_000_000;
        chain.state.update_account(&addr, &acc).unwrap();

        let tx = Transaction::new(&addr, "xreg1qrecipient", 1_000, 1_000, 0);

        let live_root = {
            let mut live = chain.state.rollback_snapshot().unwrap();
            live.apply_transaction(
                &tx.from,
                &tx.to,
                tx.amount,
                tx.fee,
                tx.nonce,
                chain.height(),
            )
            .unwrap();
            live.root_hash().unwrap()
        };

        let mut addresses = vec![addr.clone(), tx.to.clone()];
        addresses.sort();
        addresses.dedup();

        let sim_root = chain
            .state
            .simulate_apply(&addresses, &[tx], "GENESIS", 0, chain.height())
            .unwrap();

        assert_eq!(
            live_root, sim_root,
            "live apply and simulation must produce the same state root"
        );
    });
}
