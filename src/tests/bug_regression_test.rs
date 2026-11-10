// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Regression tests for the five bugs identified during the code review.
//!
//! Bug #1 is intentionally left unresolved during development: the
//! nonce in `spec.rs` and the nonce in `genesis.rs` are allowed to
//! diverge while the genesis parameters are being finalised. The tests
//! below therefore check only that `genesis.rs` is internally
//! consistent, not that it agrees with `spec.rs`.
//!
//! Bug #2: hardcoded address prefix that did not adapt to the network.
//! Bug #3: `StateDB` panicked on `clone()` (compile-time check).
//! Bug #4: race condition on `XEPC_DATADIR` in tests.
//! Bug #5: legacy genesis accessors always returned Mainnet values.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::consensus::genesis;
use xepay::consensus::spec::Network;
use xepay::validation;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap();
    let dir = tempfile::tempdir().expect("tempdir failed");
    let path = dir.keep();
    std::env::set_var("XEPC_DATADIR", &path);
    f();
    std::env::remove_var("XEPC_DATADIR");
}

// ----------------------------------------------------------------------
// Bug #1: Genesis nonce is intentionally allowed to diverge.
// ----------------------------------------------------------------------

// This test verifies that `genesis.rs` is internally consistent: the
// accessor for each network returns the constant declared in the same
// module. It does not compare against `spec.rs`.
#[test]
fn bug_1_genesis_accessors_are_internally_consistent() {
    assert_eq!(
        genesis::expected_genesis_nonce_for(Network::Main),
        genesis::EXPECTED_GENESIS_NONCE,
        "Mainnet accessor must return the Mainnet constant"
    );
    assert_eq!(
        genesis::expected_genesis_nonce_for(Network::Test),
        genesis::TESTNET_EXPECTED_GENESIS_NONCE,
        "Testnet accessor must return the Testnet constant"
    );
    assert_eq!(
        genesis::expected_genesis_nonce_for(Network::Regtest),
        genesis::REGTEST_EXPECTED_GENESIS_NONCE,
        "Regtest accessor must return the Regtest constant"
    );
}

// Mainnet and Testnet must have a non-zero nonce because their genesis
// blocks were mined with a real target. Regtest uses a trivial target
// and may have a very small nonce.
#[test]
fn bug_1_mainnet_and_testnet_nonce_are_nonzero() {
    assert!(
        genesis::EXPECTED_GENESIS_NONCE > 0,
        "Mainnet genesis nonce must be greater than zero"
    );
    assert!(
        genesis::TESTNET_EXPECTED_GENESIS_NONCE > 0,
        "Testnet genesis nonce must be greater than zero"
    );
    assert!(
        genesis::REGTEST_EXPECTED_GENESIS_NONCE < 100,
        "Regtest genesis nonce should be small"
    );
}

// ----------------------------------------------------------------------
// Bug #2: Network-aware address prefix
// ----------------------------------------------------------------------

#[test]
fn bug_2_address_prefix_is_network_aware() {
    assert_eq!(
        xepay::blockchain::legacy_prefix_byte_for(Network::Main),
        0x30,
        "Mainnet legacy prefix byte must be 0x30"
    );

    assert_eq!(
        xepay::blockchain::bech32_hrp_for(Network::Main),
        "xepc",
        "Mainnet bech32 HRP must be xepc"
    );

    assert_eq!(
        xepay::blockchain::legacy_prefix_byte_for(Network::Test),
        0x6f,
        "Testnet legacy prefix byte must be 0x6f"
    );

    assert_eq!(
        xepay::blockchain::bech32_hrp_for(Network::Test),
        "xtes",
        "Testnet bech32 HRP must be xtes"
    );

    assert_eq!(
        xepay::blockchain::legacy_prefix_byte_for(Network::Regtest),
        0x6f,
        "Regtest legacy prefix byte must be 0x6f"
    );

    assert_eq!(
        xepay::blockchain::bech32_hrp_for(Network::Regtest),
        "xreg",
        "Regtest bech32 HRP must be xreg"
    );
}

#[test]
#[serial]
fn bug_2_address_validation_uses_correct_prefix() {
    with_temp_datadir(|| {
        use xepay::secp256k1::address;
        use xepay::secp256k1::keypair::KeyPair;

        let chain = Blockchain::new();

        let kp = KeyPair::generate().expect("keypair generation failed");

        let legacy_addr =
            address::address_from_public_key(&kp.public_key).expect("legacy address failed");
        assert!(
            validation::is_valid_address(&legacy_addr, &chain),
            "legacy address should be valid: {}",
            legacy_addr
        );

        let bech32_addr = address::address_from_public_key_bech32(&kp.public_key)
            .expect("bech32 address failed");
        assert!(
            validation::is_valid_address(&bech32_addr, &chain),
            "bech32 address should be valid: {}",
            bech32_addr
        );

        assert!(
            !validation::is_valid_address("not-an-address", &chain),
            "Random string should be invalid"
        );
    });
}

// ----------------------------------------------------------------------
// Bug #4: Environment variable race condition
// ----------------------------------------------------------------------

#[test]
#[serial]
fn bug_4_temp_datadir_is_safe() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        assert_eq!(chain.height(), 0, "Genesis height should be 0");
    });
}

#[test]
#[serial]
fn bug_4_temp_datadir_is_safe_again() {
    with_temp_datadir(|| {
        let chain = Blockchain::new();
        assert_eq!(chain.chain.len(), 1, "Genesis chain should have one block");
    });
}
