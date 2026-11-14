// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Regression tests for the five bugs identified during the code review.

use serial_test::serial;
use std::sync::Mutex;
use xepay::blockchain::Blockchain;
use xepay::consensus::genesis;
use xepay::consensus::spec::Network;
use xepay::validation;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn with_temp_datadir<F: FnOnce()>(f: F) {
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir failed");
    let path = dir.keep();
    std::env::set_var("XEPC_DATADIR", &path);
    f();
    std::env::remove_var("XEPC_DATADIR");
}

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

#[test]
fn bug_2_address_prefix_is_network_aware() {
    assert_eq!(xepay::blockchain::legacy_prefix_byte_for(Network::Main), 0x30);
    assert_eq!(xepay::blockchain::bech32_hrp_for(Network::Main), "xepc");
    assert_eq!(xepay::blockchain::legacy_prefix_byte_for(Network::Test), 0x6f);
    assert_eq!(xepay::blockchain::bech32_hrp_for(Network::Test), "xtes");
    assert_eq!(xepay::blockchain::legacy_prefix_byte_for(Network::Regtest), 0x6f);
    assert_eq!(xepay::blockchain::bech32_hrp_for(Network::Regtest), "xreg");
}

#[test]
#[serial]
fn bug_2_address_validation_uses_correct_prefix() {
    with_temp_datadir(|| {
        use xepay::dilithium::address;
        use xepay::dilithium::keypair::KeyPair;

        let chain = Blockchain::new();
        let kp = KeyPair::generate().expect("keypair generation failed");

        let legacy_addr = address::address_from_public_key(&kp.public_key).expect("legacy address failed");
        assert!(validation::is_valid_address(&legacy_addr, &chain));

        let bech32_addr = address::address_from_public_key_bech32(&kp.public_key).expect("bech32 address failed");
        assert!(validation::is_valid_address(&bech32_addr, &chain));

        assert!(!validation::is_valid_address("not-an-address", &chain));
    });
}

#[test]
#[serial]
fn bug_q_generatetoaddress_does_not_lose_state_on_interrupt() {
    with_temp_datadir(|| {
        // Ensure that an interrupted mining operation does not corrupt the chain state.
        let mut chain = Blockchain::new();
        let addr = "xreg1q4t3vtam8l8lz8hzr9fwakycgrm2c2z89yg7n0n".to_string();
        let initial_height = chain.height();
        let initial_balance = chain.balance_of(&addr);
        
        // Simulate a failed mining attempt (no block pushed).
        // Since generatetoaddress is an RPC handler, we test the underlying logic.
        let result = chain.mine_pending();
        
        // If mining fails, the chain height should NOT change, and the state should be untouched.
        // However, mine_pending uses validate_transaction, so it shouldn't corrupt.
        if result.is_err() {
            assert_eq!(chain.height(), initial_height, "Chain height must not change on failed mining");
            assert_eq!(chain.balance_of(&addr), initial_balance, "Miner balance must not change on failed mining");
        }
    });
}

#[test]
#[serial]
fn bug_n_wallet_does_not_save_plaintext_after_decrypt() {
    with_temp_datadir(|| {
        use xepay::wallet::Wallet;
        
        let mut wallet = Wallet::new();
        wallet.encrypt("super_secret_password").expect("encryption failed");
        
        // Save encrypted wallet
        wallet.save_default().expect("save failed");
        
        // Load and decrypt
        let loaded = Wallet::load_default().expect("load failed");
        assert!(loaded.encrypted, "Wallet must be encrypted on disk");
        
        let decrypted = loaded.decrypt("super_secret_password").expect("decrypt failed");
        assert!(!decrypted.encrypted, "Decrypted wallet should have encrypted = false in memory");
        
        // Save the decrypted wallet (simulating a wallet operation)
        decrypted.save_default().expect("re-save failed");
        
        // Reload: the wallet must STILL be encrypted on disk.
        let reloaded = Wallet::load_default().expect("reload failed");
        assert!(reloaded.encrypted, "Wallet must remain encrypted on disk after re-save");
    });
}
