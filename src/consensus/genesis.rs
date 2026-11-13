// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Genesis consensus parameters for XEPAY.
//!
//! Each network has its own genesis block. The mainnet genesis is
//! locked forever; the testnet and regtest genesis blocks may be
//! regenerated when the consensus rules change.

use crate::consensus::spec::{self, Network}; // Network selector and parameters.

// ----------------------------------------------------------------------
// Shared genesis messages (same on all networks)
// ----------------------------------------------------------------------

// The message embedded in the genesis coinbase transaction.
pub const GENESIS_MESSAGE: &str = "XEPAY Genesis - 2026";
// The secret embedded in the genesis secret transaction.
pub const GENESIS_SECRET: &str = "ID Today 12/Nov/2026 Aldianokto, Chaos in the Treasury, Order in the Code";

// ----------------------------------------------------------------------
// Genesis output script (P2PK, same format as the reference implementation)
// ----------------------------------------------------------------------
//
// The genesis output script locks the genesis block reward to a specific
// public key. With ML-DSA-65, the public key is 1952 bytes. Because the
// genesis output is never spent, the script is a placeholder that
// documents the intent without committing to a verifiable ML-DSA key.
pub const GENESIS_OUTPUT_SCRIPT: &str = "ML-DSA-65 OP_CHECKSIG";

// ----------------------------------------------------------------------
// Mainnet genesis
// ----------------------------------------------------------------------

// The mainnet genesis timestamp (in milliseconds).
pub const GENESIS_TIMESTAMP: u128 = 1794497705601;

// The expected mainnet genesis hash.
//
// NOTE: This value must be regenerated after any change to
// GENESIS_OUTPUT_SCRIPT or the signature algorithm. Run `xepay-genesis`
// and paste the output here.
pub const EXPECTED_GENESIS_HASH: &str =
    "00000ea8a2c578692cd5a06e9231f438b703ddbb351487361e5b8579c6d27602";

// The expected mainnet genesis merkle root.
pub const EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "5b5f87574865b0d5978f82cc026ffe79f3712b7ff0fa9a8810a38f1ed508fe56";

// The expected mainnet genesis timestamp.
pub const EXPECTED_GENESIS_TIMESTAMP: u128 = 1794497705601;

// The expected mainnet genesis nonce.
pub const EXPECTED_GENESIS_NONCE: u64 = 227407;

// ----------------------------------------------------------------------
// Testnet genesis
// ----------------------------------------------------------------------

// The testnet genesis timestamp (in milliseconds).
pub const TESTNET_GENESIS_TIMESTAMP: u128 = 1792303198446;

// The expected testnet genesis hash.
pub const TESTNET_EXPECTED_GENESIS_HASH: &str =
    "PLACEHOLDER_RUN_XEPAY_GENESIS_TESTNET";

// The expected testnet genesis merkle root.
pub const TESTNET_EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "PLACEHOLDER_RUN_XEPAY_GENESIS_TESTNET";

// The expected testnet genesis timestamp.
pub const TESTNET_EXPECTED_GENESIS_TIMESTAMP: u128 = 1792303198446;

// The expected testnet genesis nonce.
pub const TESTNET_EXPECTED_GENESIS_NONCE: u64 = 0;

// ----------------------------------------------------------------------
// Regtest genesis
// ----------------------------------------------------------------------

// The regtest genesis timestamp (in milliseconds).
pub const REGTEST_GENESIS_TIMESTAMP: u128 = 1792303198447;

// The expected regtest genesis hash.
pub const REGTEST_EXPECTED_GENESIS_HASH: &str =
    "PLACEHOLDER_RUN_XEPAY_GENESIS_REGTEST";

// The expected regtest genesis merkle root.
pub const REGTEST_EXPECTED_GENESIS_MERKLE_ROOT: &str =
    "PLACEHOLDER_RUN_XEPAY_GENESIS_REGTEST";

// The expected regtest genesis timestamp.
pub const REGTEST_EXPECTED_GENESIS_TIMESTAMP: u128 = 1792303198447;

// The expected regtest genesis nonce.
pub const REGTEST_EXPECTED_GENESIS_NONCE: u64 = 0;

// ----------------------------------------------------------------------
// Network-aware accessors
// ----------------------------------------------------------------------

// Returns the shared genesis message.
pub fn genesis_message() -> &'static str {
    GENESIS_MESSAGE
}

// Returns the shared genesis secret.
pub fn genesis_secret() -> &'static str {
    GENESIS_SECRET
}

// Returns the genesis timestamp for the active network.
pub fn genesis_timestamp() -> u128 {
    spec::current_network().genesis_timestamp()
}

// Returns the shared genesis output script.
pub fn genesis_output_script() -> String {
    GENESIS_OUTPUT_SCRIPT.to_string()
}

// Returns the expected genesis hash for the given network.
pub fn expected_genesis_hash_for(network: Network) -> &'static str {
    match network {
        Network::Main => EXPECTED_GENESIS_HASH,
        Network::Test => TESTNET_EXPECTED_GENESIS_HASH,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_HASH,
    }
}

// Returns the expected genesis merkle root for the given network.
pub fn expected_genesis_merkle_root_for(network: Network) -> &'static str {
    match network {
        Network::Main => EXPECTED_GENESIS_MERKLE_ROOT,
        Network::Test => TESTNET_EXPECTED_GENESIS_MERKLE_ROOT,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_MERKLE_ROOT,
    }
}

// Returns the expected genesis timestamp for the given network.
pub fn expected_genesis_timestamp_for(network: Network) -> u128 {
    match network {
        Network::Main => EXPECTED_GENESIS_TIMESTAMP,
        Network::Test => TESTNET_EXPECTED_GENESIS_TIMESTAMP,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_TIMESTAMP,
    }
}

// Returns the expected genesis nonce for the given network.
pub fn expected_genesis_nonce_for(network: Network) -> u64 {
    match network {
        Network::Main => EXPECTED_GENESIS_NONCE,
        Network::Test => TESTNET_EXPECTED_GENESIS_NONCE,
        Network::Regtest => REGTEST_EXPECTED_GENESIS_NONCE,
    }
}
