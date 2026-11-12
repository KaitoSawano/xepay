# XEPAY Release History - v0.3.0

This release is a major milestone for XEPAY. We have fully migrated from ECDSA (secp256k1) to post-quantum cryptography **ML-DSA-65 (Dilithium)**, optimized transaction storage size by 50%, and introduced a **Dynamic Fee Market** to defend against spam attacks.

### 🚀 New Features
- **Migration to ML-DSA-65 (Post-Quantum):** The entire signature system now uses ML-DSA-65 (FIPS 204), replacing secp256k1. Public keys are 1952 bytes, signatures are 3309 bytes, and secret keys are 32 bytes (seed).
- **Dynamic Fee Market:** The minimum relay fee per byte now adjusts dynamically based on mempool fullness (50%, 75%, 90% thresholds). This prevents attackers from flooding the network with low-cost transactions.
- **Raw Bytes Storage:** `public_key` and `signature` inside transactions are now stored as `Vec<u8>` (raw bytes) instead of hex strings. This cuts storage size by 50%.
- **Strict State Verification:** `submitblock` now recalculates the actual `state_root` after transactions and rewards are applied. Blocks with a fake or empty root are rejected.
- **Future Time Limit:** Blocks with a timestamp more than 2 hours in the future are rejected to prevent time manipulation.

### 🛠️ Critical Bug Fixes (Security Hardening)
- **Self-Transfer (Bug #3):** Transactions sending funds to the same address (`from == to`) are now strictly rejected at both the block and state levels. Previously, this could be exploited to create coins out of thin air.
- **Read-Only Template (Bug #4):** `getblocktemplate` no longer mutates the state database. The `simulate_apply` function has been rewritten to use an in-memory trie (MemoryDb), ensuring the node state remains intact even when the template is requested repeatedly.
- **Rollback Verification (Bug #5):** The `rollback_to` function now verifies that the target root hash actually exists in the database before switching, preventing corrupted state from reverting to an empty trie.
- **Empty State Root (Bug #6):** Blocks with an empty or invalid `state_root` are now rejected before Proof-of-Work verification.
- **Block Panic (Bug #2):** `Block::new` no longer panics when receiving malformed data from peers. The function now returns a safe `Result`.

### ⚡ Optimizations & Refactoring
- **Transaction Size Reduced by 50%:** 1,000 transactions now consume only ~5.4 MB (down from ~10.6 MB).
- **Lighter Maximum Block Size:** With `MAX_TX_PER_BLOCK = 1,000`, the maximum block size has dropped from ~11 MB to ~5.4 MB.
- **Raw Byte Hashing:** The `compute_txid` and `calculate_hash` functions now use null-byte (`0`) separators on byte arrays instead of pipe (`|`) formatted strings. This prevents collisions and is more efficient.
- **Code Cleanup:** The `secp256k1` and `hdwallet` modules have been completely removed to simplify the codebase.

### 🗑️ Removed Features
- **HD Wallet:** Removed because there is no established post-quantum key derivation standard (equivalent to BIP-32 for ML-DSA) yet. The legacy wallet (`wallet.dat`) remains fully functional.
- **ECDSA secp256k1:** All dependencies on classical elliptic curve cryptography have been removed.

### ⚠️ Upgrade Notes (Breaking Changes)
- **Genesis Reset:** Due to the signature algorithm change and block hashing method update, all genesis blocks (Mainnet, Testnet, Regtest) must be re-mined.
- **Delete Old Datadir:** Old nodes attempting to run version 0.3.0 with a datadir from version 0.2.0 will refuse to start (genesis mismatch). Users **must** delete the `~/.xepay`, `~/.xepay-testnet`, or `~/.xepay-regtest` folders.
- **RPC API Changes:** `getblocktemplate` now **requires** a `mining_address` parameter as the first argument. The `public_key` and `signature` formats in RPC output are now hex strings representing raw bytes.
