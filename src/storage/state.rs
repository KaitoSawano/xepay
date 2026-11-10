// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! State database using a Merkle Patricia Trie backed by LevelDB.

use alloy_primitives::B256;
use eth_trie::{EthTrie, Trie, DB};
use keccak_hash::keccak;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::account::Account;
use super::adapter::LevelDbAdapter;

pub struct StateDB {
    trie: EthTrie<LevelDbAdapter>,
    adapter: Arc<LevelDbAdapter>,
    /// The root hash of the trie after the most recent insertion or
    /// rollback. The trie implementation does not reliably report the
    /// current root through `root_hash()` after an insertion, so the
    /// root is cached here and updated on every mutation.
    cached_root: B256,
}

impl StateDB {
    pub fn open(path: &Path) -> Result<Self, String> {
        let adapter = Arc::new(LevelDbAdapter::open(path)?);

        let root_path = crate::datadir::chainstate_dir().join("root_hash.txt");
        if let Ok(hex_str) = std::fs::read_to_string(&root_path) {
            let hex_str = hex_str.trim();
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let root = B256::from_slice(&bytes);
                    if let Ok(trie) = EthTrie::from(adapter.clone(), root) {
                        return Ok(StateDB {
                            trie,
                            adapter,
                            cached_root: root,
                        });
                    }
                }
            }
        }

        let trie = EthTrie::new(adapter.clone());
        let cached_root = B256::from_slice(keccak_hash::keccak(&[]).as_bytes());
        Ok(StateDB {
            trie,
            adapter,
            cached_root,
        })
    }

    fn address_key(address: &str) -> [u8; 32] {
        keccak(address.as_bytes()).0
    }

    fn recompute_root(&mut self) -> Result<(), String> {
        let root = self.trie.root_hash().map_err(|e| e.to_string())?;
        self.cached_root = B256::from_slice(root.as_slice());
        Ok(())
    }

    pub fn update_account(&mut self, address: &str, account: &Account) -> Result<(), String> {
        let key = Self::address_key(address);
        let value = rlp::encode(account).to_vec();
        self.trie.insert(&key, &value).map_err(|e| e.to_string())?;
        self.recompute_root()?;
        Ok(())
    }

    pub fn get_account(&self, address: &str) -> Result<Option<Account>, String> {
        let key = Self::address_key(address);
        match self.trie.get(&key).map_err(|e| e.to_string())? {
            Some(value) => {
                let account: Account =
                    rlp::decode(&value).map_err(|e| format!("RLP decode error: {}", e))?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    pub fn root_hash(&mut self) -> Result<[u8; 32], String> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(self.cached_root.as_slice());
        Ok(arr)
    }

    /// Verify that a trie root is present in the backing database before
    /// switching to it. Without this check, `EthTrie::from` silently accepts
    /// an arbitrary root because no node is loaded, and `root_hash` then
    /// returns the same value even though the database has no data for it.
    pub fn rollback_to(&mut self, root_hash: &[u8; 32]) -> Result<(), String> {
        let root = B256::from_slice(root_hash);

        let empty_root = B256::from_slice(keccak_hash::keccak(&[]).as_bytes());
        if root != empty_root {
            if self.adapter.get(root.as_slice()).map_err(|e| e.to_string())?.is_none() {
                return Err(format!(
                    "state root {} is not present in the database",
                    hex::encode(root_hash)
                ));
            }
        }

        let new_trie = EthTrie::from(self.adapter.clone(), root)
            .map_err(|e| format!("failed to create trie from root: {}", e))?;

        self.trie = new_trie;
        self.cached_root = root;
        Ok(())
    }

    /// Create a temporary snapshot of the current state without modifying
    /// the original. The snapshot shares the backing database with the
    /// original, so it must not be used to apply transactions unless the
    /// caller accepts that the writes reach the shared database. Callers
    /// that need a read-only simulation must use `simulate_apply` instead.
    pub fn rollback_snapshot(&mut self) -> Result<StateDB, String> {
        let root_b256 = self.cached_root;

        let new_trie = EthTrie::from(self.adapter.clone(), root_b256)
            .map_err(|e| format!("failed to create snapshot trie: {}", e))?;

        Ok(StateDB {
            trie: new_trie,
            adapter: self.adapter.clone(),
            cached_root: root_b256,
        })
    }

    /// Simulate applying a list of transactions and crediting the block
    /// reward, then return the state root that would result. The
    /// simulation builds an in-memory copy of the current trie from the
    /// supplied address list, applies the transactions to that copy,
    /// credits the reward to the miner, and reads the resulting root.
    /// The persistent database is never written to, so the live state is
    /// not affected.
    pub fn simulate_apply(
        &self,
        addresses: &[String],
        transactions: &[crate::transaction::Transaction],
        miner: &str,
        reward: u64,
        block_height: u64,
    ) -> Result<[u8; 32], String> {
        let memory_db = Arc::new(MemoryDb::new());
        let mut temp_trie = EthTrie::new(memory_db.clone());

        for address in addresses {
            if let Some(account) = self.get_account(address)? {
                let key = Self::address_key(address);
                let value = rlp::encode(&account).to_vec();
                temp_trie
                    .insert(&key, &value)
                    .map_err(|e| format!("failed to seed simulation trie: {}", e))?;
            }
        }

        for tx in transactions {
            if crate::validation::is_special_tx(tx) {
                continue;
            }

            if tx.from == tx.to {
                return Err(format!(
                    "self-transfer rejected during simulation: {}",
                    tx.txid
                ));
            }

            let from_key = Self::address_key(&tx.from);
            let to_key = Self::address_key(&tx.to);

            let mut from_acc = read_account_from_trie(&mut temp_trie, &from_key)?
                .unwrap_or_else(empty_account);
            let mut to_acc = read_account_from_trie(&mut temp_trie, &to_key)?
                .unwrap_or_else(empty_account);

            if from_acc.nonce != tx.nonce {
                return Err(format!(
                    "invalid nonce for {}: got {}, expected {}",
                    tx.from, tx.nonce, from_acc.nonce
                ));
            }

            let total = tx
                .amount
                .checked_add(tx.fee)
                .ok_or_else(|| "amount + fee overflows u64".to_string())?;
            if from_acc.balance < total {
                return Err(format!(
                    "insufficient balance for {}: required {}, available {}",
                    tx.from, total, from_acc.balance
                ));
            }

            from_acc.balance -= total;
            from_acc.nonce = from_acc
                .nonce
                .checked_add(1)
                .ok_or_else(|| "sender nonce overflow".to_string())?;
            to_acc.balance = to_acc
                .balance
                .checked_add(tx.amount)
                .ok_or_else(|| "recipient balance overflow".to_string())?;

            let from_value = rlp::encode(&from_acc).to_vec();
            let to_value = rlp::encode(&to_acc).to_vec();
            temp_trie
                .insert(&from_key, &from_value)
                .map_err(|e| format!("failed to insert sender into simulation: {}", e))?;
            temp_trie
                .insert(&to_key, &to_value)
                .map_err(|e| format!("failed to insert recipient into simulation: {}", e))?;
        }

        credit_reward_on_trie(
            &mut temp_trie,
            miner,
            reward,
            block_height,
            crate::consensus::rules::COINBASE_MATURITY,
        )?;

        let root = temp_trie
            .root_hash()
            .map_err(|e| format!("failed to compute simulation root: {}", e))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(root.as_slice());
        Ok(arr)
    }

    pub fn balance_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let immature: u64 = acc
                    .immature_rewards
                    .iter()
                    .map(|(_, a)| *a)
                    .fold(0u64, |acc, x| acc.saturating_add(x));
                acc.balance.saturating_add(immature)
            }
            _ => 0,
        }
    }

    pub fn mature_balance_at(&self, address: &str, current_height: u64) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let maturity = crate::consensus::rules::COINBASE_MATURITY;
                let mut mature = acc.balance;
                for (height, amount) in &acc.immature_rewards {
                    if current_height >= height.saturating_add(maturity) {
                        mature = mature.saturating_add(*amount);
                    }
                }
                mature
            }
            _ => 0,
        }
    }

    pub fn mature_balance_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.balance,
            _ => 0,
        }
    }

    pub fn immature_balance_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.immature_rewards.iter().map(|(_, a)| a).sum(),
            _ => 0,
        }
    }

    pub fn nonce_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.nonce,
            _ => 0,
        }
    }

    pub fn get_code(&self, address: &str) -> Vec<u8> {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.code.clone(),
            _ => Vec::new(),
        }
    }

    pub fn get_storage(&self, address: &str) -> BTreeMap<[u8; 32], [u8; 32]> {
        match self.get_account(address) {
            Ok(Some(acc)) => acc.storage.clone(),
            _ => BTreeMap::new(),
        }
    }

    pub fn set_storage(
        &mut self,
        address: &str,
        storage: BTreeMap<[u8; 32], [u8; 32]>,
    ) -> Result<(), String> {
        let mut acc = self.get_account(address)?.unwrap_or(Account {
            nonce: 0,
            balance: 0,
            immature_rewards: Vec::new(),
            code: Vec::new(),
            storage: BTreeMap::new(),
        });
        acc.storage = storage;
        self.update_account(address, &acc)
    }

    pub fn apply_transaction(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Result<(), String> {
        // Defensive check: a self-transfer would cause the recipient
        // update to overwrite the sender update because both addresses
        // map to the same trie key. Rejecting it here guarantees that the
        // state layer never creates coins, even if a caller bypasses the
        // consensus validation layer.
        if from == to {
            return Err("self-transfer is not allowed".to_string());
        }

        let mut from_acc = self.get_account(from)?.unwrap_or(Account {
            nonce: 0,
            balance: 0,
            immature_rewards: Vec::new(),
            code: Vec::new(),
            storage: BTreeMap::new(),
        });

        if from_acc.nonce != nonce {
            return Err(format!(
                "invalid nonce: got {}, expected {}",
                nonce, from_acc.nonce
            ));
        }

        let total = amount
            .checked_add(fee)
            .ok_or_else(|| "amount + fee overflows u64".to_string())?;

        if from_acc.balance < total {
            return Err(format!(
                "insufficient mature balance: required {}, available {}",
                total, from_acc.balance
            ));
        }

        let mut to_acc = self.get_account(to)?.unwrap_or(Account {
            nonce: 0,
            balance: 0,
            immature_rewards: Vec::new(),
            code: Vec::new(),
            storage: BTreeMap::new(),
        });

        from_acc.balance -= total;
        from_acc.nonce = from_acc
            .nonce
            .checked_add(1)
            .ok_or_else(|| "sender nonce overflow".to_string())?;
        to_acc.balance = to_acc
            .balance
            .checked_add(amount)
            .ok_or_else(|| "recipient balance overflow".to_string())?;

        self.update_account(from, &from_acc)?;
        self.update_account(to, &to_acc)?;

        Ok(())
    }

    pub fn credit_reward(
        &mut self,
        miner: &str,
        reward: u64,
        block_height: u64,
    ) -> Result<(), String> {
        let mut acc = self.get_account(miner)?.unwrap_or(Account {
            nonce: 0,
            balance: 0,
            immature_rewards: Vec::new(),
            code: Vec::new(),
            storage: BTreeMap::new(),
        });

        let maturity = crate::consensus::rules::COINBASE_MATURITY;

        let mut still_immature = Vec::new();
        for (height, amount) in acc.immature_rewards.drain(..) {
            if block_height >= height.saturating_add(maturity) {
                acc.balance = acc.balance.checked_add(amount).ok_or_else(|| {
                    "balance overflow during maturity".to_string()
                })?;
            } else {
                still_immature.push((height, amount));
            }
        }
        acc.immature_rewards = still_immature;
        acc.immature_rewards.push((block_height, reward));

        self.update_account(miner, &acc)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        let path = crate::datadir::chainstate_dir().join("root_hash.txt");
        let _ = std::fs::write(path, hex::encode(self.cached_root));

        self.adapter.flush().map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for StateDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateDB").finish()
    }
}

fn empty_account() -> Account {
    Account {
        nonce: 0,
        balance: 0,
        immature_rewards: Vec::new(),
        code: Vec::new(),
        storage: BTreeMap::new(),
    }
}

fn read_account_from_trie<D: DB>(
    trie: &mut EthTrie<D>,
    key: &[u8; 32],
) -> Result<Option<Account>, String> {
    match trie.get(key).map_err(|e| format!("trie read failed: {}", e))? {
        Some(value) => {
            let account: Account =
                rlp::decode(&value).map_err(|e| format!("RLP decode error: {}", e))?;
            Ok(Some(account))
        }
        None => Ok(None),
    }
}

/// Apply a block reward to the miner account in the given trie. This
/// mirrors `StateDB::credit_reward` but operates on any trie, which
/// allows the simulation to use an in-memory trie.
fn credit_reward_on_trie<D: DB>(
    trie: &mut EthTrie<D>,
    miner: &str,
    reward: u64,
    block_height: u64,
    maturity: u64,
) -> Result<(), String> {
    let key = keccak(miner.as_bytes()).0;
    let mut acc = read_account_from_trie(trie, &key)?.unwrap_or_else(empty_account);

    let mut still_immature = Vec::new();
    for (height, amount) in acc.immature_rewards.drain(..) {
        if block_height >= height.saturating_add(maturity) {
            acc.balance = acc
                .balance
                .checked_add(amount)
                .ok_or_else(|| "balance overflow during maturity".to_string())?;
        } else {
            still_immature.push((height, amount));
        }
    }
    acc.immature_rewards = still_immature;
    acc.immature_rewards.push((block_height, reward));

    let value = rlp::encode(&acc).to_vec();
    trie.insert(&key, &value)
        .map_err(|e| format!("failed to credit reward in simulation: {}", e))?;
    Ok(())
}

// A minimal in-memory DB implementation used by `simulate_apply` so that
// the simulation never writes to the persistent LevelDB.
#[derive(Clone, Default)]
struct MemoryDb {
    inner: Arc<Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryDb {
    fn new() -> Self {
        MemoryDb {
            inner: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl DB for MemoryDb {
    type Error = std::io::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let guard = self.inner.lock().unwrap();
        Ok(guard.get(key).cloned())
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        guard.insert(key.to_vec(), value);
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        let mut guard = self.inner.lock().unwrap();
        guard.remove(key);
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}
