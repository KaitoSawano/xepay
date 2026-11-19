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
use crate::consensus::rules;

/// Move every immature reward whose maturity height has been reached into
/// the spendable balance, and keep the rest in the map. This is the only
/// place where maturity is resolved, so the live path and the simulation
/// path cannot disagree about when a reward becomes spendable.
fn settle_maturity(acc: &mut Account, current_height: u64, maturity: u64) {
    let mut still_immature = BTreeMap::new();
    for (height, amount) in std::mem::take(&mut acc.immature_rewards) {
        if current_height >= height.saturating_add(maturity) {
            acc.balance = acc.balance.saturating_add(amount);
        } else {
            still_immature.insert(height, amount);
        }
    }
    acc.immature_rewards = still_immature;
}

/// Apply a single transaction to an in-memory account.
///
/// The caller loads the account, calls this function, and stores the
/// result back into the trie. The function performs no I/O and reads no
/// global state, so it can be reused by the simulation path without
/// touching the persistent database. This is the single source of truth
/// for the state transition, which guarantees that a block accepted by
/// the live path produces exactly the same state root as the simulation
/// that validated it.
fn apply_tx_to_account(
    from_acc: &mut Account,
    to_acc: Option<&mut Account>,
    tx_from: &str,
    tx_to: &str,
    amount: u64,
    fee: u64,
    nonce: u64,
    current_height: u64,
) -> Result<(), String> {
    let maturity = rules::COINBASE_MATURITY;

    settle_maturity(from_acc, current_height, maturity);

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

    from_acc.balance = from_acc
        .balance
        .checked_sub(total)
        .ok_or_else(|| "underflow during deduction".to_string())?;

    from_acc.nonce = from_acc
        .nonce
        .checked_add(1)
        .ok_or_else(|| "sender nonce overflow".to_string())?;

    if tx_from != tx_to {
        let to = to_acc.ok_or_else(|| "recipient account is required".to_string())?;
        to.balance = to
            .balance
            .checked_add(amount)
            .ok_or_else(|| "recipient balance overflow".to_string())?;
    } else {
        from_acc.balance = from_acc
            .balance
            .checked_add(amount)
            .ok_or_else(|| "self-send refund overflow".to_string())?;
    }

    Ok(())
}

/// Record a block reward as an immature reward keyed by the block height.
/// It is moved into the spendable balance lazily by `settle_maturity`
/// when the account is next touched. Because the immature rewards are
/// stored in a `BTreeMap`, the encoding is deterministic.
fn credit_reward_to_account(acc: &mut Account, reward: u64, block_height: u64) {
    let entry = acc.immature_rewards.entry(block_height).or_insert(0u64);
    *entry = entry.saturating_add(reward);
}

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
        // Recompute the root from the trie on every call to guarantee
        // that the returned root matches the current state. The cached
        // root is only a fallback for read-only paths.
        let root = self.trie.root_hash().map_err(|e| e.to_string())?;
        self.cached_root = B256::from_slice(root.as_slice());
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
    ///
    /// The simulation uses the same `settle_maturity`, `apply_tx_to_account`,
    /// and `credit_reward_to_account` helpers that the live path uses. Any
    /// divergence between the two paths is a consensus bug, and this
    /// function exists to make that divergence impossible by construction.
    ///
    /// The seed set is the union of the caller-supplied address list, the
    /// sender and recipient of every transaction in the block, and the
    /// miner. This makes the simulation independent of whether the caller
    /// remembered to add those addresses to `addresses`, which is the
    /// class of bug that caused state root mismatches when a block
    /// touched an account that was not yet in the local address list.
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

        // Build the seed set from the caller-supplied addresses, the
        // miner, and every account touched by the transactions in the
        // block. Duplicates are removed by the BTreeMap.
        let mut seed_addresses: BTreeMap<String, ()> = BTreeMap::new();
        for address in addresses {
            seed_addresses.insert(address.clone(), ());
        }
        seed_addresses.insert(miner.to_string(), ());
        for tx in transactions {
            if crate::validation::is_special_tx(tx) {
                continue;
            }
            seed_addresses.insert(tx.from.clone(), ());
            seed_addresses.insert(tx.to.clone(), ());
        }

        // Seed the simulation trie from the live state for every address
        // in the seed set. Accounts that do not exist in the live state
        // are left out, which is correct: they are created by the
        // simulation itself when the first transaction or reward touches
        // them, starting from an empty account.
        for address in seed_addresses.keys() {
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

            let is_message = tx.is_message_tx();

            if tx.from == tx.to {
                if !is_message || tx.amount != rules::MIN_MESSAGE_AMOUNT {
                    return Err(format!(
                        "self-transfer rejected during simulation: {}",
                        tx.txid
                    ));
                }
            } else if is_message {
                return Err(format!(
                    "message transaction must be a self-send: {}",
                    tx.txid
                ));
            }

            if tx.amount == 0 {
                return Err(format!(
                    "zero amount rejected during simulation: {}",
                    tx.txid
                ));
            }

            let from_key = Self::address_key(&tx.from);
            let to_key = Self::address_key(&tx.to);

            let mut from_acc = read_account_from_trie(&mut temp_trie, &from_key)?
                .unwrap_or_else(empty_account);

            if tx.from == tx.to {
                apply_tx_to_account(
                    &mut from_acc,
                    None,
                    &tx.from,
                    &tx.to,
                    tx.amount,
                    tx.fee,
                    tx.nonce,
                    block_height,
                )?;
                let from_value = rlp::encode(&from_acc).to_vec();
                temp_trie
                    .insert(&from_key, &from_value)
                    .map_err(|e| format!("failed to insert sender into simulation: {}", e))?;
            } else {
                let mut to_acc = read_account_from_trie(&mut temp_trie, &to_key)?
                    .unwrap_or_else(empty_account);
                apply_tx_to_account(
                    &mut from_acc,
                    Some(&mut to_acc),
                    &tx.from,
                    &tx.to,
                    tx.amount,
                    tx.fee,
                    tx.nonce,
                    block_height,
                )?;
                let from_value = rlp::encode(&from_acc).to_vec();
                let to_value = rlp::encode(&to_acc).to_vec();
                temp_trie
                    .insert(&from_key, &from_value)
                    .map_err(|e| format!("failed to insert sender into simulation: {}", e))?;
                temp_trie
                    .insert(&to_key, &to_value)
                    .map_err(|e| format!("failed to insert recipient into simulation: {}", e))?;
            }
        }

        // Credit the reward with the same helper that the live path uses.
        // The fee is part of `reward` because the miner receives both the
        // subsidy and the transaction fees. Maturity is settled before
        // the new reward is pushed, matching `credit_reward` on the live
        // path.
        let miner_key = Self::address_key(miner);
        let mut miner_acc = read_account_from_trie(&mut temp_trie, &miner_key)?
            .unwrap_or_else(empty_account);
        settle_maturity(&mut miner_acc, block_height, rules::COINBASE_MATURITY);
        credit_reward_to_account(&mut miner_acc, reward, block_height);
        let miner_value = rlp::encode(&miner_acc).to_vec();
        temp_trie
            .insert(&miner_key, &miner_value)
            .map_err(|e| format!("failed to credit reward in simulation: {}", e))?;

        let root = temp_trie
            .root_hash()
            .map_err(|e| format!("failed to compute simulation root: {}", e))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(root.as_slice());
        Ok(arr)
    }

    /// Return the total balance of an address.
    ///
    /// Total balance = `acc.balance` (mature) + sum of all
    /// `immature_rewards` (whether mature or not). This is the amount
    /// that would be available if all immature rewards were mature.
    pub fn balance_of(&self, address: &str) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let immature: u64 = acc
                    .immature_rewards
                    .values()
                    .copied()
                    .fold(0u64, |acc, x| acc.saturating_add(x));
                acc.balance.saturating_add(immature)
            }
            _ => 0,
        }
    }

    /// Return the mature balance of an address at the given height.
    ///
    /// Mature balance = `acc.balance` + sum of `immature_rewards` whose
    /// maturity height has been reached. Rewards that are still immature
    /// are NOT included.
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

    /// Return the mature balance of an address using the given height.
    pub fn mature_balance_of(&self, address: &str, current_height: u64) -> u64 {
        self.mature_balance_at(address, current_height)
    }

    /// Return the immature balance of an address at the given height.
    ///
    /// Immature balance = sum of `immature_rewards` whose maturity
    /// height has NOT been reached yet.
    pub fn immature_balance_of(&self, address: &str, current_height: u64) -> u64 {
        match self.get_account(address) {
            Ok(Some(acc)) => {
                let maturity = crate::consensus::rules::COINBASE_MATURITY;
                acc.immature_rewards
                    .iter()
                    .filter(|(height, _)| current_height < height.saturating_add(maturity))
                    .map(|(_, amount)| *amount)
                    .sum()
            }
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
        let mut acc = self.get_account(address)?.unwrap_or_else(empty_account);
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
        current_height: u64,
    ) -> Result<(), String> {
        if from == to {
            if amount != rules::MIN_MESSAGE_AMOUNT {
                return Err("self-transfer is only allowed for message transactions".to_string());
            }
        }

        if amount == 0 {
            return Err("amount must be greater than zero".to_string());
        }

        let mut from_acc = self.get_account(from)?.unwrap_or_else(empty_account);

        if from == to {
            apply_tx_to_account(
                &mut from_acc,
                None,
                from,
                to,
                amount,
                fee,
                nonce,
                current_height,
            )?;
            self.update_account(from, &from_acc)?;
        } else {
            let mut to_acc = self.get_account(to)?.unwrap_or_else(empty_account);
            apply_tx_to_account(
                &mut from_acc,
                Some(&mut to_acc),
                from,
                to,
                amount,
                fee,
                nonce,
                current_height,
            )?;
            self.update_account(to, &to_acc)?;
            self.update_account(from, &from_acc)?;
        }

        Ok(())
    }

    /// Credit a block reward to the miner account.
    ///
    /// The reward is added to `immature_rewards` and stays there until
    /// it matures. Maturity is resolved lazily by `settle_maturity`,
    /// which is called here before the new reward is pushed so that the
    /// live path and the simulation path resolve maturity at the same
    /// point. This keeps `acc.balance` and `acc.immature_rewards`
    /// consistent between the two paths.
    pub fn credit_reward(
        &mut self,
        miner: &str,
        reward: u64,
        block_height: u64,
    ) -> Result<(), String> {
        let mut acc = self.get_account(miner)?.unwrap_or_else(empty_account);
        settle_maturity(&mut acc, block_height, rules::COINBASE_MATURITY);
        credit_reward_to_account(&mut acc, reward, block_height);
        self.update_account(miner, &acc)
    }

    pub fn flush(&mut self) -> Result<(), String> {
        // Recompute the root before writing so that root_hash.txt always
        // reflects the current trie state.
        self.recompute_root()?;
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
        immature_rewards: BTreeMap::new(),
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

// A minimal in-memory DB implementation used by `simulate_apply` so that
// the simulation never writes to the persistent LevelDB. A `BTreeMap`
// is used instead of a `HashMap` so that any internal iteration over
// the backing store is deterministic. This removes the last source of
// state root divergence between the live path, which uses the persistent
// LevelDB adapter, and the simulation path.
#[derive(Clone, Default)]
struct MemoryDb {
    inner: Arc<Mutex<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl MemoryDb {
    fn new() -> Self {
        MemoryDb {
            inner: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
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
