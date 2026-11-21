// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Flat key-value state database backed by LevelDB.
//!
//! Each account is stored under its address bytes. The value is the RLP
//! encoding of the account. There is no trie and no state root: the
//! block header does not commit to a state root, and the node does not
//! compare a computed root against a declared one. This mirrors the
//! design of account-based chains that keep the state as a plain
//! key-value store and rely on full block validation instead of a state
//! commitment.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use rusty_leveldb::{LdbIterator, Options, DB as LevelDB};

use super::account::Account;
use crate::consensus::rules;

/// Move every immature reward whose maturity height has been reached into
/// the spendable balance, and keep the rest in the map. This is the only
/// place where maturity is resolved, so the live path and any other
/// caller cannot disagree about when a reward becomes spendable.
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
/// result back into the database. The function performs no I/O and reads
/// no global state, so it is the single source of truth for the state
/// transition.
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
    db: Mutex<LevelDB>,
}

impl StateDB {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut opt = Options::default();
        opt.create_if_missing = true;
        let db = LevelDB::open(path, opt).map_err(|e| format!("{:?}", e))?;
        Ok(StateDB { db: Mutex::new(db) })
    }

    fn address_key(address: &str) -> Vec<u8> {
        address.as_bytes().to_vec()
    }

    pub fn update_account(&mut self, address: &str, account: &Account) -> Result<(), String> {
        let key = Self::address_key(address);
        let value = rlp::encode(account).to_vec();
        let mut db = self.db.lock().unwrap();
        db.put(&key, &value).map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    pub fn get_account(&self, address: &str) -> Result<Option<Account>, String> {
        let key = Self::address_key(address);
        let mut db = self.db.lock().unwrap();
        match db.get(&key) {
            Some(value) => {
                let account: Account =
                    rlp::decode(&value).map_err(|e| format!("RLP decode error: {}", e))?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Drop every account from the live state and start from an empty
    /// database. This is used by the reorg path to rebuild the state from
    /// the block history after a rollback, because the block header no
    /// longer commits to a state root and there is no shorter way to
    /// undo a state transition.
    pub fn reset(&mut self) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        let keys = collect_keys(&mut db)?;
        for key in keys {
            db.delete(&key).map_err(|e| format!("{:?}", e))?;
        }
        db.flush().map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    /// Return the number of accounts currently stored in the database.
    /// This is used by the node to decide whether the state database is
    /// empty and needs to be rebuilt from the block history.
    pub fn account_count(&self) -> usize {
        let mut db = self.db.lock().unwrap();
        match collect_keys(&mut db) {
            Ok(keys) => keys.len(),
            Err(_) => 0,
        }
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
    /// live path resolves maturity at the same point every time. This
    /// keeps `acc.balance` and `acc.immature_rewards` consistent.
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
        let mut db = self.db.lock().unwrap();
        db.flush().map_err(|e| format!("{:?}", e))
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

/// Collect every key currently stored in the database.
///
/// The iterator returned by `rusty-leveldb` does not seek to the first
/// entry automatically. Without an explicit `seek_to_first`, the loop
/// below would either return nothing or start from an arbitrary point,
/// which is why the previous version of `reset` left stale accounts in
/// the database. The explicit seek fixes that.
fn collect_keys(db: &mut LevelDB) -> Result<Vec<Vec<u8>>, String> {
    let mut iter = db.new_iter().map_err(|e| format!("{:?}", e))?;
    iter.seek_to_first();
    let mut keys = Vec::new();
    while let Some((key, _)) = iter.next() {
        keys.push(key);
    }
    Ok(keys)
}
