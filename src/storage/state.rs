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

pub struct StateDB {
    trie: EthTrie<LevelDbAdapter>,
    adapter: Arc<LevelDbAdapter>,
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

        let maturity = crate::consensus::rules::COINBASE_MATURITY;
        let mut mature_balance = from_acc.balance;
        let mut still_immature = Vec::new();
        for (height, reward_amount) in from_acc.immature_rewards.drain(..) {
            if current_height >= height.saturating_add(maturity) {
                mature_balance = mature_balance
                    .checked_add(reward_amount)
                    .ok_or_else(|| "balance overflow during maturity".to_string())?;
            } else {
                still_immature.push((height, reward_amount));
            }
        }
        from_acc.immature_rewards = still_immature;

        if mature_balance < total {
            return Err(format!(
                "insufficient mature balance: required {}, available {}",
                total, mature_balance
            ));
        }

        let remaining_mature = mature_balance
            .checked_sub(total)
            .ok_or_else(|| "underflow during deduction".to_string())?;

        from_acc.balance = remaining_mature;
        from_acc.nonce = from_acc
            .nonce
            .checked_add(1)
            .ok_or_else(|| "sender nonce overflow".to_string())?;

        if from != to {
            let mut to_acc = self.get_account(to)?.unwrap_or(Account {
                nonce: 0,
                balance: 0,
                immature_rewards: Vec::new(),
                code: Vec::new(),
                storage: BTreeMap::new(),
            });
            to_acc.balance = to_acc
                .balance
                .checked_add(amount)
                .ok_or_else(|| "recipient balance overflow".to_string())?;
            self.update_account(to, &to_acc)?;
        } else {
            from_acc.balance = from_acc
                .balance
                .checked_add(amount)
                .ok_or_else(|| "self-send refund overflow".to_string())?;
        }

        self.update_account(from, &from_acc)?;
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
