// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Undo data for fast chain reorganization.
//!
//! Bitcoin does not commit to a state root in the block header. Instead,
//! it stores a reverse patch for every block in `rev*.dat` files. When a
//! reorganization happens, the node reads the undo data for the blocks
//! that are being disconnected and applies the reverse patch to the
//! state, which restores the exact state that existed before those
//! blocks were applied.
//!
//! XEPAY uses the same approach, adapted to the account-based model.
//! For every block, the undo file stores the previous value of every
//! account that the block modifies (sender, recipient, and miner). When
//! the block is disconnected, the stored accounts are written back to
//! the state database, which restores the pre-block state without
//! replaying the whole chain from genesis.

use std::path::PathBuf;

use crate::datadir;
use crate::storage::Account;

/// One account snapshot: the address and the account value that existed
/// before the block was applied.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UndoEntry {
    pub address: String,
    pub account: Account,
}

/// Undo data for a single block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UndoData {
    pub height: u64,
    pub entries: Vec<UndoEntry>,
}

impl UndoData {
    pub fn new(height: u64) -> Self {
        UndoData {
            height,
            entries: Vec::new(),
        }
    }

    /// Record the pre-block value of an account. If the account is
    /// already recorded, the earlier value is kept, because that is the
    /// value that existed before the block started.
    pub fn record(&mut self, address: &str, account: Account) {
        if self.entries.iter().any(|e| e.address == address) {
            return;
        }
        self.entries.push(UndoEntry {
            address: address.to_string(),
            account,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Return the path of the undo file for the given block height.
pub fn undo_file(height: u64) -> PathBuf {
    datadir::undo_dir().join(format!("rev{:08}.bin", height))
}

/// Persist the undo data for a block. The write is atomic: the data is
/// written to a temporary file and then renamed into place, so a crash
/// in the middle of the write cannot leave a half-written undo file.
pub fn save(undo: &UndoData) -> Result<(), String> {
    datadir::ensure_dirs().map_err(|e| e.to_string())?;
    let path = undo_file(undo.height);
    let tmp = path.with_extension("bin.tmp");

    let encoded = bincode::serialize(undo).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, &encoded).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Load the undo data for a block. Returns `None` when the file does not
/// exist, which means the block was applied by an older build that did
/// not write undo data, or the block is the genesis block.
pub fn load(height: u64) -> Result<Option<UndoData>, String> {
    let path = undo_file(height);
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let undo: UndoData = bincode::deserialize(&data).map_err(|e| e.to_string())?;
    Ok(Some(undo))
}

/// Delete the undo file for a block. This is called when the block is
/// disconnected and its undo data has been applied, or when the node
/// performs a full reindex and the undo files are rebuilt from scratch.
pub fn delete(height: u64) -> Result<(), String> {
    let path = undo_file(height);
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Delete every undo file. Used by the reindex path before the undo
/// files are rebuilt from the block history.
pub fn delete_all() -> Result<(), String> {
    let dir = datadir::undo_dir();
    if !dir.exists() {
        return Ok(());
    }
    let entries = std::fs::read_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("bin") {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
