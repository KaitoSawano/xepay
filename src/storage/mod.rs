// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Storage layer for XEPAY.

pub mod account;
pub mod adapter;
pub mod state;
pub mod block_store;
pub mod block_index;

pub use account::Account;
pub use state::StateDB;
pub use block_store::BlockStore;
pub use block_index::{BlockIndex, BlockIndexEntry, BlockStatus};

// Fungsi khusus buat P2P: Cuma nulis block ke disk, nggak nulis state.
// Ini biar P2P nggak ganggu proses Mining.
pub fn save_block_only(block: &crate::block::Block) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.write_block(block, BlockStatus::Active)
        .map_err(|e| format!("failed to write block: {}", e))?;
    Ok(())
}

/// Save a block that has been validated but does not extend the current
/// active chain. The block is stored on disk and indexed with the
/// `ValidFork` status, so that it can be connected later if its branch
/// gains more chainwork.
pub fn save_side_chain_block(block: &crate::block::Block) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.write_block(block, BlockStatus::ValidFork)
        .map_err(|e| format!("failed to write side chain block: {}", e))?;
    Ok(())
}

/// Switch the status of a stored block. Used during a reorganization to
/// demote the old active tip to `ValidFork` and promote the new tip to
/// `Active`.
pub fn set_block_status(hash: &str, status: BlockStatus) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.set_status(hash, status)
        .map_err(|e| format!("failed to update block status: {}", e))?;
    Ok(())
}

pub use crate::storage_legacy::*;
