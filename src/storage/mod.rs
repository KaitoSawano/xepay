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
pub use block_index::BlockIndex;

// Fungsi khusus buat P2P: Cuma nulis block ke disk, nggak nulis state.
// Ini biar P2P nggak ganggu proses Mining.
pub fn save_block_only(block: &crate::block::Block) -> Result<(), String> {
    let store = BlockStore::open_default()
        .map_err(|e| format!("failed to open block store: {}", e))?;
    store.write_block(block)
        .map_err(|e| format!("failed to write block: {}", e))?;
    Ok(())
}

pub use crate::storage_legacy::*;
