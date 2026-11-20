// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Persistent block index backed by LevelDB. Stores the file number,
//! byte offset, height, previous hash, chainwork, and validation status
//! for each block hash.
//!
//! The index is the on-disk source of truth for the shape of the block
//! tree. Every block that has ever been accepted, including blocks that
//! are not on the active chain, has an entry here. This mirrors the
//! reference node's block index: the active chain is a path through the
//! tree, and side branches are kept until they are pruned.
//!
//! On-disk value layout (variable length):
//!   [0..4]    file_number   (u32, little-endian)
//!   [4..12]   offset        (u64, little-endian)
//!   [12..20]  height        (u64, little-endian)
//!   [20..52]  previous_hash (32 bytes, raw)
//!   [52..68]  chainwork     (u128, little-endian)
//!   [68]      status        (u8: 0=Active, 1=ValidFork, 2=Invalid)
//!
//! The legacy 20-byte layout written by older builds is still readable:
//! if the value is exactly 20 bytes, the previous hash is treated as the
//! zero hash, the chainwork is treated as zero, and the status is
//! treated as Active. This keeps old datadirs loadable for inspection,
//! but a full reindex is required to populate the new fields.

use std::path::Path;
use std::sync::Mutex;

use rusty_leveldb::{LdbIterator, Options, DB as LevelDB};

/// Validation status of a block in the block tree.
///
/// `Active` means the block is on the currently selected chain.
/// `ValidFork` means the block is fully valid and connected to the tree,
/// but its branch does not have the most chainwork. `Invalid` means the
/// block failed validation and must never be connected again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    Active = 0,
    ValidFork = 1,
    Invalid = 2,
}

impl BlockStatus {
    pub fn from_u8(v: u8) -> BlockStatus {
        match v {
            0 => BlockStatus::Active,
            1 => BlockStatus::ValidFork,
            _ => BlockStatus::Invalid,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A single entry in the block index.
#[derive(Debug, Clone)]
pub struct BlockIndexEntry {
    pub hash: String,
    pub file_number: u32,
    pub offset: u64,
    pub height: u64,
    pub previous_hash: String,
    pub chainwork: u128,
    pub status: BlockStatus,
}

pub struct BlockIndex {
    db: Mutex<LevelDB>,
}

impl BlockIndex {
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut opt = Options::default();
        opt.create_if_missing = true;
        let db = LevelDB::open(path, opt).map_err(|e| format!("{:?}", e))?;
        Ok(BlockIndex { db: Mutex::new(db) })
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.get(hash).ok().flatten().is_some()
    }

    /// Read a single entry. Returns `None` if the hash is not present.
    pub fn get(&self, hash: &str) -> Result<Option<BlockIndexEntry>, String> {
        let mut db = self.db.lock().unwrap();
        match db.get(hash.as_bytes()) {
            Some(value) => {
                let entry = decode_entry(hash, &value)?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Insert a new entry. If an entry with the same hash already exists,
    /// it is left untouched. Call `update_status` to change the status of
    /// an existing entry.
    pub fn insert(
        &self,
        hash: &str,
        file_number: u32,
        offset: u64,
        height: u64,
        previous_hash: &str,
        chainwork: u128,
        status: BlockStatus,
    ) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        if db.get(hash.as_bytes()).is_some() {
            return Ok(());
        }
        let value = encode_entry(file_number, offset, height, previous_hash, chainwork, status)?;
        db.put(hash.as_bytes(), &value)
            .map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    /// Update the status of an existing entry.
    pub fn update_status(&self, hash: &str, status: BlockStatus) -> Result<(), String> {
        let mut db = self.db.lock().unwrap();
        let value = match db.get(hash.as_bytes()) {
            Some(v) => v,
            None => return Err(format!("block index entry not found: {}", hash)),
        };
        let mut entry = decode_entry(hash, &value)?;
        if entry.status == status {
            return Ok(());
        }
        entry.status = status;
        let new_value = encode_entry(
            entry.file_number,
            entry.offset,
            entry.height,
            &entry.previous_hash,
            entry.chainwork,
            entry.status,
        )?;
        db.put(hash.as_bytes(), &new_value)
            .map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    /// Return every entry in the index.
    pub fn all_entries(&self) -> Result<Vec<BlockIndexEntry>, String> {
        let mut db = self.db.lock().unwrap();
        let mut entries: Vec<BlockIndexEntry> = Vec::new();
        let mut iter = db.new_iter().map_err(|e| format!("{:?}", e))?;

        while let Some((key, value)) = iter.next() {
            let hash = String::from_utf8_lossy(&key).to_string();
            let entry = decode_entry(&hash, &value)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Return every entry whose status is `Active`.
    pub fn all_active(&self) -> Result<Vec<BlockIndexEntry>, String> {
        let mut out = Vec::new();
        for entry in self.all_entries()? {
            if entry.status == BlockStatus::Active {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Return every entry whose status is `ValidFork`.
    pub fn all_valid_forks(&self) -> Result<Vec<BlockIndexEntry>, String> {
        let mut out = Vec::new();
        for entry in self.all_entries()? {
            if entry.status == BlockStatus::ValidFork {
                out.push(entry);
            }
        }
        Ok(out)
    }
}

fn encode_entry(
    file_number: u32,
    offset: u64,
    height: u64,
    previous_hash: &str,
    chainwork: u128,
    status: BlockStatus,
) -> Result<Vec<u8>, String> {
    let mut value = Vec::with_capacity(69);
    value.extend_from_slice(&file_number.to_le_bytes());
    value.extend_from_slice(&offset.to_le_bytes());
    value.extend_from_slice(&height.to_le_bytes());
    let prev_bytes = hex::decode(previous_hash)
        .map_err(|e| format!("invalid previous_hash hex: {}", e))?;
    if prev_bytes.len() != 32 {
        return Err("previous_hash must be 32 bytes".into());
    }
    value.extend_from_slice(&prev_bytes);
    value.extend_from_slice(&chainwork.to_le_bytes());
    value.push(status.as_u8());
    Ok(value)
}

fn decode_entry(hash: &str, value: &[u8]) -> Result<BlockIndexEntry, String> {
    if value.len() == 20 {
        // Legacy layout: file_number, offset, height only.
        let file_number = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
        let offset = u64::from_le_bytes([
            value[4], value[5], value[6], value[7],
            value[8], value[9], value[10], value[11],
        ]);
        let height = u64::from_le_bytes([
            value[12], value[13], value[14], value[15],
            value[16], value[17], value[18], value[19],
        ]);
        return Ok(BlockIndexEntry {
            hash: hash.to_string(),
            file_number,
            offset,
            height,
            previous_hash: "0".repeat(64),
            chainwork: 0,
            status: BlockStatus::Active,
        });
    }

    if value.len() < 69 {
        return Err(format!(
            "block index entry has unexpected length {} (expected at least 69)",
            value.len()
        ));
    }

    let file_number = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
    let offset = u64::from_le_bytes([
        value[4], value[5], value[6], value[7],
        value[8], value[9], value[10], value[11],
    ]);
    let height = u64::from_le_bytes([
        value[12], value[13], value[14], value[15],
        value[16], value[17], value[18], value[19],
    ]);
    let previous_hash = hex::encode(&value[20..52]);
    let mut cw_bytes = [0u8; 16];
    cw_bytes.copy_from_slice(&value[52..68]);
    let chainwork = u128::from_le_bytes(cw_bytes);
    let status = BlockStatus::from_u8(value[68]);

    Ok(BlockIndexEntry {
        hash: hash.to_string(),
        file_number,
        offset,
        height,
        previous_hash,
        chainwork,
        status,
    })
}
