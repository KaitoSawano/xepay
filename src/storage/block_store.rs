// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Append-only block storage in flat files, modeled after Bitcoin Core's
//! `blk*.dat` files. Each block is written with a 4-byte network magic
//! followed by a 4-byte little-endian size and the bincode-encoded block.
//!
//! The store is shared by every branch of the block tree. A block is
//! written once, and its location is recorded in the block index. The
//! active chain is a path through the index; side branches are kept in
//! the same files and distinguished only by the index status.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::block::Block;
use crate::storage::block_index::{BlockIndex, BlockIndexEntry, BlockStatus};
use crate::consensus::spec;

/// Maximum size of a single block file before rolling over to a new one.
/// Mirrors the 128 MiB used by reference node implementations.
pub const MAX_BLOCKFILE_SIZE: u64 = 128 * 1024 * 1024;

pub struct BlockStore {
    blocks_dir: PathBuf,
    index: BlockIndex,
}

impl BlockStore {
    pub fn open(blocks_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(blocks_dir).map_err(|e| e.to_string())?;
        let index_path = blocks_dir.join("index");
        let index = BlockIndex::open(&index_path)?;
        Ok(BlockStore {
            blocks_dir: blocks_dir.to_path_buf(),
            index,
        })
    }

    pub fn open_default() -> Result<Self, String> {
        Self::open(&crate::datadir::blocks_dir())
    }

    pub fn index(&self) -> &BlockIndex {
        &self.index
    }

    /// Write a block to disk in append-only format.
    ///
    /// The block is written to the current file. If the file would exceed
    /// `MAX_BLOCKFILE_SIZE`, a new file is started. The block index is
    /// updated with the file number, offset, height, previous hash,
    /// chainwork, and status.
    ///
    /// The status is passed in by the caller because the store does not
    /// know whether the block belongs to the active chain or to a side
    /// branch. The active chain selection lives in the sync layer.
    pub fn write_block(&self, block: &Block, status: BlockStatus) -> Result<(), String> {
        if self.index.contains(&block.hash) {
            return Ok(());
        }

        let magic = spec::current_network().magic();
        let encoded = bincode::serialize(block).map_err(|e| e.to_string())?;
        let size = encoded.len() as u32;

        let (file_number, offset) = self.append_to_file(&magic, size, &encoded)?;

        self.index
            .insert(
                &block.hash,
                file_number,
                offset,
                block.index,
                &block.previous_hash,
                block.chainwork,
                status,
            )
            .map_err(|e| format!("failed to update block index: {}", e))?;

        Ok(())
    }

    /// Update the status of an already stored block.
    pub fn set_status(&self, hash: &str, status: BlockStatus) -> Result<(), String> {
        self.index.update_status(hash, status)
    }

    /// Return the block index entry for the given hash, if present.
    pub fn get_entry(&self, hash: &str) -> Result<Option<BlockIndexEntry>, String> {
        self.index.get(hash)
    }

    /// Return every entry in the index.
    pub fn all_entries(&self) -> Result<Vec<BlockIndexEntry>, String> {
        self.index.all_entries()
    }

    /// Return every entry whose status is `Active`.
    pub fn all_active(&self) -> Result<Vec<BlockIndexEntry>, String> {
        self.index.all_active()
    }

    /// Return every entry whose status is `ValidFork`.
    pub fn all_valid_forks(&self) -> Result<Vec<BlockIndexEntry>, String> {
        self.index.all_valid_forks()
    }

    fn append_to_file(
        &self,
        magic: &[u8; 4],
        size: u32,
        payload: &[u8],
    ) -> Result<(u32, u64), String> {
        let mut file_number = self.current_file_number()?;
        let mut path = self.block_file_path(file_number);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;

        let current_size = file.metadata().map_err(|e| e.to_string())?.len();

        if current_size >= MAX_BLOCKFILE_SIZE {
            file_number += 1;
            path = self.block_file_path(file_number);
            file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&path)
                .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
        }

        let offset = file.metadata().map_err(|e| e.to_string())?.len();

        file.write_all(magic).map_err(|e| e.to_string())?;
        file.write_all(&size.to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(payload).map_err(|e| e.to_string())?;
        file.flush().map_err(|e| e.to_string())?;

        Ok((file_number, offset))
    }

    fn current_file_number(&self) -> Result<u32, String> {
        let mut max = 0u32;
        let entries = std::fs::read_dir(&self.blocks_dir).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(num_str) = name.strip_prefix("blk").and_then(|s| s.strip_suffix(".dat")) {
                if let Ok(n) = num_str.parse::<u32>() {
                    max = max.max(n);
                }
            }
        }
        Ok(max)
    }

    fn block_file_path(&self, file_number: u32) -> PathBuf {
        self.blocks_dir.join(format!("blk{:05}.dat", file_number))
    }

    /// Read a block from disk using the index.
    pub fn read_block(&self, hash: &str) -> Result<Option<Block>, String> {
        let entry = match self.index.get(hash)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let path = self.block_file_path(entry.file_number);
        let mut file = File::open(&path)
            .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;

        file.seek(SeekFrom::Start(entry.offset))
            .map_err(|e| e.to_string())?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| e.to_string())?;

        let mut size_buf = [0u8; 4];
        file.read_exact(&mut size_buf).map_err(|e| e.to_string())?;
        let size = u32::from_le_bytes(size_buf) as usize;

        let mut payload = vec![0u8; size];
        file.read_exact(&mut payload).map_err(|e| e.to_string())?;

        let block: Block = bincode::deserialize(&payload).map_err(|e| e.to_string())?;
        Ok(Some(block))
    }

    /// Iterate over every block on the active chain, in height order.
    ///
    /// Side branches are skipped. The order is determined by the `index`
    /// field of each block, not by the order of the index iteration.
    pub fn all_blocks(&self) -> Result<Vec<Block>, String> {
        let entries = self.all_active()?;
        let mut sorted: Vec<BlockIndexEntry> = entries;
        sorted.sort_by_key(|e| e.height);

        let mut blocks = Vec::with_capacity(sorted.len());
        for entry in sorted {
            if let Some(block) = self.read_block(&entry.hash)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Iterate over every block in the index, on the active chain or on
    /// a side branch, in no particular order.
    pub fn all_blocks_all_branches(&self) -> Result<Vec<(BlockIndexEntry, Block)>, String> {
        let entries = self.all_entries()?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(block) = self.read_block(&entry.hash)? {
                out.push((entry, block));
            }
        }
        Ok(out)
    }
}
