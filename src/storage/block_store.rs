// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Append-only block storage in flat files, modeled after Bitcoin Core's
//! `blk*.dat` files. Each block is written with a 4-byte network magic
//! followed by a 4-byte little-endian size and the bincode-encoded block.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::block::Block;
use crate::storage::block_index::BlockIndex;
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
    /// updated with the file number and offset.
    pub fn write_block(&self, block: &Block) -> Result<(), String> {
        if self.index.contains(&block.hash) {
            return Ok(());
        }

        let magic = spec::current_network().magic();
        let encoded = bincode::serialize(block).map_err(|e| e.to_string())?;
        let size = encoded.len() as u32;

        let (file_number, offset) = self.append_to_file(&magic, size, &encoded)?;

        self.index
            .insert(&block.hash, file_number, offset, block.index)
            .map_err(|e| format!("failed to update block index: {}", e))?;

        Ok(())
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
        let (file_number, offset) = match self.index.get(hash)? {
            Some(v) => v,
            None => return Ok(None),
        };

        let path = self.block_file_path(file_number);
        let mut file = File::open(&path)
            .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;

        file.seek(SeekFrom::Start(offset))
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

    /// Iterate over all blocks in order of height using the index.
    pub fn all_blocks(&self) -> Result<Vec<Block>, String> {
        let entries = self.index.all_entries()?;
        let mut sorted: Vec<(String, u32, u64, u64)> = entries;
        sorted.sort_by_key(|(_, _, _, height)| *height);

        let mut blocks = Vec::with_capacity(sorted.len());
        for (hash, _, _, _) in sorted {
            if let Some(block) = self.read_block(&hash)? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }
}
