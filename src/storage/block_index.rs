// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Persistent block index backed by LevelDB. Stores the file number,
//! byte offset, and height for each block hash.

use std::path::Path;
use std::sync::Mutex;

use rusty_leveldb::{LdbIterator, Options, DB as LevelDB};

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

    pub fn get(&self, hash: &str) -> Result<Option<(u32, u64)>, String> {
        let mut db = self.db.lock().unwrap();
        match db.get(hash.as_bytes()) {
            Some(value) if value.len() >= 12 => {
                let file_number = u32::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ]);
                let offset = u64::from_le_bytes([
                    value[4], value[5], value[6], value[7],
                    value[8], value[9], value[10], value[11],
                ]);
                Ok(Some((file_number, offset)))
            }
            _ => Ok(None),
        }
    }

    pub fn insert(
        &self,
        hash: &str,
        file_number: u32,
        offset: u64,
        height: u64,
    ) -> Result<(), String> {
        let mut value = Vec::with_capacity(20);
        value.extend_from_slice(&file_number.to_le_bytes());
        value.extend_from_slice(&offset.to_le_bytes());
        value.extend_from_slice(&height.to_le_bytes());

        let mut db = self.db.lock().unwrap();
        db.put(hash.as_bytes(), &value)
            .map_err(|e| format!("{:?}", e))?;
        Ok(())
    }

    pub fn all_entries(&self) -> Result<Vec<(String, u32, u64, u64)>, String> {
        let mut db = self.db.lock().unwrap();
        let mut entries: Vec<(String, u32, u64, u64)> = Vec::new();
        let mut iter = db.new_iter().map_err(|e| format!("{:?}", e))?;

        while let Some((key, value)) = iter.next() {
            if value.len() >= 20 {
                let hash = String::from_utf8_lossy(&key).to_string();
                let file_number = u32::from_le_bytes([
                    value[0], value[1], value[2], value[3],
                ]);
                let offset = u64::from_le_bytes([
                    value[4], value[5], value[6], value[7],
                    value[8], value[9], value[10], value[11],
                ]);
                let height = u64::from_le_bytes([
                    value[12], value[13], value[14], value[15],
                    value[16], value[17], value[18], value[19],
                ]);
                entries.push((hash, file_number, offset, height));
            }
        }

        Ok(entries)
    }
}
