// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Legacy storage functions (blocks, mempool, state snapshot).

use std::collections::BTreeMap;
use std::io::{Error, Read, Write};

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::consensus::genesis;
use crate::consensus::spec;
use crate::datadir;
use crate::storage::Account;
use crate::storage::BlockStore;
use crate::validation;

pub const BLOCKS_PER_FILE: usize = 1000;

/// Persist the chain to disk.
///
/// The order of operations is important:
///   1. Flush the state database so that `root_hash.txt` is written.
///   2. Save the mempool and state snapshot.
///   3. Persist every block that is not yet in the append-only block store.
///
/// Blocks are normally written to disk by `save_block_only` as soon as they
/// are accepted through P2P, but blocks produced by the local miner
/// (`generatetoaddress`) or submitted through RPC (`submitblock`) never go
/// through that path. This function closes the gap: it walks the in-memory
/// chain and appends any missing block to the block store. `write_block` is
/// idempotent, so calling it on every save is safe.
pub fn save_chain(chain: &mut Blockchain) -> std::io::Result<()> {
    datadir::ensure_dirs()?;

    // Step 1: flush the state database so that root_hash.txt is written.
    chain
        .state
        .flush()
        .map_err(|e| Error::other(format!("failed to flush state: {}", e)))?;

    // Step 2: persist mempool and the state snapshot.
    save_mempool(&chain.mempool)?;
    save_state_snapshot(chain)?;

    // Step 3: persist every block to the append-only block store.
    // `write_block` is idempotent, so re-writing already-stored blocks
    // is harmless and guarantees that locally mined blocks are persisted.
    if let Ok(store) = BlockStore::open_default() {
        for block in &chain.chain {
            if let Err(e) = store.write_block(block) {
                eprintln!(
                    "[storage] WARNING: failed to persist block {}: {}",
                    block.index, e
                );
            }
        }
    }

    Ok(())
}

pub fn load_chain() -> std::io::Result<Blockchain> {
    let db_path = datadir::state_db_path();

    let store = BlockStore::open_default()
        .map_err(|e| Error::other(format!("failed to open block store: {}", e)))?;

    let mut blocks = store
        .all_blocks()
        .map_err(|e| Error::other(format!("failed to read blocks: {}", e)))?;

    let expected_genesis_hash =
        genesis::expected_genesis_hash_for(spec::current_network());

    // If the block store does not start with genesis, try to find it
    // among the stored blocks and prepend it. This handles datadirs that
    // were created by older versions of the code, which never persisted
    // the genesis block to the append-only store.
    if !blocks.is_empty()
        && (blocks[0].index != 0 || blocks[0].hash != expected_genesis_hash)
    {
        if let Some(pos) = blocks
            .iter()
            .position(|b| b.index == 0 && b.hash == expected_genesis_hash)
        {
            let genesis_block = blocks.remove(pos);
            blocks.insert(0, genesis_block);
            if let Err(e) = store.write_block(&blocks[0]) {
                eprintln!(
                    "[storage] WARNING: failed to persist recovered genesis block: {}",
                    e
                );
            }
        }
    }

    // Fallback: if the block index is empty (for example, because the
    // datadir was created before the append-only block store was
    // introduced), read blocks from the legacy whole-Vec files and
    // re-index them into the block store so that future starts are fast.
    if blocks.is_empty() {
        let legacy = load_blocks()?;
        if !legacy.is_empty() {
            for block in &legacy {
                let _ = store.write_block(block);
            }
            blocks = legacy;
        }
    }

    if blocks.is_empty() {
        return Ok(Blockchain::new());
    }

    // If the stored chain still does not start with genesis, reconstruct
    // the genesis block from the compiled-in parameters and prepend it.
    // This is safe because the genesis block is deterministic and the
    // first stored block must extend it. Datadirs created before the
    // genesis block was persisted to the block store fall into this
    // branch and are recovered without requiring a full reindex.
    if blocks[0].index != 0 {
        let genesis_block = Block::genesis();
        if blocks[0].index == 1
            && blocks[0].previous_hash == genesis_block.hash
            && genesis_block.hash == expected_genesis_hash
        {
            if let Err(e) = store.write_block(&genesis_block) {
                eprintln!(
                    "[storage] WARNING: failed to persist reconstructed genesis block: {}",
                    e
                );
            }
            blocks.insert(0, genesis_block);
        } else {
            return Err(Error::other(
                "consensus failure: the first block on disk is not the genesis block.",
            ));
        }
    }
    if blocks[0].previous_hash != crate::consensus::rules::ZERO_HASH {
        return Err(Error::other(
            "consensus failure: the genesis block previous_hash is not zero.",
        ));
    }

    // FIX: Force the genesis block's state_root to be empty and recompute
    // its hash. The genesis block was originally mined with an empty
    // state_root, and its hash must match EXPECTED_GENESIS_HASH. An older
    // version of the code accidentally filled in the genesis state_root
    // after initialization, which made the on-disk hash inconsistent
    // with the recomputed hash. This fix restores consistency without
    // requiring a reindex.
    if let Some(genesis) = blocks.first_mut() {
        genesis.state_root = String::new();
        genesis.hash = genesis.calculate_hash();
    }

    // ------------------------------------------------------------------
    // Genesis hash validation
    // ------------------------------------------------------------------
    //
    // Verify that the genesis block on disk matches the expected genesis
    // hash for the current network. If it does not match, the on-disk
    // chain was created with a different genesis block (for example,
    // before a hard fork) and must be reindexed or deleted.
    //
    // This check mirrors the behaviour of reference node implementations,
    // which refuse to start when the on-disk genesis block does not match
    // the consensus parameters compiled into the binary.
    if blocks[0].hash != expected_genesis_hash {
        return Err(Error::other(format!(
            "consensus failure: the genesis block on disk (hash {}) does not match \
             the expected genesis hash ({}). The on-disk chain was created with a \
             different genesis block. This usually means the datadir was created \
             before a hard fork. To fix, delete the datadir and restart:\n\
             \n    rm -rf {}\n\
             \nAlternatively, run with -reindex to rebuild the state from the \
             block history. Note that -reindex alone does not replace the genesis \
             block; if the genesis hash does not match, the datadir must be deleted.",
            blocks[0].hash,
            expected_genesis_hash,
            datadir::as_str(&datadir::datadir())
        )));
    }

    let mempool = load_mempool().unwrap_or_default();

    // Check the reindex mode.
    let reindex_requested = std::env::var("XEPAY_REINDEX").is_ok();

    if reindex_requested {
        eprintln!("[node] Manual reindex requested. Deleting state database...");
        let _ = std::fs::remove_dir_all(&db_path);

        // Delete root_hash.txt so that the trie starts from empty.
        let root_path = datadir::chainstate_dir().join("root_hash.txt");
        let _ = std::fs::remove_file(root_path);
    }

    let state = crate::storage::StateDB::open(&db_path)
        .map_err(|e| Error::other(format!("failed to open state db: {}", e)))?;

    let mut chain = Blockchain {
        chain: blocks,
        nbits: crate::consensus::spec::current_network().genesis_nbits(),
        mempool,
        balances: std::collections::HashMap::new(),
        nonces: std::collections::HashMap::new(),
        mempool_timestamps: std::collections::HashMap::new(),
        addresses: Vec::new(),
        state,
    };

    // Populate the address list from the state snapshot and from the
    // block history. The address list is used by GetStateRange to serve
    // accounts to peers during fast sync, so it must be complete even if
    // the snapshot file is missing or empty.
    chain.addresses.push("GENESIS".to_string());

    let snapshot_path = datadir::chainstate_dir().join("state_snapshot.json");
    if let Ok(data) = std::fs::read_to_string(&snapshot_path) {
        if let Ok(map) =
            serde_json::from_str::<std::collections::HashMap<String, serde_json::Value>>(&data)
        {
            for addr in map.keys() {
                if !chain.addresses.contains(addr) {
                    chain.addresses.push(addr.clone());
                }
            }
        }
    }

    // Always walk the block history to recover addresses that are not
    // present in the snapshot. This is cheap because the chain is
    // already loaded in memory.
    for block in chain.chain.iter() {
        if !block.mined_for.is_empty() && !chain.addresses.contains(&block.mined_for) {
            chain.addresses.push(block.mined_for.clone());
        }
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                continue;
            }
            if !chain.addresses.contains(&tx.from) {
                chain.addresses.push(tx.from.clone());
            }
            if !chain.addresses.contains(&tx.to) {
                chain.addresses.push(tx.to.clone());
            }
        }
    }

    println!(
        "[node] loaded {} addresses from state snapshot and block history",
        chain.addresses.len()
    );

    if reindex_requested {
        eprintln!("[node] Rebuilding state from block history...");
        if let Err(e) = rebuild_state_from_blocks(&mut chain) {
            eprintln!("[node] FATAL: Reindex failed: {}", e);
            std::process::exit(1);
        }

        // Flush after reindex so that the root hash is persisted.
        if let Err(e) = chain.state.flush() {
            eprintln!("[node] FATAL: Failed to flush state after reindex: {}", e);
            std::process::exit(1);
        }

        eprintln!("[node] Reindex successful! State fully rebuilt from blocks.");
    } else {
        // Strict verification: the node refuses to start with an
        // inconsistent state. The caller (AppInit) decides whether to
        // exit or prompt the user to run with -reindex.
        if let Err(e) = verify_state_root(&mut chain) {
            return Err(Error::other(format!(
                "state root verification failed: {}. \
                 The state database is corrupted or out of sync. \
                 Run with -reindex to rebuild the state from the block history.",
                e
            )));
        }
    }

    Ok(chain)
}

fn rebuild_state_from_blocks(chain: &mut Blockchain) -> std::io::Result<()> {
    let blocks = chain.chain.clone();

    if let Some(genesis_block) = blocks.first() {
        chain.state.update_account(
            "GENESIS",
            &Account {
                nonce: 0,
                balance: genesis_block.reward,
                immature_rewards: BTreeMap::new(),
                code: Vec::new(),
                storage: BTreeMap::new(),
            },
        ).map_err(Error::other)?;
    }

    for block in blocks.iter().skip(1) {
        for tx in &block.transactions {
            if !validation::is_special_tx(tx) {
                chain.state.apply_transaction(
                    &tx.from,
                    &tx.to,
                    tx.amount,
                    tx.fee,
                    tx.nonce,
                    block.index,
                ).map_err(|e| Error::other(format!("Failed to apply tx {}: {}", tx.txid, e)))?;
                if !chain.addresses.contains(&tx.from) {
                    chain.addresses.push(tx.from.clone());
                }
                if !chain.addresses.contains(&tx.to) {
                    chain.addresses.push(tx.to.clone());
                }
            }
        }
        chain.state.credit_reward(&block.mined_for, block.reward, block.index)
            .map_err(|e| Error::other(format!("Failed to credit reward block {}: {}", block.index, e)))?;
        if !block.mined_for.is_empty() && !chain.addresses.contains(&block.mined_for) {
            chain.addresses.push(block.mined_for.clone());
        }
    }

    println!(
        "[node] reindex populated {} addresses",
        chain.addresses.len()
    );
    Ok(())
}

/// Verify that the state database matches the state root committed in the
/// tip block. Returns an error if the roots do not match.
///
/// This function does NOT call `std::process::exit`. It returns an error
/// to the caller so that the caller can decide how to handle the
/// inconsistency (e.g. print a message and exit, or retry with reindex).
fn verify_state_root(chain: &mut Blockchain) -> std::io::Result<()> {
    if chain.chain.is_empty() {
        return Ok(());
    }

    let tip = chain.chain.last().unwrap();

    if tip.state_root.is_empty() {
        return Ok(());
    }

    let current_root = chain
        .state
        .root_hash()
        .map_err(|e| Error::other(format!("failed to compute state root: {}", e)))?;

    let current_root_hex = hex::encode(current_root);

    if current_root_hex != tip.state_root {
        return Err(Error::other(format!(
            "state root mismatch at height {}.\nExpected: {}\nGot:      {}",
            tip.index, tip.state_root, current_root_hex
        )));
    }

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AccountSnapshot {
    nonce: u64,
    balance: u64,
    /// Immature rewards keyed by height. The snapshot mirrors the
    /// in-memory account representation so that a snapshot written by an
    /// older build (which stored a `Vec`) fails to deserialize instead
    /// of silently producing a different state.
    immature_rewards: BTreeMap<u64, u64>,
    code: Vec<u8>,
    storage: Vec<(String, String)>,
}

pub fn save_state_snapshot(chain: &Blockchain) -> std::io::Result<()> {
    // Write the snapshot even if the address list is small, so that
    // load_chain can recover the addresses from it on the next start.
    let mut accounts: std::collections::HashMap<String, AccountSnapshot> =
        std::collections::HashMap::new();

    for addr in &chain.addresses {
        if let Ok(Some(acc)) = chain.state.get_account(addr) {
            let storage_hex: Vec<(String, String)> = acc
                .storage
                .iter()
                .map(|(k, v)| (hex::encode(k), hex::encode(v)))
                .collect();
            accounts.insert(
                addr.clone(),
                AccountSnapshot {
                    nonce: acc.nonce,
                    balance: acc.balance,
                    immature_rewards: acc.immature_rewards,
                    code: acc.code,
                    storage: storage_hex,
                },
            );
        }
    }

    let json = serde_json::to_string_pretty(&accounts).map_err(Error::other)?;
    std::fs::write(datadir::chainstate_dir().join("state_snapshot.json"), json)
}

/// Write all blocks in the chain to the legacy whole-Vec block files.
///
/// This function is kept for backward compatibility with datadirs
/// created before the append-only block store was introduced. New
/// blocks are written by `save_block_only` through the block store.
pub fn save_blocks(chain: &Blockchain) -> std::io::Result<()> {
    let total = chain.chain.len();
    let mut file_index = 0u32;
    let mut written = 0usize;

    while written < total {
        let end = (written + BLOCKS_PER_FILE).min(total);
        let slice = &chain.chain[written..end];
        let path = datadir::block_file(file_index);

        let encoded = bincode::serialize(slice)
            .map_err(|e| Error::other(format!("bincode serialize error: {}", e)))?;

        let mut file = std::fs::File::create(path)?;
        file.write_all(&encoded)?;
        file.flush()?;

        written = end;
        file_index += 1;
    }
    Ok(())
}

/// Load all blocks from the legacy whole-Vec block files.
///
/// The loader tries the whole-`Vec<Block>` format first, because that is
/// the format written by `save_blocks` and used by datadirs created
/// before the append-only block store was introduced. If that fails, it
/// falls back to the length-prefixed append format written by
/// `crate::storage::save_block_only`.
pub fn load_blocks() -> std::io::Result<Vec<Block>> {
    let mut all: Vec<Block> = Vec::new();
    let mut i = 0u32;

    loop {
        let path = datadir::block_file(i);
        if !path.exists() {
            break;
        }

        let mut file = std::fs::File::open(&path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            i += 1;
            continue;
        }

        // Try the whole-Vec format first.
        match bincode::deserialize::<Vec<Block>>(&buffer) {
            Ok(mut chunk) => {
                all.append(&mut chunk);
                i += 1;
                continue;
            }
            Err(_) => {}
        }

        // Fall back to the length-prefixed append format.
        let mut offset = 0usize;
        let mut ok = true;
        let mut blocks = Vec::new();
        while offset + 4 <= buffer.len() {
            let len_bytes = &buffer[offset..offset + 4];
            let len = u32::from_le_bytes([
                len_bytes[0],
                len_bytes[1],
                len_bytes[2],
                len_bytes[3],
            ]) as usize;
            offset += 4;
            if offset + len > buffer.len() {
                ok = false;
                break;
            }
            match bincode::deserialize::<Block>(&buffer[offset..offset + len]) {
                Ok(b) => blocks.push(b),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
            offset += len;
        }

        if ok && !blocks.is_empty() {
            all.extend(blocks);
            i += 1;
            continue;
        }

        return Err(Error::other(format!(
            "bincode deserialize error in {}",
            path.display()
        )));
    }
    Ok(all)
}

pub fn save_mempool(mempool: &[crate::transaction::Transaction]) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(mempool).map_err(Error::other)?;
    std::fs::write(datadir::mempool_path(), json)
}

pub fn load_mempool() -> std::io::Result<Vec<crate::transaction::Transaction>> {
    let data = std::fs::read_to_string(datadir::mempool_path())?;
    let v: Vec<crate::transaction::Transaction> =
        serde_json::from_str(&data).map_err(Error::other)?;
    Ok(v)
}
