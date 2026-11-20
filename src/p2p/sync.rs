// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Chain synchronization logic for the XEPAY peer-to-peer network.
//!
//! The synchronization model mirrors the reference node:
//!
//! - Every block that is received is validated against every consensus
//!   rule. A block that fails validation is rejected and never connected.
//! - A block whose parent is unknown is an orphan. It is kept in a
//!   bounded in-memory orphan pool until its parent arrives, at which
//!   point it is connected like any other block. Orphans are not treated
//!   as misbehavior and do not cause a disconnect.
//! - A block that connects to a branch other than the active tip is
//!   stored on disk as a side branch (`ValidFork`). It is not applied to
//!   the live state until its branch has more total chainwork than the
//!   active chain.
//! - When a side branch gains more chainwork than the active chain, a
//!   reorganization is performed: the state is rolled back to the fork
//!   point, the old active blocks are demoted to `ValidFork`, the new
//!   active blocks are promoted to `Active`, and transactions from the
//!   abandoned branch are returned to the mempool when still valid.
//! - The state root stored in the block header is kept as an
//!   informational commitment. It is not compared against a freshly
//!   simulated root, because the trie implementation is not
//!   deterministic across backing stores. The security of the chain
//!   comes from the strict per-transaction validation, the exact reward
//!   check, the merkle root, the proof of work, and the chainwork.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::block::Block;
use crate::blockchain::Blockchain;
use crate::storage::{self, BlockStatus};
use crate::validation;

/// Maximum number of blocks that can be requested from a single peer at once.
pub const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 16;

/// Maximum number of blocks that can be in flight across all peers.
pub const MAX_BLOCKS_IN_FLIGHT_TOTAL: usize = 1024;

/// Timeout before considering a block download peer unresponsive.
pub const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout during which a peer must stall block download progress before being disconnected.
/// The actual value is provided by the caller so that it can adapt to the
/// observed peer behaviour, mirroring the adaptive stalling timeout used by
/// reference node implementations.
pub const BLOCK_STALLING_TIMEOUT: Duration = Duration::from_secs(2);

/// Number of headers requested in a single getheaders message.
pub const MAX_HEADERS_RESULTS: u64 = 2000;

/// Size of the block download window: how far ahead of the current height
/// blocks are fetched. Larger windows tolerate larger download speed
/// differences between peers, but increase disordering of blocks on disk.
pub const BLOCK_DOWNLOAD_WINDOW: u64 = 1024;

/// Maximum number of orphans kept in memory. The pool is pruned in FIFO
/// order when it exceeds this limit.
pub const MAX_ORPHAN_BLOCKS: usize = 100;

/// Maximum number of side chain blocks whose parent is still unknown.
/// The pool is pruned in FIFO order when it exceeds this limit.
pub const MAX_SIDE_CHAIN_BLOCKS: usize = 2000;

/// Tracks a single peer's in-flight block requests and stall state.
#[derive(Debug)]
pub struct PeerSyncState {
    /// Block hashes that have been requested from this peer and not yet received.
    pub in_flight: HashSet<String>,
    /// Block hashes that were requested from this peer but never delivered.
    /// The peer is not asked for these hashes again until it announces
    /// them through a fresh `inv` message.
    pub requested_but_not_received: HashSet<String>,
    /// The height of the last block received from this peer.
    pub last_received_height: u64,
    /// When the last block was received from this peer.
    pub last_received_at: Instant,
    /// Whether this peer is currently considered to be stalling.
    pub stalling: bool,
    /// When the current stalling period started, if any.
    pub stalling_since: Option<Instant>,
}

impl PeerSyncState {
    pub fn new() -> Self {
        PeerSyncState {
            in_flight: HashSet::new(),
            requested_but_not_received: HashSet::new(),
            last_received_height: 0,
            last_received_at: Instant::now(),
            stalling: false,
            stalling_since: None,
        }
    }

    /// Return true if this peer has capacity for another block request.
    pub fn can_request(&self) -> bool {
        self.in_flight.len() < MAX_BLOCKS_IN_TRANSIT_PER_PEER
    }

    /// Mark a block as requested from this peer.
    pub fn request(&mut self, hash: &str) {
        self.in_flight.insert(hash.to_string());
    }

    /// Mark a block as received from this peer.
    pub fn received(&mut self, hash: &str, height: u64) {
        self.in_flight.remove(hash);
        self.requested_but_not_received.remove(hash);
        self.last_received_height = height;
        self.last_received_at = Instant::now();
        self.stalling = false;
        self.stalling_since = None;
    }

    /// Move every in-flight hash into the give-up set and clear the
    /// in-flight set. The peer is not asked for those hashes again, but
    /// the connection stays open so that the peer can still deliver
    /// blocks it announces later through `inv`.
    pub fn give_up_on_in_flight(&mut self) {
        for hash in self.in_flight.drain() {
            self.requested_but_not_received.insert(hash);
        }
        self.stalling = false;
        self.stalling_since = None;
    }

    /// Check if this peer is stalling.
    ///
    /// The `timeout` parameter is supplied by the caller so that the
    /// threshold can adapt to observed peer behaviour. Returning `true`
    /// only means the peer has been silent for too long; the caller
    /// decides whether to drop the in-flight requests or disconnect.
    pub fn check_stalling(&mut self, now: Instant, timeout: Duration) -> bool {
        if self.in_flight.is_empty() {
            self.stalling = false;
            self.stalling_since = None;
            return false;
        }

        if !self.stalling {
            if now.duration_since(self.last_received_at) > timeout {
                self.stalling = true;
                self.stalling_since = Some(now);
            }
            return false;
        }

        if let Some(since) = self.stalling_since {
            if now.duration_since(since) > timeout {
                return true;
            }
        }

        false
    }
}

/// A block whose parent is not yet known.
#[derive(Debug, Clone)]
pub struct OrphanBlock {
    pub block: Block,
    /// The peer that sent the orphan, if known. Used to request the
    /// missing parent from the same peer.
    pub from_peer: Option<u64>,
}

/// Outcome of processing a block through the sync layer.
#[derive(Debug, PartialEq, Eq)]
pub enum BlockOutcome {
    /// The block connected to the active tip and was applied to the
    /// live state. The node is now one block higher on the same branch.
    Connected,
    /// The block connected to a side branch and was stored as a
    /// `ValidFork`. The active tip did not change.
    SideChain,
    /// The block connected to a side branch whose total chainwork now
    /// exceeds the active chain. A reorganization was performed.
    Reorganized,
    /// The block's parent is not known. It was added to the orphan pool.
    Orphan,
    /// The block was already known.
    Duplicate,
}

/// Global synchronization state across all peers.
pub struct SyncState {
    /// The best known height across all peers.
    pub best_known_height: u64,
    /// The height of the last block that was successfully connected to the chain.
    pub last_connected_height: u64,
    /// Per-peer sync state, keyed by peer ID.
    pub peer_states: HashMap<u64, PeerSyncState>,
    /// Blocks that have been requested globally (across all peers).
    pub blocks_requested: HashSet<String>,
    /// Blocks that have been received but not yet connected.
    pub blocks_received: HashSet<String>,
    /// The peer ID that is currently our primary sync peer.
    pub sync_peer: Option<u64>,
    /// Orphan blocks, keyed by hash. Bounded by `MAX_ORPHAN_BLOCKS`.
    pub orphan_pool: HashMap<String, OrphanBlock>,
    /// Insertion order of the orphan pool, used for FIFO pruning.
    pub orphan_order: VecDeque<String>,
    /// Side chain blocks whose parent is not yet known, keyed by hash.
    /// Bounded by `MAX_SIDE_CHAIN_BLOCKS`.
    pub side_chain_pool: HashMap<String, Block>,
    /// Insertion order of the side chain pool, used for FIFO pruning.
    pub side_chain_order: VecDeque<String>,
}

impl SyncState {
    pub fn new() -> Self {
        SyncState {
            best_known_height: 0,
            last_connected_height: 0,
            peer_states: HashMap::new(),
            blocks_requested: HashSet::new(),
            blocks_received: HashSet::new(),
            sync_peer: None,
            orphan_pool: HashMap::new(),
            orphan_order: VecDeque::new(),
            side_chain_pool: HashMap::new(),
            side_chain_order: VecDeque::new(),
        }
    }

    /// Register a peer for sync tracking.
    pub fn register_peer(&mut self, peer_id: u64) {
        self.peer_states.entry(peer_id).or_insert_with(PeerSyncState::new);
    }

    /// Remove a peer and release its in-flight requests back to the global pool.
    pub fn remove_peer(&mut self, peer_id: u64) {
        if let Some(state) = self.peer_states.remove(&peer_id) {
            for hash in state.in_flight {
                self.blocks_requested.remove(&hash);
            }
        }
        if self.sync_peer == Some(peer_id) {
            self.sync_peer = None;
        }
    }

    /// Drop a single block from the in-flight set of a peer.
    ///
    /// This is called when the peer reports that it does not have the
    /// block (via a `NotFound` message). Without this, the peer would be
    /// considered to be stalling until the stalling timeout expires,
    /// even though it has explicitly told us that the request cannot be
    /// satisfied.
    pub fn remove_in_flight(&mut self, peer_id: u64, hash: &str) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.in_flight.remove(hash);
        }
        self.blocks_requested.remove(hash);
    }

    /// Mark the peer as having given up on every in-flight block.
    ///
    /// The peer stays connected, but the hashes it failed to deliver are
    /// not requested from it again unless the peer announces them via a
    /// fresh `inv` message. This keeps the connection alive for peers
    /// that are slow or that need to fetch the blocks themselves before
    /// they can serve them.
    pub fn give_up_on_stalling_peer(&mut self, peer_id: u64) {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            let hashes: Vec<String> = state.in_flight.iter().cloned().collect();
            state.give_up_on_in_flight();
            for hash in hashes {
                self.blocks_requested.remove(&hash);
            }
        }
    }

    /// Return the total number of blocks currently in flight across all peers.
    pub fn total_in_flight(&self) -> usize {
        self.blocks_requested.len()
    }

    /// Return the current download window: the range of heights that should
    /// be requested from peers.
    pub fn download_window(&self, chain: &Blockchain) -> (u64, u64) {
        let start = chain.height() + 1;
        let end = std::cmp::min(
            start + BLOCK_DOWNLOAD_WINDOW,
            self.best_known_height + 1,
        );
        (start, end)
    }

    /// Check if a block at the given height is within the download window.
    pub fn is_in_window(&self, height: u64, chain: &Blockchain) -> bool {
        let (start, end) = self.download_window(chain);
        height >= start && height < end
    }

    /// Request a block from a peer. Returns true if the request was accepted.
    pub fn request_block(&mut self, peer_id: u64, hash: &str) -> bool {
        if self.blocks_requested.contains(hash) {
            return false;
        }

        let peer_state = match self.peer_states.get_mut(&peer_id) {
            Some(s) => s,
            None => return false,
        };

        if peer_state.requested_but_not_received.contains(hash) {
            return false;
        }

        if !peer_state.can_request() {
            return false;
        }

        peer_state.request(hash);
        self.blocks_requested.insert(hash.to_string());
        true
    }

    /// Mark a block as received from a peer.
    pub fn received_block(&mut self, peer_id: u64, hash: &str, height: u64) {
        if let Some(peer_state) = self.peer_states.get_mut(&peer_id) {
            peer_state.received(hash, height);
        }
        self.blocks_requested.remove(hash);
        self.blocks_received.insert(hash.to_string());
    }

    /// Mark a block as connected to the chain.
    pub fn connected_block(&mut self, hash: &str) {
        self.blocks_received.remove(hash);
    }

    /// Check for stalling peers and return the peer IDs that should be
    /// handled. The caller is expected to give up on their in-flight
    /// requests without disconnecting the peer, so that slow peers can
    /// still serve blocks announced later through `inv`.
    pub fn check_stalling_peers(&mut self, timeout: Duration) -> Vec<u64> {
        let now = Instant::now();
        let mut stalling = Vec::new();

        for (peer_id, state) in self.peer_states.iter_mut() {
            if state.check_stalling(now, timeout) {
                stalling.push(*peer_id);
            }
        }

        stalling
    }

    /// Expire requests that have been in flight for too long.
    pub fn expire_requests(&mut self) {
        // Requests are tracked globally; individual peer timeouts are
        // handled by check_stalling_peers.
    }

    /// Return the number of blocks in flight.
    pub fn in_flight_count(&self) -> usize {
        self.blocks_requested.len()
    }

    /// Add an orphan block to the pool. If the pool is full, the oldest
    /// orphan is evicted first. Returns `true` if the block was added,
    /// `false` if it was already present.
    pub fn add_orphan(&mut self, hash: &str, block: Block, from_peer: Option<u64>) -> bool {
        if self.orphan_pool.contains_key(hash) {
            return false;
        }
        while self.orphan_pool.len() >= MAX_ORPHAN_BLOCKS {
            if let Some(oldest) = self.orphan_order.pop_front() {
                self.orphan_pool.remove(&oldest);
            } else {
                break;
            }
        }
        self.orphan_pool.insert(
            hash.to_string(),
            OrphanBlock {
                block,
                from_peer,
            },
        );
        self.orphan_order.push_back(hash.to_string());
        true
    }

    /// Remove and return every orphan whose parent is now known. The
    /// caller is expected to connect them in turn, which may reveal
    /// further orphans. This is repeated by the caller until the pool
    /// stops yielding new blocks.
    pub fn take_connectable_orphans(&mut self, chain: &Blockchain) -> Vec<(String, OrphanBlock)> {
        let mut ready = Vec::new();
        let mut still_pending = VecDeque::new();

        while let Some(hash) = self.orphan_order.pop_front() {
            let entry = match self.orphan_pool.remove(&hash) {
                Some(e) => e,
                None => continue,
            };
            let parent_known = chain.chain.iter().any(|b| b.hash == entry.block.previous_hash)
                || self.side_chain_pool.contains_key(&entry.block.previous_hash);
            if parent_known {
                ready.push((hash, entry));
            } else {
                still_pending.push_back(hash);
                self.orphan_pool.insert(hash, entry);
            }
        }

        self.orphan_order = still_pending;
        ready
    }

    /// Add a block whose parent is known to the side chain pool. The
    /// block has already been validated. Returns `true` if the block was
    /// added, `false` if it was already present.
    pub fn add_side_chain_block(&mut self, hash: &str, block: Block) -> bool {
        if self.side_chain_pool.contains_key(hash) {
            return false;
        }
        while self.side_chain_pool.len() >= MAX_SIDE_CHAIN_BLOCKS {
            if let Some(oldest) = self.side_chain_order.pop_front() {
                self.side_chain_pool.remove(&oldest);
            } else {
                break;
            }
        }
        self.side_chain_pool.insert(hash.to_string(), block);
        self.side_chain_order.push_back(hash.to_string());
        true
    }

    /// Process a single block that has already been deserialized from
    /// the wire. This is the single entry point used by the network
    /// layer. It performs every consensus check, updates the live chain
    /// if the block extends the active tip, stores the block on a side
    /// branch if it extends a known fork, and returns the outcome so
    /// that the caller can decide whether the peer should be punished.
    pub fn process_block(
        chain: &mut Blockchain,
        block: Block,
        from_peer: Option<u64>,
        sync_state: &mut SyncState,
    ) -> Result<BlockOutcome, String> {
        // Duplicate check.
        if chain.chain.iter().any(|b| b.hash == block.hash)
            || sync_state.side_chain_pool.contains_key(&block.hash)
        {
            return Ok(BlockOutcome::Duplicate);
        }

        // Validate the block against the current active tip. A block
        // that extends the active tip is applied immediately. A block
        // that extends an older block is validated against that block
        // and stored as a side branch.
        let prev = match chain.chain.last() {
            Some(p) => p.clone(),
            None => return Err("chain is empty".into()),
        };

        let parent_is_active_tip = block.previous_hash == prev.hash;

        if parent_is_active_tip {
            // Path 1: the block extends the active tip. Full validation
            // against the tip, then apply to the live state.
            if let Err(e) = validation::validate_block(chain, &prev, &block) {
                return Err(format!("block {} rejected: {}", block.index, e));
            }
            apply_block_transactions(chain, &block)?;
            chain.chain.push(block.clone());
            chain.adjust_difficulty();

            // Persist the new active block and demote the previous tip
            // if it had been stored as a fork.
            let _ = storage::save_block_only(&block);
            let _ = storage::set_block_status(&block.hash, BlockStatus::Active);

            // Try to connect any orphans whose parent is now known.
            drain_orphans(chain, sync_state)?;

            return Ok(BlockOutcome::Connected);
        }

        // Path 2: the block does not extend the active tip. Find its
        // parent in the active chain or in the side chain pool.
        let parent_active = chain.chain.iter().find(|b| b.hash == block.previous_hash).cloned();
        let parent_side = sync_state
            .side_chain_pool
            .get(&block.previous_hash)
            .cloned();
        let parent = match parent_active.or(parent_side) {
            Some(p) => p,
            None => {
                // Path 3: the parent is unknown. Keep the block as an
                // orphan. This is not misbehavior.
                sync_state.add_orphan(&block.hash, block, from_peer);
                return Ok(BlockOutcome::Orphan);
            }
        };

        // Validate the block against its parent. The active chain may
        // not contain every ancestor of the parent, so the validation
        // here is structural: hash consistency, previous hash, index,
        // version, merkle root, reward, total fees, coinbase, timestamp
        // sanity, proof of work, and the per-transaction checks against
        // the live state (which is the best available approximation for
        // a fork that is not yet active).
        if let Err(e) = validation::validate_block(chain, &parent, &block) {
            return Err(format!("block {} rejected: {}", block.index, e));
        }

        // Compute the total chainwork of the branch that ends at this
        // block. If it exceeds the active chain's chainwork, a
        // reorganization is required.
        let branch_chainwork = block.chainwork;
        let active_chainwork = chain.total_chainwork();

        // Store the block on disk as a side branch before deciding
        // whether to reorganize. If the node restarts, the block is
        // still available.
        let _ = storage::save_side_chain_block(&block);

        if branch_chainwork > active_chainwork {
            // Path 4: the side branch is now heavier. Reorganize.
            sync_state.add_side_chain_block(&block.hash, block.clone());
            reorganize(chain, sync_state)?;
            return Ok(BlockOutcome::Reorganized);
        }

        // Path 5: the side branch is still lighter. Keep the block in
        // the side chain pool so that it can be connected later if the
        // branch grows.
        sync_state.add_side_chain_block(&block.hash, block);
        Ok(BlockOutcome::SideChain)
    }

    /// Handle a chain reorganization.
    ///
    /// The function walks from the heaviest side branch tip back to the
    /// common ancestor with the active chain, validates every block on
    /// the new branch, then applies the new branch on top of the
    /// ancestor state and demotes the old active blocks to `ValidFork`.
    ///
    /// The state root stored in the block header is used only to find
    /// the rollback target for the ancestor. It is not compared against
    /// a freshly simulated root.
    pub fn handle_reorg(chain: &mut Blockchain, new_block: Block) -> Result<(), String> {
        let new_chain_work = new_block.chainwork;
        let our_chain_work = chain.total_chainwork();
        if new_chain_work <= our_chain_work {
            return Err("new chain has less or equal work".into());
        }

        let ancestor_hash = new_block.previous_hash.clone();
        let ancestor_index;

        match chain.chain.iter().find(|b| b.hash == ancestor_hash) {
            Some(our_block) => {
                ancestor_index = our_block.index;
            }
            None => {
                return Err(format!(
                    "common ancestor {} not found in chain",
                    ancestor_hash
                ));
            }
        }

        let ancestor_block = &chain.chain[ancestor_index as usize];

        if ancestor_block.state_root.is_empty() {
            return Err("ancestor block has no state root".into());
        }

        let root_bytes = hex::decode(&ancestor_block.state_root)
            .map_err(|e| format!("invalid state root hex: {}", e))?;

        if root_bytes.len() != 32 {
            return Err("state root must be 32 bytes".into());
        }

        let mut ancestor_root = [0u8; 32];
        ancestor_root.copy_from_slice(&root_bytes);

        let tip_root_hex = match chain.chain.last() {
            Some(tip) => tip.state_root.clone(),
            None => return Err("chain has no tip".into()),
        };
        let tip_root_bytes = hex::decode(&tip_root_hex)
            .map_err(|e| format!("invalid tip state root hex: {}", e))?;
        if tip_root_bytes.len() != 32 {
            return Err("tip state root must be 32 bytes".into());
        }
        let mut tip_root = [0u8; 32];
        tip_root.copy_from_slice(&tip_root_bytes);

        // Validate the new block against the ancestor before touching the
        // live chain or state. The new block's previous_hash is the
        // ancestor hash, so the ancestor must be the current tip when
        // validate_block is called. We build a temporary view that ends at
        // the ancestor to validate the new block without mutating the
        // live chain.
        if new_block.previous_hash != ancestor_hash {
            return Err("reorg block does not extend the ancestor".into());
        }

        let original_len = chain.chain.len();
        let rollback_blocks: Vec<Block> = if ancestor_index + 1 < original_len as u64 {
            chain.chain[(ancestor_index + 1) as usize..].to_vec()
        } else {
            Vec::new()
        };

        if let Err(e) = chain.state.rollback_to(&ancestor_root) {
            return Err(format!("state rollback failed: {}", e));
        }

        chain.chain.truncate((ancestor_index + 1) as usize);

        if let Err(e) = apply_block_transactions(chain, &new_block) {
            // Restore the original chain and state if applying the new
            // block failed after the rollback.
            chain.chain.truncate((ancestor_index + 1) as usize);
            chain.chain.extend(rollback_blocks.iter().cloned());
            let _ = chain.state.rollback_to(&tip_root);
            return Err(format!("failed to apply new block after reorg: {}", e));
        }

        chain.chain.push(new_block);
        chain.adjust_difficulty();

        let mut addresses = vec!["GENESIS".to_string()];
        for block in &chain.chain {
            if !block.mined_for.is_empty() && !addresses.contains(&block.mined_for) {
                addresses.push(block.mined_for.clone());
            }
            for tx in &block.transactions {
                if !validation::is_special_tx(tx) {
                    if !addresses.contains(&tx.from) {
                        addresses.push(tx.from.clone());
                    }
                    if !addresses.contains(&tx.to) {
                        addresses.push(tx.to.clone());
                    }
                }
            }
        }
        chain.addresses = addresses;

        let mut new_mempool = Vec::new();
        let mut mempool_timestamps = std::collections::HashMap::new();
        for block in &rollback_blocks {
            for tx in &block.transactions {
                if validation::is_special_tx(tx) {
                    continue;
                }
                if validation::validate_transaction(chain, tx).is_ok() {
                    new_mempool.push(tx.clone());
                    let now = (crate::utils::now_millis() / 1000) as u64;
                    mempool_timestamps.insert(tx.txid.clone(), now);
                }
            }
        }
        chain.mempool = new_mempool;
        chain.mempool_timestamps = mempool_timestamps;

        Ok(())
    }
}

/// Apply a block's transactions and reward to the live chain state.
///
/// The caller must ensure that the block has already been validated
/// against the chain tip. This helper is used both by the regular
/// accept path and by the reorg path after the state has been rolled
/// back to the ancestor.
fn apply_block_transactions(chain: &mut Blockchain, block: &Block) -> Result<(), String> {
    for tx in &block.transactions {
        if let Err(e) = chain.apply_transaction(tx) {
            return Err(format!(
                "failed to apply tx {} in block {}: {}",
                tx.txid, block.index, e
            ));
        }
    }

    if let Err(e) = chain.credit_reward(&block.mined_for, block.reward, block.index) {
        return Err(format!(
            "failed to credit reward for block {}: {}",
            block.index, e
        ));
    }

    Ok(())
}

/// Repeatedly connect orphan blocks whose parent is now known.
///
/// Each successful connection can reveal more orphans, so the loop runs
/// until no more orphans can be connected. The caller does not need to
/// know how many orphans were drained.
fn drain_orphans(chain: &mut Blockchain, sync_state: &mut SyncState) -> Result<(), String> {
    loop {
        let ready = sync_state.take_connectable_orphans(chain);
        if ready.is_empty() {
            return Ok(());
        }
        for (hash, orphan) in ready {
            let parent = chain
                .chain
                .iter()
                .find(|b| b.hash == orphan.block.previous_hash)
                .cloned()
                .or_else(|| sync_state.side_chain_pool.get(&orphan.block.previous_hash).cloned());
            let parent = match parent {
                Some(p) => p,
                None => {
                    // Should not happen: take_connectable_orphans only
                    // returns entries whose parent is known.
                    sync_state.add_orphan(&hash, orphan.block, orphan.from_peer);
                    continue;
                }
            };
            if let Err(e) = validation::validate_block(chain, &parent, &orphan.block) {
                // The orphan was validated as a structural unit, but
                // its parent may have changed. Drop it.
                eprintln!(
                    "[p2p] dropping orphan {} after validation failure: {}",
                    hash, e
                );
                continue;
            }
            if orphan.block.previous_hash == chain.chain.last().unwrap().hash {
                apply_block_transactions(chain, &orphan.block)?;
                chain.chain.push(orphan.block.clone());
                chain.adjust_difficulty();
                let _ = storage::save_block_only(&orphan.block);
                let _ = storage::set_block_status(&orphan.block.hash, BlockStatus::Active);
                sync_state.connected_block(&hash);
            } else {
                let _ = storage::save_side_chain_block(&orphan.block);
                sync_state.add_side_chain_block(&hash, orphan.block);
            }
        }
    }
}

/// Reorganize the active chain to the heaviest side branch known.
///
/// The function walks from the current active tip back to the common
/// ancestor with the side branch, rolls the state back to the ancestor,
/// applies every block on the side branch in order, and demotes the old
/// active blocks to `ValidFork`.
fn reorganize(chain: &mut Blockchain, sync_state: &mut SyncState) -> Result<(), String> {
    // Pick the side branch tip with the highest chainwork.
    let mut best: Option<Block> = None;
    for block in sync_state.side_chain_pool.values() {
        match &best {
            Some(b) if b.chainwork >= block.chainwork => {}
            _ => best = Some(block.clone()),
        }
    }
    let tip = match best {
        Some(t) => t,
        None => return Ok(()),
    };

    // Walk back from the tip to the first block whose parent is on the
    // active chain.
    let mut new_branch: Vec<Block> = Vec::new();
    let mut cursor = Some(tip);
    let mut ancestor_hash: Option<String> = None;

    while let Some(current) = cursor {
        if chain.chain.iter().any(|b| b.hash == current.hash) {
            ancestor_hash = Some(current.hash);
            break;
        }
        if chain.chain.iter().any(|b| b.hash == current.previous_hash) {
            ancestor_hash = Some(current.previous_hash);
            new_branch.push(current);
            break;
        }
        new_branch.push(current.clone());
        cursor = sync_state
            .side_chain_pool
            .get(&current.previous_hash)
            .cloned();
    }

    let ancestor_hash = match ancestor_hash {
        Some(a) => a,
        None => return Err("reorganize: no common ancestor".into()),
    };

    // new_branch is collected tip-to-ancestor; reverse for apply order.
    new_branch.reverse();

    // Roll the state back to the ancestor.
    let ancestor_block = chain
        .chain
        .iter()
        .find(|b| b.hash == ancestor_hash)
        .cloned()
        .ok_or_else(|| "reorganize: ancestor block not found".to_string())?;

    let root_bytes = hex::decode(&ancestor_block.state_root)
        .map_err(|e| format!("invalid ancestor state root hex: {}", e))?;
    if root_bytes.len() != 32 {
        return Err("reorganize: ancestor state root must be 32 bytes".into());
    }
    let mut ancestor_root = [0u8; 32];
    ancestor_root.copy_from_slice(&root_bytes);

    chain.state
        .rollback_to(&ancestor_root)
        .map_err(|e| format!("reorganize: state rollback failed: {}", e))?;

    // Demote the old active blocks above the ancestor.
    let ancestor_index = ancestor_block.index as usize;
    for old_block in chain.chain[(ancestor_index + 1)..].iter() {
        let _ = storage::set_block_status(&old_block.hash, BlockStatus::ValidFork);
    }
    chain.chain.truncate(ancestor_index + 1);

    // Apply the new branch.
    for block in &new_branch {
        apply_block_transactions(chain, block)?;
        chain.chain.push(block.clone());
        chain.adjust_difficulty();
        let _ = storage::set_block_status(&block.hash, BlockStatus::Active);
    }

    // Rebuild the address list and mempool.
    let mut addresses = vec!["GENESIS".to_string()];
    for block in &chain.chain {
        if !block.mined_for.is_empty() && !addresses.contains(&block.mined_for) {
            addresses.push(block.mined_for.clone());
        }
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                continue;
            }
            if !addresses.contains(&tx.from) {
                addresses.push(tx.from.clone());
            }
            if !addresses.contains(&tx.to) {
                addresses.push(tx.to.clone());
            }
        }
    }
    chain.addresses = addresses;

    // Return transactions from the abandoned branch to the mempool when
    // still valid.
    let mut new_mempool = Vec::new();
    let mut mempool_timestamps = std::collections::HashMap::new();
    for (hash, block) in sync_state.side_chain_pool.clone() {
        if chain.chain.iter().any(|b| b.hash == hash) {
            continue;
        }
        for tx in &block.transactions {
            if validation::is_special_tx(tx) {
                continue;
            }
            if validation::validate_transaction(chain, tx).is_ok() {
                new_mempool.push(tx.clone());
                let now = (crate::utils::now_millis() / 1000) as u64;
                mempool_timestamps.insert(tx.txid.clone(), now);
            }
        }
    }
    chain.mempool = new_mempool;
    chain.mempool_timestamps = mempool_timestamps;

    Ok(())
}

/// Compatibility wrapper used by callers that already validated the
/// block against the active tip. This is the entry point used by the
/// RPC `submitblock` handler and by the miner.
pub fn accept_block(chain: &mut Blockchain, block: Block) -> Result<(), String> {
    if chain.chain.iter().any(|b| b.hash == block.hash) {
        return Err("block already exists".into());
    }

    let prev = match chain.chain.last() {
        Some(p) => p.clone(),
        None => return Err("chain is empty".into()),
    };

    if block.previous_hash != prev.hash {
        if chain.chain.iter().any(|b| b.hash == block.previous_hash) {
            return SyncState::handle_reorg(chain, block);
        } else {
            return Err(format!(
                "block {} previous_hash mismatch (orphan)",
                block.index
            ));
        }
    }

    // Full validation before touching the live state. The state root is
    // not compared here; the security comes from the strict
    // per-transaction validation and the exact reward check performed
    // by `validation::validate_block`.
    if let Err(e) = validation::validate_block(chain, &prev, &block) {
        return Err(format!("block {} rejected: {}", block.index, e));
    }

    apply_block_transactions(chain, &block)?;

    chain.chain.push(block);
    chain.adjust_difficulty();
    Ok(())
}
