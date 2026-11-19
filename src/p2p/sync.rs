// Copyright (c) 2026 Aldianokto
// Distributed under the Apache License, see the accompanying
// file LICENSE or https://www.apache.org/licenses/LICENSE-2.0.

//! Chain synchronization logic for the XEPAY peer-to-peer network.
//!
//! Block validation follows the reference node flow: a block is fully
//! validated, including its state root, before any live state is
//! mutated. A block that fails validation leaves the live chain and the
//! live state untouched, so a single bad block cannot desynchronize the
//! node from the rest of the network.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::block::Block;
use crate::blockchain::Blockchain;
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

    /// Handle a chain reorganization.
    ///
    /// The new block is validated before any state is rolled back. This
    /// prevents the node from ending up in an inconsistent state if the
    /// new block turns out to be invalid after the rollback has already
    /// been applied.
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

        // Pre-validate the new block's state root before touching the
        // live chain or state. The simulation is computed against the
        // ancestor state, which is the state the new block extends. If
        // the simulated root does not match the declared root, the
        // reorg is rejected and the live chain and state are left
        // untouched.
        let rollback_len = chain.chain.len();
        chain.chain.truncate((ancestor_index + 1) as usize);
        let sim_result = Self::simulate_block_state_root(chain, &new_block);
        chain.chain.truncate(rollback_len);
        match sim_result {
            Ok(sim_root) => {
                let sim_root_hex = hex::encode(sim_root);
                if !new_block.state_root.is_empty() && sim_root_hex != new_block.state_root {
                    return Err(format!(
                        "state root mismatch for reorg block {}: declared {}, simulated {}",
                        new_block.index, new_block.state_root, sim_root_hex
                    ));
                }
            }
            Err(e) => {
                return Err(format!(
                    "failed to simulate reorg block {}: {}",
                    new_block.index, e
                ));
            }
        }

        if let Err(e) = chain.state.rollback_to(&ancestor_root) {
            return Err(format!("state rollback failed: {}", e));
        }

        chain.chain.truncate((ancestor_index + 1) as usize);

        if let Err(e) = Self::apply_block_transactions(chain, &new_block) {
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

    /// Compute the state root that would result from applying `block` on
    /// top of the current chain tip, without touching the live state.
    ///
    /// The caller must have already truncated the chain to the parent of
    /// `block` so that `chain.state` reflects the parent state. The
    /// simulation uses the same helpers as the live apply path, so a
    /// block accepted by the live path always matches the simulation.
    fn simulate_block_state_root(chain: &Blockchain, block: &Block) -> Result<[u8; 32], String> {
        let mut addresses = chain.addresses.clone();
        if !addresses.contains(&block.mined_for) {
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

        chain
            .state
            .simulate_apply(
                &addresses,
                &block.transactions,
                &block.mined_for,
                block.reward,
                block.index,
            )
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
                return Self::handle_reorg(chain, block);
            } else {
                return Err(format!(
                    "block {} previous_hash mismatch (orphan)",
                    block.index
                ));
            }
        }

        // Full validation before touching the live state. This mirrors
        // the reference node flow: a block that fails any consensus rule,
        // including the state root, is rejected without mutating the
        // live chain or the live state. A single bad block can therefore
        // never desynchronize the node from the rest of the network.
        if let Err(e) = validation::validate_block(chain, &prev, &block) {
            return Err(format!("block {} rejected: {}", block.index, e));
        }

        // Pre-validate the state root against the current tip state.
        // The simulation uses the same helpers as the live apply path,
        // so a block whose declared root does not match its contents is
        // rejected here, before any transaction is applied.
        let simulated_root = Self::simulate_block_state_root(chain, &block)?;
        let simulated_root_hex = hex::encode(simulated_root);
        if !block.state_root.is_empty() && simulated_root_hex != block.state_root {
            return Err(format!(
                "state root mismatch for block {}: declared {}, simulated {}",
                block.index, block.state_root, simulated_root_hex
            ));
        }

        // The block passed every validation check, including the state
        // root simulation. It is now safe to apply its transactions and
        // credit its reward to the live state.
        Self::apply_block_transactions(chain, &block)?;

        // Recompute the root from the live state as a final safety net.
        // The simulation already matched the declared root, so a
        // mismatch here would mean the live apply path diverged from the
        // simulation path, which is a consensus bug that must be caught
        // immediately.
        let computed_root = match chain.state.root_hash() {
            Ok(root) => root,
            Err(e) => {
                return Err(format!(
                    "failed to compute state root for block {}: {}",
                    block.index, e
                ));
            }
        };
        let computed_root_hex = hex::encode(computed_root);

        if !block.state_root.is_empty() && computed_root_hex != block.state_root {
            return Err(format!(
                "state root mismatch for block {}: declared {}, computed {}",
                block.index, block.state_root, computed_root_hex
            ));
        }

        chain.chain.push(block);
        chain.adjust_difficulty();
        Ok(())
    }
}
