use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::antispam::{challenge_matches_anchor_window, verify_micro_pow, AntiSpamError, Hash32};
use crate::chain_state::{HybridBlockReport, HybridChainError, HybridChainState, HybridTx};
use crate::params::{
    ANTI_SPAM_ANCHOR_WINDOW_BLOCKS, DIFFICULTY_RETARGET_WINDOW_BLOCKS, MEDIAN_TIME_PAST_BLOCKS,
};
use crate::pow_randomx::{
    retarget_difficulty_with_window, BlockHeader, ChainWork, ConsensusError, Hash256,
    RandomXHasher, MAX_DIFFICULTY_TARGET, MIN_DIFFICULTY_TARGET,
};
use crate::privacy::Key32;

pub const MAX_MEMPOOL_TXS: usize = 4_096;
pub const MAX_BLOCK_TXS: usize = 1_024;

pub fn hybrid_tx_challenge(tx: &HybridTx) -> &crate::antispam::AntiSpamChallenge {
    match tx {
        HybridTx::Transparent { challenge, .. } | HybridTx::Confidential { challenge, .. } => {
            challenge
        }
    }
}

pub fn hybrid_tx_nonce(tx: &HybridTx) -> u64 {
    match tx {
        HybridTx::Transparent { nonce, .. } | HybridTx::Confidential { nonce, .. } => *nonce,
    }
}

pub fn hybrid_tx_key_images(tx: &HybridTx) -> Vec<Key32> {
    match tx {
        HybridTx::Transparent { .. } => Vec::new(),
        HybridTx::Confidential { tx, .. } => {
            tx.inputs.iter().map(|input| input.key_image).collect()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub reward_recipient: String,
    pub txs: Vec<HybridTx>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockInfo {
    pub hash: Hash256,
    pub parent_hash: Option<Hash256>,
    pub chainwork: ChainWork,
    pub occupancy_ppm: u128,
    pub block: Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEngineError {
    MerkleRootMismatch { expected: Hash256, actual: Hash256 },
    EmptyRewardRecipient,
    RewardRecipientMismatch { supplied: String, committed: String },
    ChainWorkOverflow,
    TooManyTransactions { actual: usize, max: usize },
    MempoolFull { max: usize },
    DuplicateTx(Hash256),
    DuplicatePendingKeyImage(Key32),
    InvalidAnchorWindow,
    InsufficientMicroPow(AntiSpamError),
    Consensus(ConsensusError),
    Chain(HybridChainError),
    UnknownParent(Hash256),
    ReorgFailed(String),
}

impl fmt::Display for ChainEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MerkleRootMismatch { .. } => write!(f, "invalid merkle_root in block header"),
            Self::EmptyRewardRecipient => write!(f, "block reward recipient must not be empty"),
            Self::RewardRecipientMismatch {
                supplied,
                committed,
            } => write!(
                f,
                "submitted reward recipient {supplied} differs from block commitment {committed}"
            ),
            Self::ChainWorkOverflow => write!(f, "accumulated chainwork exceeds 512 bits"),
            Self::TooManyTransactions { actual, max } => {
                write!(f, "block exceeds transaction limit: {actual} > {max}")
            }
            Self::MempoolFull { max } => write!(f, "mempool is full (limit {max})"),
            Self::DuplicateTx(_) => write!(f, "duplicate transaction in mempool"),
            Self::DuplicatePendingKeyImage(_) => {
                write!(f, "key image already pending in mempool")
            }
            Self::InvalidAnchorWindow => {
                write!(f, "stamp prev_block_hash outside anchor window")
            }
            Self::InsufficientMicroPow(e) => write!(f, "insufficient micro-PoW: {e:?}"),
            Self::Consensus(e) => write!(f, "consensus error: {e}"),
            Self::Chain(e) => write!(f, "chain state error: {e}"),
            Self::UnknownParent(_) => write!(f, "unknown parent block"),
            Self::ReorgFailed(msg) => write!(f, "reorganization failed: {msg}"),
        }
    }
}

impl std::error::Error for ChainEngineError {}

impl From<ConsensusError> for ChainEngineError {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}

impl From<HybridChainError> for ChainEngineError {
    fn from(e: HybridChainError) -> Self {
        Self::Chain(e)
    }
}

/// Calculates the canonical BLAKE3 digest of a hybrid transaction.
pub fn hybrid_tx_digest(tx: &HybridTx) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_HYBRID_TX_V1");
    match tx {
        HybridTx::Transparent {
            tx,
            challenge,
            nonce,
        } => {
            hasher.update(b"TRANSPARENT");
            hasher.update(&(tx.from.len() as u64).to_le_bytes());
            hasher.update(tx.from.as_bytes());
            hasher.update(&(tx.to.len() as u64).to_le_bytes());
            hasher.update(tx.to.as_bytes());
            hasher.update(&tx.amount_atomic.to_le_bytes());
            hasher.update(&challenge.prev_block_hash);
            hasher.update(&challenge.tx_digest);
            hasher.update(&challenge.amount_atomic.to_le_bytes());
            hasher.update(&challenge.occupancy_ppm.to_le_bytes());
            hasher.update(&nonce.to_le_bytes());
        }
        HybridTx::Confidential {
            tx,
            challenge,
            nonce,
        } => {
            hasher.update(b"CONFIDENTIAL");
            hasher.update(&tx.discount_atomic.to_le_bytes());
            hasher.update(&(tx.inputs.len() as u64).to_le_bytes());
            for inp in &tx.inputs {
                hasher.update(&(inp.ring_members.len() as u64).to_le_bytes());
                for member in &inp.ring_members {
                    hasher.update(member);
                }
                hasher.update(&inp.key_image);
                hasher.update(&inp.pseudo_commitment.point);
            }
            hasher.update(&(tx.outputs.len() as u64).to_le_bytes());
            for out in &tx.outputs {
                hasher.update(&out.one_time_pub);
                hasher.update(&out.tx_ephemeral_pub);
                hasher.update(&[out.view_tag]);
                hasher.update(&out.commitment.point);
                hasher.update(&[out.range_proof.bit_length]);
                hasher.update(&out.range_proof.lo_commitment);
                hasher.update(&out.range_proof.hi_commitment);
                hasher.update(&(out.range_proof.lo_proof_bytes.len() as u64).to_le_bytes());
                hasher.update(&out.range_proof.lo_proof_bytes);
                hasher.update(&(out.range_proof.hi_proof_bytes.len() as u64).to_le_bytes());
                hasher.update(&out.range_proof.hi_proof_bytes);
            }
            hasher.update(&(tx.signature.inputs.len() as u64).to_le_bytes());
            for signature in &tx.signature.inputs {
                hasher.update(&signature.challenge_c0);
                hasher.update(&(signature.responses.len() as u64).to_le_bytes());
                for response in &signature.responses {
                    hasher.update(response);
                }
            }
            hasher.update(&challenge.prev_block_hash);
            hasher.update(&challenge.tx_digest);
            hasher.update(&challenge.amount_atomic.to_le_bytes());
            hasher.update(&challenge.occupancy_ppm.to_le_bytes());
            hasher.update(&nonce.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// Calculates the binary Merkle root with BLAKE3, duplicating the final node if necessary.
pub fn compute_merkle_root(txs: &[HybridTx]) -> Hash256 {
    if txs.is_empty() {
        let mut h = blake3::Hasher::new();
        h.update(b"SUL_EMPTY_MERKLE_ROOT_V1");
        return *h.finalize().as_bytes();
    }

    let mut level: Vec<Hash256> = txs.iter().map(hybrid_tx_digest).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"SUL_MERKLE_NODE_V1");
            hasher.update(&left);
            hasher.update(&right);
            next.push(*hasher.finalize().as_bytes());
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Commits both the transaction tree and reward recipient into the block header.
pub fn compute_block_merkle_root(txs: &[HybridTx], reward_recipient: &str) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_BLOCK_CONTENT_ROOT_V1");
    hasher.update(&(reward_recipient.len() as u64).to_le_bytes());
    hasher.update(reward_recipient.as_bytes());
    hasher.update(&compute_merkle_root(txs));
    *hasher.finalize().as_bytes()
}

impl Block {
    pub fn verify_merkle_root(&self) -> Result<(), ChainEngineError> {
        if self.reward_recipient.trim().is_empty() {
            return Err(ChainEngineError::EmptyRewardRecipient);
        }
        let actual = compute_block_merkle_root(&self.txs, &self.reward_recipient);
        if actual != self.header.merkle_root {
            return Err(ChainEngineError::MerkleRootMismatch {
                expected: self.header.merkle_root,
                actual,
            });
        }
        Ok(())
    }
}

/// Mempool with anti-spam validation, anchor windows, and key-image uniqueness.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mempool {
    pub max_txs: usize,
    entries: HashMap<Hash256, HybridTx>,
    order: VecDeque<Hash256>,
    pending_key_images: HashSet<Key32>,
}

impl Mempool {
    pub fn new(max_txs: usize) -> Self {
        Self {
            max_txs,
            entries: HashMap::new(),
            order: VecDeque::new(),
            pending_key_images: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn insert_tx(
        &mut self,
        tx: HybridTx,
        recent_block_hashes: &[Hash32],
    ) -> Result<Hash256, ChainEngineError> {
        if self.entries.len() >= self.max_txs {
            return Err(ChainEngineError::MempoolFull { max: self.max_txs });
        }

        let challenge = hybrid_tx_challenge(&tx).clone();
        let nonce = hybrid_tx_nonce(&tx);
        let key_images = hybrid_tx_key_images(&tx);

        if !recent_block_hashes.is_empty()
            && !challenge_matches_anchor_window(&challenge, recent_block_hashes)
        {
            return Err(ChainEngineError::InvalidAnchorWindow);
        }

        verify_micro_pow(&challenge, nonce).map_err(ChainEngineError::InsufficientMicroPow)?;

        let id = hybrid_tx_digest(&tx);
        if self.entries.contains_key(&id) {
            return Err(ChainEngineError::DuplicateTx(id));
        }

        for ki in &key_images {
            if self.pending_key_images.contains(ki) {
                return Err(ChainEngineError::DuplicatePendingKeyImage(*ki));
            }
        }

        for ki in key_images {
            self.pending_key_images.insert(ki);
        }
        self.order.push_back(id);
        self.entries.insert(id, tx);
        Ok(id)
    }

    pub fn drain_for_block(&mut self, max_txs: usize) -> Vec<HybridTx> {
        let take = max_txs.min(self.order.len());
        let mut selected = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(id) = self.order.pop_front() {
                if let Some(tx) = self.entries.remove(&id) {
                    if let HybridTx::Confidential { tx: ctx, .. } = &tx {
                        for inp in &ctx.inputs {
                            self.pending_key_images.remove(&inp.key_image);
                        }
                    }
                    selected.push(tx);
                }
            }
        }
        selected
    }

    pub fn prune_stale_anchors(&mut self, recent_block_hashes: &[Hash32]) {
        if recent_block_hashes.is_empty() {
            return;
        }
        let mut kept_order = VecDeque::with_capacity(self.order.len());
        while let Some(id) = self.order.pop_front() {
            let keep = self
                .entries
                .get(&id)
                .map(|tx| {
                    let ch = hybrid_tx_challenge(tx);
                    challenge_matches_anchor_window(ch, recent_block_hashes)
                })
                .unwrap_or(false);

            if keep {
                kept_order.push_back(id);
            } else if let Some(tx) = self.entries.remove(&id) {
                if let HybridTx::Confidential { tx: ctx, .. } = tx {
                    for inp in ctx.inputs {
                        self.pending_key_images.remove(&inp.key_image);
                    }
                }
            }
        }
        self.order = kept_order;
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredNode {
    block: Block,
    hash: Hash256,
    parent_hash: Option<Hash256>,
    chainwork: ChainWork,
    occupancy_ppm: u128,
}

/// Chain engine with branch support and chainwork-based reorganization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainEngine {
    pub genesis_seed: Hash256,
    pub initial_supply_sul: u128,
    pub initial_emission_bps: u128,
    pub state: HybridChainState,
    nodes: HashMap<Hash256, StoredNode>,
    canonical_hashes: Vec<Hash256>,
    pub mempool: Mempool,
}

impl ChainEngine {
    pub fn new(
        genesis_seed: Hash256,
        initial_supply_sul: u128,
        initial_emission_bps: u128,
    ) -> Self {
        Self {
            genesis_seed,
            initial_supply_sul,
            initial_emission_bps,
            state: HybridChainState::new(initial_supply_sul, initial_emission_bps),
            nodes: HashMap::new(),
            canonical_hashes: Vec::new(),
            mempool: Mempool::new(MAX_MEMPOOL_TXS),
        }
    }

    pub fn tip_hash(&self) -> Option<Hash256> {
        self.canonical_hashes.last().copied()
    }

    /// Returns accumulated work for the canonical tip, or zero for an empty chain.
    pub fn current_tip_work(&self) -> ChainWork {
        self.tip_hash()
            .and_then(|hash| self.nodes.get(&hash))
            .map(|node| node.chainwork)
            .unwrap_or(ChainWork::ZERO)
    }

    pub fn has_block(&self, hash: &Hash256) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Copies stored block metadata needed by synchronization and disk persistence.
    pub fn stored_block_info(&self, hash: &Hash256) -> Option<StoredBlockInfo> {
        self.nodes.get(hash).map(|node| StoredBlockInfo {
            hash: node.hash,
            parent_hash: node.parent_hash,
            chainwork: node.chainwork,
            occupancy_ppm: node.occupancy_ppm,
            block: node.block.clone(),
        })
    }

    pub fn header_by_hash(&self, hash: &Hash256) -> Option<&BlockHeader> {
        self.nodes.get(hash).map(|node| &node.block.header)
    }

    pub fn ancestor_header(&self, hash: &Hash256, height: u64) -> Option<&BlockHeader> {
        let mut node = self.nodes.get(hash)?;
        while node.block.header.height > height {
            node = self.nodes.get(&node.parent_hash?)?;
        }
        (node.block.header.height == height).then_some(&node.block.header)
    }

    pub fn recent_ancestor_headers(&self, hash: &Hash256, limit: usize) -> Vec<BlockHeader> {
        let mut headers = Vec::with_capacity(limit);
        let mut cursor = self.nodes.get(hash).and_then(|node| node.parent_hash);
        while headers.len() < limit {
            let Some(parent_hash) = cursor else {
                break;
            };
            let Some(node) = self.nodes.get(&parent_hash) else {
                break;
            };
            headers.push(node.block.header.clone());
            cursor = node.parent_hash;
        }
        headers
    }

    pub fn discard_staged_blocks(&mut self, hashes: &[Hash256]) {
        let staged: HashSet<Hash256> = hashes.iter().copied().collect();
        for hash in hashes.iter().rev() {
            if self.canonical_hashes.contains(hash) {
                continue;
            }
            let has_external_child = self
                .nodes
                .values()
                .any(|node| node.parent_hash == Some(*hash) && !staged.contains(&node.hash));
            if !has_external_child {
                self.nodes.remove(hash);
            }
        }
    }

    /// Returns canonical blocks after the newest matching locator hash.
    pub fn canonical_blocks_after(
        &self,
        locator: &[Hash256],
        limit: usize,
    ) -> Vec<StoredBlockInfo> {
        let start = locator
            .iter()
            .find_map(|hash| {
                self.canonical_hashes
                    .iter()
                    .position(|canonical_hash| canonical_hash == hash)
                    .map(|index| index + 1)
            })
            .unwrap_or(0);

        self.canonical_hashes
            .iter()
            .skip(start)
            .take(limit)
            .filter_map(|hash| self.stored_block_info(hash))
            .collect()
    }

    pub fn canonical_hashes(&self) -> &[Hash256] {
        &self.canonical_hashes
    }

    pub fn tip_header(&self) -> Option<&BlockHeader> {
        self.tip_hash()
            .and_then(|h| self.nodes.get(&h))
            .map(|n| &n.block.header)
    }

    pub fn expected_next_difficulty_target(&self) -> Result<Hash256, ChainEngineError> {
        let Some(parent_hash) = self.tip_hash() else {
            return Ok(MAX_DIFFICULTY_TARGET);
        };
        let parent = self
            .header_by_hash(&parent_hash)
            .expect("canonical tip hash has a stored header");
        let height = parent
            .height
            .checked_add(1)
            .ok_or(ConsensusError::HeightOverflow)?;
        self.expected_difficulty_target(&parent_hash, height)
    }

    pub fn recent_block_hashes(&self) -> Vec<Hash32> {
        let win = ANTI_SPAM_ANCHOR_WINDOW_BLOCKS as usize;
        let start = self.canonical_hashes.len().saturating_sub(win);
        self.canonical_hashes[start..].to_vec()
    }

    /// Validates and stores a block without changing the canonical chain state.
    pub fn stage_block<H: RandomXHasher>(
        &mut self,
        block: Block,
        hasher: &H,
        occupancy_ppm: u128,
    ) -> Result<Hash256, ChainEngineError> {
        if block.txs.len() > MAX_BLOCK_TXS {
            return Err(ChainEngineError::TooManyTransactions {
                actual: block.txs.len(),
                max: MAX_BLOCK_TXS,
            });
        }
        block.verify_merkle_root()?;
        let parent_node = if block.header.height == 0 {
            None
        } else {
            let parent = self.nodes.get(&block.header.prev_block_hash).ok_or(
                ChainEngineError::UnknownParent(block.header.prev_block_hash),
            )?;
            block.header.validate_parent(&parent.block.header)?;
            Some(parent)
        };
        self.validate_header_consensus(&block.header)?;
        block.header.verify_pow(hasher, &self.genesis_seed)?;
        let hash = block.header.structural_digest();
        if self.nodes.contains_key(&hash) {
            return Ok(hash);
        }

        let chainwork = parent_node
            .map_or(ChainWork::ZERO, |parent| parent.chainwork)
            .checked_add(ChainWork::from_difficulty_target(
                &block.header.difficulty_target,
            ))
            .ok_or(ChainEngineError::ChainWorkOverflow)?;
        self.nodes.insert(
            hash,
            StoredNode {
                block,
                hash,
                parent_hash: parent_node.map(|parent| parent.hash),
                chainwork,
                occupancy_ppm,
            },
        );
        Ok(hash)
    }

    /// Activates a fully staged branch only when its accumulated work beats the current tip.
    pub fn activate_chain<H: RandomXHasher>(
        &mut self,
        target_tip_hash: Hash256,
        hasher: &H,
    ) -> Result<HybridBlockReport, ChainEngineError> {
        let target_work = self
            .nodes
            .get(&target_tip_hash)
            .ok_or(ChainEngineError::UnknownParent(target_tip_hash))?
            .chainwork;
        if target_work <= self.current_tip_work() {
            return Err(ChainEngineError::ReorgFailed(
                "staged branch does not exceed canonical chainwork".to_string(),
            ));
        }
        self.reorganize_to(target_tip_hash, hasher)
    }

    pub fn submit_block<H: RandomXHasher>(
        &mut self,
        block: Block,
        hasher: &H,
        miner_id: impl Into<String>,
        occupancy_ppm: u128,
    ) -> Result<HybridBlockReport, ChainEngineError> {
        if block.txs.len() > MAX_BLOCK_TXS {
            return Err(ChainEngineError::TooManyTransactions {
                actual: block.txs.len(),
                max: MAX_BLOCK_TXS,
            });
        }

        block.verify_merkle_root()?;
        let supplied_recipient = miner_id.into();
        if supplied_recipient != block.reward_recipient {
            return Err(ChainEngineError::RewardRecipientMismatch {
                supplied: supplied_recipient,
                committed: block.reward_recipient,
            });
        }

        let parent_node = if block.header.height == 0 {
            None
        } else {
            let p = self.nodes.get(&block.header.prev_block_hash).ok_or(
                ChainEngineError::UnknownParent(block.header.prev_block_hash),
            )?;
            Some(p.clone())
        };

        self.validate_header_consensus(&block.header)?;
        block.header.verify_pow(hasher, &self.genesis_seed)?;
        let block_hash = block.header.structural_digest();
        if self.nodes.contains_key(&block_hash) {
            return Err(ChainEngineError::Consensus(
                ConsensusError::InvalidPrevHash {
                    expected: block.header.prev_block_hash,
                    actual: block_hash,
                },
            ));
        }

        let parent_work = parent_node
            .as_ref()
            .map(|node| node.chainwork)
            .unwrap_or(ChainWork::ZERO);
        let new_work = parent_work
            .checked_add(ChainWork::from_difficulty_target(
                &block.header.difficulty_target,
            ))
            .ok_or(ChainEngineError::ChainWorkOverflow)?;

        let is_extending_tip = match (self.tip_hash(), &parent_node) {
            (Some(tip), Some(p)) => p.hash == tip,
            (None, None) => true,
            _ => false,
        };

        if is_extending_tip {
            let parent_header = parent_node.as_ref().map(|n| &n.block.header);
            let recent_hashes = self.recent_block_hashes();
            let report = self.state.apply_hybrid_block(
                parent_header,
                &block.header,
                hasher,
                &self.genesis_seed,
                &block.txs,
                &recent_hashes,
                block.reward_recipient.clone(),
                occupancy_ppm,
            )?;

            self.nodes.insert(
                block_hash,
                StoredNode {
                    block,
                    hash: block_hash,
                    parent_hash: parent_node.map(|n| n.hash),
                    chainwork: new_work,
                    occupancy_ppm,
                },
            );
            self.canonical_hashes.push(block_hash);

            let recent = self.recent_block_hashes();
            self.mempool.prune_stale_anchors(&recent);
            return Ok(report);
        }

        // Store the alternative branch and check whether it exceeds the canonical chainwork.
        let current_tip_work = self
            .tip_hash()
            .and_then(|h| self.nodes.get(&h))
            .map(|n| n.chainwork)
            .unwrap_or(ChainWork::ZERO);

        let parent_hash_opt = parent_node.map(|n| n.hash);
        self.nodes.insert(
            block_hash,
            StoredNode {
                block,
                hash: block_hash,
                parent_hash: parent_hash_opt,
                chainwork: new_work,
                occupancy_ppm,
            },
        );

        if new_work > current_tip_work {
            self.reorganize_to(block_hash, hasher)
        } else {
            Err(ChainEngineError::ReorgFailed(
                "alternative branch does not exceed canonical chainwork".to_string(),
            ))
        }
    }

    fn reorganize_to<H: RandomXHasher>(
        &mut self,
        target_tip_hash: Hash256,
        hasher: &H,
    ) -> Result<HybridBlockReport, ChainEngineError> {
        let mut branch_hashes = Vec::new();
        let mut cursor = Some(target_tip_hash);
        while let Some(h) = cursor {
            let node = self
                .nodes
                .get(&h)
                .ok_or_else(|| ChainEngineError::ReorgFailed("broken fork path".into()))?;
            branch_hashes.push(h);
            cursor = node.parent_hash;
        }
        branch_hashes.reverse();

        let state_backup = self.state.clone();
        let canon_backup = self.canonical_hashes.clone();

        self.state = HybridChainState::new(self.initial_supply_sul, self.initial_emission_bps);

        let mut last_report: Option<HybridBlockReport> = None;
        let mut prev_header_opt: Option<BlockHeader> = None;
        let mut recent_hashes = Vec::new();
        for h in &branch_hashes {
            let node = self
                .nodes
                .get(h)
                .ok_or_else(|| ChainEngineError::ReorgFailed("missing fork node".into()))?
                .clone();

            match self.state.apply_hybrid_block(
                prev_header_opt.as_ref(),
                &node.block.header,
                hasher,
                &self.genesis_seed,
                &node.block.txs,
                &recent_hashes,
                node.block.reward_recipient.clone(),
                node.occupancy_ppm,
            ) {
                Ok(rep) => {
                    prev_header_opt = Some(node.block.header.clone());
                    last_report = Some(rep);
                    recent_hashes.push(*h);
                    let anchor_window = ANTI_SPAM_ANCHOR_WINDOW_BLOCKS as usize;
                    if recent_hashes.len() > anchor_window {
                        recent_hashes.remove(0);
                    }
                }
                Err(err) => {
                    self.state = state_backup;
                    self.canonical_hashes = canon_backup;
                    return Err(ChainEngineError::Chain(err));
                }
            }
        }

        self.canonical_hashes = branch_hashes;
        let recent = self.recent_block_hashes();
        self.mempool.prune_stale_anchors(&recent);

        last_report.ok_or_else(|| ChainEngineError::ReorgFailed("empty branch".into()))
    }

    fn validate_header_consensus(&self, header: &BlockHeader) -> Result<(), ChainEngineError> {
        if header.height == 0 {
            let hash = header.structural_digest();
            let conflicting_genesis = self
                .nodes
                .values()
                .any(|node| node.block.header.height == 0 && node.hash != hash);
            if header.prev_block_hash != [0; 32] || conflicting_genesis {
                return Err(ConsensusError::InvalidGenesisHeader.into());
            }
            if header.difficulty_target < MIN_DIFFICULTY_TARGET {
                return Err(ConsensusError::InvalidDifficultyTargetRange {
                    actual: header.difficulty_target,
                }
                .into());
            }
            return Ok(());
        }

        let parent = self
            .nodes
            .get(&header.prev_block_hash)
            .ok_or(ChainEngineError::UnknownParent(header.prev_block_hash))?;
        let parent_header = &parent.block.header;
        let recent_headers =
            self.recent_ancestor_headers(&parent.hash, MEDIAN_TIME_PAST_BLOCKS.saturating_sub(1));
        let expected_target = self.expected_difficulty_target(&parent.hash, header.height)?;
        if header.difficulty_target < MIN_DIFFICULTY_TARGET {
            return Err(ConsensusError::InvalidDifficultyTargetRange {
                actual: header.difficulty_target,
            }
            .into());
        }
        header.validate_parent_with_history(
            parent_header,
            &recent_headers,
            Some(&expected_target),
        )?;
        Ok(())
    }

    fn expected_difficulty_target(
        &self,
        parent_hash: &Hash256,
        child_height: u64,
    ) -> Result<Hash256, ChainEngineError> {
        let parent = self
            .nodes
            .get(parent_hash)
            .ok_or(ChainEngineError::UnknownParent(*parent_hash))?;
        if child_height % DIFFICULTY_RETARGET_WINDOW_BLOCKS != 0 {
            return Ok(parent.block.header.difficulty_target);
        }

        let start_height = child_height.saturating_sub(DIFFICULTY_RETARGET_WINDOW_BLOCKS);
        let start_header = self.ancestor_header(parent_hash, start_height).ok_or(
            ConsensusError::MissingDifficultyHistory {
                height: start_height,
            },
        )?;
        Ok(retarget_difficulty_with_window(
            &parent.block.header.difficulty_target,
            DIFFICULTY_RETARGET_WINDOW_BLOCKS,
            start_header.timestamp,
            parent.block.header.timestamp,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::antispam::{solve_micro_pow, AntiSpamChallenge};
    use crate::ledger::{LedgerError, TransferTx};
    use crate::monetary::OCCUPANCY_SCALE;
    use crate::params::ATOMIC_UNITS_PER_SUL;
    use crate::pow_randomx::MockRandomXHasher;

    #[test]
    fn block_merkle_root_commits_to_reward_recipient() {
        let header = BlockHeader {
            version: 1,
            height: 0,
            prev_block_hash: [0; 32],
            merkle_root: compute_block_merkle_root(&[], "alice"),
            timestamp: 1_700_000_000,
            difficulty_target: [0xFF; 32],
            nonce: 0,
        };
        let block = Block {
            header,
            reward_recipient: "bob".into(),
            txs: Vec::new(),
        };
        assert!(matches!(
            block.verify_merkle_root(),
            Err(ChainEngineError::MerkleRootMismatch { .. })
        ));
    }

    fn mine_valid_header(
        hasher: &MockRandomXHasher,
        genesis_seed: &Hash256,
        height: u64,
        prev_block_hash: Hash256,
        merkle_root: Hash256,
        timestamp: u64,
        target: Hash256,
    ) -> (BlockHeader, Hash256) {
        let mut header = BlockHeader {
            version: 1,
            height,
            prev_block_hash,
            merkle_root,
            timestamp,
            difficulty_target: target,
            nonce: 0,
        };
        loop {
            if header.verify_pow(hasher, genesis_seed).is_ok() {
                let block_hash = header.structural_digest();
                return (header, block_hash);
            }
            header.nonce = header.nonce.wrapping_add(1);
        }
    }

    fn make_tx(
        from: &str,
        to: &str,
        amount_sul: u128,
        prev_block_hash: Hash32,
        tag_byte: u8,
        occ: u128,
    ) -> HybridTx {
        let amount = amount_sul * ATOMIC_UNITS_PER_SUL;
        let ch = AntiSpamChallenge {
            prev_block_hash,
            tx_digest: [tag_byte; 32],
            amount_atomic: amount,
            occupancy_ppm: occ,
        };
        let nonce = solve_micro_pow(&ch);
        HybridTx::Transparent {
            tx: TransferTx {
                from: from.to_string(),
                to: to.to_string(),
                amount_atomic: amount,
            },
            challenge: ch,
            nonce,
        }
    }

    #[test]
    fn stage_and_submit_enforce_parent_mtp_and_retarget_rules() {
        let seed = [0x19; 32];
        let hasher = MockRandomXHasher;
        let occupancy = OCCUPANCY_SCALE / 2;
        let mut engine = ChainEngine::new(seed, 1_000, 125);
        let (genesis, genesis_hash) = mine_valid_header(
            &hasher,
            &seed,
            0,
            [0; 32],
            compute_block_merkle_root(&[], "miner_genesis"),
            1_700_000_000,
            [0xFF; 32],
        );
        engine
            .submit_block(
                Block {
                    header: genesis,
                    reward_recipient: "miner_genesis".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_genesis",
                occupancy,
            )
            .unwrap();

        let wrong_target_block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block_hash: genesis_hash,
                merkle_root: compute_block_merkle_root(&[], "miner_wrong_target"),
                timestamp: 1_700_000_120,
                difficulty_target: [0x7F; 32],
                nonce: 0,
            },
            reward_recipient: "miner_wrong_target".into(),
            txs: Vec::new(),
        };
        assert!(matches!(
            engine.submit_block(wrong_target_block, &hasher, "miner_wrong_target", occupancy,),
            Err(ChainEngineError::Consensus(
                ConsensusError::InvalidDifficultyTarget { .. }
            ))
        ));

        let median_time_block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block_hash: genesis_hash,
                merkle_root: compute_block_merkle_root(&[], "miner_mtp"),
                timestamp: 1_700_000_000,
                difficulty_target: [0xFF; 32],
                nonce: 0,
            },
            reward_recipient: "miner_mtp".into(),
            txs: Vec::new(),
        };
        assert!(matches!(
            engine.stage_block(median_time_block, &hasher, occupancy),
            Err(ChainEngineError::Consensus(
                ConsensusError::InvalidMedianTimePast { .. }
            ))
        ));
    }

    #[test]
    fn reorg_switches_to_higher_chainwork_branch_and_updates_ledger() {
        let genesis = [0x11u8; 32];
        let hasher = MockRandomXHasher;
        let target = [0xFFu8; 32];

        let mut engine = ChainEngine::new(genesis, 1_000, 125);
        let occ = OCCUPANCY_SCALE / 2;

        let (genesis_header, genesis_hash) = mine_valid_header(
            &hasher,
            &genesis,
            0,
            [0u8; 32],
            compute_block_merkle_root(&[], "miner_genesis"),
            1_700_000_000,
            [0xFF; 32],
        );
        engine
            .submit_block(
                Block {
                    header: genesis_header,
                    reward_recipient: "miner_genesis".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_genesis",
                occ,
            )
            .unwrap();

        let (canonical_header, canonical_hash) = mine_valid_header(
            &hasher,
            &genesis,
            1,
            genesis_hash,
            compute_block_merkle_root(&[], "miner_canonical"),
            1_700_000_120,
            target,
        );
        engine
            .submit_block(
                Block {
                    header: canonical_header,
                    reward_recipient: "miner_canonical".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_canonical",
                occ,
            )
            .unwrap();
        let canonical_miner_balance = engine.state.ledger.balance_of("miner_canonical");

        let (fork_header, fork_hash) = mine_valid_header(
            &hasher,
            &genesis,
            1,
            genesis_hash,
            compute_block_merkle_root(&[], "miner_fork"),
            1_700_000_121,
            target,
        );
        assert!(matches!(
            engine.submit_block(
                Block {
                    header: fork_header,
                    reward_recipient: "miner_fork".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_fork",
                occ,
            ),
            Err(ChainEngineError::ReorgFailed(_))
        ));

        let (fork_tip, fork_hash) = empty_block_for(
            &hasher,
            &genesis,
            2,
            fork_hash,
            1_700_000_241,
            "miner_fork_tip",
        );
        engine
            .submit_block(fork_tip, &hasher, "miner_fork_tip", occ)
            .unwrap();

        assert_eq!(engine.tip_hash(), Some(fork_hash));
        assert_ne!(engine.tip_hash(), Some(canonical_hash));
        assert!(canonical_miner_balance > 0);
        assert_eq!(engine.state.ledger.balance_of("miner_canonical"), 0);
        assert!(engine.state.ledger.balance_of("miner_fork") > 0);
        assert!(engine.state.ledger.balance_of("miner_fork_tip") > 0);
    }

    #[test]
    fn failed_branch_reorg_rolls_back_state_and_preserves_canonical_tip() {
        let genesis = [0x22u8; 32];
        let hasher = MockRandomXHasher;
        let target = [0xFFu8; 32];

        let mut engine = ChainEngine::new(genesis, 1_000, 125);

        let occ = OCCUPANCY_SCALE / 2;
        let (genesis_header, genesis_hash) = mine_valid_header(
            &hasher,
            &genesis,
            0,
            [0u8; 32],
            compute_block_merkle_root(&[], "miner_genesis"),
            1_700_000_000,
            [0xFF; 32],
        );
        engine
            .submit_block(
                Block {
                    header: genesis_header,
                    reward_recipient: "miner_genesis".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_genesis",
                occ,
            )
            .unwrap();

        let (canonical_header, canonical_hash) = mine_valid_header(
            &hasher,
            &genesis,
            1,
            genesis_hash,
            compute_block_merkle_root(&[], "miner_canonical"),
            1_700_000_120,
            target,
        );
        engine
            .submit_block(
                Block {
                    header: canonical_header,
                    reward_recipient: "miner_canonical".into(),
                    txs: Vec::new(),
                },
                &hasher,
                "miner_canonical",
                occ,
            )
            .unwrap();

        let state_before = engine.state.clone();
        let tip_before = engine.tip_hash();
        assert_eq!(tip_before, Some(canonical_hash));

        let bad_tx = make_tx(
            "missing_sender",
            "missing_receiver",
            1_000,
            genesis_hash,
            0x11,
            occ,
        );
        let bad_merkle = compute_block_merkle_root(std::slice::from_ref(&bad_tx), "miner_bad_fork");
        let (bad_header, bad_hash) = mine_valid_header(
            &hasher,
            &genesis,
            1,
            genesis_hash,
            bad_merkle,
            1_700_000_121,
            target,
        );
        assert!(matches!(
            engine.submit_block(
                Block {
                    header: bad_header,
                    reward_recipient: "miner_bad_fork".into(),
                    txs: vec![bad_tx],
                },
                &hasher,
                "miner_bad_fork",
                occ,
            ),
            Err(ChainEngineError::ReorgFailed(_))
        ));
        let (bad_tip, _) = empty_block_for(
            &hasher,
            &genesis,
            2,
            bad_hash,
            1_700_000_241,
            "miner_bad_tip",
        );
        let result = engine.submit_block(bad_tip, &hasher, "miner_bad_tip", occ);

        assert!(matches!(
            result,
            Err(ChainEngineError::Chain(HybridChainError::Ledger(
                LedgerError::AccountNotFound(_)
            )))
        ));
        assert_eq!(engine.tip_hash(), tip_before);
        assert_eq!(engine.state.ledger.balances, state_before.ledger.balances);
        assert_eq!(engine.state.monetary, state_before.monetary);
    }

    fn empty_block(
        hasher: &MockRandomXHasher,
        genesis_seed: &Hash256,
        height: u64,
        parent_hash: Hash256,
        timestamp: u64,
    ) -> (Block, Hash256) {
        empty_block_for(
            hasher,
            genesis_seed,
            height,
            parent_hash,
            timestamp,
            "miner",
        )
    }

    fn empty_block_for(
        hasher: &MockRandomXHasher,
        genesis_seed: &Hash256,
        height: u64,
        parent_hash: Hash256,
        timestamp: u64,
        reward_recipient: &str,
    ) -> (Block, Hash256) {
        let mut header = BlockHeader {
            version: 1,
            height,
            prev_block_hash: parent_hash,
            merkle_root: compute_block_merkle_root(&[], reward_recipient),
            timestamp,
            difficulty_target: [0xFF; 32],
            nonce: 0,
        };
        loop {
            if header.verify_pow(hasher, genesis_seed).is_ok() {
                let hash = header.structural_digest();
                return (
                    Block {
                        header,
                        reward_recipient: reward_recipient.to_string(),
                        txs: Vec::new(),
                    },
                    hash,
                );
            }
            header.nonce = header.nonce.wrapping_add(1);
        }
    }

    #[test]
    fn hybrid_tx_digest_commits_to_antispam_challenge_fields() {
        let tx = HybridTx::Transparent {
            tx: TransferTx {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount_atomic: 1,
            },
            challenge: AntiSpamChallenge {
                prev_block_hash: [1; 32],
                tx_digest: [2; 32],
                amount_atomic: 3,
                occupancy_ppm: 4,
            },
            nonce: 5,
        };
        let original_digest = hybrid_tx_digest(&tx);

        let mut changed = tx.clone();
        if let HybridTx::Transparent { challenge, .. } = &mut changed {
            challenge.amount_atomic += 1;
        }
        assert_ne!(original_digest, hybrid_tx_digest(&changed));

        let mut changed = tx;
        if let HybridTx::Transparent { challenge, .. } = &mut changed {
            challenge.occupancy_ppm += 1;
        }
        assert_ne!(original_digest, hybrid_tx_digest(&changed));
    }

    #[test]
    fn chain_engine_stores_genesis_parameters_and_block_occupancy() {
        let genesis_seed = [0xAA; 32];
        let occupancy_ppm = 234_567;
        let mut engine = ChainEngine::new(genesis_seed, 1_000, 125);
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 0,
                prev_block_hash: [0; 32],
                merkle_root: compute_block_merkle_root(&[], "miner"),
                timestamp: 1_700_000_000,
                difficulty_target: [0xFF; 32],
                nonce: 0,
            },
            reward_recipient: "miner".into(),
            txs: Vec::new(),
        };

        engine
            .submit_block(block, &MockRandomXHasher, "miner", occupancy_ppm)
            .unwrap();

        assert_eq!(engine.initial_supply_sul, 1_000);
        assert_eq!(engine.initial_emission_bps, 125);
        let tip = engine.tip_hash().unwrap();
        assert_eq!(engine.nodes[&tip].occupancy_ppm, occupancy_ppm);
    }

    #[test]
    fn reorganization_replays_with_original_genesis_monetary_parameters() {
        let genesis_seed = [0xA5; 32];
        let hasher = MockRandomXHasher;
        let mut engine = ChainEngine::new(genesis_seed, 1_000, 125);
        let (genesis_block, genesis_hash) =
            empty_block(&hasher, &genesis_seed, 0, [0; 32], 1_700_000_000);
        engine
            .submit_block(genesis_block, &hasher, "miner", 100_000)
            .unwrap();

        let (canonical_child, _) =
            empty_block(&hasher, &genesis_seed, 1, genesis_hash, 1_700_000_120);
        engine
            .submit_block(canonical_child, &hasher, "miner", 200_000)
            .unwrap();

        let (fork_child, fork_child_hash) =
            empty_block(&hasher, &genesis_seed, 1, genesis_hash, 1_700_000_121);
        assert!(matches!(
            engine.submit_block(fork_child, &hasher, "miner", 300_000),
            Err(ChainEngineError::ReorgFailed(_))
        ));

        engine.state.monetary.quarter_start_supply = 2_000 * ATOMIC_UNITS_PER_SUL;
        engine.state.monetary.annual_emission_bps = 333;

        let (fork_tip, _) = empty_block(&hasher, &genesis_seed, 2, fork_child_hash, 1_700_000_241);
        engine
            .submit_block(fork_tip, &hasher, "miner", 400_000)
            .unwrap();

        assert_eq!(
            engine.state.monetary.quarter_start_supply,
            1_000 * ATOMIC_UNITS_PER_SUL
        );
        assert_eq!(engine.state.monetary.annual_emission_bps, 125);
        let tip = engine.tip_hash().unwrap();
        assert_eq!(engine.nodes[&tip].occupancy_ppm, 400_000);
    }

    #[test]
    fn mempool_rejects_duplicate_tx_and_tracks_key_images() {
        let mut mempool = Mempool::new(2);
        let tx = HybridTx::Transparent {
            tx: TransferTx {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount_atomic: ATOMIC_UNITS_PER_SUL,
            },
            challenge: AntiSpamChallenge {
                prev_block_hash: [0x11; 32],
                tx_digest: [0x22; 32],
                amount_atomic: ATOMIC_UNITS_PER_SUL,
                occupancy_ppm: 500_000,
            },
            nonce: 0,
        };
        let nonce = solve_micro_pow(match &tx {
            HybridTx::Transparent { challenge, .. } => challenge,
            HybridTx::Confidential { challenge, .. } => challenge,
        });
        let tx = match tx {
            HybridTx::Transparent { tx, challenge, .. } => HybridTx::Transparent {
                tx,
                challenge,
                nonce,
            },
            other => other,
        };

        mempool.insert_tx(tx.clone(), &[]).unwrap();
        assert!(matches!(
            mempool.insert_tx(tx, &[]),
            Err(ChainEngineError::DuplicateTx(_))
        ));
    }
}
