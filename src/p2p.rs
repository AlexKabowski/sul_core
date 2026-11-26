use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use bincode::Options;

use crate::antispam::Hash32;
use crate::chain_engine::{
    hybrid_tx_digest, Block, ChainEngine, ChainEngineError, StoredBlockInfo, MAX_BLOCK_TXS,
};
use crate::chain_state::{HybridChainError, HybridTx};
use crate::params::{
    DIFFICULTY_RETARGET_WINDOW_BLOCKS, MAX_SYNC_BLOCKS_PER_MESSAGE, MAX_SYNC_BLOCKS_PER_SESSION,
    MAX_SYNC_ITERATIONS_PER_SESSION, MEDIAN_TIME_PAST_BLOCKS,
};
use crate::persistence::{DiskStore, PersistenceError};
use crate::pow_randomx::{retarget_difficulty_with_window, BlockHeader, Hash256, RandomXHasher};
use crate::privacy::verify_confidential_tx_against_outputs;

pub type PeerId = String;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_BATCH_BLOCKS: usize = MAX_SYNC_BLOCKS_PER_MESSAGE;
pub const MAX_PEERS: usize = 64;
pub const MAX_PENDING_BLOCKS: usize = 128;
pub const MAX_SEEN_TX_DIGESTS: usize = 8_192;
pub const MAX_ENCODED_MESSAGE_BYTES: u64 = 2 * 1024 * 1024;
const MESSAGE_MAGIC: &[u8; 8] = b"SULP2P01";
const FRAME_HEADER_SIZE: usize = 8 + 4 + 8;
const CHECKSUM_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: PeerId,
    pub tip_height: u64,
    pub tip_hash: Option<Hash256>,
    pub tip_work: u128,
}

/// P2P synchronization is controlled-trust only while occupancy is not consensus-committed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderAnnouncement {
    pub hash: Hash256,
    pub header: BlockHeader,
    pub occupancy_ppm: u128,
}

/// Version-framed wire messages exchanged by SUL peers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum P2pMessage {
    Hello {
        network_id: Hash256,
        genesis_hash: Hash256,
        peer_id: PeerId,
    },
    Status {
        tip_height: u64,
        tip_hash: Option<Hash256>,
        tip_work: u128,
    },
    GetHeaders {
        locator: Vec<Hash256>,
    },
    Headers {
        entries: Vec<HeaderAnnouncement>,
    },
    GetBlocksByHash {
        hashes: Vec<Hash256>,
    },
    BlockData {
        block: Block,
        occupancy_ppm: u128,
    },
    AnnounceTx(HybridTx),
    Ping(u64),
    Pong(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pError {
    NetworkMismatch,
    GenesisMismatch,
    ProtocolVersionMismatch(u32),
    UnknownPeer(PeerId),
    PeerLimitReached,
    PeerIdentityMismatch,
    BatchTooLarge {
        actual: usize,
        max: usize,
    },
    MessageTooLarge {
        actual: usize,
        max: usize,
    },
    SyncLimitExceeded {
        max_blocks: usize,
        max_iterations: usize,
    },
    InvalidMessage(&'static str),
    InvalidTransaction(ChainEngineError),
    Chain(ChainEngineError),
    Persistence(String),
    Transport(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkMismatch => write!(formatter, "peer uses an incompatible network"),
            Self::GenesisMismatch => write!(formatter, "peer has an incompatible genesis block"),
            Self::ProtocolVersionMismatch(version) => {
                write!(formatter, "unsupported P2P protocol version: {version}")
            }
            Self::UnknownPeer(peer) => write!(formatter, "unknown or unhandshaked peer: {peer}"),
            Self::PeerLimitReached => write!(formatter, "peer limit reached"),
            Self::PeerIdentityMismatch => write!(formatter, "peer identity does not match sender"),
            Self::BatchTooLarge { actual, max } => {
                write!(formatter, "batch exceeds limit: {actual} > {max}")
            }
            Self::MessageTooLarge { actual, max } => {
                write!(formatter, "message exceeds limit: {actual} > {max}")
            }
            Self::SyncLimitExceeded {
                max_blocks,
                max_iterations,
            } => write!(
                formatter,
                "sync session limit exceeded ({max_blocks} blocks, {max_iterations} iterations)"
            ),
            Self::InvalidMessage(message) => write!(formatter, "invalid P2P message: {message}"),
            Self::InvalidTransaction(error) => {
                write!(formatter, "peer announced an invalid transaction: {error}")
            }
            Self::Chain(error) => write!(formatter, "chain rejected peer data: {error}"),
            Self::Persistence(error) => write!(formatter, "persistence failed: {error}"),
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
        }
    }
}

impl std::error::Error for P2pError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    pub to: PeerId,
    pub message: P2pMessage,
}

#[derive(Debug, Clone)]
struct PendingBlock {
    announcement: HeaderAnnouncement,
    block: Block,
    provider: PeerId,
}

#[derive(Debug, Default)]
pub struct SyncEngine {
    requested_headers: HashSet<PeerId>,
    peer_locators: HashMap<PeerId, Hash256>,
    sessions: HashMap<PeerId, SyncSession>,
    requested_blocks: HashMap<Hash256, (PeerId, HeaderAnnouncement)>,
    pending_blocks: HashMap<Hash256, PendingBlock>,
}

#[derive(Debug, Clone)]
struct SyncSession {
    tip_hash: Option<Hash256>,
    header_batches: usize,
    headers_received: usize,
    headers_complete: bool,
    staged_hashes: Vec<Hash256>,
}

#[derive(Debug, Default)]
pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
}

impl PeerManager {
    pub fn get(&self, peer_id: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values()
    }

    fn insert(&mut self, peer: PeerInfo) -> Result<(), P2pError> {
        if !self.peers.contains_key(&peer.id) && self.peers.len() >= MAX_PEERS {
            return Err(P2pError::PeerLimitReached);
        }
        self.peers.insert(peer.id.clone(), peer);
        Ok(())
    }
}

/// Coordinates peer identity, message handling, bounded sync state, and optional persistence.
pub struct P2pNode {
    pub peer_id: PeerId,
    pub network_id: Hash256,
    pub genesis_hash: Hash256,
    pub peers: PeerManager,
    pub sync: SyncEngine,
    seen_tx_digests: HashSet<Hash256>,
    seen_tx_order: VecDeque<Hash256>,
    store: Option<DiskStore>,
}

impl P2pNode {
    /// Creates a node bound to a network and expected genesis block hash.
    pub fn new(peer_id: impl Into<String>, network_id: Hash256, genesis_hash: Hash256) -> Self {
        Self {
            peer_id: peer_id.into(),
            network_id,
            genesis_hash,
            peers: PeerManager::default(),
            sync: SyncEngine::default(),
            seen_tx_digests: HashSet::new(),
            seen_tx_order: VecDeque::new(),
            store: None,
        }
    }

    pub fn with_store(mut self, store: DiskStore) -> Self {
        self.store = Some(store);
        self
    }

    pub fn hello(&self) -> P2pMessage {
        P2pMessage::Hello {
            network_id: self.network_id,
            genesis_hash: self.genesis_hash,
            peer_id: self.peer_id.clone(),
        }
    }

    fn status(&self, engine: &ChainEngine) -> P2pMessage {
        P2pMessage::Status {
            tip_height: engine.tip_header().map_or(0, |header| header.height),
            tip_hash: engine.tip_hash(),
            tip_work: engine.current_tip_work(),
        }
    }

    pub fn announce_tx(&mut self, tx: HybridTx) -> P2pMessage {
        self.remember_tx(hybrid_tx_digest(&tx));
        P2pMessage::AnnounceTx(tx)
    }

    /// Builds status packets for all handshaked peers after a local chain update.
    pub fn announce_tip(&self, engine: &ChainEngine) -> Vec<OutboundPacket> {
        let message = self.status(engine);
        self.peers
            .iter()
            .map(|peer| OutboundPacket {
                to: peer.id.clone(),
                message: message.clone(),
            })
            .collect()
    }

    /// Validates and processes one peer message, returning packets to send.
    pub fn handle_message<H: RandomXHasher>(
        &mut self,
        from: &str,
        message: P2pMessage,
        engine: &mut ChainEngine,
        hasher: &H,
        miner_id: &str,
    ) -> Result<Vec<OutboundPacket>, P2pError> {
        let mut outbound = Vec::new();
        match message {
            P2pMessage::Hello {
                network_id,
                genesis_hash,
                peer_id,
            } => {
                if network_id != self.network_id {
                    return Err(P2pError::NetworkMismatch);
                }
                if genesis_hash != self.genesis_hash {
                    return Err(P2pError::GenesisMismatch);
                }
                if peer_id != from || peer_id.is_empty() || peer_id == self.peer_id {
                    return Err(P2pError::PeerIdentityMismatch);
                }
                self.peers.insert(PeerInfo {
                    id: peer_id.clone(),
                    tip_height: 0,
                    tip_hash: None,
                    tip_work: 0,
                })?;
                outbound.push(OutboundPacket {
                    to: peer_id,
                    message: self.status(engine),
                });
            }
            P2pMessage::Status {
                tip_height,
                tip_hash,
                tip_work,
            } => {
                let peer = self.peer_mut(from)?;
                peer.tip_height = tip_height;
                peer.tip_hash = tip_hash;
                peer.tip_work = tip_work;
                if tip_work > engine.current_tip_work()
                    && self.sync.requested_headers.insert(from.to_string())
                {
                    self.sync.sessions.insert(
                        from.to_string(),
                        SyncSession {
                            tip_hash,
                            header_batches: 0,
                            headers_received: 0,
                            headers_complete: false,
                            staged_hashes: Vec::new(),
                        },
                    );
                    outbound.push(OutboundPacket {
                        to: from.to_string(),
                        message: P2pMessage::GetHeaders {
                            locator: build_locator(engine, None),
                        },
                    });
                }
            }
            P2pMessage::GetHeaders { locator } => {
                self.peer(from)?;
                if locator.len() > MAX_BATCH_BLOCKS {
                    return Err(P2pError::BatchTooLarge {
                        actual: locator.len(),
                        max: MAX_BATCH_BLOCKS,
                    });
                }
                let entries = engine
                    .canonical_blocks_after(&locator, MAX_BATCH_BLOCKS)
                    .into_iter()
                    .map(header_announcement)
                    .collect();
                outbound.push(OutboundPacket {
                    to: from.to_string(),
                    message: P2pMessage::Headers { entries },
                });
            }
            P2pMessage::Headers { entries } => {
                let peer = self.peer(from)?.clone();
                if !self.sync.requested_headers.remove(from) {
                    return Err(P2pError::InvalidMessage(
                        "received headers without a matching request",
                    ));
                }
                if entries.len() > MAX_BATCH_BLOCKS {
                    self.abort_sync(from, engine);
                    return Err(P2pError::BatchTooLarge {
                        actual: entries.len(),
                        max: MAX_BATCH_BLOCKS,
                    });
                }
                let session = self
                    .sync
                    .sessions
                    .get_mut(from)
                    .ok_or(P2pError::InvalidMessage(
                        "header request has no active sync session",
                    ))?;
                session.header_batches += 1;
                session.headers_received += entries.len();
                if session.header_batches > MAX_SYNC_ITERATIONS_PER_SESSION
                    || session.headers_received > MAX_SYNC_BLOCKS_PER_SESSION
                {
                    self.abort_sync(from, engine);
                    return Err(P2pError::SyncLimitExceeded {
                        max_blocks: MAX_SYNC_BLOCKS_PER_SESSION,
                        max_iterations: MAX_SYNC_ITERATIONS_PER_SESSION,
                    });
                }
                if entries
                    .iter()
                    .any(|entry| entry.header.height == 0 && entry.hash != self.genesis_hash)
                {
                    self.abort_sync(from, engine);
                    return Err(P2pError::GenesisMismatch);
                }
                if let Err(error) = validate_header_batch(&entries, engine) {
                    self.abort_sync(from, engine);
                    return Err(error);
                }
                let reached_tip = entries.last().map_or(false, |entry| {
                    Some(entry.hash) == self.sync.sessions[from].tip_hash
                });
                let headers_complete = entries.len() < MAX_BATCH_BLOCKS || reached_tip;
                if let Some(last) = entries.last() {
                    self.sync.peer_locators.insert(peer.id.clone(), last.hash);
                }
                let session = self
                    .sync
                    .sessions
                    .get_mut(from)
                    .expect("sync session exists");
                session.headers_complete = headers_complete;
                let mut requested = Vec::new();
                for entry in entries {
                    if !engine.has_block(&entry.hash)
                        && !self.sync.requested_blocks.contains_key(&entry.hash)
                    {
                        self.sync
                            .requested_blocks
                            .insert(entry.hash, (peer.id.clone(), entry.clone()));
                        requested.push(entry.hash);
                    }
                }
                for batch in requested.chunks(MAX_BATCH_BLOCKS) {
                    outbound.push(OutboundPacket {
                        to: peer.id.clone(),
                        message: P2pMessage::GetBlocksByHash {
                            hashes: batch.to_vec(),
                        },
                    });
                }
                if requested.is_empty() && !headers_complete {
                    self.request_more_headers(&peer.id, engine, &mut outbound)?;
                }
                let old_tip = engine.tip_hash();
                self.finish_sync_if_ready(&peer.id, engine, hasher, miner_id, &mut outbound)?;
                if engine.tip_hash() != old_tip {
                    for other in self.peers.iter() {
                        if other.id != from {
                            outbound.push(OutboundPacket {
                                to: other.id.clone(),
                                message: self.status(engine),
                            });
                        }
                    }
                }
            }
            P2pMessage::GetBlocksByHash { hashes } => {
                self.peer(from)?;
                if hashes.len() > MAX_BATCH_BLOCKS {
                    return Err(P2pError::BatchTooLarge {
                        actual: hashes.len(),
                        max: MAX_BATCH_BLOCKS,
                    });
                }
                for hash in hashes {
                    if let Some(info) = engine.stored_block_info(&hash) {
                        outbound.push(OutboundPacket {
                            to: from.to_string(),
                            message: P2pMessage::BlockData {
                                block: info.block,
                                occupancy_ppm: info.occupancy_ppm,
                            },
                        });
                    }
                }
            }
            P2pMessage::BlockData {
                block,
                occupancy_ppm,
            } => {
                self.peer(from)?;
                let hash = block.header.structural_digest();
                let Some((provider, announcement)) = self.sync.requested_blocks.remove(&hash)
                else {
                    if engine.has_block(&hash) {
                        return Ok(outbound);
                    }
                    return Err(P2pError::InvalidMessage(
                        "received a block that was not requested",
                    ));
                };
                if block.txs.len() > MAX_BLOCK_TXS {
                    self.abort_sync(&provider, engine);
                    return Err(P2pError::Chain(ChainEngineError::TooManyTransactions {
                        actual: block.txs.len(),
                        max: MAX_BLOCK_TXS,
                    }));
                }
                if provider != from
                    || announcement.header != block.header
                    || announcement.hash != hash
                    || announcement.occupancy_ppm != occupancy_ppm
                {
                    self.abort_sync(&provider, engine);
                    return Err(P2pError::InvalidMessage(
                        "block does not match its requested header",
                    ));
                }
                if block.header.height == 0 && hash != self.genesis_hash {
                    self.abort_sync(&provider, engine);
                    return Err(P2pError::GenesisMismatch);
                }
                if self.sync.pending_blocks.len() >= MAX_PENDING_BLOCKS {
                    self.abort_sync(&provider, engine);
                    return Err(P2pError::BatchTooLarge {
                        actual: self.sync.pending_blocks.len() + 1,
                        max: MAX_PENDING_BLOCKS,
                    });
                }
                self.sync.pending_blocks.insert(
                    hash,
                    PendingBlock {
                        announcement,
                        block,
                        provider: provider.clone(),
                    },
                );
                let old_tip = engine.tip_hash();
                if let Err(error) = self.apply_ready_blocks(engine, hasher) {
                    self.abort_sync(&provider, engine);
                    return Err(error);
                }
                let activated =
                    self.finish_sync_if_ready(&provider, engine, hasher, miner_id, &mut outbound)?;
                if engine.tip_hash() != old_tip {
                    for peer in self.peers.iter() {
                        if peer.id != from {
                            outbound.push(OutboundPacket {
                                to: peer.id.clone(),
                                message: self.status(engine),
                            });
                        }
                    }
                }
                if !activated
                    && !self
                        .sync
                        .requested_blocks
                        .values()
                        .any(|(peer_id, _)| peer_id == from)
                {
                    self.request_more_headers(from, engine, &mut outbound)?;
                }
            }
            P2pMessage::AnnounceTx(tx) => {
                self.peer(from)?;
                if let HybridTx::Confidential {
                    tx: confidential_tx,
                    challenge,
                    ..
                } = &tx
                {
                    verify_confidential_tx_against_outputs(
                        confidential_tx,
                        &engine.state.spent_key_images,
                        &engine.state.valid_outputs,
                        challenge.occupancy_ppm,
                    )
                    .map_err(|error| {
                        P2pError::InvalidTransaction(ChainEngineError::Chain(
                            HybridChainError::Privacy(error),
                        ))
                    })?;
                }
                let digest = hybrid_tx_digest(&tx);
                if !self.seen_tx_digests.contains(&digest) {
                    let anchors = engine.recent_block_hashes();
                    match engine.mempool.insert_tx(tx.clone(), &anchors) {
                        Ok(_) => {
                            self.remember_tx(digest);
                            for peer in self.peers.iter() {
                                if peer.id != from {
                                    outbound.push(OutboundPacket {
                                        to: peer.id.clone(),
                                        message: P2pMessage::AnnounceTx(tx.clone()),
                                    });
                                }
                            }
                        }
                        Err(ChainEngineError::DuplicateTx(_))
                        | Err(ChainEngineError::DuplicatePendingKeyImage(_)) => {
                            self.remember_tx(digest);
                        }
                        Err(error) => return Err(P2pError::InvalidTransaction(error)),
                    }
                }
            }
            P2pMessage::Ping(nonce) => {
                self.peer(from)?;
                outbound.push(OutboundPacket {
                    to: from.to_string(),
                    message: P2pMessage::Pong(nonce),
                });
            }
            P2pMessage::Pong(_) => {
                self.peer(from)?;
            }
        }
        Ok(outbound)
    }

    /// Handles one queued transport message and sends all resulting packets.
    pub fn poll_transport<T: Transport, H: RandomXHasher>(
        &mut self,
        transport: &mut T,
        engine: &mut ChainEngine,
        hasher: &H,
        miner_id: &str,
    ) -> Result<bool, P2pError> {
        let Some((from, message)) = transport.receive(&self.peer_id) else {
            return Ok(false);
        };
        let outbound = self.handle_message(&from, message, engine, hasher, miner_id)?;
        for packet in outbound {
            transport.send(&self.peer_id, &packet.to, packet.message)?;
        }
        Ok(true)
    }

    fn peer(&self, peer_id: &str) -> Result<&PeerInfo, P2pError> {
        self.peers
            .get(peer_id)
            .ok_or_else(|| P2pError::UnknownPeer(peer_id.to_string()))
    }

    fn peer_mut(&mut self, peer_id: &str) -> Result<&mut PeerInfo, P2pError> {
        self.peers
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| P2pError::UnknownPeer(peer_id.to_string()))
    }

    fn remember_tx(&mut self, digest: Hash256) {
        if self.seen_tx_digests.insert(digest) {
            self.seen_tx_order.push_back(digest);
            while self.seen_tx_order.len() > MAX_SEEN_TX_DIGESTS {
                if let Some(expired) = self.seen_tx_order.pop_front() {
                    self.seen_tx_digests.remove(&expired);
                }
            }
        }
    }

    fn request_more_headers(
        &mut self,
        peer_id: &str,
        engine: &mut ChainEngine,
        outbound: &mut Vec<OutboundPacket>,
    ) -> Result<(), P2pError> {
        let Some(peer) = self.peers.get(peer_id).cloned() else {
            return Ok(());
        };
        let Some(session) = self.sync.sessions.get(peer_id) else {
            return Ok(());
        };
        if session.headers_complete {
            return Ok(());
        }
        if session.header_batches >= MAX_SYNC_ITERATIONS_PER_SESSION
            || session.headers_received >= MAX_SYNC_BLOCKS_PER_SESSION
        {
            self.abort_sync(peer_id, engine);
            return Err(P2pError::SyncLimitExceeded {
                max_blocks: MAX_SYNC_BLOCKS_PER_SESSION,
                max_iterations: MAX_SYNC_ITERATIONS_PER_SESSION,
            });
        }
        if peer.tip_work > engine.current_tip_work()
            && self.sync.requested_headers.insert(peer_id.to_string())
        {
            outbound.push(OutboundPacket {
                to: peer_id.to_string(),
                message: P2pMessage::GetHeaders {
                    locator: build_locator(engine, self.sync.peer_locators.get(peer_id).copied()),
                },
            });
        }
        Ok(())
    }

    fn apply_ready_blocks<H: RandomXHasher>(
        &mut self,
        engine: &mut ChainEngine,
        hasher: &H,
    ) -> Result<(), P2pError> {
        loop {
            let ready_hash = self.sync.pending_blocks.iter().find_map(|(hash, pending)| {
                let parent = pending.block.header.prev_block_hash;
                (pending.block.header.height == 0 || engine.has_block(&parent)).then_some(*hash)
            });
            let Some(hash) = ready_hash else {
                break;
            };
            let pending = self
                .sync
                .pending_blocks
                .remove(&hash)
                .expect("pending block exists");
            let occupancy = pending.announcement.occupancy_ppm;
            let was_known = engine.has_block(&hash);
            engine
                .stage_block(pending.block.clone(), hasher, occupancy)
                .map_err(P2pError::Chain)?;
            if !was_known {
                if let Some(session) = self.sync.sessions.get_mut(&pending.provider) {
                    session.staged_hashes.push(hash);
                }
            }
            if let Some(store) = &self.store {
                store
                    .write_block(&hash, &pending.block)
                    .map_err(persistence_error)?;
            }
        }
        Ok(())
    }

    fn finish_sync_if_ready<H: RandomXHasher>(
        &mut self,
        peer_id: &str,
        engine: &mut ChainEngine,
        hasher: &H,
        miner_id: &str,
        outbound: &mut Vec<OutboundPacket>,
    ) -> Result<bool, P2pError> {
        let ready = self.sync.sessions.get(peer_id).map_or(false, |session| {
            session.headers_complete
                && !self
                    .sync
                    .requested_blocks
                    .values()
                    .any(|(provider, _)| provider == peer_id)
                && !self
                    .sync
                    .pending_blocks
                    .values()
                    .any(|pending| pending.provider == peer_id)
        });
        if !ready {
            return Ok(false);
        }

        let session = self
            .sync
            .sessions
            .get(peer_id)
            .expect("ready session exists");
        let Some(target_hash) = session.tip_hash else {
            self.abort_sync(peer_id, engine);
            return Err(P2pError::InvalidMessage(
                "sync session has no announced tip",
            ));
        };
        if !engine.has_block(&target_hash) {
            self.abort_sync(peer_id, engine);
            return Err(P2pError::InvalidMessage(
                "peer completed headers without providing the announced tip",
            ));
        }

        let target_work = engine
            .stored_block_info(&target_hash)
            .expect("checked staged tip exists")
            .chainwork;
        let activated = target_work > engine.current_tip_work();
        if activated {
            if let Err(error) = engine.activate_chain(target_hash, hasher, miner_id) {
                self.abort_sync(peer_id, engine);
                return Err(P2pError::Chain(error));
            }
            if let Some(store) = &self.store {
                if let Err(error) = store.save_engine_snapshot(engine) {
                    self.abort_sync(peer_id, engine);
                    return Err(persistence_error(error));
                }
            }
            outbound.extend(self.announce_tip(engine));
        } else if let Some(session) = self.sync.sessions.get(peer_id) {
            engine.discard_staged_blocks(&session.staged_hashes);
        }

        self.sync.sessions.remove(peer_id);
        self.sync.requested_headers.remove(peer_id);
        self.sync.peer_locators.remove(peer_id);
        Ok(activated)
    }

    fn abort_sync(&mut self, peer_id: &str, engine: &mut ChainEngine) {
        self.sync.requested_headers.remove(peer_id);
        self.sync
            .requested_blocks
            .retain(|_, (provider, _)| provider != peer_id);
        self.sync
            .pending_blocks
            .retain(|_, pending| pending.provider != peer_id);
        self.sync.peer_locators.remove(peer_id);
        if let Some(session) = self.sync.sessions.remove(peer_id) {
            engine.discard_staged_blocks(&session.staged_hashes);
        }
    }
}

/// Encodes a protocol version, bounded binary payload, and BLAKE3 frame checksum.
pub fn encode_message(message: &P2pMessage) -> Result<Vec<u8>, P2pError> {
    let payload = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ENCODED_MESSAGE_BYTES)
        .serialize(message)
        .map_err(|_| P2pError::InvalidMessage("message serialization failed"))?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len() + CHECKSUM_SIZE);
    frame.extend_from_slice(MESSAGE_MAGIC);
    frame.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(&payload);
    let checksum = blake3::hash(&frame);
    frame.extend_from_slice(checksum.as_bytes());
    Ok(frame)
}

/// Verifies protocol framing and checksum before deserializing a bounded message.
pub fn decode_message(frame: &[u8]) -> Result<P2pMessage, P2pError> {
    let max_frame = FRAME_HEADER_SIZE as u64 + MAX_ENCODED_MESSAGE_BYTES + CHECKSUM_SIZE as u64;
    if frame.len() as u64 > max_frame {
        return Err(P2pError::MessageTooLarge {
            actual: frame.len(),
            max: max_frame as usize,
        });
    }
    if frame.len() < FRAME_HEADER_SIZE + CHECKSUM_SIZE || &frame[..8] != MESSAGE_MAGIC {
        return Err(P2pError::InvalidMessage("invalid frame header"));
    }
    let version = u32::from_le_bytes(frame[8..12].try_into().expect("fixed version size"));
    if version != PROTOCOL_VERSION {
        return Err(P2pError::ProtocolVersionMismatch(version));
    }
    let payload_len = u64::from_le_bytes(frame[12..20].try_into().expect("fixed length size"));
    if payload_len > MAX_ENCODED_MESSAGE_BYTES
        || frame.len() as u64 != FRAME_HEADER_SIZE as u64 + payload_len + CHECKSUM_SIZE as u64
    {
        return Err(P2pError::InvalidMessage("inconsistent frame length"));
    }
    let checksum_start = frame.len() - CHECKSUM_SIZE;
    let expected: Hash32 = frame[checksum_start..]
        .try_into()
        .expect("fixed checksum size");
    let actual = *blake3::hash(&frame[..checksum_start]).as_bytes();
    if expected != actual {
        return Err(P2pError::InvalidMessage("checksum mismatch"));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ENCODED_MESSAGE_BYTES)
        .deserialize(&frame[FRAME_HEADER_SIZE..checksum_start])
        .map_err(|_| P2pError::InvalidMessage("message payload is malformed"))
}

/// Transport adapters move typed protocol messages without owning chain logic.
pub trait Transport {
    fn send(&mut self, from: &str, to: &str, message: P2pMessage) -> Result<(), P2pError>;
    fn receive(&mut self, recipient: &str) -> Option<(PeerId, P2pMessage)>;
}

#[derive(Debug, Default)]
pub struct InMemoryMesh {
    inboxes: HashMap<PeerId, VecDeque<(PeerId, P2pMessage)>>,
}

impl InMemoryMesh {
    pub fn register(&mut self, peer_id: impl Into<PeerId>) {
        self.inboxes.entry(peer_id.into()).or_default();
    }

    pub fn pending_messages(&self, peer_id: &str) -> usize {
        self.inboxes.get(peer_id).map_or(0, VecDeque::len)
    }
}

impl Transport for InMemoryMesh {
    fn send(&mut self, from: &str, to: &str, message: P2pMessage) -> Result<(), P2pError> {
        if !self.inboxes.contains_key(from) {
            return Err(P2pError::Transport(format!("unregistered sender: {from}")));
        }
        let inbox = self
            .inboxes
            .get_mut(to)
            .ok_or_else(|| P2pError::Transport(format!("unregistered recipient: {to}")))?;
        inbox.push_back((from.to_string(), message));
        Ok(())
    }

    fn receive(&mut self, recipient: &str) -> Option<(PeerId, P2pMessage)> {
        self.inboxes
            .get_mut(recipient)
            .and_then(VecDeque::pop_front)
    }
}

fn build_locator(engine: &ChainEngine, preferred: Option<Hash256>) -> Vec<Hash256> {
    let mut locator = Vec::with_capacity(MAX_BATCH_BLOCKS);
    if let Some(hash) = preferred {
        locator.push(hash);
    }
    for hash in engine.canonical_hashes().iter().rev() {
        if locator.len() == MAX_BATCH_BLOCKS {
            break;
        }
        if !locator.contains(hash) {
            locator.push(*hash);
        }
    }
    locator
}

fn header_announcement(info: StoredBlockInfo) -> HeaderAnnouncement {
    HeaderAnnouncement {
        hash: info.hash,
        header: info.block.header,
        occupancy_ppm: info.occupancy_ppm,
    }
}

fn validate_header_batch(
    entries: &[HeaderAnnouncement],
    engine: &ChainEngine,
) -> Result<(), P2pError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut parent_header = None;
    let mut parent_hash = None;
    let mut recent_headers = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        if entry.hash != entry.header.structural_digest() {
            return Err(P2pError::InvalidMessage("header hash mismatch"));
        }
        if entry.header.height == 0 {
            if index != 0 {
                return Err(P2pError::InvalidMessage(
                    "genesis header appears after the start of the batch",
                ));
            }
            if entry.header.prev_block_hash != [0; 32] {
                return Err(P2pError::InvalidMessage("invalid genesis header"));
            }
            parent_header = Some(entry.header.clone());
            parent_hash = Some(entry.hash);
            recent_headers.clear();
            continue;
        }

        if index == 0 {
            let parent = engine.header_by_hash(&entry.header.prev_block_hash).ok_or(
                P2pError::InvalidMessage("header batch does not connect to a known block"),
            )?;
            if entry.header.height != parent.height.saturating_add(1) {
                return Err(P2pError::InvalidMessage("headers are not contiguous"));
            }
            parent_header = Some(parent.clone());
            recent_headers = engine.recent_ancestor_headers(
                &entry.header.prev_block_hash,
                MEDIAN_TIME_PAST_BLOCKS.saturating_sub(1),
            );
        } else if entry.header.height
            != parent_header
                .as_ref()
                .expect("previous header exists")
                .height
                .saturating_add(1)
            || Some(entry.header.prev_block_hash) != parent_hash
        {
            return Err(P2pError::InvalidMessage("headers are not contiguous"));
        }

        let parent = parent_header
            .as_ref()
            .expect("non-genesis header has a parent");
        let expected_target = if entry.header.height % DIFFICULTY_RETARGET_WINDOW_BLOCKS == 0 {
            let start_height = entry
                .header
                .height
                .saturating_sub(DIFFICULTY_RETARGET_WINDOW_BLOCKS);
            let start_header = entries[..index]
                .iter()
                .rev()
                .find(|candidate| candidate.header.height == start_height)
                .map(|candidate| &candidate.header)
                .or_else(|| {
                    engine.ancestor_header(&entries[0].header.prev_block_hash, start_height)
                })
                .ok_or(P2pError::InvalidMessage(
                    "missing difficulty retarget history",
                ))?;
            Some(retarget_difficulty_with_window(
                &parent.difficulty_target,
                DIFFICULTY_RETARGET_WINDOW_BLOCKS,
                start_header.timestamp,
                parent.timestamp,
            ))
        } else {
            Some(parent.difficulty_target)
        };
        entry
            .header
            .validate_parent_with_history(parent, &recent_headers, expected_target.as_ref())
            .map_err(|error| P2pError::Chain(ChainEngineError::Consensus(error)))?;

        recent_headers.insert(0, parent.clone());
        recent_headers.truncate(MEDIAN_TIME_PAST_BLOCKS.saturating_sub(1));
        parent_header = Some(entry.header.clone());
        parent_hash = Some(entry.hash);
    }

    Ok(())
}

fn persistence_error(error: PersistenceError) -> P2pError {
    P2pError::Persistence(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_engine::compute_merkle_root;
    use crate::chain_state::HybridTx;
    use crate::ledger::TransferTx;
    use crate::params::ATOMIC_UNITS_PER_SUL;
    use crate::pow_randomx::MockRandomXHasher;

    fn empty_block(seed: &Hash256, height: u64, parent_hash: Hash256, timestamp: u64) -> Block {
        empty_block_with_target(seed, height, parent_hash, timestamp, [0xFF; 32])
    }

    fn empty_block_with_target(
        seed: &Hash256,
        height: u64,
        parent_hash: Hash256,
        timestamp: u64,
        difficulty_target: Hash256,
    ) -> Block {
        let mut header = BlockHeader {
            version: 1,
            height,
            prev_block_hash: parent_hash,
            merkle_root: compute_merkle_root(&[]),
            timestamp,
            difficulty_target,
            nonce: 0,
        };
        let hasher = MockRandomXHasher;
        while header.verify_pow(&hasher, seed).is_err() {
            header.nonce = header.nonce.wrapping_add(1);
        }
        Block {
            header,
            txs: Vec::new(),
        }
    }

    fn handshake(
        left_node: &mut P2pNode,
        right_node: &mut P2pNode,
        left_engine: &mut ChainEngine,
        right_engine: &mut ChainEngine,
        mesh: &mut InMemoryMesh,
    ) {
        mesh.register(&left_node.peer_id);
        mesh.register(&right_node.peer_id);
        mesh.send(&left_node.peer_id, &right_node.peer_id, left_node.hello())
            .unwrap();
        mesh.send(&right_node.peer_id, &left_node.peer_id, right_node.hello())
            .unwrap();
        let hasher = MockRandomXHasher;
        for _ in 0..8 {
            let mut did_work = false;
            did_work |= left_node
                .poll_transport(mesh, left_engine, &hasher, "miner")
                .unwrap();
            did_work |= right_node
                .poll_transport(mesh, right_engine, &hasher, "miner")
                .unwrap();
            if !did_work {
                break;
            }
        }
    }

    fn synchronize(
        left_node: &mut P2pNode,
        right_node: &mut P2pNode,
        left_engine: &mut ChainEngine,
        right_engine: &mut ChainEngine,
        mesh: &mut InMemoryMesh,
    ) {
        let hasher = MockRandomXHasher;
        for _ in 0..1_000 {
            let mut did_work = false;
            did_work |= left_node
                .poll_transport(mesh, left_engine, &hasher, "miner")
                .unwrap();
            did_work |= right_node
                .poll_transport(mesh, right_engine, &hasher, "miner")
                .unwrap();
            if !did_work {
                break;
            }
        }
        assert_eq!(mesh.pending_messages(&left_node.peer_id), 0);
        assert_eq!(mesh.pending_messages(&right_node.peer_id), 0);
    }

    #[test]
    fn p2p_message_roundtrip_checks_version_and_checksum() {
        let message = P2pMessage::Ping(42);
        let frame = encode_message(&message).unwrap();
        assert_eq!(decode_message(&frame).unwrap(), message);

        let mut damaged = frame.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(matches!(
            decode_message(&damaged),
            Err(P2pError::InvalidMessage("checksum mismatch"))
        ));

        let mut unsupported = frame;
        unsupported[8..12].copy_from_slice(&(PROTOCOL_VERSION + 1).to_le_bytes());
        assert!(matches!(
            decode_message(&unsupported),
            Err(P2pError::ProtocolVersionMismatch(_))
        ));
    }

    #[test]
    fn mesh_handshake_and_sync_fetch_blocks_in_chain_order() {
        let seed = [0xA1; 32];
        let network = [0xB2; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let mut left_engine = ChainEngine::new(seed, 1_000, 125);
        let mut right_engine = ChainEngine::new(seed, 1_000, 125);
        let hasher = MockRandomXHasher;
        left_engine
            .submit_block(genesis.clone(), &hasher, "miner", 100_000)
            .unwrap();
        right_engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();
        let child = empty_block(&seed, 1, genesis_hash, 1_700_000_120);
        left_engine
            .submit_block(child, &hasher, "miner", 200_000)
            .unwrap();

        let mut left_node = P2pNode::new("left", network, genesis_hash);
        let mut right_node = P2pNode::new("right", network, genesis_hash);
        let mut mesh = InMemoryMesh::default();
        handshake(
            &mut left_node,
            &mut right_node,
            &mut left_engine,
            &mut right_engine,
            &mut mesh,
        );
        synchronize(
            &mut left_node,
            &mut right_node,
            &mut left_engine,
            &mut right_engine,
            &mut mesh,
        );

        assert_eq!(right_engine.tip_hash(), left_engine.tip_hash());
        assert_eq!(
            right_engine.current_tip_work(),
            left_engine.current_tip_work()
        );
    }

    #[test]
    fn mesh_sync_resolves_a_fork_by_chainwork_and_persists_the_new_tip() {
        let seed = [0xC1; 32];
        let network = [0xD2; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut left_engine = ChainEngine::new(seed, 1_000, 125);
        let mut right_engine = ChainEngine::new(seed, 1_000, 125);
        left_engine
            .submit_block(genesis.clone(), &hasher, "miner", 100_000)
            .unwrap();
        right_engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();

        let left_child = empty_block(&seed, 1, genesis_hash, 1_700_000_120);
        let left_child_hash = left_child.header.structural_digest();
        left_engine
            .submit_block(left_child, &hasher, "miner", 200_000)
            .unwrap();
        left_engine
            .submit_block(
                empty_block(&seed, 2, left_child_hash, 1_700_000_240),
                &hasher,
                "miner",
                300_000,
            )
            .unwrap();

        let right_child = empty_block(&seed, 1, genesis_hash, 1_700_000_121);
        right_engine
            .submit_block(right_child, &hasher, "miner", 400_000)
            .unwrap();

        let store_dir =
            std::env::temp_dir().join(format!("sul_p2p_sync_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store_dir);
        let store = DiskStore::new(&store_dir).unwrap();
        let mut left_node = P2pNode::new("left", network, genesis_hash);
        let mut right_node = P2pNode::new("right", network, genesis_hash).with_store(store.clone());
        let mut mesh = InMemoryMesh::default();
        handshake(
            &mut left_node,
            &mut right_node,
            &mut left_engine,
            &mut right_engine,
            &mut mesh,
        );
        synchronize(
            &mut left_node,
            &mut right_node,
            &mut left_engine,
            &mut right_engine,
            &mut mesh,
        );

        assert_eq!(right_engine.tip_hash(), left_engine.tip_hash());
        let tip_hash = right_engine.tip_hash().unwrap();
        assert_eq!(
            store
                .read_block(&tip_hash)
                .unwrap()
                .header
                .structural_digest(),
            tip_hash
        );
        assert_eq!(
            store.load_engine_snapshot().unwrap().tip_hash(),
            Some(tip_hash)
        );
        std::fs::remove_dir_all(store_dir).unwrap();
    }

    #[test]
    fn mesh_paginates_sync_for_a_fork_longer_than_one_header_batch() {
        let seed = [0xE1; 32];
        let network = [0xF2; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut remote_engine = ChainEngine::new(seed, 1_000, 125);
        let mut local_engine = ChainEngine::new(seed, 1_000, 125);
        remote_engine
            .submit_block(genesis.clone(), &hasher, "miner", 100_000)
            .unwrap();
        local_engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();

        let mut remote_parent = genesis_hash;
        let mut remote_target = [0xFF; 32];
        for height in 1..=70 {
            let timestamp = 1_700_000_000 + height * 120;
            if height == DIFFICULTY_RETARGET_WINDOW_BLOCKS {
                remote_target = retarget_difficulty_with_window(
                    &remote_target,
                    DIFFICULTY_RETARGET_WINDOW_BLOCKS,
                    1_700_000_000,
                    timestamp - 120,
                );
            }
            let block =
                empty_block_with_target(&seed, height, remote_parent, timestamp, remote_target);
            remote_parent = block.header.structural_digest();
            remote_engine
                .submit_block(block, &hasher, "miner", 200_000)
                .unwrap();
        }

        let mut local_parent = genesis_hash;
        let mut local_target = [0xFF; 32];
        for height in 1..=65 {
            let timestamp = 1_700_000_001 + height * 120;
            if height == DIFFICULTY_RETARGET_WINDOW_BLOCKS {
                local_target = retarget_difficulty_with_window(
                    &local_target,
                    DIFFICULTY_RETARGET_WINDOW_BLOCKS,
                    1_700_000_000,
                    timestamp - 120,
                );
            }
            let block =
                empty_block_with_target(&seed, height, local_parent, timestamp, local_target);
            local_parent = block.header.structural_digest();
            local_engine
                .submit_block(block, &hasher, "miner", 300_000)
                .unwrap();
        }

        let mut remote_node = P2pNode::new("remote", network, genesis_hash);
        let mut local_node = P2pNode::new("local", network, genesis_hash);
        let mut mesh = InMemoryMesh::default();
        handshake(
            &mut remote_node,
            &mut local_node,
            &mut remote_engine,
            &mut local_engine,
            &mut mesh,
        );
        synchronize(
            &mut remote_node,
            &mut local_node,
            &mut remote_engine,
            &mut local_engine,
            &mut mesh,
        );

        assert_eq!(local_engine.tip_hash(), remote_engine.tip_hash());
        assert_eq!(
            local_engine.current_tip_work(),
            remote_engine.current_tip_work()
        );
    }

    #[test]
    fn sync_stages_partial_fork_without_changing_canonical_tip() {
        let seed = [0x71; 32];
        let network = [0x72; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut remote_engine = ChainEngine::new(seed, 1_000, 125);
        let mut local_engine = ChainEngine::new(seed, 1_000, 125);
        remote_engine
            .submit_block(genesis.clone(), &hasher, "miner", 100_000)
            .unwrap();
        local_engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();
        let first = empty_block(&seed, 1, genesis_hash, 1_700_000_120);
        let first_hash = first.header.structural_digest();
        remote_engine
            .submit_block(first, &hasher, "miner", 100_000)
            .unwrap();
        remote_engine
            .submit_block(
                empty_block(&seed, 2, first_hash, 1_700_000_240),
                &hasher,
                "miner",
                100_000,
            )
            .unwrap();

        let mut remote = P2pNode::new("remote", network, genesis_hash);
        let mut local = P2pNode::new("local", network, genesis_hash);
        remote
            .handle_message("local", local.hello(), &mut remote_engine, &hasher, "miner")
            .unwrap();
        local
            .handle_message(
                "remote",
                remote.hello(),
                &mut local_engine,
                &hasher,
                "miner",
            )
            .unwrap();

        let status = remote.status(&remote_engine);
        let request = local
            .handle_message("remote", status, &mut local_engine, &hasher, "miner")
            .unwrap()
            .remove(0);
        let headers = remote
            .handle_message(
                "local",
                request.message,
                &mut remote_engine,
                &hasher,
                "miner",
            )
            .unwrap()
            .remove(0);
        let block_request = local
            .handle_message(
                "remote",
                headers.message,
                &mut local_engine,
                &hasher,
                "miner",
            )
            .unwrap()
            .remove(0);
        let blocks = remote
            .handle_message(
                "local",
                block_request.message,
                &mut remote_engine,
                &hasher,
                "miner",
            )
            .unwrap();
        assert_eq!(blocks.len(), 2);

        local
            .handle_message(
                "remote",
                blocks[0].message.clone(),
                &mut local_engine,
                &hasher,
                "miner",
            )
            .unwrap();
        assert_eq!(local_engine.tip_hash(), Some(genesis_hash));

        local
            .handle_message(
                "remote",
                blocks[1].message.clone(),
                &mut local_engine,
                &hasher,
                "miner",
            )
            .unwrap();
        assert_eq!(local_engine.tip_hash(), remote_engine.tip_hash());
    }

    #[test]
    fn sync_rejects_header_batches_over_session_limits() {
        let seed = [0x81; 32];
        let network = [0x82; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut engine = ChainEngine::new(seed, 1_000, 125);
        engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();
        let mut node = P2pNode::new("local", network, genesis_hash);
        node.handle_message(
            "remote",
            P2pMessage::Hello {
                network_id: network,
                genesis_hash,
                peer_id: "remote".into(),
            },
            &mut engine,
            &hasher,
            "miner",
        )
        .unwrap();

        for (header_batches, headers_received, entries) in [
            (MAX_SYNC_ITERATIONS_PER_SESSION, 0, Vec::new()),
            (
                0,
                MAX_SYNC_BLOCKS_PER_SESSION,
                vec![header_announcement(StoredBlockInfo {
                    hash: [0; 32],
                    parent_hash: Some(genesis_hash),
                    chainwork: 0,
                    occupancy_ppm: 0,
                    block: empty_block(&seed, 1, genesis_hash, 1_700_000_120),
                })],
            ),
        ] {
            node.sync.sessions.insert(
                "remote".into(),
                SyncSession {
                    tip_hash: Some([0x99; 32]),
                    header_batches,
                    headers_received,
                    headers_complete: false,
                    staged_hashes: Vec::new(),
                },
            );
            node.sync.requested_headers.insert("remote".into());
            assert!(matches!(
                node.handle_message(
                    "remote",
                    P2pMessage::Headers { entries },
                    &mut engine,
                    &hasher,
                    "miner",
                ),
                Err(P2pError::SyncLimitExceeded { .. })
            ));
            assert!(!node.sync.sessions.contains_key("remote"));
        }
    }

    #[test]
    fn header_validation_rejects_invalid_median_time_and_target() {
        let seed = [0x91; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let genesis_hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut engine = ChainEngine::new(seed, 1_000, 125);
        engine
            .submit_block(genesis, &hasher, "miner", 100_000)
            .unwrap();

        let same_timestamp = empty_block(&seed, 1, genesis_hash, 1_700_000_000);
        let announcement = header_announcement(StoredBlockInfo {
            hash: same_timestamp.header.structural_digest(),
            parent_hash: Some(genesis_hash),
            chainwork: 0,
            occupancy_ppm: 0,
            block: same_timestamp,
        });
        assert!(matches!(
            validate_header_batch(&[announcement], &engine),
            Err(P2pError::Chain(ChainEngineError::Consensus(
                crate::pow_randomx::ConsensusError::InvalidMedianTimePast { .. }
            )))
        ));

        let mut wrong_target = empty_block(&seed, 1, genesis_hash, 1_700_000_120);
        wrong_target.header.difficulty_target = [0xFE; 32];
        let announcement = header_announcement(StoredBlockInfo {
            hash: wrong_target.header.structural_digest(),
            parent_hash: Some(genesis_hash),
            chainwork: 0,
            occupancy_ppm: 0,
            block: wrong_target,
        });
        assert!(matches!(
            validate_header_batch(&[announcement], &engine),
            Err(P2pError::Chain(ChainEngineError::Consensus(
                crate::pow_randomx::ConsensusError::InvalidDifficultyTarget { .. }
            )))
        ));
    }

    #[test]
    fn peer_does_not_relay_confidential_tx_with_unknown_ring_members() {
        let seed = [0xA0; 32];
        let mut engine = ChainEngine::new(seed, 1_000, 125);
        let mut node = P2pNode::new("local", [1; 32], [2; 32]);
        node.peers
            .insert(PeerInfo {
                id: "remote".into(),
                tip_height: 0,
                tip_hash: None,
                tip_work: 0,
            })
            .unwrap();
        let tx = HybridTx::Confidential {
            tx: crate::privacy::ConfidentialTx {
                inputs: vec![crate::privacy::RingCtInput {
                    ring_members: vec![[0x55; 32]],
                    pseudo_commitment: crate::privacy::PedersenCommitment::zero(),
                    key_image: [0x66; 32],
                }],
                outputs: Vec::new(),
                discount_atomic: 0,
                signature: crate::privacy::RingCtSignature { inputs: Vec::new() },
            },
            challenge: crate::antispam::AntiSpamChallenge {
                prev_block_hash: [0; 32],
                tx_digest: [0; 32],
                amount_atomic: 1,
                occupancy_ppm: 0,
            },
            nonce: 0,
        };

        assert!(matches!(
            node.handle_message(
                "remote",
                P2pMessage::AnnounceTx(tx),
                &mut engine,
                &MockRandomXHasher,
                "miner",
            ),
            Err(P2pError::InvalidTransaction(ChainEngineError::Chain(
                HybridChainError::Privacy(crate::privacy::PrivacyError::UnknownRingMember(_))
            )))
        ));
        assert_eq!(engine.mempool.len(), 0);
    }

    #[test]
    fn mesh_rejects_mismatched_networks_and_relays_valid_transactions_once() {
        let seed = [0xA1; 32];
        let genesis = empty_block(&seed, 0, [0; 32], 1_700_000_000);
        let hash = genesis.header.structural_digest();
        let hasher = MockRandomXHasher;
        let mut left_engine = ChainEngine::new(seed, 1_000, 125);
        let mut right_engine = ChainEngine::new(seed, 1_000, 125);
        let mut downstream_engine = ChainEngine::new(seed, 1_000, 125);
        for engine in [&mut left_engine, &mut right_engine, &mut downstream_engine] {
            engine
                .submit_block(genesis.clone(), &hasher, "miner", 100_000)
                .unwrap();
        }

        let mut left_node = P2pNode::new("left", [1; 32], hash);
        let wrong_network_node = P2pNode::new("wrong", [2; 32], seed);
        assert!(matches!(
            left_node.handle_message(
                "wrong",
                wrong_network_node.hello(),
                &mut left_engine,
                &hasher,
                "miner"
            ),
            Err(P2pError::NetworkMismatch)
        ));

        let mut right_node = P2pNode::new("right", [1; 32], hash);
        let mut downstream_node = P2pNode::new("downstream", [1; 32], hash);
        let mut mesh = InMemoryMesh::default();
        handshake(
            &mut left_node,
            &mut right_node,
            &mut left_engine,
            &mut right_engine,
            &mut mesh,
        );
        handshake(
            &mut right_node,
            &mut downstream_node,
            &mut right_engine,
            &mut downstream_engine,
            &mut mesh,
        );
        let challenge = crate::antispam::AntiSpamChallenge {
            prev_block_hash: hash,
            tx_digest: [0xCC; 32],
            amount_atomic: ATOMIC_UNITS_PER_SUL,
            occupancy_ppm: 500_000,
        };
        let nonce = crate::antispam::solve_micro_pow(&challenge);
        let tx = HybridTx::Transparent {
            tx: TransferTx {
                from: "alice".into(),
                to: "bob".into(),
                amount_atomic: ATOMIC_UNITS_PER_SUL,
            },
            challenge,
            nonce,
        };
        let tx_message = left_node.announce_tx(tx.clone());
        mesh.send(&left_node.peer_id, &right_node.peer_id, tx_message.clone())
            .unwrap();
        mesh.send(&left_node.peer_id, &right_node.peer_id, tx_message)
            .unwrap();
        for _ in 0..32 {
            let mut did_work = false;
            did_work |= left_node
                .poll_transport(&mut mesh, &mut left_engine, &hasher, "miner")
                .unwrap();
            did_work |= right_node
                .poll_transport(&mut mesh, &mut right_engine, &hasher, "miner")
                .unwrap();
            did_work |= downstream_node
                .poll_transport(&mut mesh, &mut downstream_engine, &hasher, "miner")
                .unwrap();
            if !did_work {
                break;
            }
        }

        assert_eq!(right_engine.mempool.len(), 1);
        assert_eq!(downstream_engine.mempool.len(), 1);
    }
}
