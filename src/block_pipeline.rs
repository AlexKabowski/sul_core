use std::fmt;

use crate::antispam::{
    challenge_matches_anchor_window, verify_micro_pow, AntiSpamChallenge, AntiSpamError,
};
use crate::ledger::{Ledger, LedgerError, TransferTx};
use crate::monetary::{BlockSummary, MonetaryState};
use crate::pow_randomx::{BlockHeader, ConsensusError, Hash256, RandomXHasher};

#[derive(Debug, Clone)]
pub struct CandidateTx {
    pub tx: TransferTx,
    pub challenge: AntiSpamChallenge,
    pub nonce: u64,
}

#[derive(Debug)]
pub struct ValidatedBlockResult {
    pub block_hash: Hash256,
    pub summary: BlockSummary,
    pub accepted_txs: usize,
    pub rejected_spam_txs: usize,
}

#[derive(Debug)]
pub enum BlockPipelineError {
    Consensus(ConsensusError),
    Ledger(LedgerError),
}

impl fmt::Display for BlockPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(err) => write!(f, "consensus failure: {err}"),
            Self::Ledger(err) => write!(f, "ledger/monetary failure: {err}"),
        }
    }
}

impl std::error::Error for BlockPipelineError {}

impl From<ConsensusError> for BlockPipelineError {
    fn from(err: ConsensusError) -> Self {
        Self::Consensus(err)
    }
}

impl From<LedgerError> for BlockPipelineError {
    fn from(err: LedgerError) -> Self {
        Self::Ledger(err)
    }
}

/// Filters transactions by anchor window and micro-PoW before ledger application.
pub fn filter_antispam_txs(
    candidates: &[CandidateTx],
    recent_block_hashes: &[Hash256],
) -> (Vec<TransferTx>, usize) {
    let mut accepted = Vec::with_capacity(candidates.len());
    let mut rejected_spam = 0usize;

    for item in candidates {
        if !challenge_matches_anchor_window(&item.challenge, recent_block_hashes) {
            rejected_spam += 1;
            continue;
        }
        match verify_micro_pow(&item.challenge, item.nonce) {
            Ok(()) => accepted.push(item.tx.clone()),
            Err(AntiSpamError::InsufficientWork { .. }) => {
                rejected_spam += 1;
            }
        }
    }

    (accepted, rejected_spam)
}

/// Validates the header, filters spam, and applies block transfers and monetary rules.
pub fn process_validated_block<H: RandomXHasher>(
    parent: Option<&BlockHeader>,
    header: &BlockHeader,
    hasher: &H,
    genesis_seed: &Hash256,
    candidates: &[CandidateTx],
    ledger: &mut Ledger,
    state: &mut MonetaryState,
    miner_id: impl Into<String>,
    occupancy_ppm: u128,
) -> Result<ValidatedBlockResult, BlockPipelineError> {
    if let Some(parent_header) = parent {
        header.validate_parent(parent_header)?;
    }
    let block_hash = header.verify_pow(hasher, genesis_seed)?;

    let recent_block_hashes = [parent
        .map(|header| header.structural_digest())
        .unwrap_or(header.prev_block_hash)];
    let (valid_txs, rejected_spam_txs) = filter_antispam_txs(candidates, &recent_block_hashes);
    let accepted_txs = valid_txs.len();
    let summary = ledger.apply_block(state, &valid_txs, miner_id, occupancy_ppm)?;

    Ok(ValidatedBlockResult {
        block_hash,
        summary,
        accepted_txs,
        rejected_spam_txs,
    })
}
