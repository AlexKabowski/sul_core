use std::collections::HashSet;
use std::fmt;

use crate::antispam::{
    challenge_matches_anchor_window, verify_micro_pow, AntiSpamChallenge, AntiSpamError,
};
use crate::ledger::{Ledger, LedgerError, TransferTx};
use crate::monetary::{BlockSummary, MonetaryError, MonetaryState};
use crate::pow_randomx::{BlockHeader, ConsensusError, Hash256, RandomXHasher};
use crate::privacy::{
    verify_confidential_tx_against_outputs, ConfidentialTx, KeyImageSet, PrivacyError,
    StealthOutput, ValidOutputSet,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HybridTx {
    Transparent {
        tx: TransferTx,
        challenge: AntiSpamChallenge,
        nonce: u64,
    },
    Confidential {
        tx: ConfidentialTx,
        challenge: AntiSpamChallenge,
        nonce: u64,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HybridChainState {
    pub ledger: Ledger,
    pub spent_key_images: KeyImageSet,
    pub valid_outputs: ValidOutputSet,
    pub monetary: MonetaryState,
}

#[derive(Debug)]
pub struct HybridBlockReport {
    pub block_hash: Hash256,
    pub summary: BlockSummary,
    pub transparent_applied: usize,
    pub confidential_applied: usize,
    pub rejected_spam: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridChainError {
    Consensus(ConsensusError),
    Ledger(LedgerError),
    Privacy(PrivacyError),
    Monetary(MonetaryError),
}

impl fmt::Display for HybridChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(e) => write!(f, "consensus error: {e}"),
            Self::Ledger(e) => write!(f, "ledger error: {e}"),
            Self::Privacy(e) => write!(f, "privacy error: {e}"),
            Self::Monetary(e) => write!(f, "monetary error: {e}"),
        }
    }
}

impl std::error::Error for HybridChainError {}

impl From<ConsensusError> for HybridChainError {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}

impl From<LedgerError> for HybridChainError {
    fn from(e: LedgerError) -> Self {
        Self::Ledger(e)
    }
}

impl From<PrivacyError> for HybridChainError {
    fn from(e: PrivacyError) -> Self {
        Self::Privacy(e)
    }
}

impl From<MonetaryError> for HybridChainError {
    fn from(e: MonetaryError) -> Self {
        Self::Monetary(e)
    }
}

impl HybridChainState {
    pub fn new(initial_supply_sul: u128, initial_emission_bps: u128) -> Self {
        Self {
            ledger: Ledger::new(),
            spent_key_images: KeyImageSet::new(),
            valid_outputs: ValidOutputSet::new(),
            monetary: MonetaryState::new(initial_supply_sul, initial_emission_bps),
        }
    }

    pub fn apply_hybrid_block<H: RandomXHasher>(
        &mut self,
        parent: Option<&BlockHeader>,
        header: &BlockHeader,
        hasher: &H,
        genesis_seed: &Hash256,
        txs: &[HybridTx],
        recent_block_hashes: &[Hash256],
        miner_id: impl Into<String>,
        occupancy_ppm: u128,
    ) -> Result<HybridBlockReport, HybridChainError> {
        if let Some(p) = parent {
            header.validate_parent(p)?;
        }
        header.verify_pow(hasher, genesis_seed)?;
        let block_hash = header.structural_digest();

        let ledger_snap = self.ledger.balances.clone();
        let keys_snap = self.spent_key_images.clone();
        let outputs_snap = self.valid_outputs.clone();
        let monetary_snap = self.monetary.clone();
        let default_recent_hash = [parent
            .map(|header| header.structural_digest())
            .unwrap_or(header.prev_block_hash)];
        let anchor_hashes = if recent_block_hashes.is_empty() {
            &default_recent_hash[..]
        } else {
            recent_block_hashes
        };

        let miner = miner_id.into();
        if !self.ledger.balances.contains_key(&miner) {
            self.ledger.set_balance(miner.clone(), 0);
        }

        let mut amounts_for_monetary = Vec::new();
        let mut transparent_applied = 0usize;
        let mut confidential_applied = 0usize;
        let mut rejected_spam = 0usize;
        let mut extra_discounts = 0u128;
        let mut new_outputs = Vec::<StealthOutput>::new();
        let mut new_output_keys = HashSet::new();

        for item in txs {
            match item {
                HybridTx::Transparent {
                    tx,
                    challenge,
                    nonce,
                } => {
                    if !challenge_matches_anchor_window(challenge, anchor_hashes) {
                        rejected_spam += 1;
                        continue;
                    }
                    if let Err(AntiSpamError::InsufficientWork { .. }) =
                        verify_micro_pow(challenge, *nonce)
                    {
                        rejected_spam += 1;
                        continue;
                    }

                    let discount =
                        MonetaryState::calculate_tx_discount(tx.amount_atomic, occupancy_ppm);
                    if let Err(err) = self.ledger.apply_transfer(tx, discount) {
                        self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                        return Err(err.into());
                    }

                    amounts_for_monetary.push(tx.amount_atomic);
                    transparent_applied += 1;
                }
                HybridTx::Confidential {
                    tx,
                    challenge,
                    nonce,
                } => {
                    if !challenge_matches_anchor_window(challenge, anchor_hashes) {
                        rejected_spam += 1;
                        continue;
                    }
                    if let Err(AntiSpamError::InsufficientWork { .. }) =
                        verify_micro_pow(challenge, *nonce)
                    {
                        rejected_spam += 1;
                        continue;
                    }

                    if let Err(err) = verify_confidential_tx_against_outputs(
                        tx,
                        &self.spent_key_images,
                        &self.valid_outputs,
                        occupancy_ppm,
                    ) {
                        self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                        return Err(err.into());
                    }

                    for output in &tx.outputs {
                        if self.valid_outputs.contains(&output.one_time_pub)
                            || !new_output_keys.insert(output.one_time_pub)
                        {
                            self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                            return Err(
                                PrivacyError::DuplicateStealthOutput(output.one_time_pub).into()
                            );
                        }
                        new_outputs.push(output.clone());
                    }

                    for inp in &tx.inputs {
                        if let Err(err) = self.spent_key_images.insert(inp.key_image) {
                            self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                            return Err(err.into());
                        }
                    }

                    extra_discounts = match extra_discounts.checked_add(tx.discount_atomic) {
                        Some(v) => v,
                        None => {
                            self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                            return Err(HybridChainError::Monetary(
                                MonetaryError::ArithmeticOverflow,
                            ));
                        }
                    };
                    confidential_applied += 1;
                }
            }
        }

        let summary = match self.monetary.process_block_with_discounts(
            &amounts_for_monetary,
            extra_discounts,
            occupancy_ppm,
        ) {
            Ok(s) => s,
            Err(err) => {
                self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                return Err(err.into());
            }
        };

        let miner_bal = self.ledger.balance_of(&miner);
        match miner_bal.checked_add(summary.total_miner_reward) {
            Some(new_miner_bal) => {
                self.ledger.set_balance(miner, new_miner_bal);
            }
            None => {
                self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                return Err(HybridChainError::Ledger(LedgerError::ArithmeticOverflow));
            }
        }

        for output in new_outputs {
            if !self
                .valid_outputs
                .insert(output.one_time_pub, output.commitment)
            {
                self.rollback(ledger_snap, keys_snap, outputs_snap, monetary_snap);
                return Err(PrivacyError::DuplicateStealthOutput(output.one_time_pub).into());
            }
        }

        Ok(HybridBlockReport {
            block_hash,
            summary,
            transparent_applied,
            confidential_applied,
            rejected_spam,
        })
    }

    fn rollback(
        &mut self,
        ledger_snap: std::collections::HashMap<crate::ledger::AccountId, u128>,
        keys_snap: KeyImageSet,
        outputs_snap: ValidOutputSet,
        monetary_snap: MonetaryState,
    ) {
        self.ledger.balances = ledger_snap;
        self.spent_key_images = keys_snap;
        self.valid_outputs = outputs_snap;
        self.monetary = monetary_snap;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::antispam::{solve_micro_pow, verify_micro_pow};
    use crate::monetary::OCCUPANCY_SCALE;
    use crate::params::ATOMIC_UNITS_PER_SUL;
    use crate::pow_randomx::MockRandomXHasher;
    use crate::privacy::{
        build_confidential_tx, compute_key_image, PedersenCommitment, RingCtInput,
        StealthWalletKeys, MIN_RING_SIZE,
    };
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    #[test]
    fn hybrid_block_applies_transparent_and_confidential_txs_and_rejects_spam() {
        let mut chain = HybridChainState::new(1_000, 125);
        chain
            .ledger
            .set_balance("alice", 500 * ATOMIC_UNITS_PER_SUL);
        chain.ledger.set_balance("bob", 500 * ATOMIC_UNITS_PER_SUL);

        let occupancy_ppm = OCCUPANCY_SCALE / 2;
        let amount = 10 * ATOMIC_UNITS_PER_SUL;
        let discount = MonetaryState::calculate_tx_discount(amount, occupancy_ppm);
        let prev_block_hash = [0u8; 32];

        let ch_ok = AntiSpamChallenge {
            prev_block_hash,
            tx_digest: [0x11u8; 32],
            amount_atomic: amount,
            occupancy_ppm,
        };
        let nonce_ok = solve_micro_pow(&ch_ok);
        let t_tx = HybridTx::Transparent {
            tx: TransferTx {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount_atomic: amount,
            },
            challenge: ch_ok,
            nonce: nonce_ok,
        };

        let ch_spam = AntiSpamChallenge {
            prev_block_hash,
            tx_digest: [0x22u8; 32],
            amount_atomic: amount,
            occupancy_ppm,
        };
        let mut spam_nonce = 0u64;
        while verify_micro_pow(&ch_spam, spam_nonce).is_ok() {
            spam_nonce = spam_nonce.wrapping_add(1);
        }
        let t_spam = HybridTx::Transparent {
            tx: TransferTx {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount_atomic: amount,
            },
            challenge: ch_spam,
            nonce: spam_nonce,
        };

        let carol_addr = StealthWalletKeys::from_seed(&[0x55u8; 32]).public_address();
        let ring: Vec<[u8; 32]> = (1..=MIN_RING_SIZE)
            .map(|i| {
                (Scalar::from(i as u64) * RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .to_bytes()
            })
            .collect();
        let ring_for_registry = ring.clone();
        let real_priv = Scalar::ONE.to_bytes();
        let ki = compute_key_image(&real_priv, &ring[0]).unwrap();
        let blind = 777_888_999u128;
        let c_tx = build_confidential_tx(
            vec![RingCtInput {
                ring_members: ring,
                pseudo_commitment: PedersenCommitment::commit(amount + discount, blind),
                key_image: ki,
            }],
            &[blind],
            &[(carol_addr, amount, [0x66u8; 32], 123)],
            &[0],
            &[real_priv],
            &[[0x88u8; 32]],
            discount,
        )
        .unwrap();
        let produced_outputs = c_tx.outputs.clone();
        let ch_conf = AntiSpamChallenge {
            prev_block_hash,
            tx_digest: [0x33u8; 32],
            amount_atomic: amount,
            occupancy_ppm,
        };
        let nonce_conf = solve_micro_pow(&ch_conf);
        let t_conf = HybridTx::Confidential {
            tx: c_tx,
            challenge: ch_conf,
            nonce: nonce_conf,
        };

        let genesis = [0xAAu8; 32];
        let hasher = MockRandomXHasher;
        let mut target = [0xFFu8; 32];
        target[0] = 0x1F;
        let mut header = BlockHeader {
            version: 1,
            height: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0x44u8; 32],
            timestamp: 1_700_000_120,
            difficulty_target: target,
            nonce: 0,
        };
        while header.verify_pow(&hasher, &genesis).is_err() {
            header.nonce += 1;
        }

        let ledger_before = chain.ledger.balances.clone();
        let monetary_before = chain.monetary.clone();
        let rejected = chain.apply_hybrid_block(
            None,
            &header,
            &hasher,
            &genesis,
            &[t_tx.clone(), t_spam.clone(), t_conf.clone()],
            &[],
            "miner_1",
            occupancy_ppm,
        );
        assert!(matches!(
            rejected,
            Err(HybridChainError::Privacy(PrivacyError::UnknownRingMember(
                _
            )))
        ));
        assert_eq!(chain.ledger.balances, ledger_before);
        assert_eq!(chain.monetary, monetary_before);
        assert!(!chain.spent_key_images.contains(&ki));
        assert!(chain.valid_outputs.is_empty());

        for member in ring_for_registry {
            assert!(chain
                .valid_outputs
                .insert(member, PedersenCommitment::zero()));
        }

        let report = chain
            .apply_hybrid_block(
                None,
                &header,
                &hasher,
                &genesis,
                &[t_tx, t_spam, t_conf],
                &[],
                "miner_1",
                occupancy_ppm,
            )
            .expect("hybrid block should be accepted");

        assert_eq!(report.transparent_applied, 1);
        assert_eq!(report.confidential_applied, 1);
        assert_eq!(report.rejected_spam, 1);
        assert!(chain.spent_key_images.contains(&ki));
        for output in produced_outputs {
            assert!(chain.valid_outputs.contains(&output.one_time_pub));
            assert_eq!(
                chain.valid_outputs.commitment(&output.one_time_pub),
                Some(&output.commitment)
            );
        }
    }
}
