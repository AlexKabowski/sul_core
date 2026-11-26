use crate::monetary::OCCUPANCY_SCALE;
use crate::params::ATOMIC_UNITS_PER_SUL;

pub type Hash32 = [u8; 32];

pub const MIN_MICRO_POW_BITS: u32 = 8;
pub const MAX_MICRO_POW_BITS: u32 = 20;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AntiSpamChallenge {
    pub prev_block_hash: Hash32,
    pub tx_digest: Hash32,
    pub amount_atomic: u128,
    pub occupancy_ppm: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiSpamError {
    InsufficientWork {
        required_bits: u32,
        actual_bits: u32,
    },
}

pub fn required_difficulty_bits(amount_atomic: u128, occupancy_ppm: u128) -> u32 {
    let clamped_occ = occupancy_ppm.min(OCCUPANCY_SCALE);
    let span = (MAX_MICRO_POW_BITS - MIN_MICRO_POW_BITS) as u128;
    let base_bits = MIN_MICRO_POW_BITS + ((span * clamped_occ) / OCCUPANCY_SCALE) as u32;

    let dust_penalty = if amount_atomic < ATOMIC_UNITS_PER_SUL / 10 {
        3
    } else if amount_atomic < ATOMIC_UNITS_PER_SUL {
        1
    } else {
        0
    };

    (base_bits + dust_penalty).min(MAX_MICRO_POW_BITS)
}

/// Calculates the BLAKE3 digest of the anti-spam stamp anchored to the previous block.
pub fn compute_stamp_hash(challenge: &AntiSpamChallenge, nonce: u64) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_ANTISPAM_BLAKE3_V1");
    hasher.update(&challenge.prev_block_hash);
    hasher.update(&challenge.tx_digest);
    hasher.update(&challenge.amount_atomic.to_le_bytes());
    hasher.update(&challenge.occupancy_ppm.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn count_leading_zero_bits(digest: &Hash32) -> u32 {
    let mut zeros = 0u32;
    for &byte in digest {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros();
            break;
        }
    }
    zeros
}

pub fn challenge_matches_anchor_window(
    challenge: &AntiSpamChallenge,
    recent_block_hashes: &[Hash32],
) -> bool {
    recent_block_hashes.contains(&challenge.prev_block_hash)
}

/// Checks whether the nonce meets the required transaction difficulty.
pub fn verify_micro_pow(challenge: &AntiSpamChallenge, nonce: u64) -> Result<(), AntiSpamError> {
    let required_bits = required_difficulty_bits(challenge.amount_atomic, challenge.occupancy_ppm);
    let hash = compute_stamp_hash(challenge, nonce);
    let actual_bits = count_leading_zero_bits(&hash);

    if actual_bits < required_bits {
        return Err(AntiSpamError::InsufficientWork {
            required_bits,
            actual_bits,
        });
    }

    Ok(())
}

/// Finds a valid nonce for use by a wallet or client.
pub fn solve_micro_pow(challenge: &AntiSpamChallenge) -> u64 {
    let required_bits = required_difficulty_bits(challenge.amount_atomic, challenge.occupancy_ppm);
    let mut nonce = 0u64;
    loop {
        if count_leading_zero_bits(&compute_stamp_hash(challenge, nonce)) >= required_bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_pow_solves_and_verifies_transaction_stamp() {
        let challenge = AntiSpamChallenge {
            prev_block_hash: [0x99u8; 32],
            tx_digest: [0x12u8; 32],
            amount_atomic: ATOMIC_UNITS_PER_SUL / 20,
            occupancy_ppm: OCCUPANCY_SCALE / 2,
        };

        let nonce = solve_micro_pow(&challenge);
        assert!(verify_micro_pow(&challenge, nonce).is_ok());
    }

    #[test]
    fn higher_occupancy_and_dust_increase_required_work() {
        let low_occ_normal = required_difficulty_bits(5 * ATOMIC_UNITS_PER_SUL, 0);
        let high_occ_dust = required_difficulty_bits(ATOMIC_UNITS_PER_SUL / 100, OCCUPANCY_SCALE);

        assert!(high_occ_dust > low_occ_normal);
        assert_eq!(high_occ_dust, MAX_MICRO_POW_BITS);
    }

    #[test]
    fn stamp_changes_when_previous_block_changes() {
        let mut challenge = AntiSpamChallenge {
            prev_block_hash: [0x99u8; 32],
            tx_digest: [0x12u8; 32],
            amount_atomic: ATOMIC_UNITS_PER_SUL,
            occupancy_ppm: OCCUPANCY_SCALE / 2,
        };
        let nonce = 123;
        let original = compute_stamp_hash(&challenge, nonce);

        challenge.prev_block_hash = [0xAAu8; 32];
        let anchored_elsewhere = compute_stamp_hash(&challenge, nonce);

        assert_ne!(original, anchored_elsewhere);
    }

    #[test]
    fn challenge_matches_one_of_the_recent_anchor_hashes() {
        let recent = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let challenge = AntiSpamChallenge {
            prev_block_hash: [0x22u8; 32],
            tx_digest: [0x44u8; 32],
            amount_atomic: ATOMIC_UNITS_PER_SUL,
            occupancy_ppm: OCCUPANCY_SCALE / 2,
        };

        assert!(challenge_matches_anchor_window(&challenge, &recent));
    }
}
