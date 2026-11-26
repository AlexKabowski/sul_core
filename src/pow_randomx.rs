use rust_randomx::{Context, Hasher as RandomXHasherImpl};
use std::cell::RefCell;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::params::{
    BLOCK_TIME_SECONDS, DIFFICULTY_RETARGET_WINDOW_BLOCKS, MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS,
    MAX_TARGET_ADJUST_DEN, MAX_TARGET_ADJUST_NUM, MIN_TARGET_ADJUST_DEN, MIN_TARGET_ADJUST_NUM,
    RANDOMX_SEED_EPOCH_BLOCKS,
};

/// Tamanho do digest e do alvo, em bytes (256 bits).
pub type Hash256 = [u8; 32];

pub const MAX_DIFFICULTY_TARGET: Hash256 = [0xFFu8; 32];
pub const MIN_DIFFICULTY_TARGET: Hash256 = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct U512 {
    limbs: [u64; 8],
}

impl U512 {
    const fn zero() -> Self {
        Self { limbs: [0; 8] }
    }

    fn from_be_bytes_256(bytes: &Hash256) -> Self {
        let mut limbs = [0u64; 8];
        for i in 0..4 {
            let start = 32 - (i + 1) * 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[start..start + 8]);
            limbs[i] = u64::from_be_bytes(buf);
        }
        Self { limbs }
    }

    fn to_be_bytes_256_saturated(&self) -> Hash256 {
        if self.limbs[4..].iter().any(|&limb| limb != 0) {
            return MAX_DIFFICULTY_TARGET;
        }
        let mut out = [0u8; 32];
        for i in 0..4 {
            let start = 32 - (i + 1) * 8;
            out[start..start + 8].copy_from_slice(&self.limbs[i].to_be_bytes());
        }
        out
    }

    fn bit_len(&self) -> usize {
        for i in (0..8).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    fn bit(&self, idx: usize) -> u64 {
        if idx >= 512 {
            return 0;
        }
        (self.limbs[idx / 64] >> (idx % 64)) & 1
    }

    fn set_bit(&mut self, idx: usize) {
        if idx < 512 {
            self.limbs[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    fn shl_1(&mut self) {
        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..8).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        std::cmp::Ordering::Equal
    }

    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0u64;
        for i in 0..8 {
            let (value, borrow1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (value, borrow2) = value.overflowing_sub(borrow);
            self.limbs[i] = value;
            borrow = u64::from(borrow1 || borrow2);
        }
    }

    fn checked_add_one(&mut self) -> bool {
        for limb in &mut self.limbs {
            let (value, carry) = limb.overflowing_add(1);
            *limb = value;
            if !carry {
                return true;
            }
        }
        false
    }

    fn div(&self, divisor: &Self) -> Self {
        assert!(divisor.bit_len() > 0, "division by zero in U512::div");
        let mut quotient = U512::zero();
        let mut remainder = U512::zero();
        for bit_idx in (0..self.bit_len()).rev() {
            remainder.shl_1();
            remainder.limbs[0] |= self.bit(bit_idx);
            if remainder.cmp(divisor) != std::cmp::Ordering::Less {
                remainder.sub_assign(divisor);
                quotient.set_bit(bit_idx);
            }
        }
        quotient
    }

    fn mul_u128(&self, rhs: u128) -> Self {
        let lo_rhs = rhs as u64;
        let hi_rhs = (rhs >> 64) as u64;
        let mut out = U512::zero();

        for i in 0..8 {
            let a = self.limbs[i] as u128;

            let p_lo = a * lo_rhs as u128;
            let mut carry = p_lo;
            let mut idx = i;
            while carry != 0 && idx < 8 {
                let sum = out.limbs[idx] as u128 + (carry & u64::MAX as u128);
                let old_carry = carry;
                out.limbs[idx] = sum as u64;
                carry = (old_carry >> 64) + (sum >> 64);
                idx += 1;
            }

            if hi_rhs != 0 && i + 1 < 8 {
                let p_hi = a * hi_rhs as u128;
                let mut carry = p_hi;
                let mut idx = i + 1;
                while carry != 0 && idx < 8 {
                    let sum = out.limbs[idx] as u128 + (carry & u64::MAX as u128);
                    let old_carry = carry;
                    out.limbs[idx] = sum as u64;
                    carry = (old_carry >> 64) + (sum >> 64);
                    idx += 1;
                }
            }
        }

        out
    }

    fn div_u128(&self, den: u128) -> Self {
        assert!(den > 0, "divisor zero em U512::div_u128");
        let mut divisor = U512::zero();
        divisor.limbs[0] = den as u64;
        divisor.limbs[1] = (den >> 64) as u64;

        if self.bit_len() == 0 || self.cmp(&divisor) == std::cmp::Ordering::Less {
            return U512::zero();
        }

        let mut quotient = U512::zero();
        let mut remainder = U512::zero();
        for bit_idx in (0..self.bit_len()).rev() {
            remainder.shl_1();
            remainder.limbs[0] |= self.bit(bit_idx);
            if remainder.cmp(&divisor) != std::cmp::Ordering::Less {
                remainder.sub_assign(&divisor);
                quotient.set_bit(bit_idx);
            }
        }
        quotient
    }
}

/// Exact accumulated proof-of-work value, stored as a big-endian 512-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainWork([u64; 8]);

impl ChainWork {
    pub const ZERO: Self = Self([0; 8]);

    /// Calculates `floor(2^256 / (target + 1))` without narrowing intermediate values.
    pub fn from_difficulty_target(target: &Hash256) -> Self {
        let mut divisor = U512::from_be_bytes_256(target);
        assert!(
            divisor.checked_add_one(),
            "256-bit target increment fits U512"
        );
        let mut numerator = U512::zero();
        numerator.set_bit(256);
        Self(numerator.div(&divisor).limbs)
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut sum = [0u64; 8];
        let mut carry = 0u128;
        for (index, limb) in sum.iter_mut().enumerate() {
            let value = self.0[index] as u128 + other.0[index] as u128 + carry;
            *limb = value as u64;
            carry = value >> 64;
        }
        (carry == 0).then_some(Self(sum))
    }
}

impl Default for ChainWork {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialOrd for ChainWork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChainWork {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for index in (0..8).rev() {
            match self.0[index].cmp(&other.0[index]) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl fmt::Display for ChainWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("0x")?;
        for limb in self.0.iter().rev() {
            write!(formatter, "{limb:016x}")?;
        }
        Ok(())
    }
}

fn mul_div_u256_be(target: &Hash256, num: u128, den: u128) -> Hash256 {
    let base = U512::from_be_bytes_256(target);
    let product = base.mul_u128(num);
    let quotient = product.div_u128(den);
    quotient.to_be_bytes_256_saturated()
}

pub fn retarget_difficulty_with_window(
    current_target: &Hash256,
    window_blocks: u64,
    window_start_timestamp: u64,
    window_end_timestamp: u64,
) -> Hash256 {
    let blocks = window_blocks.max(1) as u128;
    let expected_elapsed = blocks.saturating_mul(BLOCK_TIME_SECONDS as u128);

    let raw_elapsed = if window_end_timestamp > window_start_timestamp {
        (window_end_timestamp - window_start_timestamp) as u128
    } else {
        1
    };

    let (adj_num, adj_den) = if raw_elapsed.saturating_mul(MIN_TARGET_ADJUST_DEN)
        < expected_elapsed.saturating_mul(MIN_TARGET_ADJUST_NUM)
    {
        (MIN_TARGET_ADJUST_NUM, MIN_TARGET_ADJUST_DEN)
    } else if raw_elapsed.saturating_mul(MAX_TARGET_ADJUST_DEN)
        > expected_elapsed.saturating_mul(MAX_TARGET_ADJUST_NUM)
    {
        (MAX_TARGET_ADJUST_NUM, MAX_TARGET_ADJUST_DEN)
    } else {
        (raw_elapsed, expected_elapsed)
    };

    let candidate = mul_div_u256_be(current_target, adj_num, adj_den);

    if candidate > MAX_DIFFICULTY_TARGET {
        MAX_DIFFICULTY_TARGET
    } else if candidate < MIN_DIFFICULTY_TARGET {
        MIN_DIFFICULTY_TARGET
    } else {
        candidate
    }
}

pub fn retarget_difficulty(
    current_target: &Hash256,
    window_start_timestamp: u64,
    window_end_timestamp: u64,
) -> Hash256 {
    retarget_difficulty_with_window(
        current_target,
        DIFFICULTY_RETARGET_WINDOW_BLOCKS,
        window_start_timestamp,
        window_end_timestamp,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub prev_block_hash: Hash256,
    pub merkle_root: Hash256,
    pub timestamp: u64,
    pub difficulty_target: Hash256,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    HeightOverflow,
    InvalidHeight { expected: u64, actual: u64 },
    InvalidGenesisHeader,
    InvalidPrevHash { expected: Hash256, actual: Hash256 },
    InvalidTimestamp { parent_ts: u64, block_ts: u64 },
    InvalidMedianTimePast { median: u64, block_ts: u64 },
    InvalidDifficultyTarget { expected: Hash256, actual: Hash256 },
    InvalidDifficultyTargetRange { actual: Hash256 },
    MissingDifficultyHistory { height: u64 },
    HashAboveTarget { hash: Hash256, target: Hash256 },
    HasherError(String),
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightOverflow => write!(f, "parent height cannot be incremented"),
            Self::InvalidHeight { expected, actual } => {
                write!(f, "invalid height: expected {expected}, got {actual}")
            }
            Self::InvalidGenesisHeader => write!(f, "invalid or conflicting genesis header"),
            Self::InvalidPrevHash { .. } => {
                write!(f, "prev_block_hash does not match the previous block")
            }
            Self::InvalidTimestamp {
                parent_ts,
                block_ts,
            } => write!(
                f,
                "invalid timestamp: block ({block_ts}) is earlier than its parent ({parent_ts})"
            ),
            Self::InvalidMedianTimePast { median, block_ts } => write!(
                f,
                "invalid timestamp: block ({block_ts}) is not above median time past ({median})"
            ),
            Self::InvalidDifficultyTarget { .. } => {
                write!(f, "difficulty target does not match retarget calculation")
            }
            Self::InvalidDifficultyTargetRange { .. } => {
                write!(f, "difficulty target is outside the consensus range")
            }
            Self::MissingDifficultyHistory { height } => {
                write!(f, "missing difficulty history at height {height}")
            }
            Self::HashAboveTarget { .. } => {
                write!(f, "RandomX hash exceeds the difficulty target")
            }
            Self::HasherError(msg) => write!(f, "RandomX hasher error: {msg}"),
        }
    }
}

impl std::error::Error for ConsensusError {}

/// RandomX hasher abstraction implemented by test and real hasher types.
pub trait RandomXHasher {
    fn hash_block(&self, seed: &Hash256, header_bytes: &[u8]) -> Result<Hash256, String>;
}

/// Deterministically derives the epoch seed from the block height.
pub fn derive_seed_for_height(height: u64, genesis_seed: &Hash256) -> Hash256 {
    let epoch = height / RANDOMX_SEED_EPOCH_BLOCKS;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_RANDOMX_SEED_BLAKE3_V1");
    hasher.update(genesis_seed);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

impl BlockHeader {
    pub fn validate_parent_with_history(
        &self,
        parent: &BlockHeader,
        recent_headers: &[BlockHeader],
        expected_target: Option<&Hash256>,
    ) -> Result<(), ConsensusError> {
        self.validate_parent(parent)?;

        let mut timestamps: Vec<u64> = recent_headers
            .iter()
            .take(crate::params::MEDIAN_TIME_PAST_BLOCKS)
            .map(|header| header.timestamp)
            .collect();
        timestamps.push(parent.timestamp);
        timestamps.sort_unstable();
        let median = timestamps[timestamps.len() / 2];
        if self.timestamp <= median {
            return Err(ConsensusError::InvalidMedianTimePast {
                median,
                block_ts: self.timestamp,
            });
        }

        if let Some(expected) = expected_target {
            if &self.difficulty_target != expected {
                return Err(ConsensusError::InvalidDifficultyTarget {
                    expected: *expected,
                    actual: self.difficulty_target,
                });
            }
        }
        Ok(())
    }

    /// Serializes the header in canonical format, including the nonce.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 32 + 32 + 8 + 32 + 8);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.prev_block_hash);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.difficulty_target);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Validates basic linkage with the parent header.
    pub fn validate_parent(&self, parent: &BlockHeader) -> Result<(), ConsensusError> {
        let expected_height = parent
            .height
            .checked_add(1)
            .ok_or(ConsensusError::HeightOverflow)?;
        if self.height != expected_height {
            return Err(ConsensusError::InvalidHeight {
                expected: expected_height,
                actual: self.height,
            });
        }

        let parent_hash = parent.structural_digest();
        if self.prev_block_hash != parent_hash {
            return Err(ConsensusError::InvalidPrevHash {
                expected: parent_hash,
                actual: self.prev_block_hash,
            });
        }

        if self.timestamp < parent.timestamp {
            return Err(ConsensusError::InvalidTimestamp {
                parent_ts: parent.timestamp,
                block_ts: self.timestamp,
            });
        }
        if self.timestamp
            > parent
                .timestamp
                .saturating_add(MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS)
        {
            return Err(ConsensusError::InvalidTimestamp {
                parent_ts: parent.timestamp,
                block_ts: self.timestamp,
            });
        }

        Ok(())
    }

    /// Calculates the header's canonical structural identifier.
    pub fn structural_digest(&self) -> Hash256 {
        let bytes = self.to_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SUL_BLOCK_STRUCTURAL_BLAKE3_V1");
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    /// Calculates the RandomX hash and verifies `hash <= difficulty_target` in big-endian order.
    pub fn verify_pow<H: RandomXHasher>(
        &self,
        hasher: &H,
        genesis_seed: &Hash256,
    ) -> Result<Hash256, ConsensusError> {
        let seed = derive_seed_for_height(self.height, genesis_seed);
        let hash = hasher
            .hash_block(&seed, &self.to_bytes())
            .map_err(ConsensusError::HasherError)?;

        if hash > self.difficulty_target {
            return Err(ConsensusError::HashAboveTarget {
                hash,
                target: self.difficulty_target,
            });
        }

        Ok(hash)
    }
}

/// Deterministic hasher used by local tests.
pub struct MockRandomXHasher;

impl RandomXHasher for MockRandomXHasher {
    fn hash_block(&self, seed: &Hash256, header_bytes: &[u8]) -> Result<Hash256, String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SUL_MOCK_RANDOMX_BLAKE3_V1");
        hasher.update(seed);
        hasher.update(header_bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}

thread_local! {
    static REAL_RANDOMX_THREAD_HASHER:
        RefCell<Option<(Hash256, Arc<Context>, RandomXHasherImpl)>> =
        const { RefCell::new(None) };
}

/// Hasher RandomX real, implementado com `rust-randomx`.
pub struct RealRandomXHasher {
    state: RwLock<(Hash256, Arc<Context>)>,
}

impl RealRandomXHasher {
    pub fn new(seed: &Hash256) -> Result<Self, String> {
        let context = std::sync::Arc::new(Context::new(seed, false));
        Ok(Self {
            state: RwLock::new((*seed, context)),
        })
    }
}

impl RandomXHasher for RealRandomXHasher {
    fn hash_block(&self, seed: &Hash256, header_bytes: &[u8]) -> Result<Hash256, String> {
        let context = {
            let mut state = self
                .state
                .write()
                .map_err(|_| "RandomX state lock poisoned".to_string())?;
            if state.0 != *seed {
                state.0 = *seed;
                state.1 = Arc::new(Context::new(seed, false));
            }
            Arc::clone(&state.1)
        };

        REAL_RANDOMX_THREAD_HASHER.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().map(|entry| entry.0) != Some(*seed) {
                let hasher = RandomXHasherImpl::new(Arc::clone(&context));
                *slot = Some((*seed, Arc::clone(&context), hasher));
            }
            let hash = slot
                .as_mut()
                .ok_or_else(|| "failed to initialize thread RandomX VM".to_string())?
                .2
                .hash(header_bytes);
            let hash: [u8; 32] = hash
                .as_ref()
                .try_into()
                .map_err(|_| "RandomX returned an invalid hash length".to_string())?;
            Ok(hash)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::DIFFICULTY_RETARGET_WINDOW_BLOCKS;

    #[test]
    fn chainwork_uses_exact_target_division_and_checked_512_bit_addition() {
        let unit_work = ChainWork::from_difficulty_target(&[0xFF; 32]);
        assert_eq!(unit_work.0[0], 1);
        assert!(unit_work.0[1..].iter().all(|limb| *limb == 0));

        let zero_target_work = ChainWork::from_difficulty_target(&[0; 32]);
        assert_eq!(zero_target_work.0[4], 1);
        assert!(zero_target_work
            .0
            .iter()
            .enumerate()
            .all(|(index, limb)| *limb == u64::from(index == 4)));

        let mut half_range_target = [0; 32];
        half_range_target[16..].fill(0xFF);
        let large_work = ChainWork::from_difficulty_target(&half_range_target);
        assert_eq!(large_work.0[2], 1);
        assert!(large_work
            .0
            .iter()
            .enumerate()
            .all(|(index, limb)| *limb == u64::from(index == 2)));

        let two_work = ChainWork::from_difficulty_target(&[0x7F; 32]);
        assert_eq!(two_work.0[0], 2);
        assert_eq!(unit_work.checked_add(unit_work), Some(two_work));

        assert_eq!(ChainWork([u64::MAX; 8]).checked_add(unit_work), None);
    }

    #[test]
    fn retarget_respects_half_and_double_limits() {
        let current = [0x10u8; 32];
        let expected = DIFFICULTY_RETARGET_WINDOW_BLOCKS * BLOCK_TIME_SECONDS;

        let unchanged = retarget_difficulty_with_window(
            &current,
            DIFFICULTY_RETARGET_WINDOW_BLOCKS,
            1_000,
            1_000 + expected,
        );
        assert_eq!(unchanged, current);

        let too_fast = retarget_difficulty_with_window(
            &current,
            DIFFICULTY_RETARGET_WINDOW_BLOCKS,
            1_000,
            1_000 + expected / 4,
        );
        let too_slow = retarget_difficulty_with_window(
            &current,
            DIFFICULTY_RETARGET_WINDOW_BLOCKS,
            1_000,
            1_000 + expected * 4,
        );

        assert_eq!(too_fast, [0x08u8; 32]);
        assert_eq!(too_slow, [0x20u8; 32]);
    }

    #[test]
    fn u512_round_trip_multiply_and_divide() {
        let target = [0x10u8; 32];
        let value = U512::from_be_bytes_256(&target);

        assert_eq!(value.to_be_bytes_256_saturated(), target);
        assert_eq!(
            value.mul_u128(2).div_u128(1).to_be_bytes_256_saturated(),
            [0x20u8; 32]
        );
        assert_eq!(
            value.mul_u128(1).div_u128(2).to_be_bytes_256_saturated(),
            [0x08u8; 32]
        );
    }

    #[test]
    fn real_randomx_hasher_hashes_and_rotates_seed() {
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];
        let hasher =
            RealRandomXHasher::new(&seed_a).expect("real RandomX hasher should initialize");

        let hash_a = hasher
            .hash_block(&seed_a, b"SUL_REAL_RANDOMX_TEST_A")
            .expect("hash with seed A");
        let hash_b = hasher
            .hash_block(&seed_b, b"SUL_REAL_RANDOMX_TEST_A")
            .expect("hash with seed B");

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn seed_rotates_only_on_epoch_boundary() {
        let genesis = [0x11u8; 32];
        let s0 = derive_seed_for_height(0, &genesis);
        let s1 = derive_seed_for_height(RANDOMX_SEED_EPOCH_BLOCKS - 1, &genesis);
        let s2 = derive_seed_for_height(RANDOMX_SEED_EPOCH_BLOCKS, &genesis);

        assert_eq!(s0, s1);
        assert_ne!(s1, s2);
    }

    #[test]
    fn mine_and_verify_header_against_target() {
        let genesis = [0xAAu8; 32];
        let hasher = MockRandomXHasher;
        let mut target = [0xFFu8; 32];
        target[0] = 0x0F; // Requires the first byte to be <= 0x0F (~1/16 chance)

        let mut header = BlockHeader {
            version: 1,
            height: 1,
            prev_block_hash: [0x22u8; 32],
            merkle_root: [0x33u8; 32],
            timestamp: 1_700_000_120,
            difficulty_target: target,
            nonce: 0,
        };

        let mut found = false;
        for nonce in 0..10_000 {
            header.nonce = nonce;
            if header.verify_pow(&hasher, &genesis).is_ok() {
                found = true;
                break;
            }
        }

        assert!(found, "should find a valid nonce within the test limit");
    }
}
