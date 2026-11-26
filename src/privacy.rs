use std::collections::{HashMap, HashSet};
use std::fmt;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::params::MAX_TX_DISCOUNT_ATOMIC;

pub type Key32 = [u8; 32];

const RANGE_BITS: usize = 64;

pub fn checked_commit_sum(commitments: &[PedersenCommitment]) -> Option<PedersenCommitment> {
    let mut sum = PedersenCommitment::zero();
    for commitment in commitments {
        sum = sum.checked_add(*commitment)?;
    }
    Some(sum)
}

pub fn generator_h() -> RistrettoPoint {
    let mut uniform = [0u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_RISTRETTO255_H_GENERATOR_V1");
    hasher.finalize_xof().fill(&mut uniform);
    RistrettoPoint::from_uniform_bytes(&uniform)
}

pub fn scalar_from_u128(val: u128) -> Scalar {
    Scalar::from(val)
}

pub fn pedersen_point(amount_atomic: u128, blinding: &Scalar) -> RistrettoPoint {
    scalar_from_u128(amount_atomic) * generator_h() + blinding * RISTRETTO_BASEPOINT_POINT
}

fn sul_pedersen_gens() -> PedersenGens {
    PedersenGens {
        B: generator_h(),
        B_blinding: RISTRETTO_BASEPOINT_POINT,
    }
}

fn hash_bytes(domain: &[u8], parts: &[&[u8]]) -> Key32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn hash_to_scalar(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut wide = [0u8; 64];
    hasher.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hash_to_point(domain: &[u8], point: &RistrettoPoint) -> RistrettoPoint {
    let mut uniform = [0u8; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(point.compress().as_bytes());
    hasher.finalize_xof().fill(&mut uniform);
    RistrettoPoint::from_uniform_bytes(&uniform)
}

fn scalar_from_canonical_bytes(bytes: &Key32) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
}

fn point_from_bytes(bytes: &Key32) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn public_key(secret: &Scalar) -> Key32 {
    (secret * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
}

pub fn prove_u64_range(
    amount: u64,
    blinding: Scalar,
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
) -> Result<(RangeProof, CompressedRistretto), String> {
    let mut transcript = Transcript::new(b"SUL_BULLETPROOF_RANGE_U64_V1");
    RangeProof::prove_single(
        bp_gens,
        pc_gens,
        &mut transcript,
        amount,
        &blinding,
        RANGE_BITS,
    )
    .map_err(|e| format!("failed to generate range proof: {e:?}"))
}

pub fn verify_u64_range(
    proof: &RangeProof,
    committed_value: &CompressedRistretto,
    bp_gens: &BulletproofGens,
    pc_gens: &PedersenGens,
) -> Result<(), String> {
    let mut transcript = Transcript::new(b"SUL_BULLETPROOF_RANGE_U64_V1");
    proof
        .verify_single(
            bp_gens,
            pc_gens,
            &mut transcript,
            committed_value,
            RANGE_BITS,
        )
        .map_err(|e| format!("failed to verify range proof: {e:?}"))
}

pub const MIN_RING_SIZE: usize = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    RingTooSmall { actual: usize, minimum: usize },
    EmptyInputsOrOutputs,
    DuplicateKeyImage(Key32),
    InvalidStealthOutput,
    DuplicateStealthOutput(Key32),
    UnknownRingMember(Key32),
    InvalidRingSignature,
    InvalidRangeProof { output_index: usize },
    BalanceMismatch,
    InvalidDiscount { provided: u128, max_allowed: u128 },
    ArithmeticOverflow,
    InvalidSigningData,
    CryptographicFailure(String),
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RingTooSmall { actual, minimum } => {
                write!(f, "ring is too small: {actual} members (minimum {minimum})")
            }
            Self::EmptyInputsOrOutputs => {
                write!(
                    f,
                    "confidential transaction requires at least one input and one output"
                )
            }
            Self::DuplicateKeyImage(_) => {
                write!(f, "duplicate key image: attempted double spend detected")
            }
            Self::InvalidStealthOutput => write!(f, "invalid or inconsistent stealth output"),
            Self::DuplicateStealthOutput(_) => {
                write!(f, "stealth output public key already exists")
            }
            Self::UnknownRingMember(_) => {
                write!(
                    f,
                    "ring contains a public key absent from the valid output set"
                )
            }
            Self::InvalidRingSignature => write!(f, "invalid LSAG ring signature"),
            Self::InvalidRangeProof { output_index } => {
                write!(f, "invalid bulletproof for output #{output_index}")
            }
            Self::BalanceMismatch => {
                write!(
                    f,
                    "invalid homomorphic balance: inputs != outputs + discount"
                )
            }
            Self::InvalidDiscount {
                provided,
                max_allowed,
            } => write!(
                f,
                "invalid discount ({provided} atomic units; maximum allowed {max_allowed})"
            ),
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow in the privacy layer"),
            Self::InvalidSigningData => write!(f, "invalid ring signing data"),
            Self::CryptographicFailure(message) => {
                write!(f, "cryptographic operation failed: {message}")
            }
        }
    }
}

impl std::error::Error for PrivacyError {}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StealthAddress {
    pub scan_pub: Key32,
    pub spend_pub: Key32,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StealthWalletKeys {
    pub scan_priv: Key32,
    pub spend_priv: Key32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StealthOutput {
    pub one_time_pub: Key32,
    pub tx_ephemeral_pub: Key32,
    pub view_tag: u8,
    pub commitment: PedersenCommitment,
    pub range_proof: BulletproofRangeProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct PedersenCommitment {
    pub point: Key32,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValidOutputSet {
    outputs: HashMap<Key32, PedersenCommitment>,
}

impl ValidOutputSet {
    pub fn new() -> Self {
        Self {
            outputs: HashMap::new(),
        }
    }

    pub fn insert(&mut self, one_time_pub: Key32, commitment: PedersenCommitment) -> bool {
        if self.outputs.contains_key(&one_time_pub) {
            return false;
        }
        self.outputs.insert(one_time_pub, commitment);
        true
    }

    pub fn contains(&self, one_time_pub: &Key32) -> bool {
        self.outputs.contains_key(one_time_pub)
    }

    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    pub fn iter_outputs(&self) -> impl Iterator<Item = &Key32> {
        self.outputs.keys()
    }

    pub fn commitment(&self, one_time_pub: &Key32) -> Option<&PedersenCommitment> {
        self.outputs.get(one_time_pub)
    }
}

pub fn verify_ring_members_in_chain(
    tx: &ConfidentialTx,
    valid_outputs: &ValidOutputSet,
) -> Result<(), PrivacyError> {
    for inp in &tx.inputs {
        for member in &inp.ring_members {
            if !valid_outputs.contains(member) {
                return Err(PrivacyError::UnknownRingMember(*member));
            }
        }
    }
    Ok(())
}

/// Checks chain membership before applying the pure cryptographic transaction verifier.
pub fn verify_confidential_tx_against_outputs(
    tx: &ConfidentialTx,
    spent_images: &KeyImageSet,
    valid_outputs: &ValidOutputSet,
    occupancy_ppm: u128,
) -> Result<(), PrivacyError> {
    verify_ring_members_in_chain(tx, valid_outputs)?;
    verify_confidential_tx(tx, spent_images, occupancy_ppm)
}

impl PedersenCommitment {
    pub fn commit(amount_atomic: u128, blinding: u128) -> Self {
        Self::commit_scalar(amount_atomic, scalar_from_u128(blinding))
    }

    fn commit_scalar(amount_atomic: u128, blinding: Scalar) -> Self {
        Self {
            point: pedersen_point(amount_atomic, &blinding)
                .compress()
                .to_bytes(),
        }
    }

    pub fn zero() -> Self {
        Self {
            point: RistrettoPoint::default().compress().to_bytes(),
        }
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let left = point_from_bytes(&self.point)?;
        let right = point_from_bytes(&other.point)?;
        Some(Self {
            point: (left + right).compress().to_bytes(),
        })
    }

    fn point(self) -> Option<RistrettoPoint> {
        point_from_bytes(&self.point)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BulletproofRangeProof {
    pub bit_length: u8,
    pub lo_commitment: Key32,
    pub hi_commitment: Key32,
    pub lo_proof_bytes: Vec<u8>,
    pub hi_proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RingCtInput {
    pub ring_members: Vec<Key32>,
    pub pseudo_commitment: PedersenCommitment,
    pub key_image: Key32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RingSignature {
    pub challenge_c0: Key32,
    pub responses: Vec<Key32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RingCtSignature {
    pub inputs: Vec<RingSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfidentialTx {
    pub inputs: Vec<RingCtInput>,
    pub outputs: Vec<StealthOutput>,
    pub discount_atomic: u128,
    pub signature: RingCtSignature,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyImageSet {
    spent: HashSet<Key32>,
}

impl KeyImageSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, image: &Key32) -> bool {
        self.spent.contains(image)
    }

    pub fn insert(&mut self, image: Key32) -> Result<(), PrivacyError> {
        if !self.spent.insert(image) {
            return Err(PrivacyError::DuplicateKeyImage(image));
        }
        Ok(())
    }

    pub fn iter_spent(&self) -> impl Iterator<Item = &Key32> {
        self.spent.iter()
    }
}

impl StealthWalletKeys {
    pub fn from_seed(seed: &Key32) -> Self {
        let mut scan = hash_to_scalar(b"SUL_SCAN_PRIV_V1", &[seed]);
        let mut spend = hash_to_scalar(b"SUL_SPEND_PRIV_V1", &[seed]);
        if scan == Scalar::ZERO {
            scan = Scalar::ONE;
        }
        if spend == Scalar::ZERO {
            spend = Scalar::ONE;
        }
        Self {
            scan_priv: scan.to_bytes(),
            spend_priv: spend.to_bytes(),
        }
    }

    pub fn public_address(&self) -> StealthAddress {
        let scan = scalar_from_canonical_bytes(&self.scan_priv)
            .expect("wallet scan key is a canonical scalar");
        let spend = scalar_from_canonical_bytes(&self.spend_priv)
            .expect("wallet spend key is a canonical scalar");
        StealthAddress {
            scan_pub: public_key(&scan),
            spend_pub: public_key(&spend),
        }
    }

    pub fn scan_output(&self, output: &StealthOutput) -> Option<Key32> {
        let scan_priv = scalar_from_canonical_bytes(&self.scan_priv)?;
        let spend_priv = scalar_from_canonical_bytes(&self.spend_priv)?;
        let ephemeral_pub = point_from_bytes(&output.tx_ephemeral_pub)?;
        let shared = scan_priv * ephemeral_pub;
        let shared_bytes = shared.compress().to_bytes();
        if view_tag(&shared_bytes) != output.view_tag {
            return None;
        }

        let tweak = stealth_tweak(&shared_bytes);
        let spend_pub = public_key(&spend_priv);
        let expected_pub = (tweak * RISTRETTO_BASEPOINT_POINT + point_from_bytes(&spend_pub)?)
            .compress()
            .to_bytes();
        if expected_pub != output.one_time_pub {
            return None;
        }
        Some((tweak + spend_priv).to_bytes())
    }
}

fn view_tag(shared: &Key32) -> u8 {
    hash_bytes(b"SUL_STEALTH_VIEW_TAG_V1", &[shared])[0]
}

fn stealth_tweak(shared: &Key32) -> Scalar {
    hash_to_scalar(b"SUL_STEALTH_TWEAK_V1", &[shared])
}

pub fn derive_stealth_destination(
    recipient: &StealthAddress,
    ephemeral_secret: &Key32,
) -> Result<(Key32, Key32, u8), PrivacyError> {
    let scan_pub =
        point_from_bytes(&recipient.scan_pub).ok_or(PrivacyError::InvalidStealthOutput)?;
    let spend_pub =
        point_from_bytes(&recipient.spend_pub).ok_or(PrivacyError::InvalidStealthOutput)?;
    let ephemeral = Scalar::from_bytes_mod_order(*ephemeral_secret);
    if ephemeral == Scalar::ZERO {
        return Err(PrivacyError::InvalidStealthOutput);
    }
    let ephemeral_pub = public_key(&ephemeral);
    let shared = (ephemeral * scan_pub).compress().to_bytes();
    let tweak = stealth_tweak(&shared);
    let one_time_pub = (tweak * RISTRETTO_BASEPOINT_POINT + spend_pub)
        .compress()
        .to_bytes();
    Ok((one_time_pub, ephemeral_pub, view_tag(&shared)))
}

fn prove_range_u128(
    amount: u128,
    blinding: Scalar,
) -> Result<(PedersenCommitment, BulletproofRangeProof), PrivacyError> {
    let low = amount as u64;
    let high = (amount >> 64) as u64;
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
    let pc_gens = sul_pedersen_gens();
    let low_blinding = Scalar::random(&mut OsRng);
    let high_blinding = (blinding - low_blinding) * Scalar::from(1u128 << 64).invert();
    let (low_proof, low_commitment) = prove_u64_range(low, low_blinding, &bp_gens, &pc_gens)
        .map_err(PrivacyError::CryptographicFailure)?;
    let (high_proof, high_commitment) = prove_u64_range(high, high_blinding, &bp_gens, &pc_gens)
        .map_err(PrivacyError::CryptographicFailure)?;

    let weight = Scalar::from(1u128 << 64);
    let low_point = low_commitment
        .decompress()
        .ok_or(PrivacyError::InvalidSigningData)?;
    let high_point = high_commitment
        .decompress()
        .ok_or(PrivacyError::InvalidSigningData)?;
    let combined = (low_point + weight * high_point).compress().to_bytes();
    let commitment = PedersenCommitment { point: combined };
    Ok((
        commitment,
        BulletproofRangeProof {
            bit_length: 128,
            lo_commitment: low_commitment.to_bytes(),
            hi_commitment: high_commitment.to_bytes(),
            lo_proof_bytes: low_proof.to_bytes(),
            hi_proof_bytes: high_proof.to_bytes(),
        },
    ))
}

pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &BulletproofRangeProof) -> bool {
    if proof.bit_length != 128 {
        return false;
    }
    let Some(commitment_point) = commitment.point() else {
        return false;
    };
    let low_commitment = CompressedRistretto(proof.lo_commitment);
    let high_commitment = CompressedRistretto(proof.hi_commitment);
    let (Some(low_point), Some(high_point)) =
        (low_commitment.decompress(), high_commitment.decompress())
    else {
        return false;
    };
    let weight = Scalar::from(1u128 << 64);
    if low_point + weight * high_point != commitment_point {
        return false;
    }

    let (Ok(low_proof), Ok(high_proof)) = (
        RangeProof::from_bytes(&proof.lo_proof_bytes),
        RangeProof::from_bytes(&proof.hi_proof_bytes),
    ) else {
        return false;
    };
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
    let pc_gens = sul_pedersen_gens();
    verify_u64_range(&low_proof, &low_commitment, &bp_gens, &pc_gens).is_ok()
        && verify_u64_range(&high_proof, &high_commitment, &bp_gens, &pc_gens).is_ok()
}

pub fn compute_key_image(
    one_time_priv: &Key32,
    one_time_pub: &Key32,
) -> Result<Key32, PrivacyError> {
    let secret =
        scalar_from_canonical_bytes(one_time_priv).ok_or(PrivacyError::InvalidSigningData)?;
    let public = point_from_bytes(one_time_pub).ok_or(PrivacyError::InvalidSigningData)?;
    if secret == Scalar::ZERO
        || public == RistrettoPoint::default()
        || secret * RISTRETTO_BASEPOINT_POINT != public
    {
        return Err(PrivacyError::InvalidSigningData);
    }
    Ok((secret * hash_to_point(b"SUL_LSAG_KEY_IMAGE_V1", &public))
        .compress()
        .to_bytes())
}

fn confidential_message(
    inputs: &[RingCtInput],
    outputs: &[StealthOutput],
    discount_atomic: u128,
) -> Key32 {
    let mut h = blake3::Hasher::new();
    h.update(b"SUL_CONFIDENTIAL_TX_LSAG_V1");
    h.update(&(inputs.len() as u64).to_le_bytes());
    for input in inputs {
        h.update(&(input.ring_members.len() as u64).to_le_bytes());
        for member in &input.ring_members {
            h.update(member);
        }
        h.update(&input.pseudo_commitment.point);
        h.update(&input.key_image);
    }
    h.update(&(outputs.len() as u64).to_le_bytes());
    for output in outputs {
        h.update(&output.one_time_pub);
        h.update(&output.tx_ephemeral_pub);
        h.update(&[output.view_tag]);
        h.update(&output.commitment.point);
        h.update(&[output.range_proof.bit_length]);
        h.update(&output.range_proof.lo_commitment);
        h.update(&output.range_proof.hi_commitment);
        h.update(&(output.range_proof.lo_proof_bytes.len() as u64).to_le_bytes());
        h.update(&output.range_proof.lo_proof_bytes);
        h.update(&(output.range_proof.hi_proof_bytes.len() as u64).to_le_bytes());
        h.update(&output.range_proof.hi_proof_bytes);
    }
    h.update(&discount_atomic.to_le_bytes());
    *h.finalize().as_bytes()
}

fn lsag_challenge(message: &Key32, left: &RistrettoPoint, right: &RistrettoPoint) -> Scalar {
    hash_to_scalar(
        b"SUL_LSAG_CHALLENGE_V1",
        &[
            message,
            left.compress().as_bytes(),
            right.compress().as_bytes(),
        ],
    )
}

fn random_lsag_scalar(
    domain: &[u8],
    rng_seed: &Key32,
    message: &Key32,
    key_image: &Key32,
    index: usize,
) -> Scalar {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    hash_to_scalar(
        domain,
        &[
            rng_seed,
            message,
            key_image,
            &(index as u64).to_le_bytes(),
            &entropy,
        ],
    )
}

fn sign_lsag(
    input: &RingCtInput,
    message: &Key32,
    member_index: usize,
    secret_bytes: &Key32,
    rng_seed: &Key32,
) -> Result<RingSignature, PrivacyError> {
    let ring_len = input.ring_members.len();
    if ring_len < MIN_RING_SIZE || member_index >= ring_len {
        return Err(PrivacyError::InvalidSigningData);
    }
    let secret =
        scalar_from_canonical_bytes(secret_bytes).ok_or(PrivacyError::InvalidSigningData)?;
    let signer_public = public_key(&secret);
    if secret == Scalar::ZERO || input.ring_members[member_index] != signer_public {
        return Err(PrivacyError::InvalidSigningData);
    }
    let image = point_from_bytes(&input.key_image).ok_or(PrivacyError::InvalidSigningData)?;
    if image == RistrettoPoint::default() {
        return Err(PrivacyError::InvalidSigningData);
    }
    let signer_point = point_from_bytes(&signer_public).ok_or(PrivacyError::InvalidSigningData)?;
    let expected_image = secret * hash_to_point(b"SUL_LSAG_KEY_IMAGE_V1", &signer_point);
    if image != expected_image {
        return Err(PrivacyError::InvalidSigningData);
    }

    let ring_points: Vec<RistrettoPoint> = input
        .ring_members
        .iter()
        .map(point_from_bytes)
        .collect::<Option<_>>()
        .ok_or(PrivacyError::InvalidSigningData)?;
    if ring_points
        .iter()
        .any(|point| *point == RistrettoPoint::default())
        || input
            .ring_members
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != ring_len
    {
        return Err(PrivacyError::InvalidSigningData);
    }
    let hp: Vec<RistrettoPoint> = ring_points
        .iter()
        .map(|point| hash_to_point(b"SUL_LSAG_KEY_IMAGE_V1", point))
        .collect();

    let alpha = random_lsag_scalar(
        b"SUL_LSAG_ALPHA_V1",
        rng_seed,
        message,
        &input.key_image,
        member_index,
    );
    if alpha == Scalar::ZERO {
        return Err(PrivacyError::InvalidSigningData);
    }
    let next = (member_index + 1) % ring_len;
    let mut challenges = vec![Scalar::ZERO; ring_len];
    let mut responses = vec![Scalar::ZERO; ring_len];
    challenges[next] = lsag_challenge(
        message,
        &(alpha * RISTRETTO_BASEPOINT_POINT),
        &(alpha * hp[member_index]),
    );
    let mut index = next;
    while index != member_index {
        responses[index] = random_lsag_scalar(
            b"SUL_LSAG_RESPONSE_V1",
            rng_seed,
            message,
            &input.key_image,
            index,
        );
        let left =
            responses[index] * RISTRETTO_BASEPOINT_POINT + challenges[index] * ring_points[index];
        let right = responses[index] * hp[index] + challenges[index] * image;
        let next_index = (index + 1) % ring_len;
        challenges[next_index] = lsag_challenge(message, &left, &right);
        index = next_index;
    }
    responses[member_index] = alpha - challenges[member_index] * secret;

    Ok(RingSignature {
        challenge_c0: challenges[0].to_bytes(),
        responses: responses.iter().map(Scalar::to_bytes).collect(),
    })
}

fn verify_lsag(input: &RingCtInput, message: &Key32, signature: &RingSignature) -> bool {
    let ring_len = input.ring_members.len();
    if ring_len < MIN_RING_SIZE || signature.responses.len() != ring_len {
        return false;
    }
    let Some(mut challenge) = scalar_from_canonical_bytes(&signature.challenge_c0) else {
        return false;
    };
    let Some(image) = point_from_bytes(&input.key_image) else {
        return false;
    };
    if image == RistrettoPoint::default() {
        return false;
    }
    let ring_points: Vec<RistrettoPoint> =
        match input.ring_members.iter().map(point_from_bytes).collect() {
            Some(points) => points,
            None => return false,
        };
    if ring_points
        .iter()
        .any(|point| *point == RistrettoPoint::default())
        || input
            .ring_members
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            != ring_len
    {
        return false;
    }
    let responses: Option<Vec<Scalar>> = signature
        .responses
        .iter()
        .map(scalar_from_canonical_bytes)
        .collect();
    let Some(responses) = responses else {
        return false;
    };
    for index in 0..ring_len {
        let left = responses[index] * RISTRETTO_BASEPOINT_POINT + challenge * ring_points[index];
        let hp = hash_to_point(b"SUL_LSAG_KEY_IMAGE_V1", &ring_points[index]);
        let right = responses[index] * hp + challenge * image;
        challenge = lsag_challenge(message, &left, &right);
    }
    challenge.to_bytes() == signature.challenge_c0
}

/// Builds a confidential transaction.
/// Each LSAG seed is combined with fresh operating-system entropy.
pub fn build_confidential_tx(
    inputs: Vec<RingCtInput>,
    input_blindings: &[u128],
    outputs_spec: &[(StealthAddress, u128, Key32, u128)],
    real_ring_indices: &[usize],
    real_one_time_privs: &[Key32],
    lsag_rng_seeds: &[Key32],
    discount_atomic: u128,
) -> Result<ConfidentialTx, PrivacyError> {
    if inputs.is_empty() || outputs_spec.is_empty() {
        return Err(PrivacyError::EmptyInputsOrOutputs);
    }
    if inputs.len() != input_blindings.len()
        || inputs.len() != real_ring_indices.len()
        || inputs.len() != real_one_time_privs.len()
        || inputs.len() != lsag_rng_seeds.len()
    {
        return Err(PrivacyError::InvalidSigningData);
    }

    let sum_input_blindings = input_blindings
        .iter()
        .fold(Scalar::ZERO, |sum, value| sum + scalar_from_u128(*value));
    let mut sum_output_blindings = Scalar::ZERO;
    let mut outputs = Vec::with_capacity(outputs_spec.len());
    for (index, (address, amount, ephemeral_secret, blinding)) in outputs_spec.iter().enumerate() {
        let output_blinding = if index + 1 == outputs_spec.len() {
            sum_input_blindings - sum_output_blindings
        } else {
            let scalar = scalar_from_u128(*blinding);
            sum_output_blindings += scalar;
            scalar
        };
        let (one_time_pub, tx_ephemeral_pub, tag) =
            derive_stealth_destination(address, ephemeral_secret)?;
        let (commitment, range_proof) = prove_range_u128(*amount, output_blinding)?;
        outputs.push(StealthOutput {
            one_time_pub,
            tx_ephemeral_pub,
            view_tag: tag,
            commitment,
            range_proof,
        });
    }

    let message = confidential_message(&inputs, &outputs, discount_atomic);
    let signatures = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            sign_lsag(
                input,
                &message,
                real_ring_indices[index],
                &real_one_time_privs[index],
                &lsag_rng_seeds[index],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConfidentialTx {
        inputs,
        outputs,
        discount_atomic,
        signature: RingCtSignature { inputs: signatures },
    })
}

/// Validates commitments, Bulletproof range proofs, and LSAG signatures.
///
/// Because output values are confidential, consensus cannot verify the occupancy-adjusted
/// minimum discount without an additional ZK proof. This validates the explicit discount cap
/// and balance commitment, but not the minimum discount.
pub fn verify_confidential_tx(
    tx: &ConfidentialTx,
    spent_images: &KeyImageSet,
    _occupancy_ppm: u128,
) -> Result<(), PrivacyError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(PrivacyError::EmptyInputsOrOutputs);
    }
    if tx.discount_atomic > MAX_TX_DISCOUNT_ATOMIC {
        return Err(PrivacyError::InvalidDiscount {
            provided: tx.discount_atomic,
            max_allowed: MAX_TX_DISCOUNT_ATOMIC,
        });
    }
    if tx.signature.inputs.len() != tx.inputs.len() {
        return Err(PrivacyError::InvalidRingSignature);
    }

    let mut seen_in_tx = HashSet::with_capacity(tx.inputs.len());
    let mut sum_inputs = PedersenCommitment::zero();
    for input in &tx.inputs {
        if input.ring_members.len() < MIN_RING_SIZE {
            return Err(PrivacyError::RingTooSmall {
                actual: input.ring_members.len(),
                minimum: MIN_RING_SIZE,
            });
        }
        if spent_images.contains(&input.key_image) || !seen_in_tx.insert(input.key_image) {
            return Err(PrivacyError::DuplicateKeyImage(input.key_image));
        }
        sum_inputs = sum_inputs
            .checked_add(input.pseudo_commitment)
            .ok_or(PrivacyError::InvalidSigningData)?;
    }

    let mut sum_outputs = PedersenCommitment::zero();
    for (index, output) in tx.outputs.iter().enumerate() {
        if point_from_bytes(&output.one_time_pub).is_none()
            || point_from_bytes(&output.tx_ephemeral_pub).is_none()
            || !verify_range_proof(&output.commitment, &output.range_proof)
        {
            return Err(PrivacyError::InvalidRangeProof {
                output_index: index,
            });
        }
        sum_outputs =
            sum_outputs
                .checked_add(output.commitment)
                .ok_or(PrivacyError::InvalidRangeProof {
                    output_index: index,
                })?;
    }

    let expected_total = sum_outputs
        .checked_add(PedersenCommitment::commit(tx.discount_atomic, 0))
        .ok_or(PrivacyError::BalanceMismatch)?;
    if sum_inputs != expected_total {
        return Err(PrivacyError::BalanceMismatch);
    }

    let message = confidential_message(&tx.inputs, &tx.outputs, tx.discount_atomic);
    for (input, signature) in tx.inputs.iter().zip(&tx.signature.inputs) {
        if !verify_lsag(input, &message, signature) {
            return Err(PrivacyError::InvalidRingSignature);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ristretto_pedersen_point_and_bulletproof_round_trip() {
        let amount = 123u64;
        let blinding = Scalar::from(777u64);
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = sul_pedersen_gens();
        let (proof, commitment) = prove_u64_range(amount, blinding, &bp_gens, &pc_gens).unwrap();
        verify_u64_range(&proof, &commitment, &bp_gens, &pc_gens).unwrap();
        assert_eq!(
            commitment,
            pc_gens.commit(Scalar::from(amount), blinding).compress()
        );
    }

    fn ring_and_signer(secret: Scalar) -> (Vec<Key32>, Key32, usize, Key32) {
        let mut ring: Vec<Key32> = (1..MIN_RING_SIZE)
            .map(|i| public_key(&Scalar::from(i as u64 + 100)))
            .collect();
        let signer_index = 3;
        ring.insert(signer_index, public_key(&secret));
        let key_image = compute_key_image(&secret.to_bytes(), &ring[signer_index]).unwrap();
        (ring, key_image, signer_index, secret.to_bytes())
    }

    #[test]
    fn confidential_tx_verifies_stealth_range_proofs_balance_and_lsag() {
        let wallet = StealthWalletKeys::from_seed(&[0x42; 32]);
        let address = wallet.public_address();
        let amount = 123_456_789_012_345_678_901u128;
        let discount = 10u128;
        let input_blinding = 0x9988_7766_5544_3322u128;
        let signer_secret = Scalar::from(0x33u64);
        let (ring, key_image, signer_index, signer_priv) = ring_and_signer(signer_secret);
        let input = RingCtInput {
            ring_members: ring,
            pseudo_commitment: PedersenCommitment::commit(amount + discount, input_blinding),
            key_image,
        };
        let tx = build_confidential_tx(
            vec![input],
            &[input_blinding],
            &[(address, amount, [0x77; 32], 12345)],
            &[signer_index],
            &[signer_priv],
            &[[0x88; 32]],
            discount,
        )
        .unwrap();
        let spent = KeyImageSet::new();
        verify_confidential_tx(&tx, &spent, 0).unwrap();
        let one_time_priv = wallet.scan_output(&tx.outputs[0]).unwrap();
        assert_eq!(
            public_key(&scalar_from_canonical_bytes(&one_time_priv).unwrap()),
            tx.outputs[0].one_time_pub
        );
        assert!(StealthWalletKeys::from_seed(&[0x43; 32])
            .scan_output(&tx.outputs[0])
            .is_none());

        let mut changed = tx.clone();
        changed.discount_atomic += 1;
        assert!(verify_confidential_tx(&changed, &spent, 0).is_err());
        let mut bad_signature = tx.clone();
        bad_signature.signature.inputs[0].responses[0][0] ^= 1;
        assert!(matches!(
            verify_confidential_tx(&bad_signature, &spent, 0),
            Err(PrivacyError::InvalidRingSignature)
        ));
    }

    #[test]
    fn invalid_range_proof_and_key_image_are_rejected() {
        let wallet = StealthWalletKeys::from_seed(&[0x42; 32]);
        let amount = 50u128;
        let discount = 2u128;
        let secret = Scalar::from(7u64);
        let (ring, key_image, signer_index, signer_priv) = ring_and_signer(secret);
        let tx = build_confidential_tx(
            vec![RingCtInput {
                ring_members: ring,
                pseudo_commitment: PedersenCommitment::commit(amount + discount, 9),
                key_image,
            }],
            &[9],
            &[(wallet.public_address(), amount, [0x55; 32], 3)],
            &[signer_index],
            &[signer_priv],
            &[[0x89; 32]],
            discount,
        )
        .unwrap();
        let mut corrupted = tx.clone();
        corrupted.outputs[0].range_proof.lo_proof_bytes[0] ^= 1;
        assert!(matches!(
            verify_confidential_tx(&corrupted, &KeyImageSet::new(), 0),
            Err(PrivacyError::InvalidRangeProof { .. })
        ));
    }

    #[test]
    fn confidential_tx_signs_and_verifies_each_input() {
        let wallet = StealthWalletKeys::from_seed(&[0x91; 32]);
        let first_secret = Scalar::from(7u64);
        let second_secret = Scalar::from(9u64);
        let (first_ring, first_image, first_index, first_priv) = ring_and_signer(first_secret);
        let (second_ring, second_image, second_index, second_priv) = ring_and_signer(second_secret);
        let tx = build_confidential_tx(
            vec![
                RingCtInput {
                    ring_members: first_ring,
                    pseudo_commitment: PedersenCommitment::commit(20, 3),
                    key_image: first_image,
                },
                RingCtInput {
                    ring_members: second_ring,
                    pseudo_commitment: PedersenCommitment::commit(32, 6),
                    key_image: second_image,
                },
            ],
            &[3, 6],
            &[(wallet.public_address(), 50, [0x33; 32], 0)],
            &[first_index, second_index],
            &[first_priv, second_priv],
            &[[0x44; 32], [0x45; 32]],
            2,
        )
        .unwrap();

        assert!(verify_confidential_tx(&tx, &KeyImageSet::new(), 0).is_ok());
        let mut corrupted = tx;
        corrupted.signature.inputs[1].responses[0][0] ^= 1;
        assert!(matches!(
            verify_confidential_tx(&corrupted, &KeyImageSet::new(), 0),
            Err(PrivacyError::InvalidRingSignature)
        ));
    }

    #[test]
    fn duplicate_key_images_and_small_rings_are_rejected() {
        let wallet = StealthWalletKeys::from_seed(&[0xA1; 32]);
        let secret = Scalar::from(21u64);
        let (ring, key_image, signer_index, signer_priv) = ring_and_signer(secret);
        let tx = build_confidential_tx(
            vec![
                RingCtInput {
                    ring_members: ring.clone(),
                    pseudo_commitment: PedersenCommitment::commit(10, 2),
                    key_image,
                },
                RingCtInput {
                    ring_members: ring,
                    pseudo_commitment: PedersenCommitment::commit(10, 2),
                    key_image,
                },
            ],
            &[2, 2],
            &[(wallet.public_address(), 20, [0x22; 32], 0)],
            &[signer_index, signer_index],
            &[signer_priv.clone(), signer_priv],
            &[[0x23; 32], [0x24; 32]],
            0,
        )
        .unwrap();

        assert!(matches!(
            verify_confidential_tx(&tx, &KeyImageSet::new(), 0),
            Err(PrivacyError::DuplicateKeyImage(_))
        ));

        let mut small_ring = tx;
        small_ring.inputs[0]
            .ring_members
            .truncate(MIN_RING_SIZE - 1);
        small_ring.inputs[1]
            .ring_members
            .truncate(MIN_RING_SIZE - 1);
        assert!(matches!(
            verify_confidential_tx(&small_ring, &KeyImageSet::new(), 0),
            Err(PrivacyError::RingTooSmall { .. })
        ));
    }
}
