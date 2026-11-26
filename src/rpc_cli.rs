use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::antispam::{solve_micro_pow, AntiSpamChallenge};
use crate::chain_engine::{
    compute_block_merkle_root, Block, ChainEngine, ChainEngineError, MAX_BLOCK_TXS,
};
use crate::chain_state::{HybridBlockReport, HybridChainError, HybridTx};
use crate::ledger::TransferTx;
use crate::monetary::OCCUPANCY_SCALE;
use crate::params::ATOMIC_UNITS_PER_SUL;
use crate::persistence::{DiskStore, PersistenceError};
use crate::pow_randomx::{
    BlockHeader, ChainWork, ConsensusError, Hash256, RandomXHasher, RealRandomXHasher,
};
use crate::privacy::verify_confidential_tx_against_outputs;

const DEFAULT_DATA_DIRECTORY: &str = ".sul-node";
const DEFAULT_GENESIS_SEED: Hash256 = [0x53; 32];
const DEFAULT_INITIAL_SUPPLY_SUL: u128 = 1_000;
const DEFAULT_INITIAL_EMISSION_BPS: u128 = 125;
const DEFAULT_OCCUPANCY_PPM: u128 = 500_000;
const DEFAULT_MAX_NONCE_ATTEMPTS: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub height: Option<u64>,
    pub tip_hash: Option<Hash256>,
    pub chainwork: ChainWork,
    pub total_supply_atomic: u128,
    pub miner_reward_pool_atomic: u128,
    pub mempool_len: usize,
    pub valid_output_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceInfo {
    pub atomic_units: u128,
    pub sul: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinedBlock {
    pub hash: Hash256,
    pub height: u64,
    pub chainwork: ChainWork,
    pub transaction_count: usize,
}

#[derive(Debug)]
pub enum RpcError {
    InvalidArgument(String),
    MissingStore,
    Chain(ChainEngineError),
    Hybrid(HybridChainError),
    Consensus(ConsensusError),
    Persistence(PersistenceError),
    Hasher(String),
    MiningFailed(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) => write!(formatter, "invalid argument: {message}"),
            Self::MissingStore => write!(formatter, "no disk store is configured"),
            Self::Chain(error) => write!(formatter, "chain operation failed: {error}"),
            Self::Hybrid(error) => write!(formatter, "transaction operation failed: {error}"),
            Self::Consensus(error) => write!(formatter, "consensus operation failed: {error}"),
            Self::Persistence(error) => write!(formatter, "persistence operation failed: {error}"),
            Self::Hasher(error) => write!(formatter, "RandomX hasher failed: {error}"),
            Self::MiningFailed(message) => write!(formatter, "mining failed: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<ChainEngineError> for RpcError {
    fn from(error: ChainEngineError) -> Self {
        Self::Chain(error)
    }
}

impl From<HybridChainError> for RpcError {
    fn from(error: HybridChainError) -> Self {
        Self::Hybrid(error)
    }
}

impl From<ConsensusError> for RpcError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<PersistenceError> for RpcError {
    fn from(error: PersistenceError) -> Self {
        Self::Persistence(error)
    }
}

/// Typed local RPC operations over chain state and optional disk persistence.
pub struct NodeRpc<'a> {
    pub engine: &'a mut ChainEngine,
    pub store: Option<&'a DiskStore>,
}

impl<'a> NodeRpc<'a> {
    pub fn new(engine: &'a mut ChainEngine, store: Option<&'a DiskStore>) -> Self {
        Self { engine, store }
    }

    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            height: self.engine.tip_header().map(|header| header.height),
            tip_hash: self.engine.tip_hash(),
            chainwork: self.engine.current_tip_work(),
            total_supply_atomic: self.engine.state.monetary.total_supply,
            miner_reward_pool_atomic: self.engine.state.monetary.miner_reward_pool,
            mempool_len: self.engine.mempool.len(),
            valid_output_count: self.engine.state.valid_outputs.len(),
        }
    }

    pub fn balance_atomic(&self, account: &str) -> u128 {
        self.engine.state.ledger.balance_of(account)
    }

    pub fn balance(&self, account: &str) -> BalanceInfo {
        let atomic_units = self.balance_atomic(account);
        BalanceInfo {
            atomic_units,
            sul: format_sul(atomic_units),
        }
    }

    pub fn submit_tx(&mut self, tx: HybridTx) -> Result<Hash256, RpcError> {
        if let HybridTx::Confidential {
            tx: confidential_tx,
            challenge,
            ..
        } = &tx
        {
            verify_confidential_tx_against_outputs(
                confidential_tx,
                &self.engine.state.spent_key_images,
                &self.engine.state.valid_outputs,
                challenge.occupancy_ppm,
            )
            .map_err(|error| {
                RpcError::Chain(ChainEngineError::Chain(HybridChainError::Privacy(error)))
            })?;
        }
        let recent = self.engine.recent_block_hashes();
        self.engine
            .mempool
            .insert_tx(tx, &recent)
            .map_err(RpcError::Chain)
    }

    pub fn mine_block<H: RandomXHasher>(
        &mut self,
        miner_id: &str,
        timestamp: u64,
        difficulty_target: Hash256,
        occupancy_ppm: u128,
        hasher: &H,
    ) -> Result<MinedBlock, RpcError> {
        self.mine_block_with_limit(
            hasher,
            miner_id,
            timestamp,
            difficulty_target,
            occupancy_ppm,
            DEFAULT_MAX_NONCE_ATTEMPTS,
        )
        .map(|(mined, _)| mined)
    }

    pub fn mine_block_with_limit<H: RandomXHasher>(
        &mut self,
        hasher: &H,
        miner_id: &str,
        timestamp: u64,
        difficulty_target: Hash256,
        occupancy_ppm: u128,
        max_nonce_attempts: u64,
    ) -> Result<(MinedBlock, HybridBlockReport), RpcError> {
        if miner_id.trim().is_empty() {
            return Err(RpcError::InvalidArgument(
                "miner ID must not be empty".into(),
            ));
        }
        if occupancy_ppm > OCCUPANCY_SCALE {
            return Err(RpcError::InvalidArgument(format!(
                "occupancy must be at most {OCCUPANCY_SCALE} ppm"
            )));
        }
        if max_nonce_attempts == 0 {
            return Err(RpcError::InvalidArgument(
                "max nonce attempts must be greater than zero".into(),
            ));
        }

        let (height, prev_block_hash) = match self.engine.tip_header() {
            Some(parent) => (
                parent
                    .height
                    .checked_add(1)
                    .ok_or_else(|| RpcError::InvalidArgument("block height overflow".into()))?,
                self.engine.tip_hash().expect("tip header has a tip hash"),
            ),
            None => (0, [0; 32]),
        };
        let reward_recipient = miner_id.to_string();
        let previous_mempool = self.engine.mempool.clone();
        let txs = self.engine.mempool.drain_for_block(MAX_BLOCK_TXS);
        let mut header = BlockHeader {
            version: 1,
            height,
            prev_block_hash,
            merkle_root: compute_block_merkle_root(&txs, &reward_recipient),
            timestamp,
            difficulty_target,
            nonce: 0,
        };

        let mut found_nonce = false;
        for _ in 0..max_nonce_attempts {
            match header.verify_pow(hasher, &self.engine.genesis_seed) {
                Ok(_) => {
                    found_nonce = true;
                    break;
                }
                Err(ConsensusError::HashAboveTarget { .. }) => {
                    let Some(next_nonce) = header.nonce.checked_add(1) else {
                        self.engine.mempool = previous_mempool;
                        return Err(RpcError::MiningFailed("nonce space exhausted".into()));
                    };
                    header.nonce = next_nonce;
                }
                Err(error) => {
                    self.engine.mempool = previous_mempool;
                    return Err(RpcError::Consensus(error));
                }
            }
        }
        if !found_nonce {
            self.engine.mempool = previous_mempool;
            return Err(RpcError::MiningFailed(
                "no valid nonce found within the attempt limit".into(),
            ));
        }

        let block = Block {
            header,
            reward_recipient,
            txs,
        };
        let block_hash = block.header.structural_digest();
        let report = match self.engine.submit_block(
            block.clone(),
            hasher,
            miner_id.to_string(),
            occupancy_ppm,
        ) {
            Ok(report) => report,
            Err(error) => {
                self.engine.mempool = previous_mempool;
                return Err(error.into());
            }
        };

        if let Some(store) = self.store {
            store.write_block(&block_hash, &block)?;
            store.save_engine_snapshot(self.engine)?;
        }

        let chainwork = self
            .engine
            .stored_block_info(&block_hash)
            .expect("successfully submitted block is stored")
            .chainwork;
        Ok((
            MinedBlock {
                hash: block_hash,
                height,
                chainwork,
                transaction_count: report.transparent_applied + report.confidential_applied,
            },
            report,
        ))
    }

    pub fn save_snapshot(&self) -> Result<(), RpcError> {
        self.store
            .ok_or(RpcError::MissingStore)?
            .save_engine_snapshot(self.engine)?;
        Ok(())
    }

    pub fn load_snapshot(&mut self) -> Result<(), RpcError> {
        *self.engine = self
            .store
            .ok_or(RpcError::MissingStore)?
            .load_engine_snapshot()?;
        Ok(())
    }

    pub fn persist_snapshot(&self) -> Result<(), RpcError> {
        if let Some(store) = self.store {
            store.save_engine_snapshot(self.engine)?;
        }
        Ok(())
    }
}

/// Runs a CLI command against an initialized node, primarily for tests and embedding.
pub fn run_cli_args<H: RandomXHasher>(
    args: &[String],
    rpc: &mut NodeRpc<'_>,
    hasher: &H,
) -> Result<String, RpcError> {
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| RpcError::InvalidArgument(usage()))?;
    let options = parse_options(&args[1..])?;

    match command {
        "status" => {
            reject_unknown_options(&options, &[])?;
            let status = rpc.status();
            Ok(format!(
                "height={}\ntip_hash={}\nchainwork={}\ntotal_supply_atomic={}\nminer_reward_pool_atomic={}\nmempool_size={}\nvalid_outputs={}",
                status.height.map_or_else(|| "none".into(), |height| height.to_string()),
                status.tip_hash.map_or_else(|| "none".into(), |hash| hex_hash(&hash)),
                status.chainwork,
                status.total_supply_atomic,
                status.miner_reward_pool_atomic,
                status.mempool_len,
                status.valid_output_count
            ))
        }
        "balance" => {
            reject_unknown_options(&options, &["account"])?;
            let account = required_option(&options, "account")?;
            let balance = rpc.balance(account);
            Ok(format!(
                "account={account}\nbalance_sul={}\nbalance_atomic={}",
                balance.sul, balance.atomic_units
            ))
        }
        "send" => {
            reject_unknown_options(&options, &["from", "to", "amount-sul", "occupancy-ppm"])?;
            let from = required_option(&options, "from")?.to_string();
            let to = required_option(&options, "to")?.to_string();
            let amount_atomic = parse_sul_amount(required_option(&options, "amount-sul")?)?;
            let occupancy_ppm = optional_u128(&options, "occupancy-ppm", DEFAULT_OCCUPANCY_PPM)?;
            if occupancy_ppm > OCCUPANCY_SCALE {
                return Err(RpcError::InvalidArgument(format!(
                    "occupancy must be at most {OCCUPANCY_SCALE} ppm"
                )));
            }
            let challenge = AntiSpamChallenge {
                prev_block_hash: rpc.engine.tip_hash().unwrap_or([0; 32]),
                tx_digest: transparent_tx_digest(&from, &to, amount_atomic),
                amount_atomic,
                occupancy_ppm,
            };
            let tx = HybridTx::Transparent {
                tx: TransferTx {
                    from,
                    to,
                    amount_atomic,
                },
                nonce: solve_micro_pow(&challenge),
                challenge,
            };
            let digest = rpc.submit_tx(tx)?;
            rpc.persist_snapshot()?;
            Ok(format!("transaction={}", hex_hash(&digest)))
        }
        "mine" => {
            reject_unknown_options(
                &options,
                &[
                    "miner",
                    "occupancy-ppm",
                    "target",
                    "timestamp",
                    "max-nonce-attempts",
                ],
            )?;
            let miner = required_option(&options, "miner")?;
            let occupancy_ppm = optional_u128(&options, "occupancy-ppm", DEFAULT_OCCUPANCY_PPM)?;
            let target = match options.get("target") {
                Some(value) => parse_hash(value)?,
                None => rpc
                    .engine
                    .expected_next_difficulty_target()
                    .map_err(RpcError::Chain)?,
            };
            let timestamp = options
                .get("timestamp")
                .map(|value| {
                    value.parse::<u64>().map_err(|error| {
                        RpcError::InvalidArgument(format!("invalid timestamp: {error}"))
                    })
                })
                .transpose()?;
            let timestamp = match timestamp {
                Some(timestamp) => timestamp,
                None => unix_timestamp()?,
            };
            let mined = if let Some(max_attempts) = options.get("max-nonce-attempts") {
                let max_attempts = max_attempts.parse::<u64>().map_err(|error| {
                    RpcError::InvalidArgument(format!("invalid max nonce attempts: {error}"))
                })?;
                rpc.mine_block_with_limit(
                    hasher,
                    miner,
                    timestamp,
                    target,
                    occupancy_ppm,
                    max_attempts,
                )?
                .0
            } else {
                rpc.mine_block(miner, timestamp, target, occupancy_ppm, hasher)?
            };
            Ok(format!(
                "height={}\nhash={}\nchainwork={}\ntransactions={}",
                mined.height,
                hex_hash(&mined.hash),
                mined.chainwork,
                mined.transaction_count
            ))
        }
        "snapshot" => {
            reject_unknown_options(&options, &[])?;
            rpc.save_snapshot()?;
            Ok("snapshot_saved=true".into())
        }
        _ => Err(RpcError::InvalidArgument(usage())),
    }
}

/// Loads local state or initializes a development chain, then executes one CLI command.
pub fn run_node_cli(args: &[String]) -> Result<String, RpcError> {
    if args == ["help"] || args == ["--help"] {
        return Ok(usage());
    }
    let (command_args, data_directory) = take_data_directory(args)?;
    let store = DiskStore::new(data_directory)?;
    let mut engine = match store.load_engine_snapshot() {
        Ok(engine) => engine,
        Err(PersistenceError::MissingFile(_)) => ChainEngine::new(
            DEFAULT_GENESIS_SEED,
            DEFAULT_INITIAL_SUPPLY_SUL,
            DEFAULT_INITIAL_EMISSION_BPS,
        ),
        Err(error) => return Err(RpcError::Persistence(error)),
    };
    let hasher = RealRandomXHasher::new(&engine.genesis_seed).map_err(RpcError::Hasher)?;
    let mut rpc = NodeRpc::new(&mut engine, Some(&store));
    run_cli_args(&command_args, &mut rpc, &hasher)
}

fn parse_options(args: &[String]) -> Result<HashMap<String, String>, RpcError> {
    if args.len() % 2 != 0 {
        return Err(RpcError::InvalidArgument(
            "options must be supplied as --name value pairs".into(),
        ));
    }
    let mut options = HashMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0].strip_prefix("--").ok_or_else(|| {
            RpcError::InvalidArgument(format!("expected option, got {}", pair[0]))
        })?;
        if name.is_empty() || options.insert(name.to_string(), pair[1].clone()).is_some() {
            return Err(RpcError::InvalidArgument(format!(
                "empty or duplicate option: --{name}"
            )));
        }
    }
    Ok(options)
}

fn reject_unknown_options(
    options: &HashMap<String, String>,
    allowed: &[&str],
) -> Result<(), RpcError> {
    if let Some(name) = options
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(RpcError::InvalidArgument(format!(
            "unknown option: --{name}"
        )));
    }
    Ok(())
}

fn required_option<'a>(
    options: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, RpcError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| RpcError::InvalidArgument(format!("missing required option --{name}")))
}

fn optional_u128(
    options: &HashMap<String, String>,
    name: &str,
    default: u128,
) -> Result<u128, RpcError> {
    options
        .get(name)
        .map(|value| {
            value.parse().map_err(|error| {
                RpcError::InvalidArgument(format!("invalid --{name} value: {error}"))
            })
        })
        .unwrap_or(Ok(default))
}

fn parse_sul_amount(value: &str) -> Result<u128, RpcError> {
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.map_or(false, |digits| {
            digits.is_empty()
                || digits.len() > 8
                || !digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(RpcError::InvalidArgument(
            "amount must be a non-negative SUL decimal with at most 8 fractional digits".into(),
        ));
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|error| RpcError::InvalidArgument(format!("invalid SUL amount: {error}")))?;
    let fractional = fraction
        .map(|digits| {
            format!("{digits:0<8}").parse::<u128>().map_err(|error| {
                RpcError::InvalidArgument(format!("invalid fractional amount: {error}"))
            })
        })
        .transpose()?
        .unwrap_or(0);
    whole
        .checked_mul(ATOMIC_UNITS_PER_SUL)
        .and_then(|amount| amount.checked_add(fractional))
        .filter(|amount| *amount > 0)
        .ok_or_else(|| RpcError::InvalidArgument("amount is zero or overflows".into()))
}

fn parse_hash(value: &str) -> Result<Hash256, RpcError> {
    if value.len() != 64 {
        return Err(RpcError::InvalidArgument(
            "target must contain exactly 64 hexadecimal characters".into(),
        ));
    }
    let mut hash = [0; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| RpcError::InvalidArgument(format!("invalid target hex: {error}")))?;
    }
    Ok(hash)
}

fn take_data_directory(args: &[String]) -> Result<(Vec<String>, PathBuf), RpcError> {
    let mut command_args = Vec::with_capacity(args.len());
    let mut data_directory = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--data-dir" {
            if data_directory.is_some() || index + 1 >= args.len() {
                return Err(RpcError::InvalidArgument(
                    "--data-dir must be supplied once with a path".into(),
                ));
            }
            data_directory = Some(PathBuf::from(&args[index + 1]));
            index += 2;
        } else {
            command_args.push(args[index].clone());
            index += 1;
        }
    }
    Ok((
        command_args,
        data_directory.unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIRECTORY)),
    ))
}

fn transparent_tx_digest(from: &str, to: &str, amount_atomic: u128) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"SUL_TRANSPARENT_TX_REQUEST_V1");
    hasher.update(&(from.len() as u64).to_le_bytes());
    hasher.update(from.as_bytes());
    hasher.update(&(to.len() as u64).to_le_bytes());
    hasher.update(to.as_bytes());
    hasher.update(&amount_atomic.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn format_sul(atomic_units: u128) -> String {
    format!(
        "{}.{:08}",
        atomic_units / ATOMIC_UNITS_PER_SUL,
        atomic_units % ATOMIC_UNITS_PER_SUL
    )
}

fn hex_hash(hash: &Hash256) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_timestamp() -> Result<u64, RpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| RpcError::InvalidArgument(format!("system clock error: {error}")))
}

fn usage() -> String {
    "usage: sul-node <status|balance|send|mine|snapshot> [options] [--data-dir PATH]".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow_randomx::{MockRandomXHasher, MAX_DIFFICULTY_TARGET};

    fn sample_tx(occupancy_ppm: u128) -> HybridTx {
        let transfer = TransferTx {
            from: "alice".into(),
            to: "bob".into(),
            amount_atomic: ATOMIC_UNITS_PER_SUL,
        };
        let challenge = AntiSpamChallenge {
            prev_block_hash: [0; 32],
            tx_digest: transparent_tx_digest(&transfer.from, &transfer.to, transfer.amount_atomic),
            amount_atomic: transfer.amount_atomic,
            occupancy_ppm,
        };
        HybridTx::Transparent {
            tx: transfer,
            nonce: solve_micro_pow(&challenge),
            challenge,
        }
    }

    #[test]
    fn status_balance_and_cli_commands_report_typed_state() {
        let mut engine = ChainEngine::new([0xA1; 32], 1_000, 125);
        engine
            .state
            .ledger
            .set_balance("alice", ATOMIC_UNITS_PER_SUL * 7);
        let mut rpc = NodeRpc::new(&mut engine, None);
        let hasher = MockRandomXHasher;

        let status = rpc.status();
        assert_eq!(status.height, None);
        assert_eq!(status.mempool_len, 0);
        assert_eq!(rpc.balance("alice").sul, "7.00000000");

        let output = run_cli_args(&["status".into()], &mut rpc, &hasher).unwrap();
        assert!(output.contains("height=none"));
        let output = run_cli_args(
            &["balance".into(), "--account".into(), "alice".into()],
            &mut rpc,
            &hasher,
        )
        .unwrap();
        assert!(output.contains("balance_atomic=700000000"));
        let output = run_cli_args(
            &[
                "send".into(),
                "--from".into(),
                "alice".into(),
                "--to".into(),
                "bob".into(),
                "--amount-sul".into(),
                "0.1".into(),
            ],
            &mut rpc,
            &hasher,
        )
        .unwrap();
        assert!(output.starts_with("transaction="));
        assert_eq!(rpc.status().mempool_len, 1);
    }

    #[test]
    fn submits_and_mines_a_pending_transaction() {
        let mut engine = ChainEngine::new([0xA2; 32], 1_000, 125);
        engine
            .state
            .ledger
            .set_balance("alice", 5 * ATOMIC_UNITS_PER_SUL);
        engine
            .state
            .ledger
            .set_balance("bob", 5 * ATOMIC_UNITS_PER_SUL);
        let mut rpc = NodeRpc::new(&mut engine, None);
        let hasher = MockRandomXHasher;

        rpc.submit_tx(sample_tx(DEFAULT_OCCUPANCY_PPM)).unwrap();
        assert_eq!(rpc.status().mempool_len, 1);
        let mined = rpc
            .mine_block(
                "miner_1",
                1_700_000_000,
                MAX_DIFFICULTY_TARGET,
                DEFAULT_OCCUPANCY_PPM,
                &hasher,
            )
            .unwrap();

        assert_eq!(mined.height, 0);
        assert_eq!(mined.transaction_count, 1);
        assert_eq!(rpc.status().mempool_len, 0);
        assert!(rpc.balance_atomic("alice") < 5 * ATOMIC_UNITS_PER_SUL);
        assert!(rpc.balance_atomic("bob") > 5 * ATOMIC_UNITS_PER_SUL);

        let output = run_cli_args(
            &[
                "mine".into(),
                "--miner".into(),
                "miner_2".into(),
                "--timestamp".into(),
                "1700000120".into(),
            ],
            &mut rpc,
            &hasher,
        )
        .unwrap();
        assert!(output.contains("height=1"));
    }

    #[test]
    fn failed_mining_restores_drained_mempool_transactions() {
        let mut engine = ChainEngine::new([0xA4; 32], 1_000, 125);
        engine
            .state
            .ledger
            .set_balance("alice", 5 * ATOMIC_UNITS_PER_SUL);
        engine
            .state
            .ledger
            .set_balance("bob", 5 * ATOMIC_UNITS_PER_SUL);
        let mut rpc = NodeRpc::new(&mut engine, None);
        let hasher = MockRandomXHasher;
        rpc.submit_tx(sample_tx(DEFAULT_OCCUPANCY_PPM)).unwrap();

        let result = rpc.mine_block_with_limit(
            &hasher,
            "miner_1",
            1_700_000_000,
            [0; 32],
            DEFAULT_OCCUPANCY_PPM,
            1,
        );
        assert!(matches!(result, Err(RpcError::MiningFailed(_))));
        assert_eq!(rpc.status().mempool_len, 1);
        assert_eq!(rpc.status().height, None);
    }

    #[test]
    fn snapshot_roundtrip_preserves_chain_and_mempool() {
        let directory =
            std::env::temp_dir().join(format!("sul_rpc_snapshot_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let store = DiskStore::new(&directory).unwrap();
        let mut engine = ChainEngine::new([0xA3; 32], 1_000, 125);
        {
            let mut rpc = NodeRpc::new(&mut engine, Some(&store));
            rpc.submit_tx(sample_tx(DEFAULT_OCCUPANCY_PPM)).unwrap();
            rpc.save_snapshot().unwrap();
        }

        let mut restored_engine = ChainEngine::new([0; 32], 0, 0);
        let mut restored = NodeRpc::new(&mut restored_engine, Some(&store));
        restored.load_snapshot().unwrap();
        assert_eq!(restored.engine.genesis_seed, [0xA3; 32]);
        assert_eq!(restored.status().mempool_len, 1);
        drop(restored);
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn parses_exact_sul_amounts_and_rejects_excess_precision() {
        assert_eq!(parse_sul_amount("12.345").unwrap(), 1_234_500_000);
        assert!(parse_sul_amount("1.000000001").is_err());
    }
}
