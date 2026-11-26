use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::chain_engine::{Block, ChainEngine};
use crate::pow_randomx::Hash256;

const SNAPSHOT_FILE: &str = "state_snapshot.bin";
const BLOCKS_DIRECTORY: &str = "blocks";
const FILE_MAGIC: &[u8; 8] = b"SULPERS1";
const BLOCK_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_SCHEMA_VERSION: u32 = 2;
const HEADER_SIZE: usize = FILE_MAGIC.len() + 4 + 8;
const CHECKSUM_SIZE: usize = 32;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum PersistenceError {
    Io(io::Error),
    Serialization(String),
    UnsupportedVersion(u32),
    InvalidFile,
    BlockHashMismatch { expected: Hash256, actual: Hash256 },
    CorruptedChecksum { expected: Hash256, actual: Hash256 },
    MissingFile(PathBuf),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Serialization(message) => write!(formatter, "serialization error: {message}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported persistence version: {version}")
            }
            Self::InvalidFile => write!(formatter, "invalid or truncated persistence file"),
            Self::BlockHashMismatch { expected, actual } => write!(
                formatter,
                "block hash mismatch: requested {}, decoded {}",
                hex_hash(expected),
                hex_hash(actual)
            ),
            Self::CorruptedChecksum { .. } => write!(formatter, "BLAKE3 checksum mismatch"),
            Self::MissingFile(path) => write!(formatter, "missing file: {}", path.display()),
        }
    }
}

impl std::error::Error for PersistenceError {}

#[derive(Debug, Clone)]
pub struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(BLOCKS_DIRECTORY)).map_err(PersistenceError::Io)?;
        Ok(Self { root })
    }

    pub fn write_block(&self, hash: &Hash256, block: &Block) -> Result<(), PersistenceError> {
        let actual = block.header.structural_digest();
        if actual != *hash {
            return Err(PersistenceError::BlockHashMismatch {
                expected: *hash,
                actual,
            });
        }
        let payload = bincode::serialize(block)
            .map_err(|error| PersistenceError::Serialization(error.to_string()))?;
        self.write_framed(&self.block_path(hash), &payload, BLOCK_SCHEMA_VERSION)
    }

    pub fn read_block(&self, hash: &Hash256) -> Result<Block, PersistenceError> {
        let path = self.block_path(hash);
        let payload = self.read_framed(&path, BLOCK_SCHEMA_VERSION)?;
        let block: Block = bincode::deserialize(&payload)
            .map_err(|error| PersistenceError::Serialization(error.to_string()))?;
        let actual = block.header.structural_digest();
        if actual != *hash {
            return Err(PersistenceError::BlockHashMismatch {
                expected: *hash,
                actual,
            });
        }
        Ok(block)
    }

    pub fn save_engine_snapshot(&self, engine: &ChainEngine) -> Result<(), PersistenceError> {
        let payload = bincode::serialize(engine)
            .map_err(|error| PersistenceError::Serialization(error.to_string()))?;
        self.write_framed(
            &self.root.join(SNAPSHOT_FILE),
            &payload,
            SNAPSHOT_SCHEMA_VERSION,
        )
    }

    pub fn load_engine_snapshot(&self) -> Result<ChainEngine, PersistenceError> {
        let path = self.root.join(SNAPSHOT_FILE);
        let payload = self.read_framed(&path, SNAPSHOT_SCHEMA_VERSION)?;
        bincode::deserialize(&payload)
            .map_err(|error| PersistenceError::Serialization(error.to_string()))
    }

    fn block_path(&self, hash: &Hash256) -> PathBuf {
        self.root
            .join(BLOCKS_DIRECTORY)
            .join(format!("{}.bin", hex_hash(hash)))
    }

    fn write_framed(
        &self,
        path: &Path,
        payload: &[u8],
        version: u32,
    ) -> Result<(), PersistenceError> {
        let len = u64::try_from(payload.len()).map_err(|_| PersistenceError::InvalidFile)?;
        let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len() + CHECKSUM_SIZE);
        frame.extend_from_slice(FILE_MAGIC);
        frame.extend_from_slice(&version.to_le_bytes());
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(payload);
        let checksum = blake3::hash(&frame);
        frame.extend_from_slice(checksum.as_bytes());

        let parent = path.parent().ok_or(PersistenceError::InvalidFile)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(PersistenceError::InvalidFile)?;
        let (temp_path, mut file) = loop {
            let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_path = parent.join(format!(
                ".{file_name}.{}.{}.tmp",
                std::process::id(),
                sequence
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(PersistenceError::Io(error)),
            }
        };

        let write_result = file.write_all(&frame).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(PersistenceError::Io(error));
        }
        if let Err(error) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(PersistenceError::Io(error));
        }
        Ok(())
    }

    fn read_framed(&self, path: &Path, expected_version: u32) -> Result<Vec<u8>, PersistenceError> {
        let frame = fs::read(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                PersistenceError::MissingFile(path.to_path_buf())
            } else {
                PersistenceError::Io(error)
            }
        })?;

        if frame.len() < HEADER_SIZE + CHECKSUM_SIZE || &frame[..8] != FILE_MAGIC {
            return Err(PersistenceError::InvalidFile);
        }
        let version = u32::from_le_bytes(frame[8..12].try_into().expect("fixed version size"));
        if version != expected_version {
            return Err(PersistenceError::UnsupportedVersion(version));
        }
        let payload_len = u64::from_le_bytes(frame[12..20].try_into().expect("fixed length size"));
        let payload_len =
            usize::try_from(payload_len).map_err(|_| PersistenceError::InvalidFile)?;
        let expected_len = HEADER_SIZE
            .checked_add(payload_len)
            .and_then(|length| length.checked_add(CHECKSUM_SIZE))
            .ok_or(PersistenceError::InvalidFile)?;
        if frame.len() != expected_len {
            return Err(PersistenceError::InvalidFile);
        }

        let checksum_start = HEADER_SIZE + payload_len;
        let expected: Hash256 = frame[checksum_start..]
            .try_into()
            .expect("fixed checksum size");
        let actual = *blake3::hash(&frame[..checksum_start]).as_bytes();
        if expected != actual {
            return Err(PersistenceError::CorruptedChecksum { expected, actual });
        }
        Ok(frame[HEADER_SIZE..checksum_start].to_vec())
    }
}

fn hex_hash(hash: &Hash256) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_engine::ChainEngine;

    fn temp_dir(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("sul_persist_test_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn snapshot_roundtrip_and_corruption_detection() {
        let dir = temp_dir("roundtrip");
        let store = DiskStore::new(&dir).unwrap();
        let mut engine = ChainEngine::new([0xAA; 32], 1_000, 125);
        let output_pub = [0xAB; 32];
        let commitment = crate::privacy::PedersenCommitment::zero();
        engine.state.valid_outputs.insert(output_pub, commitment);
        store.save_engine_snapshot(&engine).unwrap();
        let updated_output_pub = [0xAC; 32];
        let updated_commitment = crate::privacy::PedersenCommitment::commit(7, 11);
        engine
            .state
            .valid_outputs
            .insert(updated_output_pub, updated_commitment);
        store.save_engine_snapshot(&engine).unwrap();

        let restored = store.load_engine_snapshot().unwrap();
        assert_eq!(restored.genesis_seed, engine.genesis_seed);
        assert_eq!(restored.initial_supply_sul, engine.initial_supply_sul);
        assert_eq!(
            restored.state.valid_outputs.commitment(&output_pub),
            Some(&commitment)
        );
        assert_eq!(
            restored.state.valid_outputs.commitment(&updated_output_pub),
            Some(&updated_commitment)
        );

        let snapshot = dir.join(SNAPSHOT_FILE);
        let mut bytes = fs::read(&snapshot).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(snapshot, bytes).unwrap();
        assert!(matches!(
            store.load_engine_snapshot(),
            Err(PersistenceError::CorruptedChecksum { .. })
        ));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_snapshot_is_reported() {
        let dir = temp_dir("missing");
        let store = DiskStore::new(&dir).unwrap();
        assert!(matches!(
            store.load_engine_snapshot(),
            Err(PersistenceError::MissingFile(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }
}
