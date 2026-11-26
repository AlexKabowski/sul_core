mod antispam;
mod block_pipeline;
mod chain_engine;
mod chain_state;
mod ledger;
mod monetary;
mod p2p;
mod params;
mod persistence;
mod pow_randomx;
mod privacy;
mod rpc_cli;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use monetary::{BlockSummary, MonetaryState, OCCUPANCY_SCALE};
use params::*;

const POPULATION: u32 = 1_000_000;
const INITIAL_SUPPLY_SUL: u128 = 100_000;
const INITIAL_EMISSION_BPS: u128 = 125;
const SIMULATION_MONTHS: u64 = 18;
const RETRACTION_TX_PER_DAY: u64 = 1_000;
const HEATING_TX_PER_DAY: u64 = 30_000;
const MIN_RETRACTION_TX_AMOUNT: u128 = ATOMIC_UNITS_PER_SUL / 1_000;
const MAX_RETRACTION_TX_AMOUNT: u128 = ATOMIC_UNITS_PER_SUL / 100;
const MIN_HEATING_TX_AMOUNT: u128 = ATOMIC_UNITS_PER_SUL * 75 / 1_000;
const MAX_HEATING_TX_AMOUNT: u128 = ATOMIC_UNITS_PER_SUL * 99 / 1_000;
const RNG_SEED: u64 = 0x5355_4C5F_434F_5245;

struct FastLedger {
    balances: Vec<u128>,
    miner_id: u32,
}

#[derive(Debug)]
enum SimulationError {
    InvalidAccount(u32),
    ArithmeticOverflow,
    NoSpendableAccount,
    SupplyMismatch {
        ledger_and_pool: u128,
        monetary_state: u128,
    },
}

impl fmt::Display for SimulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccount(id) => write!(formatter, "Invalid account ID: {id}"),
            Self::ArithmeticOverflow => write!(formatter, "arithmetic overflow in simulation"),
            Self::NoSpendableAccount => {
                write!(formatter, "no account has sufficient balance to transact")
            }
            Self::SupplyMismatch {
                ledger_and_pool,
                monetary_state,
            } => write!(
                formatter,
                "inconsistent supply: ledger + pool = {ledger_and_pool}, monetary state = {monetary_state}"
            ),
        }
    }
}

impl Error for SimulationError {}

impl FastLedger {
    fn new(population: u32) -> Self {
        Self {
            balances: vec![0; population as usize + 1],
            miner_id: population,
        }
    }

    fn initialize_population(&mut self, total_supply: u128, population: u32) {
        let account_count = population as u128;
        let base_balance = total_supply / account_count;
        let remainder = total_supply % account_count;

        for id in 0..population {
            self.balances[id as usize] = base_balance + u128::from((id as u128) < remainder);
        }
    }

    fn balance_of(&self, id: u32) -> Result<u128, SimulationError> {
        self.balances
            .get(id as usize)
            .copied()
            .ok_or(SimulationError::InvalidAccount(id))
    }

    fn total_supply(&self) -> Result<u128, SimulationError> {
        self.balances.iter().try_fold(0u128, |total, balance| {
            total
                .checked_add(*balance)
                .ok_or(SimulationError::ArithmeticOverflow)
        })
    }

    fn rollback(&mut self, previous_balances: HashMap<usize, u128>) {
        for (index, balance) in previous_balances {
            self.balances[index] = balance;
        }
    }

    fn apply_block(
        &mut self,
        state: &mut MonetaryState,
        txs: &[(u32, u32, u128)],
        occupancy_ppm: u128,
    ) -> Result<(BlockSummary, usize), SimulationError> {
        let mut previous_balances = HashMap::with_capacity(txs.len().saturating_mul(2) + 1);
        let mut valid_amounts = Vec::with_capacity(txs.len());
        let mut applied_count = 0;

        for &(from, to, amount) in txs {
            if from == to || amount == 0 {
                continue;
            }

            let sender_index = from as usize;
            let receiver_index = to as usize;
            if sender_index >= self.balances.len() {
                self.rollback(previous_balances);
                return Err(SimulationError::InvalidAccount(from));
            }
            if receiver_index >= self.balances.len() {
                self.rollback(previous_balances);
                return Err(SimulationError::InvalidAccount(to));
            }

            let discount = MonetaryState::calculate_tx_discount(amount, occupancy_ppm);
            let Some(total_debit) = amount.checked_add(discount) else {
                self.rollback(previous_balances);
                return Err(SimulationError::ArithmeticOverflow);
            };
            let sender_balance = self.balances[sender_index];
            if sender_balance < total_debit {
                continue;
            }

            let receiver_balance = self.balances[receiver_index];
            let Some(updated_receiver) = receiver_balance.checked_add(amount) else {
                self.rollback(previous_balances);
                return Err(SimulationError::ArithmeticOverflow);
            };
            let updated_sender = sender_balance - total_debit;

            previous_balances
                .entry(sender_index)
                .or_insert(sender_balance);
            previous_balances
                .entry(receiver_index)
                .or_insert(receiver_balance);
            self.balances[sender_index] = updated_sender;
            self.balances[receiver_index] = updated_receiver;
            valid_amounts.push(amount);
            applied_count += 1;
        }

        let state_snapshot = state.clone();
        let summary = match state.process_block(&valid_amounts, occupancy_ppm) {
            Ok(summary) => summary,
            Err(monetary::MonetaryError::ArithmeticOverflow) => {
                self.rollback(previous_balances);
                *state = state_snapshot;
                return Err(SimulationError::ArithmeticOverflow);
            }
        };
        let miner_index = self.miner_id as usize;
        let miner_balance = self.balances[miner_index];
        let Some(updated_miner) = miner_balance.checked_add(summary.total_miner_reward) else {
            self.rollback(previous_balances);
            *state = state_snapshot;
            return Err(SimulationError::ArithmeticOverflow);
        };

        self.balances[miner_index] = updated_miner;
        Ok((summary, applied_count))
    }
}

fn next_u64(rng: &mut u64) -> u64 {
    *rng = rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut value = *rng;
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn generate_transactions(
    rng: &mut u64,
    count: usize,
    population: u32,
    ledger: &FastLedger,
    occupancy_ppm: u128,
    min_amount: u128,
    max_amount: u128,
) -> Result<Vec<(u32, u32, u128)>, SimulationError> {
    let mut txs = Vec::with_capacity(count);
    let mut projected_balances = HashMap::with_capacity(count.saturating_mul(2));
    let amount_range = max_amount - min_amount + 1;

    for _ in 0..count {
        let mut selected = None;
        for _ in 0..1_000 {
            let amount = min_amount + u128::from(next_u64(rng)) % amount_range;
            let discount = MonetaryState::calculate_tx_discount(amount, occupancy_ppm);
            let total_debit = amount
                .checked_add(discount)
                .ok_or(SimulationError::ArithmeticOverflow)?;
            let from = (next_u64(rng) % population as u64) as u32;
            let sender_balance = projected_balances
                .get(&from)
                .copied()
                .unwrap_or(ledger.balances[from as usize]);
            if sender_balance < total_debit {
                continue;
            }

            let mut to = (next_u64(rng) % population as u64) as u32;
            while to == from {
                to = (next_u64(rng) % population as u64) as u32;
            }
            let receiver_balance = projected_balances
                .get(&to)
                .copied()
                .unwrap_or(ledger.balances[to as usize]);
            let updated_receiver = receiver_balance
                .checked_add(amount)
                .ok_or(SimulationError::ArithmeticOverflow)?;

            projected_balances.insert(from, sender_balance - total_debit);
            projected_balances.insert(to, updated_receiver);
            selected = Some((from, to, amount));
            break;
        }
        txs.push(selected.ok_or(SimulationError::NoSpendableAccount)?);
    }

    Ok(txs)
}

fn verify_supply(ledger: &FastLedger, state: &MonetaryState) -> Result<(), SimulationError> {
    let ledger_and_pool = ledger
        .total_supply()?
        .checked_add(state.miner_reward_pool)
        .ok_or(SimulationError::ArithmeticOverflow)?;

    if ledger_and_pool != state.total_supply {
        return Err(SimulationError::SupplyMismatch {
            ledger_and_pool,
            monetary_state: state.total_supply,
        });
    }

    Ok(())
}

fn format_sul(atomic: u128) -> String {
    format!(
        "{}.{:08}",
        atomic / ATOMIC_UNITS_PER_SUL,
        atomic % ATOMIC_UNITS_PER_SUL
    )
}

fn run_simulation() -> Result<(), SimulationError> {
    let total_supply = INITIAL_SUPPLY_SUL
        .checked_mul(ATOMIC_UNITS_PER_SUL)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    let blocks_to_simulate = BLOCKS_PER_MONTH
        .checked_mul(SIMULATION_MONTHS)
        .ok_or(SimulationError::ArithmeticOverflow)?;
    let retraction_blocks = BLOCKS_PER_QUARTER;

    let mut state = MonetaryState::new(INITIAL_SUPPLY_SUL, INITIAL_EMISSION_BPS);
    let mut ledger = FastLedger::new(POPULATION);
    ledger.initialize_population(total_supply, POPULATION);

    let mut rng = RNG_SEED;
    let mut tx_day_accumulator = 0u64;
    let mut total_transactions = 0u64;
    let mut total_pool_paid = 0u128;

    println!("SUL simulation: {POPULATION} users, {SIMULATION_MONTHS} months, seed {RNG_SEED:#x}");
    println!(
        "Phases: 3 months of retraction ({RETRACTION_TX_PER_DAY} tx/day, occupancy 0.15), 15 months of heating ({HEATING_TX_PER_DAY} tx/day, occupancy 0.85)"
    );
    println!(
        "Average amounts: retraction {} SUL, heating {} SUL",
        format_sul((MIN_RETRACTION_TX_AMOUNT + MAX_RETRACTION_TX_AMOUNT) / 2),
        format_sul((MIN_HEATING_TX_AMOUNT + MAX_HEATING_TX_AMOUNT) / 2)
    );
    println!("Initial supply: {} SUL\n", format_sul(state.total_supply));

    for block in 0..blocks_to_simulate {
        let is_retraction = block < retraction_blocks;
        if block == 0 || block == retraction_blocks {
            tx_day_accumulator = 0;
        }

        let daily_target = if is_retraction {
            RETRACTION_TX_PER_DAY
        } else {
            HEATING_TX_PER_DAY
        };
        let occupancy_ppm = if is_retraction {
            OCCUPANCY_SCALE * 15 / 100
        } else {
            OCCUPANCY_SCALE * 85 / 100
        };

        tx_day_accumulator += daily_target;
        let tx_count = tx_day_accumulator / BLOCKS_PER_DAY;
        tx_day_accumulator %= BLOCKS_PER_DAY;

        let (min_amount, max_amount) = if is_retraction {
            (MIN_RETRACTION_TX_AMOUNT, MAX_RETRACTION_TX_AMOUNT)
        } else {
            (MIN_HEATING_TX_AMOUNT, MAX_HEATING_TX_AMOUNT)
        };
        let txs = generate_transactions(
            &mut rng,
            tx_count as usize,
            POPULATION,
            &ledger,
            occupancy_ppm,
            min_amount,
            max_amount,
        )?;
        let (summary, applied_count) = ledger.apply_block(&mut state, &txs, occupancy_ppm)?;
        total_transactions = total_transactions
            .checked_add(applied_count as u64)
            .ok_or(SimulationError::ArithmeticOverflow)?;
        total_pool_paid = total_pool_paid
            .checked_add(summary.pool_payout_to_miner)
            .ok_or(SimulationError::ArithmeticOverflow)?;

        let quarter_finished = (block + 1).is_multiple_of(BLOCKS_PER_QUARTER);
        if quarter_finished {
            let quarterly_emission = state
                .quarter_start_supply
                .checked_mul(state.annual_emission_bps)
                .ok_or(SimulationError::ArithmeticOverflow)?
                / (BPS_SCALE * 4);
            println!(
                "Quarter {}: discounts {}, emission reference {}, heated {}, burn {}/{}, rate {} bps, supply {}",
                (block + 1) / BLOCKS_PER_QUARTER,
                format_sul(state.quarter_discounts),
                format_sul(quarterly_emission),
                state.quarter_discounts >= quarterly_emission,
                format_sul(state.quarter_burned),
                format_sul(state.quarter_burn_budget),
                state.annual_emission_bps,
                format_sul(state.total_supply)
            );
        }

        let phase_finished = block + 1 == retraction_blocks;
        let simulation_finished = block + 1 == blocks_to_simulate;
        if phase_finished || simulation_finished {
            verify_supply(&ledger, &state)?;
            let phase = if is_retraction {
                "Retraction"
            } else {
                "Heating"
            };
            println!(
                "End of {phase} phase: supply {}, accounts {}, miner {}, applied transactions {}, emission {} bps",
                format_sul(state.total_supply),
                format_sul(ledger.total_supply()?),
                format_sul(ledger.balance_of(ledger.miner_id)?),
                total_transactions,
                state.annual_emission_bps
            );
        }
    }

    println!("\nFinal summary:");
    println!("Applied transactions: {total_transactions}");
    println!("Pool payouts: {} SUL", format_sul(total_pool_paid));
    println!("Monetary supply: {} SUL", format_sul(state.total_supply));
    println!(
        "Total account balance: {} SUL",
        format_sul(ledger.total_supply()?)
    );
    println!("Pending pool: {} SUL", format_sul(state.miner_reward_pool));

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        match rpc_cli::run_node_cli(&args) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("Node command failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Err(error) = run_simulation() {
        eprintln!("Simulation failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_test_antispam_pow_and_ledger_parity() {
        use crate::antispam::{solve_micro_pow, verify_micro_pow, AntiSpamChallenge};
        use crate::pow_randomx::{BlockHeader, MockRandomXHasher};

        let occupancy_ppm = OCCUPANCY_SCALE / 2;
        let amount = 10 * ATOMIC_UNITS_PER_SUL;

        let challenge = AntiSpamChallenge {
            prev_block_hash: [0u8; 32],
            tx_digest: [0xDEu8; 32],
            amount_atomic: amount,
            occupancy_ppm,
        };
        let nonce = solve_micro_pow(&challenge);
        assert!(verify_micro_pow(&challenge, nonce).is_ok());

        let genesis_seed = [0x11u8; 32];
        let hasher = MockRandomXHasher;
        let mut target = [0xFFu8; 32];
        target[0] = 0x1F;
        let mut header = BlockHeader {
            version: 1,
            height: 1,
            prev_block_hash: [0u8; 32],
            merkle_root: [0x22u8; 32],
            timestamp: 1_700_000_120,
            difficulty_target: target,
            nonce: 0,
        };
        while header.verify_pow(&hasher, &genesis_seed).is_err() {
            header.nonce += 1;
        }

        let initial_supply_sul = 1_000;
        let mut ledger = FastLedger::new(10);
        ledger.initialize_population(initial_supply_sul * ATOMIC_UNITS_PER_SUL, 10);
        let mut state = MonetaryState::new(initial_supply_sul, INITIAL_EMISSION_BPS);

        let (_, applied) = ledger
            .apply_block(&mut state, &[(0, 1, amount)], occupancy_ppm)
            .expect("block should apply");
        assert_eq!(applied, 1);
        assert!(verify_supply(&ledger, &state).is_ok());
    }

    #[test]
    fn generated_heating_transactions_are_affordable_and_applied() {
        let population = 1_000;
        let initial_supply_sul = 100;
        let mut ledger = FastLedger::new(population);
        ledger.initialize_population(initial_supply_sul * ATOMIC_UNITS_PER_SUL, population);
        let mut state = MonetaryState::new(initial_supply_sul, INITIAL_EMISSION_BPS);
        let mut rng = RNG_SEED;
        let txs = generate_transactions(
            &mut rng,
            40,
            population,
            &ledger,
            OCCUPANCY_SCALE * 85 / 100,
            MIN_HEATING_TX_AMOUNT,
            MAX_HEATING_TX_AMOUNT,
        )
        .expect("should generate funded transactions");

        assert!(txs.iter().all(
            |(_, _, amount)| (MIN_HEATING_TX_AMOUNT..=MAX_HEATING_TX_AMOUNT).contains(amount)
        ));

        let (_, applied_count) = ledger
            .apply_block(&mut state, &txs, OCCUPANCY_SCALE * 85 / 100)
            .expect("block should apply all generated transactions");
        assert_eq!(applied_count, txs.len());
    }

    #[test]
    fn fast_and_general_ledgers_match_for_valid_transactions() {
        use crate::ledger::{Ledger, TransferTx};

        let population = 2;
        let account_balance = 100 * ATOMIC_UNITS_PER_SUL;
        let mut fast = FastLedger::new(population);
        fast.initialize_population(account_balance * u128::from(population), population);

        let mut general = Ledger::new();
        general.set_balance("account_0", account_balance);
        general.set_balance("account_1", account_balance);
        general.set_balance("miner", 0);

        let initial_supply_sul = account_balance * u128::from(population) / ATOMIC_UNITS_PER_SUL;
        let mut fast_state = MonetaryState::new(initial_supply_sul, INITIAL_EMISSION_BPS);
        let mut general_state = fast_state.clone();
        let txs = [(0, 1, 10 * ATOMIC_UNITS_PER_SUL)];
        let general_txs = [TransferTx {
            from: "account_0".to_string(),
            to: "account_1".to_string(),
            amount_atomic: 10 * ATOMIC_UNITS_PER_SUL,
        }];
        let occupancy_ppm = OCCUPANCY_SCALE * 85 / 100;

        let (fast_summary, _) = fast
            .apply_block(&mut fast_state, &txs, occupancy_ppm)
            .expect("fast ledger block should be valid");
        let general_summary = general
            .apply_block(&mut general_state, &general_txs, "miner", occupancy_ppm)
            .expect("general ledger block should be valid");

        assert_eq!(fast_summary, general_summary);
        assert_eq!(fast_state, general_state);
        assert_eq!(fast.balance_of(0).unwrap(), general.balance_of("account_0"));
        assert_eq!(fast.balance_of(1).unwrap(), general.balance_of("account_1"));
        assert_eq!(
            fast.balance_of(fast.miner_id).unwrap(),
            general.balance_of("miner")
        );
    }
}
