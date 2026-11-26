use crate::params::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MonetaryState {
    pub block_height: u64,
    pub total_supply: u128,         // Current circulating supply
    pub quarter_start_supply: u128, // Supply at the start of the quarter
    pub quarter_burned: u128,       // Amount burned this quarter
    pub quarter_discounts: u128,    // Discounts collected this quarter
    pub quarter_burn_budget: u128,  // Maximum burn allowed this quarter
    pub annual_emission_bps: u128,  // Annual gross emission rate
    pub miner_reward_pool: u128,    // Pending miner rewards
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonetaryError {
    ArithmeticOverflow,
}

impl std::fmt::Display for MonetaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow"),
        }
    }
}

impl std::error::Error for MonetaryError {}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct BlockSummary {
    pub height: u64,
    pub block_emission: u128,
    pub total_tx_discounts: u128,
    pub burned_in_block: u128,
    pub excess_to_pool: u128,
    pub pool_payout_to_miner: u128,
    pub total_miner_reward: u128,
    pub new_supply: u128,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct DaySummary {
    pub day: u64,
    pub emitted: u128,
    pub discounts: u128,
    pub burned: u128,
    pub pool_paid: u128,
    pub supply: u128,
}

impl MonetaryState {
    /// Creates the initial state from the supply in SUL.
    pub fn new(initial_supply_sul: u128, initial_emission_bps: u128) -> Self {
        let initial_atomic = initial_supply_sul.saturating_mul(ATOMIC_UNITS_PER_SUL);
        let emission_bps = clamp_emission_bps(initial_emission_bps);

        let mut state = Self {
            block_height: 0,
            total_supply: initial_atomic,
            quarter_start_supply: initial_atomic,
            quarter_burned: 0,
            quarter_discounts: 0,
            quarter_burn_budget: 0,
            annual_emission_bps: emission_bps,
            miner_reward_pool: 0,
        };
        state.set_quarter_burn_budget(false);
        state
    }

    /// Sets the quarterly burn limit and resets the accumulators.
    /// In a heated market, adds the quarterly emission to a 0.125% allowance;
    /// otherwise, it uses half of the quarterly emission.
    pub fn set_quarter_burn_budget(&mut self, allow_deflation: bool) {
        let emission_bps = clamp_emission_bps(self.annual_emission_bps);
        self.annual_emission_bps = emission_bps;

        let quarterly_emission = mul_div(self.quarter_start_supply, emission_bps, BPS_SCALE * 4);

        self.quarter_burn_budget = if allow_deflation {
            let deflation_allowance = mul_div(
                self.quarter_start_supply,
                QUARTERLY_DEFLATION_ALLOWANCE_NUM,
                QUARTERLY_DEFLATION_ALLOWANCE_DEN,
            );
            quarterly_emission.saturating_add(deflation_allowance)
        } else {
            quarterly_emission / 2
        };

        self.quarter_burned = 0;
        self.quarter_discounts = 0;
    }

    /// Updates the counter-cyclical policy at quarter end by comparing discounts and emission.
    pub fn apply_counter_cyclical_policy(&mut self) {
        let emission_bps = clamp_emission_bps(self.annual_emission_bps);
        let quarterly_emission = mul_div(self.quarter_start_supply, emission_bps, BPS_SCALE * 4);

        let is_heated = self.quarter_discounts >= quarterly_emission;
        let is_retracted = self.quarter_discounts < (quarterly_emission / 2);

        if is_heated {
            self.annual_emission_bps = emission_bps.saturating_sub(25).max(MIN_ANNUAL_EMISSION_BPS);
        } else if is_retracted {
            self.annual_emission_bps = emission_bps.saturating_add(25).min(MAX_ANNUAL_EMISSION_BPS);
        }

        self.quarter_start_supply = self.total_supply;
        self.set_quarter_burn_budget(is_heated);
    }

    /// Calculates the occupancy-adjusted discount rate, expressed in parts per million.
    pub fn current_discount_bps(occupancy_ppm: u128) -> u128 {
        let occupancy = occupancy_ppm.min(OCCUPANCY_SCALE);
        let range = MAX_DISCOUNT_BPS - MIN_DISCOUNT_BPS;
        let delta = (range * occupancy + OCCUPANCY_SCALE / 2) / OCCUPANCY_SCALE;
        MIN_DISCOUNT_BPS + delta
    }

    /// Calculates the transaction discount, capped at 0.25 SUL.
    pub fn calculate_tx_discount(amount_atomic: u128, occupancy_ppm: u128) -> u128 {
        let bps = Self::current_discount_bps(occupancy_ppm);
        let raw_discount = mul_div(amount_atomic, bps, BPS_SCALE);
        raw_discount.min(MAX_TX_DISCOUNT_ATOMIC)
    }

    /// Processes a block atomically and returns an error on accounting overflow.
    pub fn process_block(
        &mut self,
        tx_amounts_atomic: &[u128],
        occupancy_ppm: u128,
    ) -> Result<BlockSummary, MonetaryError> {
        self.process_block_with_discounts(tx_amounts_atomic, 0, occupancy_ppm)
    }

    pub fn process_block_with_discounts(
        &mut self,
        tx_amounts_atomic: &[u128],
        explicit_discounts_atomic: u128,
        occupancy_ppm: u128,
    ) -> Result<BlockSummary, MonetaryError> {
        let mut next = self.clone();
        let summary =
            next.process_block_inner(tx_amounts_atomic, explicit_discounts_atomic, occupancy_ppm)?;
        *self = next;
        Ok(summary)
    }

    fn process_block_inner(
        &mut self,
        tx_amounts_atomic: &[u128],
        explicit_discounts_atomic: u128,
        occupancy_ppm: u128,
    ) -> Result<BlockSummary, MonetaryError> {
        if self.block_height > 0 && self.block_height.is_multiple_of(BLOCKS_PER_QUARTER) {
            self.apply_counter_cyclical_policy();
        }

        let emission_bps = clamp_emission_bps(self.annual_emission_bps);
        let block_emission = mul_div(
            self.total_supply,
            emission_bps,
            BPS_SCALE * (BLOCKS_PER_YEAR as u128),
        );

        let transparent_discounts = tx_amounts_atomic
            .iter()
            .try_fold(0u128, |acc, &amt| {
                acc.checked_add(Self::calculate_tx_discount(amt, occupancy_ppm))
            })
            .ok_or(MonetaryError::ArithmeticOverflow)?;
        let total_tx_discounts = transparent_discounts
            .checked_add(explicit_discounts_atomic)
            .ok_or(MonetaryError::ArithmeticOverflow)?;

        let quarter_discounts = self
            .quarter_discounts
            .checked_add(total_tx_discounts)
            .ok_or(MonetaryError::ArithmeticOverflow)?;

        let remaining_burn_budget = self.quarter_burn_budget.saturating_sub(self.quarter_burned);
        let burned_in_block = total_tx_discounts.min(remaining_burn_budget);
        let quarter_burned = self
            .quarter_burned
            .checked_add(burned_in_block)
            .ok_or(MonetaryError::ArithmeticOverflow)?;

        let excess_to_pool = total_tx_discounts - burned_in_block;
        let miner_reward_pool = self
            .miner_reward_pool
            .checked_add(excess_to_pool)
            .ok_or(MonetaryError::ArithmeticOverflow)?;

        let pool_payout_to_miner = miner_reward_pool / REWARD_SMOOTHING_WINDOW;
        let remaining_pool = miner_reward_pool - pool_payout_to_miner;

        let total_supply = self
            .total_supply
            .checked_add(block_emission)
            .and_then(|supply| supply.checked_sub(burned_in_block))
            .ok_or(MonetaryError::ArithmeticOverflow)?;
        let block_height = self
            .block_height
            .checked_add(1)
            .ok_or(MonetaryError::ArithmeticOverflow)?;
        let total_miner_reward = block_emission
            .checked_add(pool_payout_to_miner)
            .ok_or(MonetaryError::ArithmeticOverflow)?;

        self.quarter_discounts = quarter_discounts;
        self.quarter_burned = quarter_burned;
        self.miner_reward_pool = remaining_pool;
        self.total_supply = total_supply;
        self.block_height = block_height;

        Ok(BlockSummary {
            height: self.block_height,
            block_emission,
            total_tx_discounts,
            burned_in_block,
            excess_to_pool,
            pool_payout_to_miner,
            total_miner_reward,
            new_supply: self.total_supply,
        })
    }

    /// Processes a day composed of 720 blocks.
    #[allow(dead_code)]
    pub fn process_day(
        &mut self,
        tx_amounts_atomic: &[u128],
        occupancy_ppm: u128,
    ) -> Result<DaySummary, MonetaryError> {
        let mut emitted = 0u128;
        let mut discounts = 0u128;
        let mut burned = 0u128;
        let mut pool_paid = 0u128;

        for block_in_day in 0..BLOCKS_PER_DAY {
            let txs = if block_in_day == 0 {
                tx_amounts_atomic
            } else {
                &[]
            };
            let summary = self.process_block(txs, occupancy_ppm)?;
            emitted = emitted
                .checked_add(summary.block_emission)
                .ok_or(MonetaryError::ArithmeticOverflow)?;
            discounts = discounts
                .checked_add(summary.total_tx_discounts)
                .ok_or(MonetaryError::ArithmeticOverflow)?;
            burned = burned
                .checked_add(summary.burned_in_block)
                .ok_or(MonetaryError::ArithmeticOverflow)?;
            pool_paid = pool_paid
                .checked_add(summary.pool_payout_to_miner)
                .ok_or(MonetaryError::ArithmeticOverflow)?;
        }

        Ok(DaySummary {
            day: self.block_height / BLOCKS_PER_DAY,
            emitted,
            discounts,
            burned,
            pool_paid,
            supply: self.total_supply,
        })
    }
}

pub const OCCUPANCY_SCALE: u128 = 1_000_000;

fn clamp_emission_bps(emission_bps: u128) -> u128 {
    emission_bps.clamp(MIN_ANNUAL_EMISSION_BPS, MAX_ANNUAL_EMISSION_BPS)
}

/// Calculates floor(`value * numer / denom`), returning `u128::MAX` on overflow.
fn mul_div(value: u128, numer: u128, denom: u128) -> u128 {
    if denom == 0 {
        return 0;
    }
    let mut reduced_value = value;
    let mut reduced_numer = numer;
    let mut reduced_denom = denom;

    let gcd_vd = gcd(reduced_value, reduced_denom);
    reduced_value /= gcd_vd;
    reduced_denom /= gcd_vd;

    let gcd_nd = gcd(reduced_numer, reduced_denom);
    reduced_numer /= gcd_nd;
    reduced_denom /= gcd_nd;

    if let Some(product) = reduced_value.checked_mul(reduced_numer) {
        return product / reduced_denom;
    }

    u128::MAX
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    if b == 0 {
        return a.max(1);
    }
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_confidential_discount_enters_all_monetary_accounts() {
        let mut state = MonetaryState::new(1_000, 125);
        let explicit_discount = ATOMIC_UNITS_PER_SUL;
        let summary = state
            .process_block_with_discounts(&[], explicit_discount, OCCUPANCY_SCALE / 2)
            .expect("explicit discount block should apply");

        assert_eq!(summary.total_tx_discounts, explicit_discount);
        assert_eq!(summary.burned_in_block, explicit_discount);
        assert_eq!(summary.excess_to_pool, 0);
        assert_eq!(state.quarter_discounts, explicit_discount);
        assert_eq!(state.quarter_burned, explicit_discount);
    }

    #[test]
    fn emission_rate_is_clamped_to_the_corridor() {
        assert_eq!(
            MonetaryState::new(1_000, 0).annual_emission_bps,
            MIN_ANNUAL_EMISSION_BPS
        );
        assert_eq!(
            MonetaryState::new(1_000, 10_000).annual_emission_bps,
            MAX_ANNUAL_EMISSION_BPS
        );
    }

    #[test]
    fn discount_tracks_occupancy_and_respects_the_cap() {
        assert_eq!(MonetaryState::current_discount_bps(0), MIN_DISCOUNT_BPS);
        assert_eq!(
            MonetaryState::current_discount_bps(OCCUPANCY_SCALE),
            MAX_DISCOUNT_BPS
        );
        assert_eq!(
            MonetaryState::current_discount_bps(OCCUPANCY_SCALE + 1),
            MAX_DISCOUNT_BPS
        );

        let capped =
            MonetaryState::calculate_tx_discount(500 * ATOMIC_UNITS_PER_SUL, OCCUPANCY_SCALE);
        assert_eq!(capped, MAX_TX_DISCOUNT_ATOMIC);
    }

    #[test]
    fn retraction_quarter_increases_emission_and_heat_decreases_emission() {
        let mut state = MonetaryState::new(1_000, 125);
        for _ in 0..BLOCKS_PER_QUARTER {
            state.process_block(&[], OCCUPANCY_SCALE / 10).unwrap();
        }
        state.process_block(&[], OCCUPANCY_SCALE / 10).unwrap();
        assert_eq!(state.annual_emission_bps, 150);

        let mut heated = MonetaryState::new(1_000, 125);
        let txs = [500 * ATOMIC_UNITS_PER_SUL; 4];
        for _ in 0..BLOCKS_PER_QUARTER {
            heated
                .process_block(&txs, OCCUPANCY_SCALE * 9 / 10)
                .unwrap();
        }
        heated
            .process_block(&txs, OCCUPANCY_SCALE * 9 / 10)
            .unwrap();
        assert_eq!(heated.annual_emission_bps, 100);
    }

    #[test]
    fn quarter_rolls_over_and_resets_accumulators() {
        let mut state = MonetaryState::new(1_000, 200);
        for _ in 0..BLOCKS_PER_QUARTER {
            state
                .process_block(&[100 * ATOMIC_UNITS_PER_SUL], OCCUPANCY_SCALE / 2)
                .unwrap();
        }
        assert!(state.quarter_discounts > 0);
        assert!(state.quarter_burned > 0);

        state.process_block(&[], OCCUPANCY_SCALE / 2).unwrap();
        assert_eq!(state.quarter_discounts, 0);
        assert_eq!(state.quarter_burned, 0);
        assert!(state.quarter_burn_budget > 0);
    }

    #[test]
    fn process_day_returns_consistent_totals() {
        let mut state = MonetaryState::new(1_000, 125);
        let amount = 100 * ATOMIC_UNITS_PER_SUL;

        let summary = state.process_day(&[amount], OCCUPANCY_SCALE / 2).unwrap();

        assert_eq!(summary.day, 1);
        assert!(summary.emitted > 0);
        assert_eq!(summary.supply, state.total_supply);
        assert!(summary.discounts > 0);
        assert!(summary.burned > 0);
    }

    #[test]
    fn block_overflow_fails_without_mutating_monetary_state() {
        let mut state = MonetaryState::new(1_000, 125);
        state.total_supply = u128::MAX;
        let original = state.clone();

        assert_eq!(
            state.process_block(&[], 0),
            Err(MonetaryError::ArithmeticOverflow)
        );
        assert_eq!(state, original);
    }

    #[test]
    fn explicit_and_implicit_discounts_are_added_to_the_quarter_total() {
        let mut state = MonetaryState::new(1_000, 125);
        let implicit = 40 * ATOMIC_UNITS_PER_SUL;
        let explicit = 7 * ATOMIC_UNITS_PER_SUL;

        let summary = state
            .process_block_with_discounts(&[implicit], explicit, OCCUPANCY_SCALE / 2)
            .unwrap();

        assert_eq!(
            summary.total_tx_discounts,
            MonetaryState::calculate_tx_discount(implicit, OCCUPANCY_SCALE / 2) + explicit
        );
        assert_eq!(state.quarter_discounts, summary.total_tx_discounts);
    }
}
