/// One SUL equals 100 million atomic units (8 decimal places).
pub const ATOMIC_UNITS_PER_SUL: u128 = 100_000_000;

/// Target interval between blocks, in seconds.
pub const BLOCK_TIME_SECONDS: u64 = 120;

/// Number of blocks between RandomX seed epochs.
pub const RANDOMX_SEED_EPOCH_BLOCKS: u64 = 2_048;

/// Retarget window: 60 blocks, or 2 hours with 120-second blocks.
pub const DIFFICULTY_RETARGET_WINDOW_BLOCKS: u64 = 60;

/// Maximum increase and decrease limits for difficulty in each window.
pub const MAX_TARGET_ADJUST_NUM: u128 = 2;
pub const MAX_TARGET_ADJUST_DEN: u128 = 1;
pub const MIN_TARGET_ADJUST_NUM: u128 = 1;
pub const MIN_TARGET_ADJUST_DEN: u128 = 2;

/// Maximum accepted forward timestamp drift.
pub const MAX_FUTURE_TIMESTAMP_DRIFT_SECONDS: u64 = 15 * 60;

/// Maximum number of recent blocks accepted as anti-spam anchors.
pub const ANTI_SPAM_ANCHOR_WINDOW_BLOCKS: u64 = 6;
pub const MEDIAN_TIME_PAST_BLOCKS: usize = 11;
pub const MAX_SYNC_BLOCKS_PER_MESSAGE: usize = 64;
pub const MAX_SYNC_BLOCKS_PER_SESSION: usize = 4_096;
pub const MAX_SYNC_ITERATIONS_PER_SESSION: usize = 64;

/// Monetary calendar: 30-day months and a 360-day year.
pub const DAYS_PER_MONTH: u64 = 30;
pub const MONTHS_PER_QUARTER: u64 = 3;
pub const MONTHS_PER_YEAR: u64 = 12;

/// Block quantities derived from the target interval and calendar.
pub const BLOCKS_PER_DAY: u64 = (24 * 60 * 60) / BLOCK_TIME_SECONDS;
pub const BLOCKS_PER_MONTH: u64 = BLOCKS_PER_DAY * DAYS_PER_MONTH;
pub const BLOCKS_PER_QUARTER: u64 = BLOCKS_PER_MONTH * MONTHS_PER_QUARTER;
pub const BLOCKS_PER_YEAR: u64 = BLOCKS_PER_MONTH * MONTHS_PER_YEAR;

/// Miner reward smoothing window, in blocks.
pub const REWARD_SMOOTHING_WINDOW: u128 = 144;

/// Maximum discount per transaction: 0.25 SUL.
pub const MAX_TX_DISCOUNT_ATOMIC: u128 = ATOMIC_UNITS_PER_SUL / 4;

/// Discount-rate limits in basis points (1 basis point = 0.01%).
/// 0.05% is 5 basis points; 0.25% is 25.
pub const MIN_DISCOUNT_BPS: u128 = 5;
pub const MAX_DISCOUNT_BPS: u128 = 25;
pub const BPS_SCALE: u128 = 10_000;

/// Gross annual emission limits: 0.5% (50 basis points) to 2% (200 basis points).
pub const MIN_ANNUAL_EMISSION_BPS: u128 = 50;
pub const MAX_ANNUAL_EMISSION_BPS: u128 = 200;

/// Quarterly deflation allowance: 0.125% of the initial supply.
pub const QUARTERLY_DEFLATION_ALLOWANCE_NUM: u128 = 125;
pub const QUARTERLY_DEFLATION_ALLOWANCE_DEN: u128 = 100_000;

const _: () = {
    assert!(BLOCKS_PER_DAY == 720);
    assert!(BLOCKS_PER_MONTH == 21_600);
    assert!(BLOCKS_PER_QUARTER == 64_800);
    assert!(BLOCKS_PER_YEAR == 259_200);
    assert!(BLOCKS_PER_YEAR == BLOCKS_PER_QUARTER * 4);
    assert!(MAX_TX_DISCOUNT_ATOMIC == 25_000_000);
    assert!(
        MAX_SYNC_BLOCKS_PER_SESSION
            == MAX_SYNC_ITERATIONS_PER_SESSION * MAX_SYNC_BLOCKS_PER_MESSAGE
    );
    assert!(MIN_DISCOUNT_BPS <= MAX_DISCOUNT_BPS);
    assert!(MIN_ANNUAL_EMISSION_BPS <= MAX_ANNUAL_EMISSION_BPS);
    // 125/100,000 equals one quarter of 50 basis points (0.125%).
    assert!(
        QUARTERLY_DEFLATION_ALLOWANCE_NUM * BPS_SCALE * 4
            == MIN_ANNUAL_EMISSION_BPS * QUARTERLY_DEFLATION_ALLOWANCE_DEN
    );
};
