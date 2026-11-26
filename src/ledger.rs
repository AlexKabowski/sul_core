use std::collections::HashMap;

use crate::monetary::{BlockSummary, MonetaryState};

pub type AccountId = String;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransferTx {
    pub from: AccountId,
    pub to: AccountId,
    pub amount_atomic: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    AccountNotFound(AccountId),
    InsufficientBalance {
        account: AccountId,
        required: u128,
        available: u128,
    },
    ZeroAmount,
    SameAccount(AccountId),
    ArithmeticOverflow,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountNotFound(account) => write!(f, "account not found: {account}"),
            Self::InsufficientBalance {
                account,
                required,
                available,
            } => write!(
                f,
                "insufficient balance in {account}: required {required}, available {available}"
            ),
            Self::ZeroAmount => write!(f, "amount must be greater than zero"),
            Self::SameAccount(account) => {
                write!(f, "source and destination accounts are the same: {account}")
            }
            Self::ArithmeticOverflow => write!(f, "arithmetic overflow"),
        }
    }
}

impl std::error::Error for LedgerError {}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ledger {
    pub balances: HashMap<AccountId, u128>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            balances: HashMap::new(),
        }
    }

    /// Creates or updates an account balance.
    pub fn set_balance(&mut self, account: impl Into<String>, balance_atomic: u128) {
        self.balances.insert(account.into(), balance_atomic);
    }

    pub fn balance_of(&self, account: &str) -> u128 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    /// Sums the balances of all accounts.
    pub fn total_account_supply(&self) -> Result<u128, LedgerError> {
        self.balances.values().try_fold(0u128, |acc, &bal| {
            acc.checked_add(bal).ok_or(LedgerError::ArithmeticOverflow)
        })
    }

    /// Applies a transfer and debits the sender's discount.
    pub fn apply_transfer(
        &mut self,
        tx: &TransferTx,
        discount_atomic: u128,
    ) -> Result<(), LedgerError> {
        if tx.amount_atomic == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if tx.from == tx.to {
            return Err(LedgerError::SameAccount(tx.from.clone()));
        }

        let total_debit = tx
            .amount_atomic
            .checked_add(discount_atomic)
            .ok_or(LedgerError::ArithmeticOverflow)?;

        let sender_bal = self
            .balances
            .get(&tx.from)
            .copied()
            .ok_or_else(|| LedgerError::AccountNotFound(tx.from.clone()))?;

        if sender_bal < total_debit {
            return Err(LedgerError::InsufficientBalance {
                account: tx.from.clone(),
                required: total_debit,
                available: sender_bal,
            });
        }

        let receiver_bal = self
            .balances
            .get(&tx.to)
            .copied()
            .ok_or_else(|| LedgerError::AccountNotFound(tx.to.clone()))?;
        let new_sender_bal = sender_bal
            .checked_sub(total_debit)
            .ok_or(LedgerError::ArithmeticOverflow)?;
        let new_receiver_bal = receiver_bal
            .checked_add(tx.amount_atomic)
            .ok_or(LedgerError::ArithmeticOverflow)?;

        self.balances.insert(tx.from.clone(), new_sender_bal);
        self.balances.insert(tx.to.clone(), new_receiver_bal);

        Ok(())
    }

    /// Applies the block atomically and credits the miner with emission and pool rewards.
    pub fn apply_block(
        &mut self,
        state: &mut MonetaryState,
        txs: &[TransferTx],
        miner_id: impl Into<String>,
        occupancy_ppm: u128,
    ) -> Result<BlockSummary, LedgerError> {
        let miner = miner_id.into();
        let ledger_snapshot = self.balances.clone();
        let state_snapshot = state.clone();

        if !self.balances.contains_key(&miner) {
            self.balances.insert(miner.clone(), 0);
        }

        let mut amounts_atomic = Vec::with_capacity(txs.len());

        for tx in txs {
            let discount = MonetaryState::calculate_tx_discount(tx.amount_atomic, occupancy_ppm);
            if let Err(err) = self.apply_transfer(tx, discount) {
                self.balances = ledger_snapshot;
                *state = state_snapshot;
                return Err(err);
            }
            amounts_atomic.push(tx.amount_atomic);
        }

        let summary = match state.process_block(&amounts_atomic, occupancy_ppm) {
            Ok(summary) => summary,
            Err(crate::monetary::MonetaryError::ArithmeticOverflow) => {
                self.balances = ledger_snapshot;
                *state = state_snapshot;
                return Err(LedgerError::ArithmeticOverflow);
            }
        };

        let miner_bal = self.balance_of(&miner);
        match miner_bal.checked_add(summary.total_miner_reward) {
            Some(new_miner_bal) => {
                self.balances.insert(miner, new_miner_bal);
            }
            None => {
                self.balances = ledger_snapshot;
                *state = state_snapshot;
                return Err(LedgerError::ArithmeticOverflow);
            }
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::ATOMIC_UNITS_PER_SUL;

    #[test]
    fn transfer_applies_discount_and_credits_miner_reward() {
        let mut state = MonetaryState::new(1_000, 200);
        let mut ledger = Ledger::new();
        ledger.set_balance("alice", 500 * ATOMIC_UNITS_PER_SUL);
        ledger.set_balance("bob", 500 * ATOMIC_UNITS_PER_SUL);

        let amount = 100 * ATOMIC_UNITS_PER_SUL;
        let expected_discount = MonetaryState::calculate_tx_discount(amount, 500_000);
        let txs = vec![TransferTx {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_atomic: amount,
        }];

        let summary = ledger
            .apply_block(&mut state, &txs, "miner_1", 500_000)
            .expect("block should be valid");

        assert_eq!(
            ledger.balance_of("alice"),
            500 * ATOMIC_UNITS_PER_SUL - amount - expected_discount
        );
        assert_eq!(
            ledger.balance_of("bob"),
            500 * ATOMIC_UNITS_PER_SUL + amount
        );
        assert_eq!(ledger.balance_of("miner_1"), summary.total_miner_reward);
        assert_eq!(
            ledger.total_account_supply().unwrap(),
            1_000 * ATOMIC_UNITS_PER_SUL + summary.block_emission - summary.burned_in_block
                + summary.pool_payout_to_miner
        );
    }

    #[test]
    fn insufficient_balance_rolls_back_block_changes() {
        let mut state = MonetaryState::new(1_000, 200);
        let mut ledger = Ledger::new();
        ledger.set_balance("alice", 10 * ATOMIC_UNITS_PER_SUL);
        ledger.set_balance("bob", 0);

        let txs = vec![TransferTx {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_atomic: 50 * ATOMIC_UNITS_PER_SUL,
        }];

        let err = ledger
            .apply_block(&mut state, &txs, "miner_1", 200_000)
            .unwrap_err();

        assert!(matches!(err, LedgerError::InsufficientBalance { .. }));
        assert_eq!(ledger.balance_of("alice"), 10 * ATOMIC_UNITS_PER_SUL);
        assert_eq!(ledger.balance_of("bob"), 0);
        assert_eq!(state.block_height, 0);
    }

    #[test]
    fn transfer_receiver_overflow_is_atomic() {
        let mut ledger = Ledger::new();
        ledger.set_balance("alice", 10);
        ledger.set_balance("bob", u128::MAX);

        let tx = TransferTx {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_atomic: 1,
        };

        assert!(matches!(
            ledger.apply_transfer(&tx, 0),
            Err(LedgerError::ArithmeticOverflow)
        ));
        assert_eq!(ledger.balance_of("alice"), 10);
        assert_eq!(ledger.balance_of("bob"), u128::MAX);
    }

    #[test]
    fn monetary_overflow_rolls_back_block_balances_and_state() {
        let mut state = MonetaryState::new(1_000, 200);
        state.total_supply = u128::MAX;
        let original_state = state.clone();
        let mut ledger = Ledger::new();
        ledger.set_balance("alice", 100 * ATOMIC_UNITS_PER_SUL);
        ledger.set_balance("bob", 0);

        let txs = [TransferTx {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_atomic: ATOMIC_UNITS_PER_SUL,
        }];

        assert_eq!(
            ledger.apply_block(&mut state, &txs, "miner", 0),
            Err(LedgerError::ArithmeticOverflow)
        );
        assert_eq!(ledger.balance_of("alice"), 100 * ATOMIC_UNITS_PER_SUL);
        assert_eq!(ledger.balance_of("bob"), 0);
        assert_eq!(ledger.balance_of("miner"), 0);
        assert_eq!(state, original_state);
    }
}
