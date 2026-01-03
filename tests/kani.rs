//! Kani formal verification harnesses for percolator-prog.
//!
//! Run with: `cargo kani --tests`
//!
//! These harnesses prove security-critical properties:
//! - Matcher ABI validation rejects malformed/malicious returns
//! - Risk gate blocks risk-increasing trades when threshold active
//! - Threshold policy semantics
//!
//! Note: CPI execution is not modeled; we prove wrapper logic only.

#![cfg(kani)]

use percolator::{RiskEngine, RiskParams};

// Import real matcher_abi types from the program crate
use percolator_prog::matcher_abi::{
    MatcherReturn, validate_matcher_return, FLAG_VALID, FLAG_PARTIAL_OK, FLAG_REJECTED,
};
use percolator_prog::constants::MATCHER_ABI_VERSION;

/// Create a MatcherReturn from individual symbolic fields
fn any_matcher_return() -> MatcherReturn {
    MatcherReturn {
        abi_version: kani::any(),
        flags: kani::any(),
        exec_price_e6: kani::any(),
        exec_size: kani::any(),
        req_id: kani::any(),
        lp_account_id: kani::any(),
        oracle_price_e6: kani::any(),
        reserved: kani::any(),
    }
}

// =============================================================================
// LP Risk State (mirrors main crate's LpRiskState for verification)
// =============================================================================

/// LP risk state for O(1) delta checks
struct LpRiskState {
    sum_abs: u128,
    max_abs: u128,
}

impl LpRiskState {
    /// Compute from engine state
    fn compute(engine: &RiskEngine) -> Self {
        let mut sum_abs: u128 = 0;
        let mut max_abs: u128 = 0;
        for i in 0..engine.accounts.len() {
            if engine.is_used(i) && engine.accounts[i].is_lp() {
                let abs_pos = engine.accounts[i].position_size.unsigned_abs();
                sum_abs = sum_abs.saturating_add(abs_pos);
                max_abs = max_abs.max(abs_pos);
            }
        }
        Self { sum_abs, max_abs }
    }

    /// Current risk metric
    fn risk(&self) -> u128 {
        self.max_abs.saturating_add(self.sum_abs / 8)
    }

    /// O(1) check: would applying delta increase system risk?
    fn would_increase_risk(&self, old_lp_pos: i128, delta: i128) -> bool {
        let old_lp_abs = old_lp_pos.unsigned_abs();
        let new_lp_pos = old_lp_pos.saturating_add(delta);
        let new_lp_abs = new_lp_pos.unsigned_abs();

        // Update sum_abs in O(1)
        let new_sum_abs = self.sum_abs
            .saturating_sub(old_lp_abs)
            .saturating_add(new_lp_abs);

        // Update max_abs in O(1) (conservative)
        let new_max_abs = if new_lp_abs >= self.max_abs {
            new_lp_abs
        } else if old_lp_abs == self.max_abs && new_lp_abs < old_lp_abs {
            self.max_abs // conservative
        } else {
            self.max_abs
        };

        let old_risk = self.risk();
        let new_risk = new_max_abs.saturating_add(new_sum_abs / 8);
        new_risk > old_risk
    }
}

// =============================================================================
// Test Fixtures - using real engine APIs
// =============================================================================

/// Create RiskParams suitable for Kani proofs
fn params_for_kani() -> RiskParams {
    RiskParams {
        warmup_period_slots: 100,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1000,
        trading_fee_bps: 10,
        max_accounts: 8, // Small for Kani
        new_account_fee: 0, // So fee_payment=0 works
        risk_reduction_threshold: 0, // Off by default
        maintenance_fee_per_slot: 0,
        max_crank_staleness_slots: u64::MAX, // Disable crank freshness
        liquidation_fee_bps: 50,
        liquidation_fee_cap: u128::MAX,
        liquidation_buffer_bps: 100,
        min_liquidation_abs: 0,
    }
}

/// Create a minimal RiskEngine with one LP at given position
fn make_engine_with_lp(lp_position: i128) -> (RiskEngine, u16) {
    let params = params_for_kani();
    let mut engine = RiskEngine::new(params);

    // Use real add_lp to properly set used bitmap
    let lp_idx = engine
        .add_lp([2u8; 32], [3u8; 32], 0)
        .expect("add_lp should succeed");

    // Set position and owner
    engine.accounts[lp_idx as usize].position_size = lp_position;
    engine.accounts[lp_idx as usize].owner = [1u8; 32];

    (engine, lp_idx)
}

/// Create engine with two LPs
fn make_engine_with_two_lps(pos1: i128, pos2: i128) -> (RiskEngine, u16, u16) {
    let params = params_for_kani();
    let mut engine = RiskEngine::new(params);

    let lp_idx1 = engine.add_lp([2u8; 32], [3u8; 32], 0).expect("add_lp 1");
    let lp_idx2 = engine.add_lp([4u8; 32], [5u8; 32], 0).expect("add_lp 2");

    engine.accounts[lp_idx1 as usize].position_size = pos1;
    engine.accounts[lp_idx1 as usize].owner = [1u8; 32];
    engine.accounts[lp_idx2 as usize].position_size = pos2;
    engine.accounts[lp_idx2 as usize].owner = [6u8; 32];

    (engine, lp_idx1, lp_idx2)
}

// =============================================================================
// MATCHER ABI HARNESSES (Pure - using real validate_matcher_return)
// =============================================================================

/// Prove: wrong ABI version is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_abi_version() {
    let mut ret = any_matcher_return();

    // Force wrong ABI version
    kani::assume(ret.abi_version != MATCHER_ABI_VERSION);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong ABI version must be rejected");
}

/// Prove: missing VALID flag is always rejected
#[kani::proof]
fn kani_matcher_rejects_missing_valid_flag() {
    let mut ret = any_matcher_return();

    // Correct ABI version but missing VALID flag
    ret.abi_version = MATCHER_ABI_VERSION;
    kani::assume((ret.flags & FLAG_VALID) == 0);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "missing VALID flag must be rejected");
}

/// Prove: REJECTED flag always causes rejection
#[kani::proof]
fn kani_matcher_rejects_rejected_flag() {
    let mut ret = any_matcher_return();

    // Valid ABI, has VALID flag, but also has REJECTED flag
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags |= FLAG_VALID;
    ret.flags |= FLAG_REJECTED;

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "REJECTED flag must cause rejection");
}

/// Prove: wrong req_id is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_req_id() {
    let mut ret = any_matcher_return();

    // Make it otherwise valid
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = ret.lp_account_id; // match
    let oracle_price: u64 = ret.oracle_price_e6; // match
    let req_size: i128 = kani::any();
    kani::assume(req_size != 0);
    kani::assume(req_size != i128::MIN); // abs() overflow
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN); // abs() overflow
    kani::assume(ret.exec_size.signum() == req_size.signum());
    kani::assume(ret.exec_size.abs() <= req_size.abs());

    let req_id: u64 = kani::any();
    // Force mismatch
    kani::assume(ret.req_id != req_id);

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong req_id must be rejected");
}

/// Prove: wrong lp_account_id is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_lp_account_id() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = kani::any();
    // Force mismatch
    kani::assume(ret.lp_account_id != lp_account_id);

    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong lp_account_id must be rejected");
}

/// Prove: wrong oracle_price is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_oracle_price() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = kani::any();
    // Force mismatch
    kani::assume(ret.oracle_price_e6 != oracle_price);

    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong oracle_price must be rejected");
}

/// Prove: non-zero reserved field is always rejected
#[kani::proof]
fn kani_matcher_rejects_nonzero_reserved() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    kani::assume(ret.exec_price_e6 != 0);
    // Force non-zero reserved
    kani::assume(ret.reserved != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "non-zero reserved must be rejected");
}

/// Prove: zero exec_price is always rejected
#[kani::proof]
fn kani_matcher_rejects_zero_exec_price() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    ret.exec_price_e6 = 0; // Force zero price

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "zero exec_price must be rejected");
}

/// Prove: zero exec_size without PARTIAL_OK is rejected
#[kani::proof]
fn kani_matcher_zero_size_requires_partial_ok() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID; // No PARTIAL_OK
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.exec_size = 0; // Zero size

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "zero exec_size without PARTIAL_OK must be rejected");
}

/// Prove: exec_size exceeding req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_exec_size_exceeds_req() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN); // abs() overflow

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(req_size != i128::MIN); // abs() overflow
    // Force exec_size > req_size (absolute)
    kani::assume(ret.exec_size.abs() > req_size.abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "exec_size exceeding req_size must be rejected");
}

/// Prove: sign mismatch between exec_size and req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_sign_mismatch() {
    let mut ret = any_matcher_return();

    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);
    kani::assume(ret.exec_size != i128::MIN); // abs() overflow

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(req_size != 0);
    kani::assume(req_size != i128::MIN); // abs() overflow
    // Force sign mismatch
    kani::assume(ret.exec_size.signum() != req_size.signum());
    // But abs is ok
    kani::assume(ret.exec_size.abs() <= req_size.abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "sign mismatch must be rejected");
}

// =============================================================================
// RISK GATE HARNESSES (using real engine with proper LP allocation)
// =============================================================================

/// Prove: LpRiskState computes correct sum_abs for single LP
#[kani::proof]
fn kani_risk_state_sum_abs_single_lp() {
    let pos: i64 = kani::any(); // Use i64 to avoid overflow edge cases
    kani::assume(pos != i64::MIN); // Avoid unsigned_abs edge case

    let (engine, _lp_idx) = make_engine_with_lp(pos as i128);
    let state = LpRiskState::compute(&engine);

    let expected_abs = (pos as i128).unsigned_abs();
    assert_eq!(state.sum_abs, expected_abs, "sum_abs must equal LP abs position");
    assert_eq!(state.max_abs, expected_abs, "max_abs must equal LP abs position");
}

/// Prove: would_increase_risk returns true when absolute position grows
#[kani::proof]
fn kani_risk_gate_detects_position_growth() {
    let old_pos: i64 = kani::any();
    let delta: i64 = kani::any();

    // Avoid overflow and edge cases
    kani::assume(old_pos != i64::MIN);
    kani::assume(delta != i64::MIN);
    kani::assume((old_pos as i128).checked_add(delta as i128).is_some());

    let (engine, _lp_idx) = make_engine_with_lp(old_pos as i128);
    let state = LpRiskState::compute(&engine);

    let new_pos = (old_pos as i128).saturating_add(delta as i128);
    let old_abs = (old_pos as i128).unsigned_abs();
    let new_abs = new_pos.unsigned_abs();

    // If absolute position strictly increases, risk should increase
    if new_abs > old_abs {
        assert!(
            state.would_increase_risk(old_pos as i128, delta as i128),
            "growing absolute position must increase risk"
        );
    }
}

/// Prove: would_increase_risk returns false when position reduces toward zero
#[kani::proof]
fn kani_risk_gate_allows_position_reduction() {
    let old_pos: i64 = kani::any();

    // Non-zero starting position, avoid edge cases
    kani::assume(old_pos != 0);
    kani::assume(old_pos != i64::MIN);

    // Delta that moves toward zero (opposite sign, smaller magnitude)
    let delta: i64 = if old_pos > 0 {
        let d: i64 = kani::any();
        kani::assume(d < 0);
        kani::assume(d != i64::MIN);
        kani::assume((-d) <= old_pos); // d.abs() <= old_pos
        d
    } else {
        let d: i64 = kani::any();
        kani::assume(d > 0);
        kani::assume(d <= (-old_pos)); // d <= old_pos.abs()
        d
    };

    let (engine, _lp_idx) = make_engine_with_lp(old_pos as i128);
    let state = LpRiskState::compute(&engine);

    let new_pos = (old_pos as i128).saturating_add(delta as i128);

    // New absolute should be <= old absolute
    assert!(new_pos.unsigned_abs() <= (old_pos as i128).unsigned_abs());

    // Risk should not increase
    assert!(
        !state.would_increase_risk(old_pos as i128, delta as i128),
        "reducing position toward zero must not increase risk"
    );
}

/// Prove: sum_abs consistency - old_lp_abs is always <= sum_abs when computed from same engine
#[kani::proof]
fn kani_risk_state_sum_abs_consistency() {
    let pos: i64 = kani::any();
    kani::assume(pos != i64::MIN);

    let (engine, lp_idx) = make_engine_with_lp(pos as i128);
    let state = LpRiskState::compute(&engine);

    let old_lp_pos = engine.accounts[lp_idx as usize].position_size;
    let old_lp_abs = old_lp_pos.unsigned_abs();

    // This is the invariant we need for O(1) delta to be safe
    assert!(
        state.sum_abs >= old_lp_abs,
        "sum_abs must include old_lp_abs"
    );
}

/// Prove: with two LPs, risk tracks the max concentration correctly
#[kani::proof]
#[kani::unwind(10)] // For array iteration
fn kani_risk_state_max_concentration() {
    let pos1: i32 = kani::any(); // Use i32 for faster proofs
    let pos2: i32 = kani::any();

    let (engine, _, _) = make_engine_with_two_lps(pos1 as i128, pos2 as i128);
    let state = LpRiskState::compute(&engine);

    let abs1 = (pos1 as i128).unsigned_abs();
    let abs2 = (pos2 as i128).unsigned_abs();
    let expected_max = abs1.max(abs2);

    assert_eq!(state.max_abs, expected_max, "max_abs must be max of LP positions");
}

// =============================================================================
// THRESHOLD POLICY HARNESSES
// =============================================================================

/// Threshold gate logic (pure)
fn should_gate_trade(insurance_balance: u128, threshold: u128) -> bool {
    threshold > 0 && insurance_balance <= threshold
}

/// Prove: threshold=0 never gates
#[kani::proof]
fn kani_threshold_zero_never_gates() {
    let balance: u128 = kani::any();

    assert!(
        !should_gate_trade(balance, 0),
        "threshold=0 must never gate trades"
    );
}

/// Prove: balance > threshold never gates
#[kani::proof]
fn kani_balance_above_threshold_not_gated() {
    let threshold: u128 = kani::any();
    let balance: u128 = kani::any();

    kani::assume(balance > threshold);

    assert!(
        !should_gate_trade(balance, threshold),
        "balance above threshold must not gate"
    );
}

/// Prove: balance <= threshold with threshold > 0 always gates
#[kani::proof]
fn kani_balance_at_or_below_threshold_gates() {
    let threshold: u128 = kani::any();
    let balance: u128 = kani::any();

    kani::assume(threshold > 0);
    kani::assume(balance <= threshold);

    assert!(
        should_gate_trade(balance, threshold),
        "balance at/below positive threshold must gate"
    );
}

// =============================================================================
// RISK METRIC FORMULA HARNESSES
// =============================================================================

/// Prove: risk metric is monotonic in sum_abs
#[kani::proof]
fn kani_risk_monotonic_in_sum() {
    let max_abs: u128 = kani::any();
    let sum1: u128 = kani::any();
    let sum2: u128 = kani::any();

    kani::assume(sum2 > sum1);
    // Prevent overflow
    kani::assume(max_abs < u128::MAX / 2);
    kani::assume(sum1 < u128::MAX / 2);
    kani::assume(sum2 < u128::MAX / 2);

    let risk1 = max_abs.saturating_add(sum1 / 8);
    let risk2 = max_abs.saturating_add(sum2 / 8);

    // If sum increases, risk should not decrease
    assert!(risk2 >= risk1, "risk must be monotonic in sum_abs");
}

/// Prove: risk metric is monotonic in max_abs
#[kani::proof]
fn kani_risk_monotonic_in_max() {
    let sum_abs: u128 = kani::any();
    let max1: u128 = kani::any();
    let max2: u128 = kani::any();

    kani::assume(max2 > max1);
    // Prevent overflow
    kani::assume(sum_abs < u128::MAX / 2);
    kani::assume(max1 < u128::MAX / 2);
    kani::assume(max2 < u128::MAX / 2);

    let risk1 = max1.saturating_add(sum_abs / 8);
    let risk2 = max2.saturating_add(sum_abs / 8);

    assert!(risk2 > risk1, "risk must be strictly monotonic in max_abs");
}
