# Percolator-prog Formal Verification Audit

## Kani Proofs Summary

**Date:** 2026-01-03
**Kani Version:** 0.66.0
**Total Proofs:** 21
**Passed:** 21
**Failed:** 0
**Total Time:** ~13.2s

## Proof Results

### Matcher ABI Validation Proofs

| Harness | Status | Time |
|---------|--------|------|
| kani_matcher_rejects_wrong_abi_version | PASS | 0.110s |
| kani_matcher_rejects_missing_valid_flag | PASS | 0.107s |
| kani_matcher_rejects_rejected_flag | PASS | 0.106s |
| kani_matcher_rejects_wrong_req_id | PASS | 0.110s |
| kani_matcher_rejects_wrong_lp_account_id | PASS | 0.089s |
| kani_matcher_rejects_wrong_oracle_price | PASS | 0.088s |
| kani_matcher_rejects_nonzero_reserved | PASS | 0.091s |
| kani_matcher_rejects_zero_exec_price | PASS | 0.049s |
| kani_matcher_zero_size_requires_partial_ok | PASS | 0.052s |
| kani_matcher_rejects_exec_size_exceeds_req | PASS | 0.201s |
| kani_matcher_rejects_sign_mismatch | PASS | 0.105s |

### Risk Gate Proofs

| Harness | Status | Time |
|---------|--------|------|
| kani_risk_state_sum_abs_single_lp | PASS | 0.647s |
| kani_risk_gate_detects_position_growth | PASS | 2.923s |
| kani_risk_gate_allows_position_reduction | PASS | 2.084s |
| kani_risk_state_sum_abs_consistency | PASS | 0.641s |
| kani_risk_state_max_concentration | PASS | 0.827s |

### Threshold Policy Proofs

| Harness | Status | Time |
|---------|--------|------|
| kani_threshold_zero_never_gates | PASS | 0.011s |
| kani_balance_above_threshold_not_gated | PASS | 0.014s |
| kani_balance_at_or_below_threshold_gates | PASS | 0.013s |

### Risk Metric Formula Proofs

| Harness | Status | Time |
|---------|--------|------|
| kani_risk_monotonic_in_sum | PASS | 0.135s |
| kani_risk_monotonic_in_max | PASS | 0.246s |

## Properties Verified

### Matcher ABI Security
- Wrong ABI version is always rejected
- Missing VALID flag is always rejected
- REJECTED flag always causes rejection
- Mismatched req_id, lp_account_id, oracle_price are rejected
- Non-zero reserved field is rejected
- Zero exec_price is rejected
- Zero exec_size without PARTIAL_OK flag is rejected
- exec_size exceeding req_size is rejected
- Sign mismatch between exec_size and req_size is rejected

### Risk Gate Correctness
- LpRiskState correctly computes sum_abs and max_abs
- Risk increases when absolute LP position grows
- Risk does not increase when LP reduces position toward zero
- sum_abs consistency: old_lp_abs is always part of sum_abs
- max_abs correctly tracks maximum LP concentration

### Threshold Policy
- threshold=0 never gates any trade
- balance > threshold never gates
- balance <= threshold with threshold > 0 always gates

### Risk Metric
- Risk metric (max_abs + sum_abs/8) is monotonic in sum_abs
- Risk metric is strictly monotonic in max_abs

## Notes

- All proofs use the real `validate_matcher_return` function from `percolator_prog::matcher_abi`
- Risk gate proofs use `engine.add_lp()` to properly allocate LPs with bitmap set
- i128::MIN is excluded from abs() calls to avoid overflow (documented edge case)
- CPI execution is not modeled; proofs verify wrapper logic only
