# AUDIT: percolator-prog — Kani Formal Verification Results

<!--
  CONTEXT FOR AI/LLM READERS:
  This file documents the results of Kani formal verification harnesses for
  percolator-prog, a Solana on-chain perpetual futures protocol.
  
  Kani is a model checker for Rust that uses bounded verification to prove
  properties about code. Each "harness" is a function that asserts a property
  over symbolic (arbitrary) inputs. If Kani reports "passed", the property
  holds for ALL inputs within the specified bounds.
  
  IMPORTANT: These proofs cover the PROGRAM WRAPPER (account validation,
  CPI logic, nonce management, unit conversions). The underlying RiskEngine
  crate is NOT modeled — its behavior is assumed correct.
  
  NON-VACUITY: Vacuous proofs (trivially true assertions, identity tests,
  structural tautologies) were identified and removed in the 2026-02-06 cleanup.
  Remaining proofs have been verified as non-vacuous.
-->

## metadata

```yaml
kani_version: 0.66.0
date: 2026-02-06
total_harnesses: 143
passed: 143
failed: 0
scope: program-wrapper only (not risk engine internals)
bounded_params:
  KANI_MAX_SCALE: 64
  KANI_MAX_QUOTIENT: 4096
  price_base_bound: KANI_MAX_QUOTIENT * unit_scale
```

---

## proof-categories

### A. Matcher ABI validation (13 proofs)

These prove that the program correctly rejects invalid matcher responses. The matcher returns a 64-byte struct after CPI — every field must match the expected values.

| id | harness | property |
|----|---------|----------|
| 1 | `kani_matcher_rejects_wrong_abi_version` | wrong ABI version → reject |
| 2 | `kani_matcher_rejects_missing_valid_flag` | missing VALID flag → reject |
| 3 | `kani_matcher_rejects_rejected_flag` | REJECTED flag present → reject |
| 4 | `kani_matcher_rejects_wrong_req_id` | req_id mismatch → reject |
| 5 | `kani_matcher_rejects_wrong_lp_account_id` | lp_account_id mismatch → reject |
| 6 | `kani_matcher_rejects_wrong_oracle_price` | oracle_price mismatch → reject |
| 7 | `kani_matcher_rejects_nonzero_reserved` | nonzero reserved field → reject |
| 8 | `kani_matcher_rejects_zero_exec_price` | zero execution price → reject |
| 9 | `kani_matcher_zero_size_requires_partial_ok` | zero size without PARTIAL_OK → reject |
| 10 | `kani_matcher_rejects_exec_size_exceeds_req` | exec > requested size → reject |
| 11 | `kani_matcher_rejects_sign_mismatch` | sign(exec) != sign(req) → reject |
| 53 | `kani_matcher_zero_size_with_partial_ok_accepted` | zero size + PARTIAL_OK → accept |
| 79 | `kani_min_abs_boundary_rejected` | i128::MIN boundary → correctly handled |

### B. Matcher acceptance (3 proofs)

| id | harness | property |
|----|---------|----------|
| 80 | `kani_matcher_accepts_minimal_valid_nonzero_exec` | minimal valid inputs → accept |
| 81 | `kani_matcher_accepts_exec_size_equal_req_size` | exec == req size → accept |
| 82 | `kani_matcher_accepts_partial_fill_with_flag` | partial + PARTIAL_OK → accept |

### C. Owner/signer enforcement (2 proofs)

| id | harness | property |
|----|---------|----------|
| 12 | `kani_owner_mismatch_rejected` | owner != signer → reject |
| 13 | `kani_owner_match_accepted` | owner == signer → accept |

### D. Admin authorization (3 proofs)

| id | harness | property |
|----|---------|----------|
| 14 | `kani_admin_mismatch_rejected` | admin != signer → reject |
| 15 | `kani_admin_match_accepted` | admin == signer → accept |
| 16 | `kani_admin_burned_disables_ops` | admin == [0;32] → all ops permanently disabled |

### E. CPI identity binding (2 proofs) — CRITICAL

Proves that CPI only executes if the provided matcher program/context match the LP's registered ones.

| id | harness | property |
|----|---------|----------|
| 17 | `kani_matcher_identity_mismatch_rejected` | prog/ctx != registered → reject |
| 18 | `kani_matcher_identity_match_accepted` | prog/ctx == registered → accept |

### F. Matcher account shape validation (5 proofs)

| id | harness | property |
|----|---------|----------|
| 19 | `kani_matcher_shape_rejects_non_executable_prog` | non-executable program → reject |
| 20 | `kani_matcher_shape_rejects_executable_ctx` | executable context → reject |
| 21 | `kani_matcher_shape_rejects_wrong_ctx_owner` | context not owned by program → reject |
| 22 | `kani_matcher_shape_rejects_short_ctx` | context too small → reject |
| 23 | `kani_matcher_shape_valid_accepted` | valid shape → accept |

### G. PDA key matching (2 proofs)

| id | harness | property |
|----|---------|----------|
| 24 | `kani_pda_mismatch_rejected` | derived != provided → reject |
| 25 | `kani_pda_match_accepted` | derived == provided → accept |

### H. Nonce monotonicity (3 proofs)

| id | harness | property |
|----|---------|----------|
| 26 | `kani_nonce_unchanged_on_failure` | any failure → nonce unchanged |
| 27 | `kani_nonce_advances_on_success` | success → nonce += 1 |
| 28 | `kani_nonce_wraps_at_max` | u64::MAX → wraps to 0 |

### I. CPI uses exec_size (1 proof) — CRITICAL

| id | harness | property |
|----|---------|----------|
| 29 | `kani_cpi_uses_exec_size` | engine receives matcher's exec_size, not user's requested size |

### J. Gate activation logic (3 proofs)

Risk gate controls whether trades are allowed during low-insurance conditions.

| id | harness | property |
|----|---------|----------|
| 30 | `kani_gate_inactive_when_threshold_zero` | threshold=0 → gate off |
| 31 | `kani_gate_inactive_when_balance_exceeds` | balance > threshold → gate off |
| 32 | `kani_gate_active_when_conditions_met` | threshold>0 && balance<=threshold → gate on |

### K. Per-instruction authorization (4 proofs)

| id | harness | property |
|----|---------|----------|
| 33 | `kani_single_owner_mismatch_rejected` | owner mismatch → single-owner IX rejects |
| 34 | `kani_single_owner_match_accepted` | owner match → single-owner IX accepts |
| 35 | `kani_trade_rejects_user_mismatch` | trade: user owner mismatch → reject |
| 36 | `kani_trade_rejects_lp_mismatch` | trade: LP owner mismatch → reject |

### L. TradeCpi decision coupling (14 proofs) — CRITICAL

Full decision-tree verification for TradeCpi. Every rejection reason is tested individually and proven to reject. Every acceptance is proven to advance nonce and use exec_size.

| id | harness | property |
|----|---------|----------|
| 37 | `kani_tradecpi_rejects_non_executable_prog` | bad shape → reject |
| 38 | `kani_tradecpi_rejects_executable_ctx` | bad shape → reject |
| 39 | `kani_tradecpi_rejects_pda_mismatch` | PDA wrong → reject |
| 40 | `kani_tradecpi_rejects_user_auth_failure` | user auth fail → reject |
| 41 | `kani_tradecpi_rejects_lp_auth_failure` | LP auth fail → reject |
| 42 | `kani_tradecpi_rejects_identity_mismatch` | identity fail → reject |
| 43 | `kani_tradecpi_rejects_abi_failure` | ABI fail → reject |
| 44 | `kani_tradecpi_rejects_gate_risk_increase` | gate active + risk up → reject |
| 45 | `kani_tradecpi_allows_gate_risk_decrease` | gate active + risk down → accept |
| 46 | `kani_tradecpi_reject_nonce_unchanged` | reject → nonce unchanged |
| 47 | `kani_tradecpi_accept_increments_nonce` | accept → nonce += 1 |
| 48 | `kani_tradecpi_accept_uses_exec_size` | accept → uses exec_size |
| 54 | `kani_tradecpi_rejects_ctx_owner_mismatch` | ctx owner wrong → reject |
| 55 | `kani_tradecpi_rejects_ctx_len_short` | ctx too small → reject |

### M. TradeNoCpi decision coupling (4 proofs)

| id | harness | property |
|----|---------|----------|
| 49 | `kani_tradenocpi_rejects_user_auth_failure` | user auth fail → reject |
| 50 | `kani_tradenocpi_rejects_lp_auth_failure` | LP auth fail → reject |
| 51 | `kani_tradenocpi_rejects_gate_risk_increase` | gate + risk up → reject |
| 52 | `kani_tradenocpi_accepts_valid` | all valid → accept |

### N. Universal nonce properties (2 proofs) — CRITICAL

These use `kani::any()` for ALL decision inputs, proving nonce behavior is correct regardless of rejection reason.

| id | harness | property |
|----|---------|----------|
| 56 | `kani_tradecpi_any_reject_nonce_unchanged` | ANY rejection → nonce unchanged |
| 57 | `kani_tradecpi_any_accept_increments_nonce` | ANY acceptance → nonce += 1 |

### O-P. Account & LP PDA validation (5 proofs)

| id | harness | property |
|----|---------|----------|
| 58 | `kani_len_ok_universal` | len_ok(actual, need) == (actual >= need) for all values |
| 59-62 | `kani_lp_pda_shape_*` | LP PDA validation: non-system owner, has data, funded → reject |

### Q. Oracle key validation (2 proofs)

| id | harness | property |
|----|---------|----------|
| 63 | `kani_oracle_feed_id_match` | matching feed IDs → accept |
| 64 | `kani_oracle_feed_id_mismatch` | mismatched feed IDs → reject |

### R. Slab shape validation (2 proofs)

| id | harness | property |
|----|---------|----------|
| 65 | `kani_slab_shape_valid` | valid slab → accept |
| 66 | `kani_slab_shape_invalid` | invalid slab → reject |

### S. Simple decision functions (8 proofs)

| id | harness | property |
|----|---------|----------|
| 67-68 | `kani_decide_single_owner_*` | single-owner accept/reject |
| 69-72 | `kani_decide_crank_*` | crank auth: permissionless, self-crank, wrong owner |
| 73-74 | `kani_decide_admin_*` | admin accept/reject |

### T. ABI equivalence (1 proof) — CRITICAL

| id | harness | property |
|----|---------|----------|
| 75 | `kani_abi_ok_equals_validate` | `verify::abi_ok == validate_matcher_return.is_ok()` for ALL inputs |

### U. TradeCpi from real inputs (5 proofs) — CRITICAL

Tests the full decision path using real `MatcherReturn` struct data (not mock booleans).

| id | harness | property |
|----|---------|----------|
| 76 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | ANY rejection (real) → nonce unchanged |
| 77 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | ANY acceptance (real) → nonce += 1 |
| 78 | `kani_tradecpi_from_ret_accept_uses_exec_size` | ANY acceptance → uses exec_size |
| 121 | `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | req_id == nonce + 1 on success |
| 126 | `kani_tradecpi_from_ret_forced_acceptance` | valid inputs force Accept path |

### V. Crank panic mode authorization (6 proofs)

| id | harness | property |
|----|---------|----------|
| 83-88 | `kani_crank_panic_*` / `kani_crank_no_panic_*` | panic requires admin, permissionless accepts, wrong owner rejects |

### W. Haircut inversion (5 proofs)

| id | harness | property |
|----|---------|----------|
| 89-93 | `kani_invert_*` | zero handling, correct computation, monotonicity |

### X. Unit scale conversions (11 proofs)

| id | harness | property |
|----|---------|----------|
| 94 | `kani_base_to_units_conservation` | units + dust == base (no value loss) |
| 95 | `kani_base_to_units_dust_bound` | dust < unit_scale |
| 96 | `kani_base_to_units_scale_zero` | scale=0 → units=base, dust=0 |
| 97 | `kani_units_roundtrip` | base_to_units → units_to_base roundtrips |
| 98 | `kani_units_to_base_scale_zero` | scale=0 → base=units |
| 99 | `kani_base_to_units_monotonic` | larger base → larger units |
| 100 | `kani_units_to_base_monotonic_bounded` | larger units → larger base |
| 101 | `kani_base_to_units_monotonic_scale_zero` | monotonic at scale=0 |
| 123 | `kani_units_roundtrip_exact_when_no_dust` | perfect roundtrip when dust=0 |
| 132 | `kani_unit_conversion_deterministic` | same inputs → same outputs |
| 133 | `kani_scale_validation_pure` | scale validation is deterministic |

### Y. Withdrawal alignment (3 proofs)

| id | harness | property |
|----|---------|----------|
| 102 | `kani_withdraw_misaligned_rejects` | misaligned → reject |
| 103 | `kani_withdraw_aligned_accepts` | aligned → accept |
| 104 | `kani_withdraw_scale_zero_always_aligned` | scale=0 → always aligned |

### Z. Dust sweep (8 proofs)

| id | harness | property |
|----|---------|----------|
| 105 | `kani_sweep_dust_conservation` | swept + remaining == original |
| 106 | `kani_sweep_dust_rem_bound` | remaining bounded |
| 107 | `kani_sweep_dust_below_threshold` | swept below threshold |
| 108-112 | `kani_*_scale_zero_*` | scale=0 edge cases |

### AA. Universal rejection (6 proofs)

Prove that any single check failure causes overall rejection, regardless of other inputs.

| id | harness | property |
|----|---------|----------|
| 113-118 | `kani_universal_*_fail_rejects` | shape/PDA/user/LP/identity/ABI fail → reject |

### BB-CC. Variant consistency & gate/panic properties (5 proofs)

| id | harness | property |
|----|---------|----------|
| 119-120 | `kani_tradecpi_variants_consistent_*` | decide_trade_cpi == decide_trade_cpi_from_ret |
| 122 | `kani_universal_gate_risk_increase_rejects` | gate + risk up → reject |
| 124 | `kani_universal_panic_requires_admin` | panic → admin required |
| 125 | `kani_universal_gate_risk_increase_rejects_from_ret` | gate rejection (real inputs) |

### DD. InitMarket scale validation (5 proofs)

| id | harness | property |
|----|---------|----------|
| 127-131 | `kani_init_market_scale_*` | overflow rejected, 0 ok, MAX ok, MAX+1 rejected, valid range |

### EE-FF. scale_price_e6 properties (5 proofs)

| id | harness | property |
|----|---------|----------|
| 134-138 | `kani_scale_price_e6_*` | zero→None, valid→Some, identity for scale≤1, concrete example, consistency |

### GG. clamp_toward_with_dt rate limiting (5 proofs)

Oracle price smoothing — prevents sudden index jumps.

| id | harness | property |
|----|---------|----------|
| 139 | `kani_clamp_toward_no_movement_when_dt_zero` | dt=0 → no movement |
| 140 | `kani_clamp_toward_no_movement_when_cap_zero` | cap=0 → no movement |
| 141 | `kani_clamp_toward_bootstrap_when_index_zero` | index=0 → jump to mark |
| 142 | `kani_clamp_toward_movement_bounded_concrete` | |delta| <= cap * dt |
| 143 | `kani_clamp_toward_formula_concrete` | formula matches specification |

---

## proven-security-properties

### authorization

- owner checks cannot be bypassed (proofs 12-13, 33-36)
- admin checks cannot be bypassed (proofs 14-16, 73-74)
- burned admin (all-zeros) permanently disables all admin ops (proof 16)
- crank authorization: existing accounts require owner match, non-existent allow anyone (proofs 69-72)
- trades require both user AND LP owner signatures (proofs 35-36)

### CPI security

- matcher identity binding: CPI only if program/context match LP registration (proofs 17-18)
- matcher shape: program executable, context not executable, context owned by program (proofs 19-23)
- exec_size is used for engine call, never user's requested size (proof 29)
- identity mismatch rejects even with valid ABI (proof 42)

### state consistency

- nonce unchanged on ANY failure (proofs 26, 46, 56, 76)
- nonce advances by exactly 1 on ANY success (proofs 27, 47, 57, 77)
- nonce wraps correctly at u64::MAX (proof 28)
- req_id == nonce + 1 on success (proof 121)

### risk gate

- threshold=0 disables gate (proof 30)
- sufficient balance disables gate (proof 31)
- risk-increasing trades rejected when gate active (proofs 32, 44, 51, 122)
- risk-reducing trades allowed when gate active (proof 45)

### unit conversions

- base_to_units: units + dust == base (conservation, proof 94)
- dust < unit_scale (bounded, proof 95)
- roundtrip: units_to_base(base_to_units(x)) >= x (proof 97)
- monotonicity preserved (proofs 99-101)
- deterministic (proof 132)

---

## not-proven

These are explicitly OUT OF SCOPE for Kani verification:

- risk engine internals (LpRiskState, risk formulas, PnL math)
- Solana CPI execution mechanics (invoke_signed behavior)
- AccountInfo runtime validation (Solana runtime handles this)
- actual PDA derivation (Solana's find_program_address)
- SPL Token transfer correctness
- arbitrary u64 inputs beyond bounded ranges (SAT tractability limit)
- percolator-match program (separate codebase)

---

## proof-quality

### removed vacuous proofs (2026-02-06 cleanup)

- `kani_reject_has_no_chosen_size` — structural tautology (Reject variant has no fields)
- `kani_signer_ok_*`, `kani_writable_ok_*` — identity function tests (assert f(x)==x)
- `kani_*_independent_of_scale` — fake non-interference (compared same value to itself)
- individual `kani_len_ok_*` — consolidated into universal proof

### fixed proofs

- `kani_unit_conversion_deterministic` — now calls function twice instead of comparing output to copy
- `kani_tradecpi_from_ret_accept_uses_exec_size` — forces Accept path with valid req_id

### bounding strategy

Kani uses bounded model checking. Symbolic inputs are constrained to tractable ranges:
- `KANI_MAX_SCALE = 64` for unit_scale values
- `KANI_MAX_QUOTIENT = 4096` for price/base quotients
- price and base values bounded by `KANI_MAX_QUOTIENT * unit_scale`

This means proofs hold for ALL values within bounds, but edge cases beyond bounds are unverified.
