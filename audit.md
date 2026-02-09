# AUDIT: percolator-prog — Security Audit & Formal Verification Report


<!--
2026-02-07
  CONTEXT FOR AI/LLM READERS:
  This is a comprehensive security audit of percolator-prog, a Solana on-chain
  perpetual futures protocol. The audit covers:
  
  1. Kani formal verification (143 bounded model-checking proofs)
  2. Integration test coverage (451 tests, 240+ adversarial attack tests)
  3. Unit test coverage (34 tests)
  4. Manual code review of the 4,390-line single-file program
  
  The program wraps a `percolator` crate RiskEngine inside a single slab account
  and exposes 22 instructions for perpetual market operations.
  
  TRUST MODEL: RiskEngine is assumed correct. This audit targets the program
  wrapper: account validation, CPI logic, nonce management, authorization,
  unit conversions, and policy enforcement.
-->

## metadata

```yaml
audit_date: 2026-02-07
program: percolator-prog
language: Rust (Solana BPF)
source_file: src/percolator.rs (4,390 lines)
test_files:
  - tests/kani.rs (3,430 lines, 143 Kani proofs)
  - tests/integration.rs (28,868 lines, 451 tests, 240+ attack tests)
  - tests/unit.rs (3,235 lines, 34 tests)
  - tests/i128_alignment.rs (837 lines, 8 tests)
  - tests/cu_benchmark.rs (1,550 lines)
total_test_lines: 37,920
instructions: 22
feature_flags: 6
dependencies:
  - solana-program 1.18
  - spl-token 4.0
  - pyth-sdk-solana 0.10
  - pinocchio 0.6
  - bytemuck 1.14
  - percolator (local crate)
kani_version: 0.67.0
kani_proofs: 143
kani_passed: 143
kani_failed: 0
kani_scope: program-wrapper only (not risk engine internals)
kani_verified_on: 2026-02-09 (macOS aarch64, rustc 1.93.0-nightly, CBMC via Kani 0.67.0)
kani_runtime: 429s (~7 min)
kani_bounds:
  KANI_MAX_SCALE: 64
  KANI_MAX_QUOTIENT: 4096
  price_base_bound: KANI_MAX_QUOTIENT * unit_scale
```

---

## architecture-overview

### single-file program (src/percolator.rs)

One market = one slab account containing header + config + RiskEngine (zero-copy).

**Modules** (all in single file):
- `constants` — magic, version, instruction tags, limits
- `verify` — pure decision/validation functions (Kani-proven)
- `accounts` — AccountInfo wrappers (signer/owner/writable checks)
- `state` — slab header, market config, serialization
- `oracle` — Pyth price feed reading, authority oracle, price clamping
- `matcher_abi` — matcher return struct, ABI validation
- `processor` — instruction dispatch and handlers (22 instructions)
- `entrypoint` — Solana entrypoint macro

### trust boundaries

| Layer | Trust Level | Responsibility |
|-------|-------------|---------------|
| RiskEngine | Trusted core | Pure accounting, risk checks, state transitions |
| Percolator program | Trusted glue | Account validation, token transfers, oracle reads, CPI |
| Matcher program | LP-scoped | Execution price/size, LP-chosen, treated as adversarial |

### PDA derivations

| PDA | Seeds | Purpose |
|-----|-------|---------|
| Vault authority | `["vault", slab_key]` | Signs token transfers |
| LP identity | `["lp", slab_key, lp_idx_le]` | CPI signer for matcher |

---

## instruction-set (22 instructions)

| Tag | Instruction | Auth | Description |
|-----|-------------|------|-------------|
| 0 | InitMarket | admin | Initialize slab + config + RiskEngine |
| 1 | InitUser | any | Create user account entry |
| 2 | InitLP | any | Create LP entry with matcher binding |
| 3 | DepositCollateral | owner | Transfer collateral into vault |
| 4 | WithdrawCollateral | owner | Withdraw from vault (margin-checked) |
| 5 | KeeperCrank | permissionless | Funding accrual, fees, liquidations, threshold update |
| 6 | TradeNoCpi | user+LP | Trade without external matcher |
| 7 | LiquidateAtOracle | permissionless | Explicit liquidation at oracle price |
| 8 | CloseAccount | owner | Settle and withdraw remaining funds |
| 9 | TopUpInsurance | any | Add funds to insurance |
| 10 | TradeCpi | user+LP | Trade via LP-chosen matcher CPI |
| 11 | SetRiskThreshold | admin | Manual risk threshold override |
| 12 | UpdateAdmin | admin | Rotate or burn admin key |
| 13 | CloseSlab | admin | Decommission empty market |
| 14 | UpdateConfig | admin | Update funding/threshold config |
| 15 | SetMaintenanceFee | admin | Set per-slot maintenance fee |
| 16 | SetOracleAuthority | admin | Set oracle price authority |
| 17 | PushOraclePrice | oracle_auth | Push authority oracle price |
| 18 | SetOraclePriceCap | admin | Set price circuit breaker |
| 19 | ResolveMarket | admin | Force-close all positions (irreversible) |
| 20 | WithdrawInsurance | admin | Withdraw insurance (post-resolution) |
| 21 | AdminForceCloseAccount | admin | Force-close abandoned account (post-resolution) |

---

## feature-flags

| Flag | Purpose | Risk |
|------|---------|------|
| `no-entrypoint` | Library mode | None |
| `test-sbf` | SBF testing | None |
| `devnet` | Devnet deployment | None |
| `test` | MAX_ACCOUNTS=64 | Test only |
| `cu-audit` | CU checkpoint logging | Diagnostic |
| **`unsafe_close`** | **Skips ALL validation in CloseSlab** | **CRITICAL** |

### unsafe_close detail

When enabled, `CloseSlab` skips:
- Slab initialization check
- Admin authorization
- Vault balance check (must be zero)
- Insurance fund balance check (must be zero)
- Account count check (must be zero)
- Dust base check (must be zero)
- Data zeroing

**Verdict**: MUST NOT be enabled in production. Allows anyone to close a market slab and steal lamports regardless of state. README explicitly warns against production use.

---

## kani-formal-verification (143 proofs)

All 143 proofs pass. Verified by running `cargo kani --tests` on 2026-02-09 (Kani 0.67.0, CBMC backend, 429s runtime). Output: `Complete - 143 successfully verified harnesses, 0 failures, 143 total.`

Proofs use bounded model checking with `kani::any()` for symbolic inputs.

### A. Matcher ABI Validation (14 proofs)

Proves that `validate_matcher_return()` correctly rejects all malformed matcher responses.

| # | Harness | Property |
|---|---------|----------|
| 1 | `kani_matcher_rejects_wrong_abi_version` | wrong ABI version → reject |
| 2 | `kani_matcher_rejects_missing_valid_flag` | missing VALID flag → reject |
| 3 | `kani_matcher_rejects_rejected_flag` | REJECTED flag set → reject |
| 4 | `kani_matcher_rejects_wrong_req_id` | req_id mismatch → reject |
| 5 | `kani_matcher_rejects_wrong_lp_account_id` | lp_account_id mismatch → reject |
| 6 | `kani_matcher_rejects_wrong_oracle_price` | oracle_price mismatch → reject |
| 7 | `kani_matcher_rejects_nonzero_reserved` | nonzero reserved → reject |
| 8 | `kani_matcher_rejects_zero_exec_price` | zero exec_price → reject |
| 9 | `kani_matcher_zero_size_requires_partial_ok` | zero size without PARTIAL_OK → reject |
| 10 | `kani_matcher_rejects_exec_size_exceeds_req` | |exec| > |req| → reject |
| 11 | `kani_matcher_rejects_sign_mismatch` | sign(exec) ≠ sign(req) → reject |
| 12 | `kani_matcher_zero_size_with_partial_ok_accepted` | zero size + PARTIAL_OK → accept |
| 13 | `kani_min_abs_boundary_rejected` | i128::MIN boundary → handled |
| 14 | `kani_matcher_accepts_minimal_valid_nonzero_exec` | minimal valid → accept |

### B. Matcher Acceptance (2 proofs)

| # | Harness | Property |
|---|---------|----------|
| 15 | `kani_matcher_accepts_exec_size_equal_req_size` | exec == req → accept |
| 16 | `kani_matcher_accepts_partial_fill_with_flag` | partial + PARTIAL_OK → accept |

### C. Owner/Signer Enforcement (2 proofs)

| # | Harness | Property |
|---|---------|----------|
| 17 | `kani_owner_mismatch_rejected` | owner ≠ signer → reject |
| 18 | `kani_owner_match_accepted` | owner == signer → accept |

### D. Admin Authorization (3 proofs)

| # | Harness | Property |
|---|---------|----------|
| 19 | `kani_admin_mismatch_rejected` | admin ≠ signer → reject |
| 20 | `kani_admin_match_accepted` | admin == signer → accept |
| 21 | `kani_admin_burned_disables_ops` | admin == [0;32] → permanently disabled |

### E. CPI Identity Binding (2 proofs) — CRITICAL

| # | Harness | Property |
|---|---------|----------|
| 22 | `kani_matcher_identity_mismatch_rejected` | prog/ctx ≠ registered → reject |
| 23 | `kani_matcher_identity_match_accepted` | prog/ctx == registered → accept |

### F. Matcher Account Shape (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 24 | `kani_matcher_shape_rejects_non_executable_prog` | non-executable program → reject |
| 25 | `kani_matcher_shape_rejects_executable_ctx` | executable context → reject |
| 26 | `kani_matcher_shape_rejects_wrong_ctx_owner` | wrong context owner → reject |
| 27 | `kani_matcher_shape_rejects_short_ctx` | context too small → reject |
| 28 | `kani_matcher_shape_valid_accepted` | valid shape → accept |

### G. PDA Key Matching (2 proofs)

| # | Harness | Property |
|---|---------|----------|
| 29 | `kani_pda_mismatch_rejected` | derived ≠ provided → reject |
| 30 | `kani_pda_match_accepted` | derived == provided → accept |

### H. Nonce Monotonicity (3 proofs)

| # | Harness | Property |
|---|---------|----------|
| 31 | `kani_nonce_unchanged_on_failure` | failure → nonce unchanged |
| 32 | `kani_nonce_advances_on_success` | success → nonce += 1 |
| 33 | `kani_nonce_wraps_at_max` | u64::MAX → wraps to 0 |

### I. CPI Uses exec_size (1 proof) — CRITICAL

| # | Harness | Property |
|---|---------|----------|
| 34 | `kani_cpi_uses_exec_size` | engine receives exec_size, not requested size |

### J. Gate Activation Logic (3 proofs)

| # | Harness | Property |
|---|---------|----------|
| 35 | `kani_gate_inactive_when_threshold_zero` | threshold=0 → gate off |
| 36 | `kani_gate_inactive_when_balance_exceeds` | balance > threshold → gate off |
| 37 | `kani_gate_active_when_conditions_met` | threshold>0 ∧ balance≤threshold → gate on |

### K. Per-Instruction Authorization (4 proofs)

| # | Harness | Property |
|---|---------|----------|
| 38 | `kani_single_owner_mismatch_rejected` | owner mismatch → reject |
| 39 | `kani_single_owner_match_accepted` | owner match → accept |
| 40 | `kani_trade_rejects_user_mismatch` | user owner mismatch → reject |
| 41 | `kani_trade_rejects_lp_mismatch` | LP owner mismatch → reject |

### L. TradeCpi Decision Coupling (14 proofs) — CRITICAL

Full decision-tree verification. Every rejection reason individually proven.

| # | Harness | Property |
|---|---------|----------|
| 42 | `kani_tradecpi_rejects_non_executable_prog` | bad shape → reject |
| 43 | `kani_tradecpi_rejects_executable_ctx` | bad shape → reject |
| 44 | `kani_tradecpi_rejects_pda_mismatch` | PDA wrong → reject |
| 45 | `kani_tradecpi_rejects_user_auth_failure` | user auth fail → reject |
| 46 | `kani_tradecpi_rejects_lp_auth_failure` | LP auth fail → reject |
| 47 | `kani_tradecpi_rejects_identity_mismatch` | identity fail → reject |
| 48 | `kani_tradecpi_rejects_abi_failure` | ABI fail → reject |
| 49 | `kani_tradecpi_rejects_gate_risk_increase` | gate + risk↑ → reject |
| 50 | `kani_tradecpi_allows_gate_risk_decrease` | gate + risk↓ → accept |
| 51 | `kani_tradecpi_reject_nonce_unchanged` | reject → nonce unchanged |
| 52 | `kani_tradecpi_accept_increments_nonce` | accept → nonce += 1 |
| 53 | `kani_tradecpi_accept_uses_exec_size` | accept → uses exec_size |
| 54 | `kani_tradecpi_rejects_ctx_owner_mismatch` | ctx owner wrong → reject |
| 55 | `kani_tradecpi_rejects_ctx_len_short` | ctx too small → reject |

### M. TradeNoCpi Decision Coupling (4 proofs)

| # | Harness | Property |
|---|---------|----------|
| 56 | `kani_tradenocpi_rejects_user_auth_failure` | user auth fail → reject |
| 57 | `kani_tradenocpi_rejects_lp_auth_failure` | LP auth fail → reject |
| 58 | `kani_tradenocpi_rejects_gate_risk_increase` | gate + risk↑ → reject |
| 59 | `kani_tradenocpi_accepts_valid` | all valid → accept |

### N. Universal Nonce Properties (2 proofs) — CRITICAL

Uses `kani::any()` for ALL decision inputs simultaneously.

| # | Harness | Property |
|---|---------|----------|
| 60 | `kani_tradecpi_any_reject_nonce_unchanged` | ANY rejection → nonce unchanged |
| 61 | `kani_tradecpi_any_accept_increments_nonce` | ANY acceptance → nonce += 1 |

### O. Account & LP PDA Validation (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 62 | `kani_len_ok_universal` | len_ok(actual, need) == (actual >= need) |
| 63 | `kani_lp_pda_shape_valid` | valid PDA shape → accept |
| 64 | `kani_lp_pda_rejects_wrong_owner` | non-system owner → reject |
| 65 | `kani_lp_pda_rejects_has_data` | has data → reject |
| 66 | `kani_lp_pda_rejects_funded` | has lamports → reject |

### P. Oracle & Slab Validation (4 proofs)

| # | Harness | Property |
|---|---------|----------|
| 67 | `kani_oracle_feed_id_match` | matching feed IDs → accept |
| 68 | `kani_oracle_feed_id_mismatch` | mismatched feed IDs → reject |
| 69 | `kani_slab_shape_valid` | valid slab → accept |
| 70 | `kani_slab_shape_invalid` | invalid slab → reject |

### Q. Simple Decision Functions (8 proofs)

| # | Harness | Property |
|---|---------|----------|
| 71-72 | `kani_decide_single_owner_*` | single-owner accept/reject |
| 73-76 | `kani_decide_crank_*` | crank: permissionless, self-crank, wrong owner, no idx |
| 77-78 | `kani_decide_admin_*` | admin accept/reject |

### R. ABI Equivalence (1 proof) — CRITICAL

| # | Harness | Property |
|---|---------|----------|
| 79 | `kani_abi_ok_equals_validate` | `verify::abi_ok == validate_matcher_return.is_ok()` for ALL inputs |

### S. TradeCpi from Real Inputs (5 proofs) — CRITICAL

Tests full decision path using real `MatcherReturn` struct data.

| # | Harness | Property |
|---|---------|----------|
| 80 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | ANY rejection (real) → nonce unchanged |
| 81 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | ANY acceptance (real) → nonce += 1 |
| 82 | `kani_tradecpi_from_ret_accept_uses_exec_size` | ANY acceptance → uses exec_size |
| 83 | `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | req_id == nonce + 1 on success |
| 84 | `kani_tradecpi_from_ret_forced_acceptance` | valid inputs force Accept path |

### T. Crank Panic Mode Authorization (6 proofs)

| # | Harness | Property |
|---|---------|----------|
| 85-90 | `kani_crank_panic_*` / `kani_crank_no_panic_*` | panic requires admin, permissionless accepts, wrong owner rejects |

### U. Haircut Inversion (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 91-95 | `kani_invert_*` | zero handling, correct computation, monotonicity, None on invalid |

### V. Unit Scale Conversions (11 proofs)

| # | Harness | Property |
|---|---------|----------|
| 96 | `kani_base_to_units_conservation` | units + dust == base |
| 97 | `kani_base_to_units_dust_bound` | dust < unit_scale |
| 98 | `kani_base_to_units_scale_zero` | scale=0 → units=base, dust=0 |
| 99 | `kani_units_roundtrip` | base_to_units → units_to_base roundtrips |
| 100 | `kani_units_to_base_scale_zero` | scale=0 → base=units |
| 101 | `kani_base_to_units_monotonic` | larger base → larger units |
| 102 | `kani_units_to_base_monotonic_bounded` | larger units → larger base |
| 103 | `kani_base_to_units_monotonic_scale_zero` | monotonic at scale=0 |
| 104 | `kani_units_roundtrip_exact_when_no_dust` | perfect roundtrip when dust=0 |
| 105 | `kani_unit_conversion_deterministic` | same inputs → same outputs |
| 106 | `kani_scale_validation_pure` | scale validation is deterministic |

### W. Withdrawal Alignment (3 proofs)

| # | Harness | Property |
|---|---------|----------|
| 107 | `kani_withdraw_misaligned_rejects` | misaligned → reject |
| 108 | `kani_withdraw_aligned_accepts` | aligned → accept |
| 109 | `kani_withdraw_scale_zero_always_aligned` | scale=0 → always aligned |

### X. Dust Sweep (8 proofs)

| # | Harness | Property |
|---|---------|----------|
| 110 | `kani_sweep_dust_conservation` | swept + remaining == original |
| 111 | `kani_sweep_dust_rem_bound` | remaining bounded |
| 112 | `kani_sweep_dust_below_threshold` | swept below threshold |
| 113-116 | `kani_*_scale_zero_*` | scale=0 edge cases |
| 117 | `kani_accumulate_dust_saturates` | dust accumulation saturates |

### Y. Universal Rejection (6 proofs)

Any single check failure → overall rejection, regardless of other inputs.

| # | Harness | Property |
|---|---------|----------|
| 118-123 | `kani_universal_*_fail_rejects` | shape/PDA/user/LP/identity/ABI fail → reject |

### Z. Variant Consistency & Gate Properties (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 124-125 | `kani_tradecpi_variants_consistent_*` | decide_trade_cpi == decide_trade_cpi_from_ret |
| 126 | `kani_universal_gate_risk_increase_rejects` | gate + risk↑ → reject (universal) |
| 127 | `kani_universal_panic_requires_admin` | panic crank → admin required |
| 128 | `kani_universal_gate_risk_increase_rejects_from_ret` | gate rejection (real inputs) |

### AA. InitMarket Scale Validation (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 129 | `kani_init_market_scale_rejects_overflow` | overflow → reject |
| 130 | `kani_init_market_scale_zero_ok` | 0 → ok |
| 131 | `kani_init_market_scale_boundary_ok` | MAX → ok |
| 132 | `kani_init_market_scale_boundary_reject` | MAX+1 → reject |
| 133 | `kani_init_market_scale_valid_range` | [0, MAX] → ok |

### BB. scale_price_e6 Properties (5 proofs)

| # | Harness | Property |
|---|---------|----------|
| 134 | `kani_scale_price_e6_zero_result_rejected` | zero → None |
| 135 | `kani_scale_price_e6_valid_result` | valid → Some |
| 136 | `kani_scale_price_e6_identity_for_scale_leq_1` | scale≤1 → identity |
| 137 | `kani_scale_price_and_base_to_units_use_same_divisor` | consistent divisor |
| 138 | `kani_scale_price_e6_concrete_example` | concrete value check |

### CC. clamp_toward_with_dt Rate Limiting (5 proofs)

Oracle price smoothing — prevents sudden index jumps.

| # | Harness | Property |
|---|---------|----------|
| 139 | `kani_clamp_toward_no_movement_when_dt_zero` | dt=0 → no movement |
| 140 | `kani_clamp_toward_no_movement_when_cap_zero` | cap=0 → no movement |
| 141 | `kani_clamp_toward_bootstrap_when_index_zero` | index=0 → jump to mark |
| 142 | `kani_clamp_toward_movement_bounded_concrete` | |delta| ≤ cap × dt |
| 143 | `kani_clamp_toward_formula_concrete` | formula matches spec |

---

## integration-test-coverage

### summary

- **451 total integration tests** (28,868 lines)
- **240+ adversarial attack tests** (prefix `test_attack_*`)
- Tests run against LiteSVM (local Solana simulator)

### attack test categories

| Category | Count | Examples |
|----------|-------|---------|
| Authorization bypass | 25+ | wrong owner deposit/withdraw/close, non-admin ops, burned admin |
| Trade security | 30+ | no margin, gated risk increase, post-resolution, cross-LP binding |
| CPI manipulation | 10+ | wrong matcher program/context, wrong PDA, PDA with lamports |
| Liquidation abuse | 10+ | solvent account, self-liquidation, post-recovery |
| Withdrawal attacks | 15+ | exceed capital, wrong owner, misaligned, post-resolution |
| Conservation invariants | 25+ | deposit/withdraw/trade conservation, multi-user settlement |
| Funding manipulation | 10+ | extreme rates, same-slot double-crank, large dt gaps |
| Oracle attacks | 10+ | stale oracle, wrong authority, zero price, circuit breaker |
| Market lifecycle | 15+ | double init, double resolve, close slab conditions |
| Dust/rounding | 10+ | dust accumulation theft, rounding extraction, micro trades |
| Unit scale | 5+ | zero scale, high scale, trade conservation |
| Warmup period | 5+ | instant profit withdrawal, gradual vesting |
| Config manipulation | 10+ | extreme values, zero funding horizon, alpha over 100% |
| Index isolation | 5+ | out-of-bounds index, cross-market, same-owner isolation |
| Nonce replay | 2+ | same trade replay prevention |

### key security properties tested

1. **Conservation**: Total vault balance == sum of all account capitals + insurance + fees (tested across ALL operations)
2. **Authorization**: Every instruction rejects unauthorized callers
3. **Isolation**: Cross-market, cross-account, and cross-LP operations properly isolated
4. **Liquidation correctness**: Only truly underwater accounts are liquidatable
5. **Post-resolution**: No deposits, trades, or new accounts after market resolution
6. **Admin key lifecycle**: Rotation works, old admin blocked, burned admin permanent

---

## findings

### CRITICAL

#### C-01: `unsafe_close` feature flag bypasses all safety checks

**Location**: `src/percolator.rs`, CloseSlab handler (feature-gated)

**Impact**: If enabled in production, anyone can close a market slab regardless of whether it contains funds, positions, or insurance. Attacker can steal slab lamports.

**Status**: Mitigated by compile-time feature flag. NOT enabled in default build. README warns against production use.

**Recommendation**: Add a compile-time assertion or CI check that `unsafe_close` is never enabled in release builds:
```rust
#[cfg(all(feature = "unsafe_close", not(feature = "test")))]
compile_error!("unsafe_close must not be used in production");
```

### HIGH

#### H-01: Admin key has extensive governance powers

**Impact**: A compromised admin can:
- Resolve market (irreversible, halts all trading)
- Withdraw insurance fund (after resolution)
- Set extreme maintenance fees (drain user capital)
- Set restrictive risk thresholds (prevent trading)
- Change oracle authority (price manipulation surface)
- Force-close accounts (after resolution)

**Status**: By design. All admin operations are tested for proper authorization. Admin can be burned (set to [0;32]) to permanently disable governance.

**Mitigation**: Use multisig for admin key. Consider burning admin after stable operation period.

### MEDIUM

#### M-01: Kani bounds limit proof coverage

Kani uses `KANI_MAX_SCALE=64` and `KANI_MAX_QUOTIENT=4096` for SAT tractability. The actual `MAX_UNIT_SCALE` is 1 billion. Values beyond Kani bounds are unverified by formal methods.

**Impact**: Edge cases with very large unit scales (>64) or very large quotients (>4096) are only covered by integration tests, not formal proofs.

**Mitigation**: Integration tests cover extreme values (`test_attack_max_unit_scale_operations`, `test_attack_large_unit_scale_no_overflow`). InitMarket scale validation is formally proven for the full range.

#### M-02: Oracle staleness and confidence filters

Oracle price is read from Pyth. If oracle is stale or confidence interval too wide, operations fail.

**Impact**: Extended oracle outage prevents all trading, withdrawals (that require margin check), and liquidations.

**Mitigation**: Keeper monitoring should alert on oracle staleness. Authority oracle can be used as fallback.

### LOW

#### L-01: Dust accumulation over time

Unit scale conversions produce dust (remainder) that accumulates in the slab. Dust is swept to insurance fund during crank.

**Impact**: Negligible value accumulation. Conservation is formally proven (`kani_sweep_dust_conservation`).

#### L-02: KeeperCrank compute budget

Worst-case crank with many accounts may exceed compute budget.

**Impact**: Operational — may require pagination or higher CU limits.

### INFO

#### I-01: Single-file architecture

All 4,390 lines are in one file. While unusual, this is intentional for auditability (single point of truth, easy to verify no hidden modules).

#### I-02: `cu-audit` feature for CU profiling

Adds `sol_log_compute_units()` checkpoints. Safe — diagnostic only, no state changes.

---

## proven-security-properties (summary)

### authorization
- Owner checks: proofs 17-18, 38-41
- Admin checks: proofs 19-21, 77-78
- Burned admin permanently disables ops: proof 21
- Trades require both user AND LP signatures: proofs 40-41
- Crank authorization: proofs 73-76

### CPI security
- Matcher identity binding: proofs 22-23
- Matcher shape validation: proofs 24-28
- exec_size used for engine call: proofs 34, 53, 82
- Identity mismatch rejects even with valid ABI: proof 47

### state consistency
- Nonce unchanged on ANY failure: proofs 31, 51, 60, 80
- Nonce advances by 1 on ANY success: proofs 32, 52, 61, 81
- Nonce wraps at u64::MAX: proof 33
- req_id == nonce + 1 on success: proof 83

### risk gate
- Threshold=0 disables gate: proof 35
- Sufficient balance disables gate: proof 36
- Risk-increasing trades rejected when gate active: proofs 37, 49, 58, 126-128
- Risk-reducing trades allowed: proof 50

### unit conversions
- Conservation: units + dust == base (proof 96)
- Dust bounded: dust < unit_scale (proof 97)
- Roundtrip fidelity: proof 99
- Monotonicity: proofs 101-103
- Determinism: proof 105

### oracle price smoothing
- dt=0 → no movement: proof 139
- cap=0 → no movement: proof 140
- Movement bounded by cap × dt: proof 142

---

## not-proven

Explicitly out of scope for Kani:

- RiskEngine internals (LpRiskState, risk formulas, PnL math)
- Solana CPI execution mechanics (invoke_signed behavior)
- AccountInfo runtime validation (Solana runtime handles)
- Actual PDA derivation (Solana's find_program_address)
- SPL Token transfer correctness
- Arbitrary inputs beyond bounded ranges (SAT tractability)
- percolator-match program (separate audit)

---

## verdict

**percolator-prog** has strong security coverage:
- 143 formal proofs covering all wrapper-level security properties
- 451 integration tests with 240+ adversarial attack scenarios
- Single-file architecture enables straightforward auditing
- All authorization, CPI binding, and nonce properties formally verified

**Primary risk**: `unsafe_close` feature flag. Must never be enabled in production.

**Secondary risk**: Admin key governance power. Use multisig and consider burning admin post-stabilization.

**No exploitable vulnerabilities found** in the default build configuration.
