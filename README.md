# ZeroDiscretion

**Autonomous Zero-Discretion Bug Bounty Escrow Protocol on GenVM.**

In most bug bounty programs, the project decides whether to pay. ZeroDiscretion
takes that decision away from the project and gives it to GenLayer validator
consensus:

1. **Projects** lock bounty reserves in an autonomous vault. The vault is bound
   to a `SECURITY.md` pinned to a specific GitHub commit.
2. **Researchers** submit bonded reports with an executable PoC trace (the
   reproduction calldata).
3. **Validators** fetch the pinned policy and check the PoC mechanics against a
   deterministic on-chain disassembly. They also check the claimed severity
   against the severity matrix, using an LLM judgement under a custom
   equivalence validator.
4. **Validated reports** lock their bounty and open an immutable challenge
   window. When the window ends, anyone can settle the report and the vault
   pays out. No one has to approve it.

A project can stop a payout only with a **bonded rebuttal bound to the exact
PoC**. The rebuttal must name the PoC hash, the step indices and the 4-byte
selectors. Consensus must then accept it.

## Layout

```
contracts/zero_discretion.py          GenLayer intelligent contract
tests/direct/conftest.py              harness: mocks + native-balance mirror
tests/direct/test_bounty_lifecycle.py happy path and every settlement branch
tests/direct/test_adversarial_security.py  attacks, reverts, invariant checks
scripts/deploy.py                     lint-gated deployment via genlayer-py
specs/game_theory.md                  incentive analysis and residual risks
```

## Lifecycle

```
register_bounty_program ──► submit_vulnerability ──(consensus triage)──┬─► REJECTED (bond slashed)
      (>= 5 GEN)               (>= 1 GEN bond)                          │
                                                                        └─► VALIDATED  (bounty locked,
                                                                              │         unlock = now + window)
                             challenge_vulnerability (owner, 2 GEN, bound) ◄──┤
                                ├─ DISMISSED  ─► claim_bounty after unlock ─► PAID (+ challenge bond)
                                ├─ DOWNGRADED ─► claim_bounty after unlock ─► PAID (re-priced)
                                └─ UPHELD     ─► expire_report after unlock ─► EXPIRED (funds back to vault)
                             no challenge ─────► claim_bounty after unlock ─► PAID
```

Payouts use a pull pattern. `claim_bounty` credits a claimable balance, and the
researcher then calls `withdraw` to move the funds.

| Parameter | Value |
|---|---|
| Minimum program deposit | 5 GEN |
| Researcher bond | ≥ 1 GEN |
| Challenge bond | ≥ 2 GEN |
| Challenge window | 7 days (can increase to at most 30 days, never decrease) |
| Closure notice | 14 days (can increase to at most 90 days, never decrease) |
| Payout tiers (share of available vault) | CRITICAL 50%, HIGH 20%, MEDIUM 7.5%, LOW 2% |
| Protocol fee | 2.5% of the paid bounty |

### Input formats

**PoC trace** (`poc_trace`):

```json
{
  "target": "0x1111111111111111111111111111111111111111",
  "chain_id": 1,
  "invariant_broken": "user can withdraw more than their recorded deposit",
  "steps": [
    {"to": "0x1111111111111111111111111111111111111111",
     "calldata": "0x2e1a7d4d00000000000000000000000000000000000000000000d3c21bcecceda1000000",
     "value": "0", "expect": "withdraw succeeds with no balance check"}
  ]
}
```

**Rebuttal** (`rebuttal_proof`):

```json
{
  "poc_hash": "<get_report(id).poc_hash>",
  "rebuttal_type": "INTENDED_ADMIN_ROLE",
  "disputed_steps": [0],
  "disputed_selectors": ["0x2e1a7d4d"],
  "argument": "withdraw() is gated by onlyOwner in the deployed bytecode; ..."
}
```

`rebuttal_type` must be one of `INTENDED_ADMIN_ROLE`, `SANDBOX_MOCK_BYPASS`,
`OUT_OF_SCOPE_TARGET`, `KNOWN_ISSUE_DISCLOSED`, `NON_REPRODUCIBLE` or
`SEVERITY_OVERSTATED`.

## Invariants

* **Conservation.** At the end of every mutation, the contract checks
  `vault_reserves + bonded_researcher_funds + bonded_project_funds + claimable_bounties + treasury_fees == total_inflows - total_outflows`.
  If the check fails, the transaction reverts with `ERR_INVARIANT_VIOLATION`.
  `get_solvency()` compares this ledger with `self.balance`.
* **Zero-leak escrow.** Vault reserves can leave only in two ways: as a
  settled bounty, or through `withdraw_vault` after the closure notice ends
  with no open reports. Bounties are shares of the available vault, so they
  can never over-allocate it.
* **Policy immutability.** The policy URL must point to `SECURITY.md` on
  `github.com` or `raw.githubusercontent.com` at a full commit SHA, using
  https. The contract rejects IPs, localhost, ports, userinfo, queries and
  percent-encoding (SSRF). The policy bytes are hash-pinned on the first
  triage.
* **No discretion.** The governor can only lengthen windows and sweep booked
  fees. In-flight reports keep their unlock timestamp.

See [`specs/game_theory.md`](specs/game_theory.md) for the incentive analysis.

## Development

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python --prerelease=allow -e ".[dev]"

.venv/bin/python -m pytest tests/direct/            # direct-mode suite
.venv/bin/genvm-lint lint contracts/zero_discretion.py
.venv/bin/genvm-lint check contracts/zero_discretion.py
```

Direct mode runs only the leader function. The tests use
`direct_vm.run_validator()` to replay the captured validator functions, which
checks that validators agree with an honest leader and disagree with a leader
that flipped its verdict, forged its policy digest or saw different policy
bytes. Direct mode does not credit `gl.message.value` to the contract
balance, so the harness mirrors native value flows with `direct_vm.deal()`.
That keeps the `get_solvency()` assertions meaningful.

### Deploy

```bash
export GENLAYER_PRIVATE_KEY=0x...
.venv/bin/python scripts/deploy.py --network studionet
```

The deployer becomes the governor. The script runs `genvm-lint check` before
it sends anything, and it writes the deployment record to `deployments/`.

## License

MIT © 2026 SOBEK96 (btcehsan@yahoo.com)
