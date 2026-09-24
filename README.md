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

## Live deployment - GenLayer Studio Next

| | |
|---|---|
| Network | GenLayer Studio Next (chain `61997`, RPC `https://studio-next.genlayer.com/api`) |
| Contract | [`0xcd8cd3E7722EF7f32Fa546dB17eDC05F458B5841`](https://explorer-studio-next.genlayer.com/address/0xcd8cd3E7722EF7f32Fa546dB17eDC05F458B5841) |
| Deploy tx | [`0x1893f0b0...8257ef4`](https://explorer-studio-next.genlayer.com/tx/0x1893f0b05bae080e6b39d68fcb8b4bd6b107311c27b40f0ea8fda97398257ef4) |
| Governor | `0x7cc9f73979a548e00981561406117c95E5f54122` |
| Reference program | #1 - 10 GEN vault, target `0x...c0ffee`, policy [`SECURITY.md@0eefe76`](https://github.com/SOBEK96/ZeroDiscretion/blob/0eefe76da072138225148c30559d1913d93d7910/SECURITY.md) ([register tx](https://explorer-studio-next.genlayer.com/tx/0x73a645fcc106848f2c655c7bec709b4c9898105b0755c713d57fa6ca5259c1bb)) |

After the bootstrap, both consensus paths were run end to end on Studio Next:

* **Triage.** A bonded CRITICAL PoC against program #1 reached `MAJORITY_AGREE` and was `VALIDATED`. 5 GEN is locked, and the policy digest was pinned to the same SHA-256 the deploy script computed ([tx](https://explorer-studio-next.genlayer.com/tx/0x370e72e4972f0a82059b888cb36c4a16df6fcd34e9b17e614b9390fe63440009)).
* **Dispute.** The program owner filed a bound `INTENDED_ADMIN_ROLE` rebuttal. Consensus dismissed it because the pinned policy excludes only `onlyOwner` functions. The 2 GEN bond is held for the researcher ([tx](https://explorer-studio-next.genlayer.com/tx/0xfcd0c7d37f6dda07a391db52739a6d8f50a34c4291efc82bf080aadac4005ca6)).
* **Solvency.** `get_solvency()` reported `exact: true` after every step (10, 11, then 13 GEN).

The full record is in [`deployments/studio-next.json`](deployments/studio-next.json).

## Layout

```
contracts/zero_discretion.py          GenLayer intelligent contract
tests/direct/conftest.py              harness: mocks + native-balance mirror
tests/direct/test_bounty_lifecycle.py happy path and every settlement branch
tests/direct/test_adversarial_security.py  attacks, reverts, invariant checks
scripts/deploy.py                     lint-gated deploy + verified bootstrap via genlayer-py
specs/game_theory.md                  incentive analysis and residual risks
deployments/studio-next.json          live deployment record
frontend/                             Vite + React + Tailwind dApp (genlayer-js)
SECURITY.md                           reference program policy, pinned by commit
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
# GENLAYER_PRIVATE_KEY in the environment or in the gitignored .env
.venv/bin/python scripts/deploy.py --network studio_next --bootstrap
```

The script runs `genvm-lint check` and then deploys, taking fees from the chain's live fee policy. Studio Next reverts
transactions that carry no fee object (`FeesDistributionMissing`). With `--bootstrap`, the script checks that the
commit-pinned `SECURITY.md` returns HTTP 200, then registers the 10 GEN reference program and reads it back. Finally it
writes `deployments/<network>.json`. Use `--address <contract>` to bootstrap an existing deployment. The deployer
becomes the governor.

### Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build      # tsc -b && vite build
npm run lint
```

The dApp reads live state from the deployed contract through an account-less `genlayer-js` client, so no wallet is
needed to browse it. It writes through the injected wallet (for example MetaMask), switching to or adding Studio
Next if needed. Main views:

* **Protocol metrics:** TVL, active programs, exploits paid out, and the on-chain solvency ratio.
* **Program explorer:** commit-pinned policy links, per-tier maximum payouts, and vault top-ups.
* **Disclosure form:** a real-time bond and payout calculation, plus a dry-run inspector. The inspector runs the
  contract's deterministic checks in the browser: PoC schema, target binding, canonical SHA-256 (matches the
  contract exactly), duplicate detection and calldata disassembly. It runs before any bonded transaction is sent.
* **Triage center:** live challenge-window countdowns and both consensus verdicts. It also has the
  rebuttal builder: step selectors come from the disassembly, so every rebuttal it produces is bound by
  construction. Claim, expire and pull-withdraw actions are also here.

Override the defaults with `VITE_GENLAYER_RPC_URL` and `VITE_CONTRACT_ADDRESS` (see `frontend/.env.example`).

## License

MIT © 2026 SOBEK96 (btcehsan@yahoo.com)
