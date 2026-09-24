# ZeroDiscretion: Game-Theoretic Specification

This document explains why each actor in ZeroDiscretion does best by playing
honestly, and where that argument has limits. Numbers refer to the constants in
`contracts/zero_discretion.py`.

## 1. Actors and powers

| Actor | Can do | Cannot do |
|---|---|---|
| Project (program owner) | Fund the vault, file one bonded rebuttal per report inside the window, start closure, withdraw the leftover vault after closure | Reject a report, re-price a report, shorten a window, withdraw reserves while a report is open or before the closure notice ends |
| Researcher | File a bonded report, settle it after the window | Get paid without passing consensus triage, get paid before the window ends |
| Governor (deployer) | Lengthen the challenge window or closure notice (capped), sweep fees already booked to the treasury | Shorten any window, change the unlock time of a report already in flight, touch vaults, bonds or claimable balances |
| Anyone | Top up a vault, call `claim_bounty` / `expire_report` once the window has ended | Redirect funds: settlement always credits the parties fixed in the report |
| Validators | Run the consensus fetch and LLM judgement under the custom equivalence validator | Change the deterministic checks (URL, PoC schema, rebuttal binding, accounting). Those run identically on every node |

The protocol removes the project's discretion. The only way a project can stop
a payout is to convince the same consensus that validated the report, with a
bonded argument tied to the PoC.

## 2. Payoff table

Let `B` be the locked bounty, `b_r = 1 GEN` the researcher bond, `b_c = 2 GEN`
the challenge bond and `f = 2.5%` the protocol fee.

| Outcome | Researcher | Project | Treasury |
|---|---|---|---|
| Report rejected at triage | `-b_r` | `0` | `+b_r` |
| Validated, not challenged | `+B(1-f)` | `-B` | `+fB` |
| Validated, challenge dismissed | `+B(1-f) + b_c` | `-B - b_c` | `+fB` |
| Validated, challenge downgraded to tier `s'` | `+B'(1-f)` with `B' < B` | `-B'`, gets `b_c` back | `+fB'` |
| Validated, challenge upheld | `-b_r` | `0`, gets `b_c` back | `+b_r` |

### 2.1 Researcher incentives

* **Spam and over-claiming cost money.** If triage cannot reproduce the PoC at
  the claimed tier, the bond is slashed. The acceptance rule is
  `reproducible AND in_scope AND assessed >= claimed`, so over-claiming a
  critical to reach the 50% tier risks the whole bond. Claiming a lower tier
  than consensus assesses is accepted at the claimed tier. The researcher
  keeps full control over how much risk to take.
* **Slashed bonds go to the treasury, not the project.** If slashed bonds went
  to the project, the project would profit from reports being rejected and
  would want to steer triage toward rejection. With the treasury as the
  recipient, the project gains nothing when a researcher fails.
* **Duplicates.** Once a PoC is accepted, its canonical hash (key order, hex
  case and whitespace normalized) is recorded for the program, and replays
  revert with `ERR_DUPLICATE_REPORT`. A rejected PoC can be resubmitted at an
  honest tier, with a new bond.
* **Correct mistakes early.** A fetch failure or malformed LLM output reverts
  the whole transaction, so the bond returns natively. Researchers never pay
  for network faults.

### 2.2 Project incentives

* **No free rejection.** Every rebuttal needs a 2 GEN bond. If the rebuttal
  fails, the bond goes to the researcher, which compensates them for the
  delay and griefing.
* **No unbound rebuttals.** Before consensus runs, the rebuttal must commit to
  the report's `poc_hash`, name real step indices, and repeat the 4-byte
  selectors of those steps as the on-chain disassembly computed them.
  Consensus then checks whether the argument actually addresses those steps.
  Generic denials, unrelated transactions and replays from another report all
  revert with `ERR_REBUTTAL_NOT_BOUND`. The project cannot fall back to
  "we disagree".
* **Honest partial disputes pay off.** If a rebuttal shows the severity was
  overstated, the bounty is re-priced from the same vault basis and the
  challenge bond is returned. The project therefore has a reason to argue about
  the real impact rather than claim the report is entirely invalid.
* **One shot.** Each report can be challenged once. A dismissed challenge
  cannot be retried with a new argument.
* **No front-running with reserves.** `withdraw_vault` requires a closure
  notice (14 days by default, and the notice can only grow). Reports are
  still accepted during the notice, and withdrawal also requires
  `open_reports == 0`. A project that sees a critical report coming cannot
  empty the vault first.
* **No repricing.** Payout tiers are protocol constants, applied as a share of
  the vault that is available when the report is validated
  (`CRITICAL 50%, HIGH 20%, MEDIUM 7.5%, LOW 2%`). The same basis is used for
  a downgrade, so the project cannot change the price after a disclosure.
  Because tiers are shares of the available vault, sequential reports can
  never over-allocate it.

### 2.3 Governor incentives

The governor has two powers, both one-directional:

* Lengthening a window can only delay reports validated later. In-flight
  reports keep the `unlock_timestamp` they received at validation. Both
  windows have hard caps of 30 and 90 days.
* The governor can withdraw only `treasury_fees`, which accrues only from
  protocol fees and slashed researcher bonds. It cannot reach vaults, bonds or
  claimable balances, and every withdrawal is checked against the
  conservation invariant.

A compromised governor key can therefore only slow future payouts within the
caps and take fees that were already booked.

## 3. Consensus layer

* **Policy binding.** The policy URL must point to `SECURITY.md` on
  `github.com` or `raw.githubusercontent.com`, at a full 40-hex commit. That
  makes the content immutable, and the URL rules block SSRF (no IPs,
  localhost, ports, userinfo, queries or percent-encoding). The SHA-256 of
  the policy bytes is pinned on the first successful triage. Any later
  mismatch reverts with `ERR_POLICY_DRIFT`.
* **Deterministic ground truth.** The contract validates the PoC schema and
  disassembles each step's calldata (selector, 32-byte words, trailing bytes)
  identically on every node. The LLM receives this as ground truth, so it
  judges mechanics and not just the narrative.
* **Equivalence validator.** Each validator re-fetches the policy, re-runs the
  judgement and agrees only if the policy digest and the binary decision
  match. For challenges, the outcome and revised tier must also match. Prose
  may differ. A leader that raised an error (for example on malformed LLM
  output) is never agreed with, so the leader rotates.
* **Prompt injection.** All attacker-controlled text is wrapped in
  `<untrusted_*>` tags, and angle brackets are escaped. A payload cannot close
  a tag and write instructions.

## 4. Accounting invariant

Every unit of GEN the contract holds is in exactly one bucket:

```
vault_reserves + bonded_researcher_funds + bonded_project_funds
  + claimable_bounties + treasury_fees == total_inflows - total_outflows
```

The identity is enforced at the end of every state-changing method. Inflows
are only ever `gl.message.value` and outflows are only `emit_transfer` calls
queued by `withdraw` and `withdraw_treasury`, so the right-hand side equals the
contract's native balance, minus any GEN that someone force-sent to the
contract. That surplus is not claimable by anyone. `get_solvency()` exposes
`balance == liabilities` (`exact`) and `balance >= liabilities` (`solvent`).
The test suite checks `exact` after every lifecycle step.

## 5. Residual risks

1. **LLM judgement risk.** Consensus can be wrong in both directions. The
   bonds, the one-shot challenge and GenLayer's native appeal process limit
   the damage, but they do not remove it.
2. **Mempool copying.** Submission is a single step with no commit-reveal. If
   an observer copies a PoC and gets it ordered first, the observer wins the
   duplicate check. GenLayer's per-contract FIFO ordering makes this hard, but
   a commit-reveal wrapper is the natural next hardening step.
3. **Policy availability.** If the pinned policy becomes unreachable (for
   example the repository is deleted), submissions revert without slashing.
   The vault stays locked until the owner starts closure, and the closure
   notice gives researchers time to see this happen.
4. **Economic sizing.** The fixed 1 GEN and 2 GEN bonds are small against
   large vaults. Future versions should scale bonds with the tier and the vault
   size.
