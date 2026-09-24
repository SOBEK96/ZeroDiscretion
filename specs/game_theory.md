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
* **One payout per vulnerability.** Deduplication works on a semantic
  fingerprint of the execution path, not on the report text:
  `keccak256` over the ordered `(target address, 4-byte selector)` pairs of
  the steps that call the program target. Steps to any other address are
  excluded (`ERR_NO_TARGET_CALLS` if nothing calls the target). Free text (`expect`, `invariant_broken`, the description) and
  calldata arguments are ignored, so rewording a validated finding or changing
  an amount reverts with `ERR_DUPLICATE_VULNERABILITY` before any bond is
  taken. (An earlier version hashed the whole PoC including free text, so one
  changed word earned a second payout. The regression tests in
  `tests/direct/test_review_poc.py` reproduce that attack.) Padding with
  calls to other contracts (token approvals, `balanceOf` on a dummy address,
  helper contracts) therefore cannot change the fingerprint, and it is
  rejected deterministically. Padding with extra calls into the target itself,
  such as an incidental view, does change the fingerprint. For that case,
  every validated path of the program goes into the triage context. A consensus "duplicate of prior" verdict fails
  the report closed and slashes the bond like any other rejection. Validated
  paths are public (`get_validated_fingerprints`), so an honest researcher can
  check before bonding. A rejected PoC never blocks its path and can be
  resubmitted at an honest tier, with a new bond.
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
* **Target ABI verification (web consensus).** At registration, validators
  fetch the target's ABI from Sourcify for the program's chain and must agree
  on the exact selector-to-signature map and fallback flag. The ABI must be
  verified against the deployed bytecode. Proxies resolve to their
  implementations, and the proxy's own delegating fallback does not count.
  The map is pinned on the program. Unverified targets cannot register
  (`ERR_TARGET_NOT_VERIFIED`), which closes the "never verify, veto
  everything" strategy. The ABI comes from Sourcify, not from the project, so
  a project cannot publish a trimmed ABI to hide a vulnerable function.
  Anyone can call `refresh_target_abi` to re-pin the map after an upgrade.
* **Selector gate.** Every PoC step that calls the target must use a selector
  of the pinned ABI. The only other allowed route is an explicitly declared
  `"route": "fallback"`, and only when the verified ABI has a `fallback()`.
  A mock selector such as `0xdeadbeef` reverts with
  `ERR_SELECTOR_NOT_FOUND_ON_TARGET` before any bond is taken. Fallback
  entries count as a single path symbol in the fingerprint, so varying their
  arbitrary 4 bytes cannot mint new findings. The PoC's `chain_id` must equal
  the program's target chain (`ERR_POC_CHAIN_MISMATCH`). Calls to other
  contracts (tokens, attacker helpers) are not ABI-checked; they are marked
  `external`.
* **Deterministic ground truth.** The contract disassembles each step's
  calldata identically on every node: selector, route, the function signature
  resolved from the verified ABI, 32-byte argument words and trailing bytes.
  This is calldata-structure disassembly against a verified interface. It is
  not bytecode analysis: arguments are split into words, not type-decoded,
  and nothing is executed on-chain. The LLM receives this, along with the
  program's validated execution paths, as ground truth.
* **Equivalence validator.** Each validator re-fetches the policy, re-runs the
  judgement and agrees only if the policy digest, the binary decision and the
  duplicate verdict match. For challenges, the outcome and revised tier must also match. Prose
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

## 5. Residual risks and mitigations

1. **Public on-chain exploit exposure.** A report is public from the moment it
   is submitted. `get_report` returns the full PoC trace, the description and
   the triage reasoning, and all of it stays in chain history permanently. A
   bug the project has not fixed is therefore disclosed to everyone at
   submission, including to attackers who can replay the calldata against the
   live target. ZeroDiscretion is a payout protocol, not a private disclosure
   channel. Mitigations, for projects:
   * **Emergency brakes on the target.** Targets should have a pausable module
     or circuit breaker (for example OpenZeppelin `Pausable` on value-moving
     functions, guarded by a fast multisig or guardian role). The project can
     then freeze the vulnerable path as soon as a report lands, within the
     challenge window and before an attacker acts. Payout does not depend on
     the pause: consensus judges the PoC against the verified interface and
     the pinned policy, not against live execution.
   * **Staging-first programs.** Run a program on a fork or testnet staging
     deployment with the same verified code, and state in the pinned policy
     that production is covered by the same program. Researchers can then
     prove findings against the staging copy while production is patched.
   * **Monitoring.** Watch the contract's `submit_vulnerability` transactions
     and treat every submission as a live incident.

   For researchers: submission is disclosure. Weigh this before filing against
   a target without an emergency pause.
2. **Deduplication limits.** The target-only path fingerprint is exact by
   design. Two different root causes that use the same sequence of target
   calls collide, and only the first is paid, even when their helper calls
   differ. Padding with extra calls into the target itself passes the
   deterministic gate and relies on the consensus duplicate verdict, which
   can be wrong in either direction. Validated paths are public so researchers can check
   before bonding.
3. **ABI source dependency.** Registration and `refresh_target_abi` depend on
   Sourcify availability. Outages revert (`ERR_TARGET_ABI_UNAVAILABLE`) and
   never slash. A target upgraded without a refresh keeps its old selector
   map until someone refreshes it; anyone can.
4. **LLM judgement risk.** Consensus can be wrong in both directions. The
   bonds, the one-shot challenge and GenLayer's native appeal process limit
   the damage, but they do not remove it.
5. **Mempool copying.** Submission is a single step with no commit-reveal. If
   an observer copies a PoC and gets it ordered first, the observer wins the
   duplicate check. GenLayer's per-contract FIFO ordering makes this hard but
   does not rule it out.
6. **Policy availability.** If the pinned policy becomes unreachable (for
   example the repository is deleted), submissions revert without slashing.
   The vault stays locked until the owner starts closure, and the closure
   notice gives researchers time to see this happen.
7. **Economic sizing.** The fixed 1 GEN and 2 GEN bonds are small against
   large vaults. Future versions should scale bonds with the tier and the vault
   size.

8. **Unsolicited programs and 0-day interception (third-party honeytrap).**
   Registration is permissionless, so anyone can open a program on a contract
   they do not control, for example a large ownerless or third-party
   protocol, and fund it just enough to attract submissions. Every PoC is
   public on submission (risk 1). The "sponsor" can then run the disclosed
   exploit against the real contract before its team knows about it, and the
   researcher's work turns into an attack. Mitigations:
   * **Sponsor authorization, checked at registration by web consensus.**
     Validators fetch the pinned SECURITY.md and read the target's on-chain
     `owner()` through a public RPC for the target chain. The program records
     a `sponsor_status`:
     - `OWNER_VERIFIED`: the target's `owner()` equals the registering
       address.
     - `POLICY_ATTESTED`: the pinned policy contains both
       `ZeroDiscretion-Sponsor: 0x<sponsor>` and
       `ZeroDiscretion-Target: <chain>:0x<target>`.
     - `UNVERIFIED_SPONSOR`: neither holds.
   * **Researcher guidance.** Submit only to programs with a verified sponsor
     badge. The frontend warns before any submission to an
     `UNVERIFIED_SPONSOR` program. Treat submitting to one as publishing a
     0-day.
   * **Limits, stated plainly.** `POLICY_ATTESTED` proves only that the sponsor
     controls the repository the policy lives in, not that this repository
     speaks for the target. Researchers must still check that it is the
     project's official repository. `OWNER_VERIFIED` is the strong signal,
     but it covers only targets with an `owner()` on a supported chain, and
     it is a snapshot taken at registration. Ownerless targets (such as
     WETH9) can never be owner-verified. Registration stays permissionless on
     purpose, because requiring owner consent would reintroduce the project
     veto for ownerless code. The flag informs the researcher; it does not
     gate them. Phase 2 encryption (section 6) removes the interception
     window entirely.

## 6. Phase 2 roadmap: encrypted commit-reveal

Risks 1 and 5 share a root cause: the PoC is plaintext at submission. Phase 2
replaces the single-step submission with an asymmetric, encrypted
commit-reveal:

1. **Commit.** The researcher encrypts the PoC to the validator set's
   threshold public key (for example a distributed-key-generation key shared
   among the active GenLayer validators) and submits
   `(ciphertext, commitment = keccak256(fingerprint, researcher, salt), bond)`.
   The commitment fixes priority and ownership without revealing the path.
2. **Private triage.** Validators jointly decrypt the ciphertext only inside
   the nondeterministic triage block. A threshold `t` of `n` shares is
   required, so no single node or project can read it early. They run the
   same selector gate, fingerprint check and consensus verdict, and publish
   only the verdict, the fingerprint and the severity.
3. **Timed reveal.** The plaintext PoC is released after the program owner has
   had a private window to patch or pause. The owner receives a copy encrypted
   to its registered key at validation time. Release happens at the end of the
   challenge window, or earlier if the owner acknowledges the fix. A rebuttal
   is still bound to the PoC hash, which the owner can check against its
   private copy.
4. **Mempool safety.** Copying a commitment is useless: it is bound to the
   researcher's address and salt, and priority is the commit order.

Open design questions: validator-set rotation during a pending report,
liveness if fewer than `t` shares are available (fall back to plaintext
reveal after a timeout), and how a GenVM nondeterministic block accesses
decryption shares without exposing them to the leader alone.
