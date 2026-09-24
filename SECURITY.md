# Security Policy - ZeroDiscretion Reference Program

This policy governs the reference bounty program that ZeroDiscretion seeds on
GenLayer Studio Next. The program's vault is bound to this file at a pinned
commit, so the terms below cannot change after registration.

## Scope

| Asset | Address | Chain |
|---|---|---|
| MockVault (reference target) | `0x0000000000000000000000000000000000c0ffee` | 1 |

MockVault is a reference deposit vault exposing `deposit(uint256)`,
`withdraw(uint256)` and the administrative `setFee(uint256)`.

## In scope

- Theft or permanent freezing of deposited funds by an unprivileged caller.
- Withdrawal of more than a caller's recorded deposit.
- Accounting corruption that breaks `totalAssets == sum(deposits)`.

## Out of scope

- Functions guarded by `onlyOwner` (for example `setFee`) are intentional
  administrative roles. Findings that require the owner key are out of scope.
- Behavior that only reproduces against mocks, forks with altered bytecode, or
  sandboxed environments.
- Gas optimizations, style issues and best-practice notes without impact.

## Severity

ZeroDiscretion's default matrix applies:

- **CRITICAL** - direct theft or permanent freezing of user funds.
- **HIGH** - temporary freezing of funds or theft of unclaimed yield.
- **MEDIUM** - griefing or state corruption without loss of funds.
- **LOW** - failure to deliver promised returns without loss of value.

## Rewards

Rewards are paid automatically by the ZeroDiscretion vault as a fixed share of
the available reserves (CRITICAL 50%, HIGH 20%, MEDIUM 7.5%, LOW 2%) after the
challenge window. No manual approval is involved.

## Reporting vulnerabilities in ZeroDiscretion itself

To report a vulnerability in the ZeroDiscretion contract or frontend, open a
private security advisory on
https://github.com/SOBEK96/ZeroDiscretion/security/advisories.
