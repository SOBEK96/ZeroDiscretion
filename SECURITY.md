# Security Policy - ZeroDiscretion Reference Program

> **Demonstration program.** This policy governs the reference bounty program
> that ZeroDiscretion seeds on the GenLayer Studio Next **testnet**. Its vault
> holds testnet GEN with no monetary value. The target below is used only
> because it is a public, ownerless, immutable contract with a Sourcify-verified
> ABI, which the protocol requires. This program is not affiliated with,
> endorsed by, or operated by the target's authors, and it is not a bounty
> offer for that contract.

The program's vault is bound to this file at a pinned commit, so these terms
cannot change after registration.

## Scope

| Asset | Address | Chain |
|---|---|---|
| WETH9 (reference target) | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | Ethereum mainnet (1) |

At registration, ZeroDiscretion pins the target's verified ABI by GenLayer web
consensus from Sourcify. Every PoC step that calls the target must use one of
its functions, for example `deposit()`, `withdraw(uint256)`,
`transfer(address,uint256)`, `transferFrom(address,address,uint256)` or
`approve(address,uint256)`. A step may also use an explicitly declared
`"route": "fallback"` entry, because the verified ABI has a `fallback()`.

## In scope

- Theft or permanent freezing of wrapped ether by an unprivileged caller.
- Withdrawal of more than a caller's recorded balance.
- Accounting corruption that breaks `totalSupply == address(this).balance`.

## Out of scope

- Findings that require a privileged role. WETH9 has none, so any claim that
  relies on one is invalid.
- Behavior that only reproduces against mocks, forks with altered bytecode, or
  sandboxed environments.
- Known ERC-20 design properties, such as the approve/transferFrom allowance
  race, and gas or style notes without impact.

## Severity

ZeroDiscretion's default matrix applies:

- **CRITICAL** - direct theft or permanent freezing of user funds.
- **HIGH** - temporary freezing of funds or theft of unclaimed yield.
- **MEDIUM** - griefing or state corruption without loss of funds.
- **LOW** - failure to deliver promised returns without loss of value.

## Rewards

The ZeroDiscretion vault pays rewards automatically, as a fixed share of the
available reserves (CRITICAL 50%, HIGH 20%, MEDIUM 7.5%, LOW 2%), after the
challenge window. No manual approval is involved. Each execution path is
rewarded once: duplicates are rejected by semantic fingerprint.

## Reporting vulnerabilities in ZeroDiscretion itself

To report a vulnerability in the ZeroDiscretion contract or frontend, open a
private security advisory on
https://github.com/SOBEK96/ZeroDiscretion/security/advisories.
