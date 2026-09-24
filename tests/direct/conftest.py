"""Shared helpers for ZeroDiscretion direct-mode tests.

Uses the genlayer-test pytest plugin fixtures (direct_vm, direct_deploy,
direct_alice, direct_bob, direct_charlie).

Direct mode does not credit gl.message.value to the contract balance and does
not debit it on emit_transfer, so the Chain helper mirrors native value flow
with direct_vm.deal(). That keeps the on-chain get_solvency() view (which reads
self.balance) meaningful: it must report `exact` after every step.
"""

import hashlib
import json
from datetime import datetime, timezone

import pytest
from eth_utils.crypto import keccak

CONTRACT = "contracts/zero_discretion.py"

GEN = 10**18
DAY = 86_400

PROGRAM_DEPOSIT = 100 * GEN
RESEARCHER_BOND = 1 * GEN
CHALLENGE_BOND = 2 * GEN
CHALLENGE_WINDOW = 7 * DAY
CLOSURE_NOTICE = 14 * DAY
PROTOCOL_FEE_BPS = 250
PAYOUT_BPS = {"LOW": 200, "MEDIUM": 750, "HIGH": 2_000, "CRITICAL": 5_000}

T0 = int(datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp())

COMMIT = "3f5a9c1e0b7d4a2f8e6c1b9d0a3e5f7c2b4d6e8a"
POLICY_URL = f"https://github.com/acme-defi/vault-core/blob/{COMMIT}/SECURITY.md"
RAW_POLICY_URL = f"https://raw.githubusercontent.com/acme-defi/vault-core/{COMMIT}/SECURITY.md"

TARGET = "0x1111111111111111111111111111111111111111"
TOKEN = "0x2222222222222222222222222222222222222222"

POLICY_TEXT = """# Acme Vault Security Policy
## Scope
- VaultCore at 0x1111111111111111111111111111111111111111 (chain 1)
## Out of scope
- Functions guarded by onlyOwner are intentional administrative roles.
## Rewards
Critical issues (direct theft of deposits) are paid from the ZeroDiscretion vault.
"""

WITHDRAW_SELECTOR = "0x2e1a7d4d"  # withdraw(uint256)
SET_FEE_SELECTOR = "0x69fe0e2d"   # setFee(uint256)
FAKE_SELECTOR = "0xdeadbeef"      # not a function of the target


def selector(signature: str) -> str:
    """Independent keccak (eth_utils) used to cross-check the contract's."""
    return "0x" + keccak(text=signature)[:4].hex()


# Functions exercised by variant PoCs: distinct selectors give distinct
# execution paths, hence distinct semantic fingerprints.
VARIANT_FUNCTIONS = [f"op{n}(uint256)" for n in range(16)]


def abi_entry(signature: str) -> dict:
    name, args = signature[:-1].split("(", 1)
    return {"type": "function", "name": name, "stateMutability": "nonpayable", "outputs": [],
            "inputs": [{"name": f"a{i}", "type": t} for i, t in enumerate(a for a in args.split(",") if a)]}


TARGET_ABI = [abi_entry(sig) for sig in ["deposit(uint256)", "withdraw(uint256)", "setFee(uint256)", *VARIANT_FUNCTIONS]] + [
    {"type": "event", "name": "Withdrawn", "inputs": [], "anonymous": False},
    {"type": "constructor", "inputs": []},
]


def sourcify_body(abi, address: str = TARGET, proxy_impls=None) -> str:
    return json.dumps({
        "abi": abi,
        "match": "match",
        "chainId": "1",
        "address": address,
        "proxyResolution": {"isProxy": bool(proxy_impls), "proxyType": "EIP1967Proxy" if proxy_impls else None,
                            "implementations": [{"address": a, "name": "Impl"} for a in (proxy_impls or [])]},
    })


def mock_sourcify(vm, address: str = TARGET, abi=None, status: int = 200, proxy_impls=None, chain: int = 1) -> None:
    body = sourcify_body(TARGET_ABI if abi is None else abi, address, proxy_impls) if status == 200 else '{"error":"not found"}'
    vm.mock_web(rf"sourcify\.dev/server/v2/contract/{chain}/{address.lower()}", {"status": status, "body": body})


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def word(n: int) -> str:
    return format(n, "064x")


def make_poc(target: str = TARGET, steps=None, chain_id: int = 1) -> str:
    if steps is None:
        steps = [
            {"to": TOKEN, "calldata": "0x095ea7b3" + word(int(TARGET, 16)) + word(2**256 - 1),
             "value": "0", "expect": "approve vault"},
            {"to": target, "calldata": WITHDRAW_SELECTOR + word(10**24),
             "value": "0", "expect": "withdraw more than deposited; no balance check"},
        ]
    return json.dumps({
        "target": target,
        "chain_id": chain_id,
        "invariant_broken": "user can withdraw more than their recorded deposit",
        "steps": steps,
    })


def variant_poc(n: int, prefix_steps=()) -> str:
    """A valid PoC whose execution path differs from every other variant."""
    steps = list(prefix_steps) + [{"to": TARGET, "calldata": selector(VARIANT_FUNCTIONS[n]) + word(n + 1), "value": "0"}]
    return make_poc(steps=steps)


def canonical_hash(poc_trace: str) -> str:
    obj = json.loads(poc_trace)
    steps = []
    for s in obj["steps"]:
        steps.append({"to": s["to"].lower(), "calldata": s["calldata"].lower(),
                      "value": str(int(s.get("value", "0"))), "expect": s.get("expect", ""),
                      "route": s.get("route", "selector")})
    normalized = {"target": obj["target"].lower(), "chain_id": obj["chain_id"],
                  "invariant_broken": obj["invariant_broken"].strip(), "steps": steps}
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def make_rebuttal(poc_hash: str, steps=(1,), selectors=(WITHDRAW_SELECTOR,),
                  rebuttal_type: str = "INTENDED_ADMIN_ROLE",
                  argument: str = "Step 1 calls withdraw on the vault which is gated by the "
                                  "onlyOwner administrative role in the deployed bytecode.") -> str:
    return json.dumps({
        "poc_hash": poc_hash,
        "rebuttal_type": rebuttal_type,
        "disputed_steps": list(steps),
        "disputed_selectors": list(selectors),
        "argument": argument,
    })


# --- Mocks -------------------------------------------------------------------


def _llm(payload: dict) -> str:
    # Double-encoded: the harness json.loads() the mock once, and
    # exec_prompt(response_format="json") decodes the resulting string again.
    return json.dumps(json.dumps(payload))


def mock_policy(vm, text: str = POLICY_TEXT, status: int = 200) -> None:
    vm.mock_web(r"raw\.githubusercontent\.com/acme-defi/vault-core/", {"status": status, "body": text})


def mock_triage(vm, reproducible=True, in_scope=True, assessed="CRITICAL", duplicate=False,
                reasoning="Step 1 drains the vault; no balance check.") -> None:
    vm.mock_llm(r"ZERO_DISCRETION_TRIAGE", _llm({
        "reproducible": reproducible, "in_scope": in_scope, "duplicate_of_prior": duplicate,
        "assessed_severity": assessed, "reasoning": reasoning,
    }))


def mock_rebuttal(vm, bound=True, outcome="DISMISSED", revised="NONE",
                  reasoning="The withdraw path has no owner guard.") -> None:
    vm.mock_llm(r"ZERO_DISCRETION_REBUTTAL", _llm({
        "bound": bound, "outcome": outcome, "revised_severity": revised, "reasoning": reasoning,
    }))


def remock(vm, *, policy=None, triage=None, rebuttal=None, sourcify=None) -> None:
    """Reset every mock and install fresh ones (first registered match wins)."""
    vm.clear_mocks()
    mock_sourcify(vm, **(sourcify or {}))
    mock_policy(vm, **(policy or {}))
    mock_triage(vm, **(triage or {}))
    mock_rebuttal(vm, **(rebuttal or {}))


# --- Chain mirror ------------------------------------------------------------


class Chain:
    """Drives the contract while mirroring native GEN into the VM balance."""

    def __init__(self, vm, contract):
        self.vm = vm
        self.c = contract
        self.addr = vm._contract_address

    def balance(self) -> int:
        return self.vm._balances.get(self.addr, 0)

    def call(self, sender, method: str, *args, value: int = 0):
        self.vm.sender = sender
        self.vm.value = value
        try:
            out = getattr(self.c, method)(*args)
        finally:
            self.vm.value = 0
        if value:
            self.vm.deal(self.addr, self.balance() + value)
        if method in ("withdraw", "withdraw_treasury"):
            self.vm.deal(self.addr, self.balance() - int(out))
        return out

    def warp(self, ts: int) -> None:
        self.vm.warp(iso(ts))

    def key(self, who) -> str:
        return "0x" + bytes(who).hex() if isinstance(who, (bytes, bytearray)) else str(who).lower()

    # Lifecycle shortcuts ------------------------------------------------

    def register(self, owner, deposit: int = PROGRAM_DEPOSIT, min_severity: str = "LOW",
                 target: str = TARGET, chain: int = 1) -> int:
        return self.call(owner, "register_bounty_program", target, POLICY_URL, min_severity, chain, value=deposit)

    def submit(self, researcher, program_id: int, severity: str = "CRITICAL",
               poc: str | None = None, bond: int = RESEARCHER_BOND, description: str = "Unchecked withdraw.") -> int:
        return self.call(researcher, "submit_vulnerability", program_id, severity,
                         poc if poc is not None else make_poc(), description, value=bond)

    def challenge(self, owner, report_id: int, rebuttal: str, bond: int = CHALLENGE_BOND) -> str:
        return self.call(owner, "challenge_vulnerability", report_id, rebuttal, value=bond)

    def assert_invariant(self) -> dict:
        acc = self.c.get_accounting()
        sol = self.c.get_solvency()
        liabilities = (acc["vault_reserves"] + acc["bonded_researcher_funds"]
                       + acc["bonded_project_funds"] + acc["claimable_bounties"] + acc["treasury_fees"])
        assert liabilities == acc["total_liabilities"]
        assert liabilities == acc["total_inflows"] - acc["total_outflows"]
        assert sol["balance"] == self.balance()
        assert sol["exact"], f"balance {sol['balance']} != liabilities {sol['total_liabilities']}"
        return acc


@pytest.fixture
def chain(direct_vm, direct_deploy, direct_alice):
    # direct_alice deploys and is therefore the governor.
    direct_vm.warp(iso(T0))
    direct_vm.sender = direct_alice
    contract = direct_deploy(CONTRACT)
    remock(direct_vm)
    return Chain(direct_vm, contract)
