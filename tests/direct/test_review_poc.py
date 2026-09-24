"""Regression tests for the security review findings.

Finding 1 - dedupe bypass: the old dedupe hashed the whole PoC, free text
included, so rewording one `expect` string produced a "new" report and a
second payout for the same vulnerability. Deduplication now uses a semantic
fingerprint of the execution path.

Finding 2 - unverified disassembly: selectors were split out of calldata but
never checked against the target. Registration now pins the target's
Sourcify-verified ABI by web consensus, and every target step must enter
through a function of that ABI (or a declared, real fallback).

Every scenario also re-checks the ledger invariant after rejected and
duplicate submissions.

Roles: direct_alice deploys (governor), direct_bob runs the program,
direct_charlie is the whitehat researcher.
"""

import json

from eth_utils.crypto import keccak

from conftest import (
    FAKE_SELECTOR,
    GEN,
    PAYOUT_BPS,
    POLICY_TEXT,
    POLICY_URL,
    PROGRAM_DEPOSIT,
    RESEARCHER_BOND,
    TARGET,
    TARGET_ABI,
    TOKEN,
    VARIANT_FUNCTIONS,
    WITHDRAW_SELECTOR,
    abi_entry,
    attested_policy,
    make_poc,
    mock_owner,
    mock_policy,
    mock_sourcify,
    mock_triage,
    remock,
    selector,
    variant_poc,
    word,
)

TARGET2 = "0x3333333333333333333333333333333333333333"  # has a fallback()
PROXY = "0x4444444444444444444444444444444444444444"
IMPL = "0x5555555555555555555555555555555555555555"
UNVERIFIED = "0x6666666666666666666666666666666666666666"


def reworded_duplicate() -> str:
    """Same execution path as make_poc(): every free-text field rewritten,
    amounts changed, JSON reformatted and hex re-cased."""
    return json.dumps({
        "target": TARGET.upper().replace("0X", "0x"),
        "chain_id": 1,
        "invariant_broken": "a completely different narrative for the very same bug",
        "steps": [
            {"to": TOKEN, "calldata": "0x095EA7B3" + word(int(TARGET, 16)) + word(5), "value": "0",
             "expect": "rephrased approval step"},
            {"to": TARGET, "calldata": WITHDRAW_SELECTOR + word(12345), "value": "0",
             "expect": "rephrased: withdraw an arbitrary amount"},
        ],
    }, indent=3)


def path_fingerprint(pairs) -> str:
    return keccak(text=json.dumps(pairs, separators=(",", ":"))).hex()


def snapshot(chain) -> tuple:
    return chain.c.get_accounting(), chain.c.get_protocol_params()["next_report_id"]


# ---------------------------------------------------------------------------
# Finding 1: semantic deduplication
# ---------------------------------------------------------------------------


def test_finding1_reworded_trace_is_rejected_as_duplicate(chain, direct_alice, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    a = chain.submit(direct_charlie, pid, "CRITICAL")
    assert chain.c.get_report(a)["status"] == "VALIDATED"
    locked_after_a = chain.c.get_program(pid)["locked"]
    before = snapshot(chain)

    # Exploit attempt: the same vulnerability with reworded text, new
    # amounts and different formatting, from the same researcher and from a
    # second account.
    for who in (direct_charlie, direct_alice):
        with chain.vm.expect_revert("ERR_DUPLICATE_VULNERABILITY"):
            chain.submit(who, pid, "CRITICAL", poc=reworded_duplicate(), description="Totally new finding!")

    assert snapshot(chain) == before
    assert chain.c.get_program(pid)["locked"] == locked_after_a
    chain.assert_invariant()


def test_finding1_fingerprint_is_keccak_of_the_execution_path(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    report = chain.c.get_report(rid)
    # Target-only: the token approval step is not part of the fingerprint.
    expected = path_fingerprint([[TARGET, WITHDRAW_SELECTOR]])
    assert report["fingerprint"] == expected
    assert report["call_path"] == f"{TOKEN}.0x095ea7b3 > target.withdraw(uint256)"
    assert chain.c.get_validated_fingerprints(pid) == [
        {"fingerprint": expected, "report_id": rid, "call_path": report["call_path"]}
    ]


def test_finding1_distinct_execution_path_is_a_new_finding(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    a = chain.submit(direct_charlie, pid, "CRITICAL")
    b = chain.submit(direct_charlie, pid, "HIGH", poc=variant_poc(0))
    assert chain.c.get_report(b)["status"] == "VALIDATED"
    listed = chain.c.get_validated_fingerprints(pid)
    assert [x["report_id"] for x in listed] == [b, a]  # newest first
    chain.assert_invariant()


def test_finding1_non_target_padding_is_a_deterministic_duplicate(chain, direct_bob, direct_charlie):
    """Target-only fingerprint: inserting arbitrary external calls (token
    balanceOf / approvals on dummy addresses) around the same target step
    sequence cannot change the fingerprint, so the padded copy is rejected
    before consensus, with no bond taken."""
    pid = chain.register(direct_bob)
    a = chain.submit(direct_charlie, pid, "CRITICAL")
    assert chain.c.get_report(a)["status"] == "VALIDATED"
    dummy = "0x7777777777777777777777777777777777777777"
    padded = make_poc(steps=[
        {"to": dummy, "calldata": "0x70a08231" + word(1), "value": "0", "expect": "balanceOf on a dummy token"},
        {"to": TOKEN, "calldata": "0x18160ddd", "value": "0", "expect": "totalSupply"},
        {"to": TARGET, "calldata": WITHDRAW_SELECTOR + word(999), "value": "0"},
        {"to": dummy, "calldata": "0xa9059cbb" + word(1) + word(2), "value": "0", "expect": "transfer out"},
    ])
    before = snapshot(chain)
    with chain.vm.expect_revert("ERR_DUPLICATE_VULNERABILITY"):
        chain.submit(direct_charlie, pid, "CRITICAL", poc=padded)
    assert snapshot(chain) == before
    chain.assert_invariant()


def test_poc_without_target_calls_is_rejected(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    with chain.vm.expect_revert("ERR_NO_TARGET_CALLS"):
        chain.submit(direct_charlie, pid, "CRITICAL",
                     poc=make_poc(steps=[{"to": TOKEN, "calldata": "0x70a08231" + word(1), "value": "0"}]))


def test_finding1_target_padding_is_caught_by_consensus_duplicate_verdict(chain, direct_vm, direct_bob, direct_charlie):
    """Padding with an extra call INTO the target (for example a view such
    as op5) does change the target-only fingerprint. The prior validated
    paths are in the triage context, and a consensus duplicate verdict fails
    the report closed (bond slashed, nothing locked)."""
    pid = chain.register(direct_bob)
    a = chain.submit(direct_charlie, pid, "CRITICAL")
    fp_a = chain.c.get_report(a)["fingerprint"]

    padded = make_poc(steps=[
        {"to": TARGET, "calldata": selector("op5(uint256)") + word(1), "value": "0", "expect": "incidental read"},
        {"to": TOKEN, "calldata": "0x095ea7b3" + word(int(TARGET, 16)) + word(1), "value": "0"},
        {"to": TARGET, "calldata": WITHDRAW_SELECTOR + word(10**24), "value": "0"},
    ])

    direct_vm.clear_mocks()
    mock_owner(direct_vm)
    mock_sourcify(direct_vm)
    mock_policy(direct_vm)
    # Matches only if report A's fingerprint was placed in the triage prompt.
    direct_vm.mock_llm(rf"PREVIOUSLY VALIDATED[\s\S]*{fp_a}", json.dumps(json.dumps({
        "reproducible": True, "in_scope": True, "duplicate_of_prior": True,
        "assessed_severity": "CRITICAL", "reasoning": f"Same root cause as report #{a}.",
    })))
    mock_triage(direct_vm)

    treasury_before = chain.c.get_accounting()["treasury_fees"]
    locked_before = chain.c.get_program(pid)["locked"]
    b = chain.submit(direct_charlie, pid, "CRITICAL", poc=padded)

    report = chain.c.get_report(b)
    assert report["status"] == "REJECTED"
    assert report["rejection_reason"] == "ERR_DUPLICATE_VULNERABILITY"
    assert report["bounty"] == 0
    assert chain.c.get_program(pid)["locked"] == locked_before
    assert chain.c.get_accounting()["treasury_fees"] == treasury_before + RESEARCHER_BOND
    assert len(chain.c.get_validated_fingerprints(pid)) == 1
    chain.assert_invariant()


def test_finding1_duplicate_verdict_is_part_of_validator_agreement(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    chain.submit(direct_charlie, pid, "CRITICAL")
    chain.submit(direct_charlie, pid, "HIGH", poc=variant_poc(1))
    assert direct_vm.run_validator() is True
    leader = dict(direct_vm._captured_validators[-1][0])
    leader["duplicate"] = True
    leader["accepted"] = False
    assert direct_vm.run_validator(leader_result=leader) is False


def test_first_report_has_no_prior_to_duplicate(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    remock(direct_vm, triage={"duplicate": True})  # ignored: nothing to duplicate yet
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    assert chain.c.get_report(rid)["status"] == "VALIDATED"


# ---------------------------------------------------------------------------
# Finding 2: target ABI verification
# ---------------------------------------------------------------------------


def test_finding2_fake_selector_on_target_is_rejected(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    before = snapshot(chain)
    for steps in (
        [{"to": TARGET, "calldata": FAKE_SELECTOR + word(1), "value": "0"}],
        [{"to": TARGET, "calldata": WITHDRAW_SELECTOR + word(1), "value": "0"},
         {"to": TARGET, "calldata": FAKE_SELECTOR, "value": "0"}],
    ):
        with chain.vm.expect_revert("ERR_SELECTOR_NOT_FOUND_ON_TARGET"):
            chain.submit(direct_charlie, pid, "CRITICAL", poc=make_poc(steps=steps))
    assert snapshot(chain) == before
    chain.assert_invariant()


def test_finding2_disassembly_resolves_target_functions(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    disasm = chain.c.get_disassembly(rid)
    assert disasm[0]["function"] == "external"  # helper-contract calls are not ABI-checked
    assert disasm[1]["function"] == "withdraw(uint256)"
    assert disasm[1]["route"] == "selector"


def test_finding2_program_pins_the_verified_abi(chain, direct_bob):
    pid = chain.register(direct_bob)
    program = chain.c.get_program(pid)
    assert program["abi_source"] == "sourcify"
    assert program["target_chain_id"] == 1
    assert program["target_has_fallback"] is False
    # The contract's own keccak agrees with an independent implementation.
    for sig in ("deposit(uint256)", "withdraw(uint256)", "setFee(uint256)", *VARIANT_FUNCTIONS):
        assert program["target_abi"][selector(sig)] == sig
    assert len(program["target_abi"]) == 3 + len(VARIANT_FUNCTIONS)


def test_finding2_tuple_and_array_signatures_hash_canonically(chain, direct_vm, direct_bob):
    abi = [{
        "type": "function", "name": "execute", "stateMutability": "nonpayable", "outputs": [],
        "inputs": [
            {"name": "calls", "type": "tuple[]", "components": [
                {"name": "to", "type": "address"},
                {"name": "data", "type": "bytes"},
                {"name": "inner", "type": "tuple", "components": [{"name": "x", "type": "uint256[2]"}]},
            ]},
            {"name": "salt", "type": "bytes32"},
        ],
    }]
    remock(direct_vm, sourcify={"abi": abi})
    pid = chain.register(direct_bob)
    sig = "execute((address,bytes,(uint256[2]))[],bytes32)"
    assert chain.c.get_program(pid)["target_abi"] == {selector(sig): sig}


def test_finding2_unverified_target_cannot_register(chain, direct_vm, direct_bob):
    for status, err in ((404, "ERR_TARGET_NOT_VERIFIED"), (400, "ERR_TARGET_NOT_VERIFIED"),
                        (503, "ERR_TARGET_ABI_UNAVAILABLE"), (429, "ERR_TARGET_ABI_UNAVAILABLE")):
        remock(direct_vm, sourcify={"status": status})
        with chain.vm.expect_revert(err):
            chain.register(direct_bob)
    for abi in ([], [{"type": "event", "name": "E", "inputs": []}], {"not": "a list"},
                [{"type": "function", "name": "bad name", "inputs": []}]):
        remock(direct_vm, sourcify={"abi": abi})
        with chain.vm.expect_revert("ERR_TARGET_NOT_VERIFIED"):
            chain.register(direct_bob)
    assert chain.c.get_protocol_params()["next_program_id"] == 1
    assert chain.c.get_accounting()["total_inflows"] == 0
    chain.assert_invariant()


def test_finding2_invalid_chain_id_is_rejected(chain, direct_bob):
    for bad in (0, -1, 2**32):
        with chain.vm.expect_revert("ERR_INVALID_CHAIN"):
            chain.call(direct_bob, "register_bounty_program", TARGET, POLICY_URL, "LOW", bad, value=PROGRAM_DEPOSIT)


def test_poc_must_target_the_programs_chain(chain, direct_vm, direct_bob, direct_charlie):
    mock_sourcify(direct_vm, chain=137)
    mock_owner(direct_vm, chain_rpc=r"polygon-bor-rpc\.publicnode\.com")
    pid = chain.register(direct_bob, chain=137)
    assert chain.c.get_program(pid)["target_chain_id"] == 137
    with chain.vm.expect_revert("ERR_POC_CHAIN_MISMATCH"):
        chain.submit(direct_charlie, pid, "CRITICAL")  # make_poc() says chain 1
    rid = chain.submit(direct_charlie, pid, "CRITICAL", poc=make_poc(chain_id=137))
    assert chain.c.get_report(rid)["status"] == "VALIDATED"


def test_fallback_route_must_be_declared_and_real(chain, direct_vm, direct_bob, direct_charlie):
    # Program 1: target without fallback.
    p1 = chain.register(direct_bob)
    fallback_step = [{"to": TARGET, "calldata": FAKE_SELECTOR, "value": "0", "route": "fallback"}]
    with chain.vm.expect_revert("ERR_SELECTOR_NOT_FOUND_ON_TARGET"):
        chain.submit(direct_charlie, p1, "CRITICAL", poc=make_poc(steps=fallback_step))

    # Program 2: target whose verified ABI has a fallback().
    mock_sourcify(direct_vm, address=TARGET2, abi=[abi_entry("withdraw(uint256)"), {"type": "fallback", "stateMutability": "payable"}])
    p2 = chain.register(direct_bob, target=TARGET2)
    assert chain.c.get_program(p2)["target_has_fallback"] is True

    def poc(sel, route=None):
        step = {"to": TARGET2, "calldata": sel + word(7), "value": "0"}
        if route:
            step["route"] = route
        return make_poc(target=TARGET2, steps=[step])

    # An undeclared unknown selector is still rejected, even with a fallback.
    with chain.vm.expect_revert("ERR_SELECTOR_NOT_FOUND_ON_TARGET"):
        chain.submit(direct_charlie, p2, "CRITICAL", poc=poc(FAKE_SELECTOR))
    # Declaring a real function as a fallback entry is malformed.
    with chain.vm.expect_revert("ERR_MALFORMED_POC"):
        chain.submit(direct_charlie, p2, "CRITICAL", poc=poc(WITHDRAW_SELECTOR, "fallback"))
    # A declared fallback entry on a target that has one is admitted...
    rid = chain.submit(direct_charlie, p2, "CRITICAL", poc=poc(FAKE_SELECTOR, "fallback"))
    report = chain.c.get_report(rid)
    assert report["status"] == "VALIDATED"
    assert report["call_path"] == "target.fallback()"
    assert chain.c.get_disassembly(rid)[0]["function"] == "fallback()"
    # ...and varying the arbitrary 4 bytes does not mint a new fingerprint.
    with chain.vm.expect_revert("ERR_DUPLICATE_VULNERABILITY"):
        chain.submit(direct_charlie, p2, "CRITICAL", poc=poc("0x12345678", "fallback"))
    chain.assert_invariant()


def test_proxy_target_resolves_implementation_abi(chain, direct_vm, direct_bob, direct_charlie):
    proxy_abi = [abi_entry("upgradeTo(address)"), {"type": "fallback", "stateMutability": "payable"}]
    mock_sourcify(direct_vm, address=PROXY, abi=proxy_abi, proxy_impls=[IMPL])
    mock_sourcify(direct_vm, address=IMPL, abi=[abi_entry("withdraw(uint256)")])
    pid = chain.register(direct_bob, target=PROXY)
    program = chain.c.get_program(pid)
    assert set(program["target_abi"].values()) == {"upgradeTo(address)", "withdraw(uint256)"}
    # The proxy's fallback only delegates; it is not an open fallback entry.
    assert program["target_has_fallback"] is False
    rid = chain.submit(direct_charlie, pid, "CRITICAL", poc=make_poc(
        target=PROXY, steps=[{"to": PROXY, "calldata": WITHDRAW_SELECTOR + word(1), "value": "0"}]))
    assert chain.c.get_report(rid)["status"] == "VALIDATED"


def test_proxy_with_unverified_implementation_cannot_register(chain, direct_vm, direct_bob):
    mock_sourcify(direct_vm, address=PROXY, abi=[abi_entry("upgradeTo(address)")], proxy_impls=[UNVERIFIED])
    mock_sourcify(direct_vm, address=UNVERIFIED, status=404)
    with chain.vm.expect_revert("ERR_TARGET_NOT_VERIFIED"):
        chain.register(direct_bob, target=PROXY)


def test_refresh_target_abi_picks_up_an_upgrade(chain, direct_vm, direct_alice, direct_bob, direct_charlie):
    remock(direct_vm, sourcify={"abi": [abi_entry("withdraw(uint256)")]})
    pid = chain.register(direct_bob)
    new_fn = make_poc(steps=[{"to": TARGET, "calldata": selector("op15(uint256)") + word(1), "value": "0"}])
    with chain.vm.expect_revert("ERR_SELECTOR_NOT_FOUND_ON_TARGET"):
        chain.submit(direct_charlie, pid, "CRITICAL", poc=new_fn)
    # The implementation is upgraded; anyone (here the governor) re-pins the
    # ABI through web consensus. The project cannot block this.
    remock(direct_vm)
    assert chain.call(direct_alice, "refresh_target_abi", pid) == len([e for e in TARGET_ABI if e["type"] == "function"])
    rid = chain.submit(direct_charlie, pid, "CRITICAL", poc=new_fn)
    assert chain.c.get_report(rid)["status"] == "VALIDATED"
    chain.assert_invariant()


def test_abi_consensus_validator_rejects_a_forged_selector_set(chain, direct_vm, direct_bob):
    chain.register(direct_bob)
    # Registration runs two consensus blocks: ABI (index -2), then sponsor (-1).
    assert direct_vm.run_validator(index=-2) is True
    forged = dict(direct_vm._captured_validators[-2][0])
    forged["functions"] = dict(forged["functions"], **{FAKE_SELECTOR: "backdoor()"})
    assert direct_vm.run_validator(leader_result=forged, index=-2) is False
    forged = dict(direct_vm._captured_validators[-2][0], fallback=True)
    assert direct_vm.run_validator(leader_result=forged, index=-2) is False


# ---------------------------------------------------------------------------
# Ledger invariant across rejected and duplicate submissions
# ---------------------------------------------------------------------------


def test_ledger_invariant_after_rejected_and_duplicate_submissions(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    chain.assert_invariant()

    a = chain.submit(direct_charlie, pid, "CRITICAL")                       # validated
    bounty = chain.c.get_report(a)["bounty"]
    assert bounty == PROGRAM_DEPOSIT * PAYOUT_BPS["CRITICAL"] // 10_000
    chain.assert_invariant()

    with chain.vm.expect_revert("ERR_DUPLICATE_VULNERABILITY"):             # exact path duplicate
        chain.submit(direct_charlie, pid, "CRITICAL", poc=reworded_duplicate())
    chain.assert_invariant()

    with chain.vm.expect_revert("ERR_SELECTOR_NOT_FOUND_ON_TARGET"):        # fake selector
        chain.submit(direct_charlie, pid, "HIGH",
                     poc=make_poc(steps=[{"to": TARGET, "calldata": FAKE_SELECTOR, "value": "0"}]))
    chain.assert_invariant()

    remock(direct_vm, triage={"reproducible": False})                        # triage rejection
    r1 = chain.submit(direct_charlie, pid, "HIGH", poc=variant_poc(2))
    assert chain.c.get_report(r1)["rejection_reason"] == "TRIAGE_REJECTED"
    chain.assert_invariant()

    remock(direct_vm, triage={"duplicate": True})                            # consensus duplicate
    r2 = chain.submit(direct_charlie, pid, "HIGH", poc=variant_poc(3), bond=2 * GEN)
    assert chain.c.get_report(r2)["rejection_reason"] == "ERR_DUPLICATE_VULNERABILITY"
    acc = chain.assert_invariant()

    # Only report A holds funds; both rejected bonds were slashed.
    assert acc["vault_reserves"] == PROGRAM_DEPOSIT
    assert acc["bonded_researcher_funds"] == RESEARCHER_BOND
    assert acc["treasury_fees"] == RESEARCHER_BOND + 2 * GEN
    assert chain.c.get_program(pid)["locked"] == bounty
    assert chain.balance() == PROGRAM_DEPOSIT + 2 * RESEARCHER_BOND + 2 * GEN
    assert [x["report_id"] for x in chain.c.get_validated_fingerprints(pid)] == [a]



# ---------------------------------------------------------------------------
# Unsolicited programs: sponsor authorization
# ---------------------------------------------------------------------------


def test_sponsor_is_owner_verified_when_target_owner_matches(chain, direct_vm, direct_bob):
    bob = chain.key(direct_bob)
    remock(direct_vm, owner=bob)
    pid = chain.register(direct_bob)
    program = chain.c.get_program(pid)
    assert program["sponsor_status"] == "OWNER_VERIFIED"
    assert program["target_owner"] == bob


def test_sponsor_is_policy_attested_when_security_md_names_sponsor_and_target(chain, direct_vm, direct_bob):
    remock(direct_vm, policy={"text": attested_policy(chain.key(direct_bob))})
    pid = chain.register(direct_bob)
    program = chain.c.get_program(pid)
    assert program["sponsor_status"] == "POLICY_ATTESTED"
    assert program["target_owner"] == ""


def test_unsolicited_program_is_flagged_unverified(chain, direct_vm, direct_alice, direct_bob):
    """A third party (bob) opens a program on a contract owned by someone
    else (alice), with a policy that attests a different sponsor and a
    policy that attests bob for a different target: all UNVERIFIED."""
    alice = chain.key(direct_alice)
    other_target = "0x8888888888888888888888888888888888888888"
    for policy in (POLICY_TEXT, attested_policy(alice), attested_policy(chain.key(direct_bob), target=other_target),
                   attested_policy(chain.key(direct_bob), chain=137)):
        remock(direct_vm, owner=alice, policy={"text": policy})
        pid = chain.register(direct_bob)
        assert chain.c.get_program(pid)["sponsor_status"] == "UNVERIFIED_SPONSOR"
    chain.assert_invariant()


def test_registration_pins_policy_digest_and_rejects_unreachable_policy(chain, direct_vm, direct_bob):
    import hashlib

    pid = chain.register(direct_bob)
    assert chain.c.get_program(pid)["policy_digest"] == hashlib.sha256(POLICY_TEXT.encode()).hexdigest()
    remock(direct_vm, policy={"status": 404})
    with chain.vm.expect_revert("ERR_POLICY_UNAVAILABLE"):
        chain.register(direct_bob)
    assert chain.c.get_protocol_params()["next_program_id"] == 2


def test_sponsor_consensus_validator_rejects_forged_attestation(chain, direct_vm, direct_bob):
    chain.register(direct_bob)
    assert direct_vm.run_validator() is True
    forged = dict(direct_vm._captured_validators[-1][0], attested=True)
    assert direct_vm.run_validator(leader_result=forged) is False
    forged = dict(direct_vm._captured_validators[-1][0], owner_check="OK", owner=chain.key(direct_bob))
    assert direct_vm.run_validator(leader_result=forged) is False


def test_sponsor_resolution_explicit_owner_mismatch_blocks_attestation(chain, direct_vm, direct_bob):
    """An attacker hosts a SECURITY.md that attests themselves for a target
    that HAS an explicit owner. The owner mismatch must win: the program is
    UNVERIFIED_SPONSOR, never POLICY_ATTESTED."""
    owner = "0x1111111111111111111111111111111111111111"
    caller = type(direct_bob)("0x2222222222222222222222222222222222222222")
    remock(direct_vm, owner=owner, policy={"text": attested_policy("0x2222222222222222222222222222222222222222")})
    pid = chain.register(caller)
    program = chain.c.get_program(pid)
    assert program["sponsor_status"] == "UNVERIFIED_SPONSOR"
    assert program["sponsor_status"] != "POLICY_ATTESTED"
    assert program["target_owner"] == owner
    chain.assert_invariant()


def test_attestation_counts_only_without_an_explicit_owner(chain, direct_vm, direct_bob):
    bob = chain.key(direct_bob)
    # owner() reverts / returns empty: attestation applies.
    remock(direct_vm, owner=None, policy={"text": attested_policy(bob)})
    assert chain.c.get_program(chain.register(direct_bob))["sponsor_status"] == "POLICY_ATTESTED"
    # Chain without a supported RPC (56): attestation applies.
    remock(direct_vm, sourcify={"chain": 56}, policy={"text": attested_policy(bob, chain=56)})
    assert chain.c.get_program(chain.register(direct_bob, chain=56))["sponsor_status"] == "POLICY_ATTESTED"
    # Explicit owner equal to the sponsor: owner-verified, attestation irrelevant.
    remock(direct_vm, owner=bob, policy={"text": attested_policy(bob)})
    assert chain.c.get_program(chain.register(direct_bob))["sponsor_status"] == "OWNER_VERIFIED"


def test_failed_owner_lookup_reverts_instead_of_trusting_attestation(chain, direct_vm, direct_bob):
    remock(direct_vm, policy={"text": attested_policy(chain.key(direct_bob))})
    direct_vm.clear_mocks()
    mock_sourcify(direct_vm)
    mock_policy(direct_vm, text=attested_policy(chain.key(direct_bob)))
    direct_vm.mock_web(r"ethereum-rpc\.publicnode\.com", {"method": "POST", "status": 503, "body": "busy"})
    with chain.vm.expect_revert("ERR_OWNER_CHECK_UNAVAILABLE"):
        chain.register(direct_bob)
    assert chain.c.get_protocol_params()["next_program_id"] == 1
    assert chain.c.get_accounting()["total_inflows"] == 0
    chain.assert_invariant()
