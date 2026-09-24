"""End-to-end lifecycle of a ZeroDiscretion bounty in direct mode.

Roles: direct_alice deploys (governor), direct_bob runs the program,
direct_charlie is the whitehat researcher.
"""

from conftest import (
    CHALLENGE_BOND,
    CHALLENGE_WINDOW,
    CLOSURE_NOTICE,
    GEN,
    PAYOUT_BPS,
    PROGRAM_DEPOSIT,
    PROTOCOL_FEE_BPS,
    RAW_POLICY_URL,
    RESEARCHER_BOND,
    T0,
    TARGET,
    canonical_hash,
    make_poc,
    make_rebuttal,
    mock_policy,
    mock_triage,
    remock,
)

DAY_HALF = 43_200


def test_happy_path_register_submit_validate_lapse_payout(chain, direct_alice, direct_bob, direct_charlie):
    # 1. Program registration.
    pid = chain.register(direct_bob)
    assert pid == 1
    program = chain.c.get_program(pid)
    assert program["owner"] == chain.key(direct_bob)
    assert program["target_address"] == TARGET
    assert program["policy_url"] == RAW_POLICY_URL
    assert program["available"] == PROGRAM_DEPOSIT
    assert program["status"] == "ACTIVE"
    chain.assert_invariant()

    # 2. Bonded submission, 3. consensus validation (same transaction).
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    report = chain.c.get_report(rid)
    expected_bounty = PROGRAM_DEPOSIT * PAYOUT_BPS["CRITICAL"] // 10_000
    assert report["status"] == "VALIDATED"
    assert report["awarded_severity"] == "CRITICAL"
    assert report["bounty"] == expected_bounty
    assert report["researcher_bond"] == RESEARCHER_BOND
    assert report["unlock_timestamp"] == T0 + CHALLENGE_WINDOW
    assert report["poc_hash"] == canonical_hash(make_poc())
    assert "drains" in report["triage_reasoning"]

    program = chain.c.get_program(pid)
    assert program["available"] == PROGRAM_DEPOSIT - expected_bounty
    assert program["locked"] == expected_bounty
    assert program["open_reports"] == 1
    assert len(program["policy_digest"]) == 64  # policy bytes pinned on first triage
    chain.assert_invariant()

    # The deterministic disassembly is what validators were shown.
    disasm = chain.c.get_disassembly(rid)
    assert disasm[1]["selector"] == "0x2e1a7d4d"
    assert disasm[1]["to"] == TARGET
    assert disasm[1]["word_count"] == 1

    # 4. Window lapse, 5. public settlement by an unrelated caller.
    chain.warp(T0 + CHALLENGE_WINDOW)
    credit = chain.call(direct_alice, "claim_bounty", rid)
    fee = expected_bounty * PROTOCOL_FEE_BPS // 10_000
    assert credit == expected_bounty - fee + RESEARCHER_BOND
    assert chain.c.get_claimable(chain.key(direct_charlie)) == credit
    assert chain.c.get_report(rid)["status"] == "PAID"
    program = chain.c.get_program(pid)
    assert program["locked"] == 0
    assert program["open_reports"] == 0
    assert program["total_paid"] == expected_bounty
    acc = chain.assert_invariant()
    assert acc["treasury_fees"] == fee

    # The researcher pulls the payout out of the contract.
    before = chain.balance()
    paid = chain.call(direct_charlie, "withdraw")
    assert paid == credit
    assert chain.balance() == before - credit
    assert chain.c.get_claimable(chain.key(direct_charlie)) == 0
    acc = chain.assert_invariant()
    assert acc["vault_reserves"] == PROGRAM_DEPOSIT - expected_bounty
    assert acc["total_outflows"] == credit

    # Governor sweeps only the booked protocol fee.
    assert chain.call(direct_alice, "withdraw_treasury", fee) == fee
    acc = chain.assert_invariant()
    assert acc["treasury_fees"] == 0
    assert chain.balance() == PROGRAM_DEPOSIT - expected_bounty


def test_rejected_report_fails_closed_and_slashes_bond(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    remock(direct_vm, triage={"reproducible": True, "in_scope": True, "assessed": "MEDIUM"})
    rid = chain.submit(direct_charlie, pid, "CRITICAL")

    report = chain.c.get_report(rid)
    assert report["status"] == "REJECTED"
    assert report["bounty"] == 0
    program = chain.c.get_program(pid)
    assert program["available"] == PROGRAM_DEPOSIT
    assert program["locked"] == 0
    assert program["open_reports"] == 0
    acc = chain.assert_invariant()
    assert acc["treasury_fees"] == RESEARCHER_BOND
    assert acc["bonded_researcher_funds"] == 0


def test_unreproducible_poc_is_rejected(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    remock(direct_vm, triage={"reproducible": False, "assessed": "CRITICAL"})
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    assert chain.c.get_report(rid)["status"] == "REJECTED"
    chain.assert_invariant()


def test_conservative_claim_is_accepted_at_claimed_tier(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    remock(direct_vm, triage={"assessed": "CRITICAL"})
    rid = chain.submit(direct_charlie, pid, "HIGH")
    report = chain.c.get_report(rid)
    assert report["status"] == "VALIDATED"
    assert report["awarded_severity"] == "HIGH"
    assert report["bounty"] == PROGRAM_DEPOSIT * PAYOUT_BPS["HIGH"] // 10_000


def test_dismissed_challenge_forfeits_bond_to_researcher(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    poc_hash = chain.c.get_report(rid)["poc_hash"]

    remock(direct_vm, rebuttal={"outcome": "DISMISSED"})
    chain.warp(T0 + DAY_HALF)
    assert chain.challenge(direct_bob, rid, make_rebuttal(poc_hash)) == "DISMISSED"
    report = chain.c.get_report(rid)
    assert report["status"] == "CHALLENGE_DISMISSED"
    assert report["challenge_bond_held"] == CHALLENGE_BOND
    assert report["rebuttal_type"] == "INTENDED_ADMIN_ROLE"
    chain.assert_invariant()

    chain.warp(T0 + CHALLENGE_WINDOW)
    credit = chain.call(direct_bob, "claim_bounty", rid)
    bounty = report["bounty"]
    assert credit == bounty - bounty * PROTOCOL_FEE_BPS // 10_000 + RESEARCHER_BOND + CHALLENGE_BOND
    acc = chain.assert_invariant()
    assert acc["bonded_project_funds"] == 0


def test_upheld_challenge_then_expire_returns_funds_to_vault(chain, direct_vm, direct_alice, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    poc_hash = chain.c.get_report(rid)["poc_hash"]

    remock(direct_vm, rebuttal={"outcome": "UPHELD"})
    assert chain.challenge(direct_bob, rid, make_rebuttal(poc_hash)) == "UPHELD"
    assert chain.c.get_report(rid)["status"] == "INVALIDATED"
    chain.assert_invariant()

    chain.warp(T0 + CHALLENGE_WINDOW)
    chain.call(direct_alice, "expire_report", rid)
    report = chain.c.get_report(rid)
    assert report["status"] == "EXPIRED"
    program = chain.c.get_program(pid)
    assert program["available"] == PROGRAM_DEPOSIT
    assert program["locked"] == 0
    assert program["open_reports"] == 0
    assert chain.c.get_claimable(chain.key(direct_bob)) == CHALLENGE_BOND
    acc = chain.assert_invariant()
    assert acc["treasury_fees"] == RESEARCHER_BOND


def test_downgrade_challenge_reprices_bounty(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    report = chain.c.get_report(rid)

    remock(direct_vm, rebuttal={"outcome": "DOWNGRADED", "revised": "MEDIUM"})
    rebuttal = make_rebuttal(report["poc_hash"], rebuttal_type="SEVERITY_OVERSTATED")
    assert chain.challenge(direct_bob, rid, rebuttal) == "DOWNGRADED"

    new_bounty = report["vault_basis"] * PAYOUT_BPS["MEDIUM"] // 10_000
    after = chain.c.get_report(rid)
    assert after["status"] == "DOWNGRADED"
    assert after["awarded_severity"] == "MEDIUM"
    assert after["bounty"] == new_bounty
    program = chain.c.get_program(pid)
    assert program["locked"] == new_bounty
    assert program["available"] == PROGRAM_DEPOSIT - new_bounty
    assert chain.c.get_claimable(chain.key(direct_bob)) == CHALLENGE_BOND
    chain.assert_invariant()

    chain.warp(T0 + CHALLENGE_WINDOW)
    credit = chain.call(direct_charlie, "claim_bounty", rid)
    assert credit == new_bounty - new_bounty * PROTOCOL_FEE_BPS // 10_000 + RESEARCHER_BOND
    chain.assert_invariant()


def test_downgrade_below_program_floor_is_upheld(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob, min_severity="HIGH")
    rid = chain.submit(direct_charlie, pid, "CRITICAL")
    remock(direct_vm, rebuttal={"outcome": "DOWNGRADED", "revised": "LOW"})
    rebuttal = make_rebuttal(chain.c.get_report(rid)["poc_hash"], rebuttal_type="SEVERITY_OVERSTATED")
    assert chain.challenge(direct_bob, rid, rebuttal) == "UPHELD"
    assert chain.c.get_report(rid)["status"] == "INVALIDATED"


def test_program_closure_and_vault_withdrawal(chain, direct_bob):
    pid = chain.register(direct_bob)
    closes_at = chain.call(direct_bob, "request_program_closure", pid)
    assert closes_at == T0 + CLOSURE_NOTICE
    chain.warp(closes_at)
    assert chain.call(direct_bob, "withdraw_vault", pid) == PROGRAM_DEPOSIT
    assert chain.c.get_program(pid)["status"] == "CLOSED"
    assert chain.call(direct_bob, "withdraw") == PROGRAM_DEPOSIT
    acc = chain.assert_invariant()
    assert acc["total_liabilities"] == 0
    assert chain.balance() == 0


def test_top_up_increases_available_reserves(chain, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    chain.call(direct_charlie, "top_up_vault", pid, value=10 * GEN)
    assert chain.c.get_program(pid)["available"] == PROGRAM_DEPOSIT + 10 * GEN
    chain.assert_invariant()


def test_validator_agrees_with_honest_leader_and_rejects_flipped_verdict(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    chain.submit(direct_charlie, pid, "CRITICAL")
    assert direct_vm.run_validator() is True

    captured = direct_vm._captured_validators[-1][0]
    flipped = dict(captured)
    flipped["accepted"] = not captured["accepted"]
    assert direct_vm.run_validator(leader_result=flipped) is False

    forged = dict(captured)
    forged["digest"] = "0" * 64
    assert direct_vm.run_validator(leader_result=forged) is False

    # A leader that raised (for example on malformed LLM output) never wins.
    assert direct_vm.run_validator(leader_error=Exception("[LLM_ERROR] bad")) is False


def test_validator_disagrees_when_it_sees_a_different_policy(chain, direct_vm, direct_bob, direct_charlie):
    pid = chain.register(direct_bob)
    chain.submit(direct_charlie, pid, "CRITICAL")
    direct_vm.clear_mocks()
    mock_policy(direct_vm, text="# a different policy body")
    mock_triage(direct_vm)
    assert direct_vm.run_validator() is False

