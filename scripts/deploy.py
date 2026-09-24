"""Deploy ZeroDiscretion to a GenLayer network, seed a reference program and
record the deployment.

    .venv/bin/python scripts/deploy.py --network studio_next --bootstrap
    .venv/bin/python scripts/deploy.py --network studio_next --address 0x... --bootstrap
    .venv/bin/python scripts/deploy.py --network localnet --endpoint http://127.0.0.1:4000/api

The deployer key is read from GENLAYER_PRIVATE_KEY (environment or the
gitignored `.env` at the repository root) and never accepted on the command
line. The deployer becomes the protocol governor, whose only powers are to
LENGTHEN the challenge window / closure notice and to sweep booked fees.

Steps:
  1. genvm-lint gate (skipped with --skip-lint).
  2. Deploy, unless --address names an existing deployment.
  3. With --bootstrap: verify the pinned SECURITY.md resolves over HTTPS, then
     register the reference bounty program with a 10 GEN vault.
  4. Write deployments/<network>.json with addresses, hashes and explorer URLs.

Copyright (c) 2026 SOBEK96 <btcehsan@yahoo.com>. MIT License.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT = REPO_ROOT / "contracts" / "zero_discretion.py"
DEPLOYMENTS = REPO_ROOT / "deployments"
GITHUB_REPO = "SOBEK96/ZeroDiscretion"

GEN = 10**18
BOOTSTRAP_DEPOSIT = 10 * GEN
# Reference target: canonical WETH9 on Ethereum mainnet. Registration requires
# a Sourcify-verified ABI; WETH9 is public, ownerless and immutable. See
# SECURITY.md: this is a testnet demonstration, not a bounty offer for WETH9.
BOOTSTRAP_TARGET = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
BOOTSTRAP_CHAIN_ID = 1
BOOTSTRAP_MIN_SEVERITY = "LOW"

# name -> (genlayer_py chain preset, RPC override, explorer base, record file stem)
NETWORKS: dict[str, tuple[str, str | None, str | None, str]] = {
    "studio_next": ("studio_devnet", "https://studio-next.genlayer.com/api",
                    "https://explorer-studio-next.genlayer.com", "studio-next"),
    "studionet": ("studionet", None, "https://genlayer-explorer.vercel.app", "studionet"),
    "localnet": ("localnet", None, None, "localnet"),
    "testnet_asimov": ("testnet_asimov", None, None, "testnet-asimov"),
    "testnet_bradbury": ("testnet_bradbury", None, None, "testnet-bradbury"),
}


def load_dotenv() -> None:
    env = REPO_ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def lint() -> None:
    exe = shutil.which("genvm-lint") or str(Path(sys.executable).parent / "genvm-lint")
    result = subprocess.run([exe, "check", str(CONTRACT)], capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("genvm-lint failed; refusing to deploy")


def policy_commit() -> str:
    """Latest commit that touched SECURITY.md and is already on origin."""
    out = subprocess.run(["git", "log", "-1", "--format=%H", "origin/main", "--", "SECURITY.md"],
                         cwd=REPO_ROOT, capture_output=True, text=True)
    sha = out.stdout.strip()
    if out.returncode != 0 or len(sha) != 40:
        raise SystemExit("SECURITY.md is not on origin/main yet; push it before bootstrapping")
    return sha


def verify_policy(raw_url: str) -> str:
    """Fetch the pinned policy exactly as validators will and return its SHA-256."""
    with urllib.request.urlopen(raw_url, timeout=30) as res:  # noqa: S310 - fixed https host
        if res.status != 200:
            raise SystemExit(f"pinned policy returned HTTP {res.status}: {raw_url}")
        return hashlib.sha256(res.read()).hexdigest()


def check_receipt(receipt: dict, what: str) -> None:
    outcome = receipt.get("tx_execution_result_name")
    if outcome and outcome != "FINISHED_WITH_RETURN":
        print(json.dumps(receipt, indent=2, default=str), file=sys.stderr)
        raise SystemExit(f"{what} did not finish cleanly: {outcome}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", choices=sorted(NETWORKS), default="studio_next")
    parser.add_argument("--endpoint", help="override the network RPC endpoint")
    parser.add_argument("--address", help="use this existing deployment instead of deploying")
    parser.add_argument("--bootstrap", action="store_true", help="register the 10 GEN reference program")
    parser.add_argument("--target", default=BOOTSTRAP_TARGET, help="bootstrap target (needs a Sourcify-verified ABI)")
    parser.add_argument("--chain-id", type=int, default=BOOTSTRAP_CHAIN_ID, help="chain the bootstrap target lives on")
    parser.add_argument("--skip-lint", action="store_true", help="skip the genvm-lint gate")
    parser.add_argument("--retries", type=int, default=200, help="receipt polling attempts (3s apart)")
    args = parser.parse_args()

    load_dotenv()
    private_key = os.environ.get("GENLAYER_PRIVATE_KEY", "").strip()
    if not private_key:
        print("GENLAYER_PRIVATE_KEY is not set (environment or .env)", file=sys.stderr)
        return 2

    preset, default_endpoint, explorer, stem = NETWORKS[args.network]
    endpoint = args.endpoint or default_endpoint

    if not args.skip_lint and not args.address:
        lint()

    import genlayer_py.chains as chains
    from genlayer_py import create_account, create_client

    account = create_account(cast(Any, private_key))
    client = create_client(chain=getattr(chains, preset), endpoint=endpoint, account=account)
    record_path = DEPLOYMENTS / f"{stem}.json"
    record: dict[str, Any] = json.loads(record_path.read_text()) if record_path.exists() else {}

    source = CONTRACT.read_text(encoding="utf-8")
    if args.address:
        address = args.address
        print(f"Using existing deployment {address}")
    else:
        print(f"Deploying {CONTRACT.name} to {args.network} as {account.address} ...")
        # Studio Next has no fee manager: without an explicit fee object built
        # from the live fee policy the consensus contract reverts the deploy
        # (FeesDistributionMissing / FeeValueMustBeNonZero).
        fees = client.estimate_transaction_fees({})
        tx_hash = client.deploy_contract(code=source, account=account, args=[], fees=fees)
        print(f"  tx: {tx_hash}")
        receipt = client.wait_for_transaction_receipt(transaction_hash=tx_hash, retries=args.retries)
        check_receipt(cast(dict, receipt), "deployment")
        data = receipt.get("tx_data_decoded") or {}
        address = (data.get("contract_address") if isinstance(data, dict) else None) \
            or receipt.get("recipient") or receipt.get("to_address")
        if not address:
            print(json.dumps(receipt, indent=2, default=str), file=sys.stderr)
            raise SystemExit("deployment receipt carries no contract address")
        superseded = [
            {k: record[k] for k in ("contract_address", "deploy_tx_hash", "explorer_url", "deployed_at", "live_verification") if k in record}
        ] + record.get("superseded", []) if record.get("contract_address") else record.get("superseded", [])
        record = {
            "network": stem,
            "chain_id": client.chain.id,
            "rpc_url": endpoint or client.chain.rpc_urls["default"]["http"][0],
            "contract_address": str(address),
            "deploy_tx_hash": str(tx_hash),
            "governor": str(account.address),
            "source": "contracts/zero_discretion.py",
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "runner": source.splitlines()[1].split('"Depends": "')[1].split('"')[0],
            "deployed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if superseded:
            record["superseded"] = superseded
        if explorer:
            record["explorer_url"] = f"{explorer}/address/{address}"
            record["deploy_tx_explorer_url"] = f"{explorer}/tx/{tx_hash}"
        print(f"  contract: {address}")

    def read(fn: str, *call_args: Any) -> Any:
        return cast(Any, client.read_contract(address=address, function_name=fn, args=list(call_args)))

    params = read("get_protocol_params")
    record["protocol_params"] = params

    if args.bootstrap:
        commit = policy_commit()
        policy_url = f"https://github.com/{GITHUB_REPO}/blob/{commit}/SECURITY.md"
        raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{commit}/SECURITY.md"
        digest = verify_policy(raw_url)
        print(f"Policy verified: {raw_url} (sha256 {digest})")

        print("Registering reference program with a 10 GEN vault ...")
        tx_hash = client.write_contract(
            address=address, function_name="register_bounty_program", account=account,
            value=BOOTSTRAP_DEPOSIT, args=[args.target, policy_url, BOOTSTRAP_MIN_SEVERITY, args.chain_id],
            fees=client.estimate_transaction_fees({}),
        )
        print(f"  tx: {tx_hash}")
        receipt = client.wait_for_transaction_receipt(transaction_hash=tx_hash, retries=args.retries)
        check_receipt(cast(dict, receipt), "bootstrap registration")
        after = read("get_protocol_params")
        program_id = int(after["next_program_id"]) - 1
        program = read("get_program", program_id)
        if program["policy_url"] != raw_url or int(program["available"]) != BOOTSTRAP_DEPOSIT:
            raise SystemExit(f"registered program does not match the bootstrap request: {program}")
        if program["target_address"] != args.target.lower() or not program.get("target_abi"):
            raise SystemExit(f"registered program has no pinned target ABI: {program}")
        print(f"  target ABI pinned by web consensus: {len(program['target_abi'])} functions, "
              f"fallback={program['target_has_fallback']}")
        print(f"  sponsor status: {program['sponsor_status']} (target owner: {program['target_owner'] or 'none'})")
        solvency = read("get_solvency")
        record["protocol_params"] = after
        record["bootstrap_program"] = {
            "program_id": program_id,
            "register_tx_hash": str(tx_hash),
            "target_address": args.target,
            "target_chain_id": args.chain_id,
            "target_abi_source": "sourcify",
            "target_abi": program["target_abi"],
            "target_has_fallback": program["target_has_fallback"],
            "sponsor_status": program["sponsor_status"],
            "target_owner": program["target_owner"],
            "policy_url": policy_url,
            "policy_raw_url": raw_url,
            "policy_commit": commit,
            "policy_sha256": digest,
            "deposit_atto": str(BOOTSTRAP_DEPOSIT),
            "min_severity": BOOTSTRAP_MIN_SEVERITY,
        }
        record["solvency_after_bootstrap"] = solvency
        if explorer:
            record["bootstrap_program"]["register_tx_explorer_url"] = f"{explorer}/tx/{tx_hash}"
        print(f"  program #{program_id} active, vault {int(program['available']) / GEN:g} GEN, solvency {solvency}")

    DEPLOYMENTS.mkdir(exist_ok=True)
    record_path.write_text(json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"Recorded deployment in {record_path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
