"""Deploy ZeroDiscretion to a GenLayer network and read back its parameters.

    .venv/bin/python scripts/deploy.py --network studionet
    .venv/bin/python scripts/deploy.py --network localnet --endpoint http://127.0.0.1:4000/api

The deployer key is read from the GENLAYER_PRIVATE_KEY environment variable
and never accepted on the command line (shell history, process listings).
The deployer becomes the protocol governor, whose only powers are to LENGTHEN
the challenge window / closure notice and to sweep booked protocol fees.

Before any network I/O the contract is linted with genvm-lint; a lint or
validation failure aborts the deployment.

Copyright (c) 2026 SOBEK96 <btcehsan@yahoo.com>. MIT License.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT = REPO_ROOT / "contracts" / "zero_discretion.py"
DEPLOYMENTS = REPO_ROOT / "deployments"

NETWORKS = ("localnet", "studionet", "studio_devnet", "testnet_asimov", "testnet_bradbury")


def lint() -> None:
    exe = shutil.which("genvm-lint") or str(Path(sys.executable).parent / "genvm-lint")
    result = subprocess.run([exe, "check", str(CONTRACT)], capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("genvm-lint failed; refusing to deploy")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--network", choices=NETWORKS, default="studionet")
    parser.add_argument("--endpoint", help="override the network RPC endpoint")
    parser.add_argument("--skip-lint", action="store_true", help="skip the genvm-lint gate")
    parser.add_argument("--retries", type=int, default=120, help="receipt polling attempts")
    args = parser.parse_args()

    private_key = os.environ.get("GENLAYER_PRIVATE_KEY", "").strip()
    if not private_key:
        print("GENLAYER_PRIVATE_KEY is not set", file=sys.stderr)
        return 2

    if not args.skip_lint:
        lint()

    import genlayer_py.chains as chains
    from genlayer_py import create_account, create_client

    account = create_account(cast(Any, private_key))
    client = create_client(chain=getattr(chains, args.network), endpoint=args.endpoint, account=account)

    print(f"Deploying {CONTRACT.name} to {args.network} as {account.address} ...")
    tx_hash = client.deploy_contract(code=CONTRACT.read_text(encoding="utf-8"), account=account, args=[])
    print(f"  tx: {tx_hash}")
    receipt = client.wait_for_transaction_receipt(transaction_hash=tx_hash, retries=args.retries)

    address = None
    data = receipt.get("tx_data_decoded") or {}
    if isinstance(data, dict):
        address = data.get("contract_address")
    address = address or receipt.get("recipient") or receipt.get("to_address")
    if not address:
        print("Deployment receipt carries no contract address:", file=sys.stderr)
        print(json.dumps(receipt, indent=2, default=str), file=sys.stderr)
        return 1
    print(f"  contract: {address}")

    params = client.read_contract(address=address, function_name="get_protocol_params", args=[])
    print(json.dumps(params, indent=2, default=str))

    DEPLOYMENTS.mkdir(exist_ok=True)
    record = {"network": args.network, "address": str(address), "tx_hash": str(tx_hash),
              "governor": str(account.address), "params": params}
    out = DEPLOYMENTS / f"{args.network}.json"
    out.write_text(json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"Recorded deployment in {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
