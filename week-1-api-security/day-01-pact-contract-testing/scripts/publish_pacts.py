"""
Publish generated pact files to the Pact Broker.

Usage:
    python scripts/publish_pacts.py --version 1.0.0
    python scripts/publish_pacts.py --version $(git rev-parse HEAD)
    python scripts/publish_pacts.py --version $GITHUB_SHA --tag main
"""

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path


def publish_pacts(version: str, broker_url: str, tag: str = None):
    pact_files = glob.glob("./consumer/pacts/*.json")

    if not pact_files:
        print("ERROR: No pact files found in ./consumer/pacts/")
        print("Run 'pytest consumer/tests/' first to generate contracts.")
        sys.exit(1)

    print(f"Publishing {len(pact_files)} pact file(s) to {broker_url}")
    print(f"  Consumer version : {version}")
    if tag:
        print(f"  Tag              : {tag}")

    cmd = [
        "pact-broker",
        "publish",
        *pact_files,
        "--broker-base-url", broker_url,
        "--consumer-app-version", version,
    ]

    if tag:
        cmd.extend(["--tag", tag])

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("FAILED to publish pacts:")
        print(result.stderr)
        sys.exit(1)

    print("Successfully published pacts:")
    print(result.stdout)

    for pact_file in pact_files:
        with open(pact_file) as f:
            contract = json.load(f)
        consumer = contract["consumer"]["name"]
        provider = contract["provider"]["name"]
        print(f"  ✓ {consumer} → {provider}: {broker_url}/pacts/provider/{provider}/consumer/{consumer}/latest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Publish pact files to Pact Broker")
    parser.add_argument("--version", required=True, help="Consumer application version")
    parser.add_argument("--broker-url", default="http://localhost:9292")
    parser.add_argument("--tag", help="Optional tag (e.g. branch name, 'main')")
    args = parser.parse_args()

    publish_pacts(args.version, args.broker_url, args.tag)
