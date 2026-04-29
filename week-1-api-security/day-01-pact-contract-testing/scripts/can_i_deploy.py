"""
Pact can-i-deploy gate.

Asks the Pact Broker: "Is it safe to deploy version X of service Y to
environment Z, given all currently deployed consumer/provider versions?"

Usage:
    python scripts/can_i_deploy.py --service user-service --version 1.1.0
    python scripts/can_i_deploy.py --service user-service --version $GITHUB_SHA --env production

Exit code 0 = safe to deploy.
Exit code 1 = contracts violated — deployment blocked.
"""

import argparse
import subprocess
import sys


def can_i_deploy(service: str, version: str, environment: str, broker_url: str) -> bool:
    print(f"Checking: can {service} version {version} deploy to {environment}?")

    cmd = [
        "pact-broker",
        "can-i-deploy",
        "--pacticipant", service,
        "--version", version,
        "--to-environment", environment,
        "--broker-base-url", broker_url,
        "--output", "table",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)

    if result.returncode == 0:
        print(f"✓ SAFE TO DEPLOY: {service} {version} → {environment}")
        return True
    else:
        print(f"✗ DEPLOYMENT BLOCKED: {service} {version} would break contracts")
        print(result.stderr)
        print(f"\nView compatibility matrix: {broker_url}/matrix")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--env", default="production")
    parser.add_argument("--broker-url", default="http://localhost:9292")
    args = parser.parse_args()

    safe = can_i_deploy(args.service, args.version, args.env, args.broker_url)
    sys.exit(0 if safe else 1)
