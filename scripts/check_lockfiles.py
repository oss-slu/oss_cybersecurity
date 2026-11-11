#!/usr/bin/env python3
"""
check_lockfiles.py - OSS-SLU Dependency Lockfile Validator
Scans a target project directory to verify adherence to OSS-SLU dependency pinning standards.
Ref: oss-slu/oss_cybersecurity#70
"""

import sys
from pathlib import Path

ECOSYSTEM_RULES = [
    {
        "ecosystem": "Node.js / JavaScript / TypeScript",
        "manifests": ["package.json"],
        "lockfiles": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
        "fix": "Run 'npm install' or 'pnpm install' and commit the resulting lockfile. Use 'npm ci' in CI/Dockerfile.",
    },
    {
        "ecosystem": "Python (uv / poetry / pip-tools)",
        "manifests": ["pyproject.toml"],
        "lockfiles": ["uv.lock", "poetry.lock"],
        "fix": "Run 'uv lock' or 'poetry lock' and commit the lockfile. Use 'uv sync --frozen' in CI/Dockerfile.",
    },
    {
        "ecosystem": "Python (legacy requirements)",
        "manifests": ["requirements.txt"],
        "lockfiles": ["requirements.lock.txt", "uv.lock", "poetry.lock"],
        "fix": "Migrate to 'uv.lock' via 'uv lock' or compile hashes with 'pip-compile --generate-hashes'.",
    },
    {
        "ecosystem": "Rust",
        "manifests": ["Cargo.toml"],
        "lockfiles": ["Cargo.lock"],
        "fix": "Commit Cargo.lock and use 'cargo build --locked' in CI/Dockerfile.",
    },
    {
        "ecosystem": "Go",
        "manifests": ["go.mod"],
        "lockfiles": ["go.sum"],
        "fix": "Commit go.sum and use 'go build -mod=readonly' in CI/Dockerfile.",
    },
]


def check_directory(target_path: Path) -> int:
    print(f"[*] Scanning directory: {target_path.resolve()}\n")
    failures = 0
    detected_ecosystems = 0

    for rule in ECOSYSTEM_RULES:
        has_manifest = any((target_path / m).exists() for m in rule["manifests"])
        if not has_manifest:
            continue

        detected_ecosystems += 1
        found_manifests = [m for m in rule["manifests"] if (target_path / m).exists()]
        found_lockfiles = [l for l in rule["lockfiles"] if (target_path / l).exists()]

        print(f"-> Detected {rule['ecosystem']}")
        print(f"   Manifest(s) found: {', '.join(found_manifests)}")

        if found_lockfiles:
            print(f"   [PASS] Found lockfile(s): {', '.join(found_lockfiles)}\n")
        else:
            print(f"   [FAIL] Missing required lockfile! Expected one of: {', '.join(rule['lockfiles'])}")
            print(f"   [REMEDY] {rule['fix']}\n")
            failures += 1

    if detected_ecosystems == 0:
        print("[INFO] No dependency manifests detected in target directory.")
        return 0

    if failures > 0:
        print(f"[ERROR] Dependency check failed with {failures} missing lockfile issue(s).")
        return 1

    print("[SUCCESS] All detected package ecosystems have committed lockfiles.")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    sys.exit(check_directory(target))
