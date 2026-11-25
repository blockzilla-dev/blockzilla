#!/usr/bin/env python3
"""Check default secret detection with temporary synthetic data.

No real credential is read. Generated credential values are never printed and
are removed with the temporary test directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def credential():
    # Shuffled unique blocks give each generated value four bits of entropy
    # per character without producing the detector's common-word exclusions.
    alphabet = "0123456789qwxzjk"
    random = secrets.SystemRandom()
    return "".join("".join(random.sample(alphabet, len(alphabet))) for _ in range(4))


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n")


def scan(binary, root, report):
    # The temporary directory has no project config. Remove environment
    # overrides so this check exercises the scanner's built-in rules.
    environment = os.environ.copy()
    environment.pop("GITLEAKS_CONFIG", None)
    environment.pop("GITLEAKS_CONFIG_TOML", None)
    command = [binary, "dir", ".", "--redact=100", "--no-banner", "--no-color",
               "--report-format=json", "--report-path", str(report)]
    result = subprocess.run(command, cwd=root, env=environment,
                            capture_output=True, text=True, timeout=60)
    require(result.returncode in (0, 1), "Secret scan did not complete")
    rows = json.loads(report.read_text())
    require(all(row.get("Secret") == "REDACTED" for row in rows),
            "Scanner reports must redact credential values")
    require((result.returncode == 0) == (not rows),
            "Scanner exit status and findings differ")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks",
                        help="Path to the pinned Gitleaks 8.30.1 executable")
    args = parser.parse_args()
    binary = shutil.which(args.gitleaks)
    require(binary is not None, "Gitleaks executable is required")
    binary = str(Path(binary).resolve())
    version = subprocess.check_output([binary, "version"], text=True).strip()
    require(re.match(r"^v?8\.30\.1(?:\s|$)", version),
            "Use the pinned Gitleaks 8.30.1 version")

    with tempfile.TemporaryDirectory(prefix="secret-policy-check-") as temporary:
        temporary = Path(temporary)
        tree = temporary / "tree"
        tree.mkdir()
        digest = hashlib.sha256(b"public fixture").hexdigest()
        write(tree, "config/settings.json", json.dumps({"mode": "test", "limit": 10}))
        write(tree, "checksums.json", json.dumps({"sha256": digest}))
        require(not scan(binary, tree, temporary / "clean.json"),
                "Ordinary config and checksums must pass")

        # Check different file formats, including a credential beside harmless
        # metadata on the same line. No path-specific exception should hide it.
        fixtures = {
            "config/settings.json": json.dumps({"api_key": credential()}),
            "config/settings.toml": 'api_key = "' + credential() + '"',
            "config/combined.json": json.dumps({"sha256": digest,
                                                  "api_key": credential()}),
        }
        for name, value in fixtures.items():
            write(tree, name, value)
        rows = scan(binary, tree, temporary / "credentials.json")
        require(all(row["RuleID"] == "generic-api-key" for row in rows),
                "Synthetic cases must exercise the generic credential rule")
        require({row["File"] for row in rows} == set(fixtures),
                "Default rules must find every synthetic credential")
        require(len(rows) == len(fixtures),
                "Each synthetic credential must produce one finding")

        print(json.dumps({"status": "PASS", "gitleaks_version": "8.30.1",
                          "rules": "built-in defaults",
                          "clean_files": 2,
                          "synthetic_credentials_detected": len(rows),
                          "credential_values_printed": False}))


if __name__ == "__main__":
    main()
