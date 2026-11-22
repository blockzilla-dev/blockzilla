#!/usr/bin/env python3
"""Check metadata exceptions without saving or printing credential values.

All credential-shaped negative fixtures are generated at runtime and removed
with the temporary directory. No real credential is read by this test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".gitleaks.toml"
INCIDENT = "hivezilla/deploy/foundation-watch/evidence/incident-20261018-recurrence"
STORAGE = "hivezilla/deploy/foundation-watch/evidence/incident-20261020-storage"
SOURCE_PATHS = (
    INCIDENT + "/connection-idle/SOURCE.json",
    INCIDENT + "/connection-idle/SOURCE-BEFORE.json",
    INCIDENT + "/evening-20261018/publisher-status/SOURCE.json",
    INCIDENT + "/evening-20261018/publisher-status/SOURCE-BEFORE.json",
    STORAGE + "/PRESERVED-WORKSPACE.json",
)
JOB_PATHS = (
    INCIDENT + "/evening-20261018/HOST-SAMPLE-1.json",
    STORAGE + "/HOST-SAMPLE-1.json",
    STORAGE + "/PREPATCH-RECURRENCES.json",
)
OBJECT_PATHS = (
    INCIDENT + "/evening-20261018/publisher-status/BEFORE.json",
    INCIDENT + "/evening-20261018/RECEIPT-FINAL.json",
    INCIDENT + "/evening-20261018/publisher-status/INSTALLATION.json",
    INCIDENT + "/evening-20261018/PUBLISHER-RETRY-TYPE.json",
)
VERSION_FIELDS = {
    "reports/get-block-native-fast-20261122/deployment.json": "preEdgeAuthPerformanceVersion",
    "reports/get-block-native-r2-20261122/preparation.json": "public_api_unchanged_version",
}
PROPERTY_PATH = "reports/get-block-native-fast-20261122/platform-cpu-auth-edge.json"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def write(root, name, value, compact=False):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=None if compact else 2) + "\n")


def credential():
    # Uniform URLsafe samples can contain words from Gitleaks' default
    # stopword list. That makes an expected-positive detection nondeterministic.
    # This alphabet cannot form any of the pinned rule's stopwords except six
    # repeated zeros or x characters. Shuffled unique blocks prevent those runs.
    # Four blocks have exactly four bits of entropy per character, include
    # non-hex letters, and do not fit a metadata SHA-256 or UUID field.
    alphabet = "0123456789qwxzjk"
    random = secrets.SystemRandom()
    return "".join("".join(random.sample(alphabet, len(alphabet))) for _ in range(4))


def require_paths(rows, expected, reason):
    require(all(row["RuleID"] == "generic-api-key" for row in rows),
            "Negative fixtures must exercise the generic credential rule")
    actual = {row["File"] for row in rows}
    require(actual == expected, reason + ": " + json.dumps({
        "missing_paths": sorted(expected - actual),
        "unexpected_paths": sorted(actual - expected),
    }))


def scan(binary, root, report):
    command = [binary, "dir", ".", "--config", str(POLICY), "--redact=100",
               "--no-banner", "--no-color", "--report-format=json",
               "--report-path", str(report)]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=60)
    require(result.returncode in (0, 1), "Gitleaks scan failed before policy validation")
    rows = json.loads(report.read_text())
    require(all(row.get("Secret") == "REDACTED" for row in rows), "Gitleaks redaction is required")
    require((result.returncode == 0) == (not rows), "Gitleaks exit status and findings differ")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", default="gitleaks", help="Path to the pinned Gitleaks 8.30.1 executable")
    args = parser.parse_args()
    binary = shutil.which(args.gitleaks)
    require(binary is not None, "Gitleaks executable is required")
    binary = str(Path(binary).resolve())
    version = subprocess.check_output([binary, "version"], text=True).strip()
    require(re.match(r"^v?8\.30\.1(?:\s|$)", version), "Use the pinned Gitleaks 8.30.1 version")

    with tempfile.TemporaryDirectory(prefix="blockzilla-gitleaks-policy-") as temporary:
        temporary = Path(temporary)
        tree = temporary / "tree"
        tree.mkdir()
        digest = hashlib.sha256(b"public source and operation metadata fixture").hexdigest()
        fixtures = {}
        for name in SOURCE_PATHS:
            field = ("docs/start/token-indexer.md" if name.endswith("PRESERVED-WORKSPACE.json")
                     else "crates/compact-v2/blockzilla-compact-v2-reader/src/query_keys.rs")
            fixtures[name] = {field: digest}
        for name in JOB_PATHS:
            fixtures[name] = {"old_live_job_key" if name.endswith("PREPATCH-RECURRENCES.json") else "job_key": digest}
        for name in OBJECT_PATHS:
            field = "object_key_sha256" if name.endswith("PUBLISHER-RETRY-TYPE.json") else "commit_key_sha256"
            fixtures[name] = {field: digest}
        for name, field in VERSION_FIELDS.items():
            fixtures[name] = {field: str(uuid.uuid4())}
        fixtures[PROPERTY_PATH] = {
            "requestReceipt": "auth-edge-main.json",
            "preL2EvidenceExcluded": "A public report property, not a credential.",
        }
        for name, value in fixtures.items():
            write(tree, name, value)
        require(not scan(binary, tree, temporary / "metadata.json"), "Reviewed metadata must pass")

        # Keep metadata and a new credential on the same JSON line. A line-wide
        # exception could incorrectly suppress both; match-scoped rules must not.
        for name, value in fixtures.items():
            write(tree, name, {**value, "api_key": credential()}, compact=True)
        outside = "outside/metadata.json"
        write(tree, outside, {"job_key": digest}, compact=True)
        rows = scan(binary, tree, temporary / "adjacent.json")
        require_paths(rows, set(fixtures) | {outside},
                      "Credentials beside metadata and metadata outside reviewed paths must be found")

        # Same reviewed field and path, but no longer a SHA-256 or version UUID:
        # an exception must not accept an arbitrary credential-shaped value.
        for name, value in fixtures.items():
            field = next(iter(value)) if name != PROPERTY_PATH else "api_key"
            write(tree, name, {field: credential()}, compact=True)
        (tree / outside).unlink()
        rows = scan(binary, tree, temporary / "wrong-format.json")
        require_paths(rows, set(fixtures),
                      "Credential values with the wrong metadata format must be found")

        print(json.dumps({"status": "PASS", "gitleaks_version": "8.30.1",
                          "reviewed_metadata_paths": len(fixtures),
                          "adjacent_credential_and_outside_path_detections": len(fixtures) + 1,
                          "wrong_format_credential_detections": len(fixtures),
                          "credential_values_printed": False}))


if __name__ == "__main__":
    main()
