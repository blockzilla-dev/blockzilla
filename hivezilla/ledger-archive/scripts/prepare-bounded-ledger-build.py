#!/usr/bin/env python3
"""Prepare an isolated, pinned SDK overlay. Do not build or open a ledger."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path

BASE = "b6149a719f8fa84123ac3ce1e5f201af64bca8ee"
AGAVE = {"solana-entry": "entry", "solana-ledger": "ledger", "solana-transaction-status": "transaction-status"}


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, text=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registry_packages(lock):
    return sorted((p["name"], p["version"], p["source"]) for p in tomllib.loads(lock.read_text())["package"] if p.get("source", "").startswith("registry+"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--agave-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--allow-fetch", action="store_true", help="download missing locked crate archives")
    args = parser.parse_args()
    source = args.source_root.resolve(strict=True)
    sdk_source = args.agave_source.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(source) or output.is_relative_to(sdk_source):
        raise SystemExit("output must be a new directory outside both source trees")
    package = source / "hivezilla/ledger-archive"
    patch = package / "patches/agave-v4.4.0-rc.1-read-only-file-cap.patch"
    revision = run(["git", "-C", str(sdk_source), "rev-parse", "HEAD"], capture_output=True).stdout.strip()
    dirty = run(["git", "-C", str(sdk_source), "status", "--porcelain", "--untracked-files=no"], capture_output=True).stdout
    if revision != BASE or dirty:
        raise SystemExit("Agave source must be the clean pinned revision")
    if not patch.is_file():
        raise SystemExit("the checked read-only SDK patch is missing")
    if shutil.disk_usage(output.parent).free < 800 * 1024**3:
        raise SystemExit("free space is below the 800 GiB build reserve")
    output.mkdir()
    sdk = output / "agave"
    run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(sdk_source), str(sdk)])
    run(["git", "-C", str(sdk), "checkout", "--quiet", "--detach", BASE])
    run(["git", "-C", str(sdk), "apply", "--check", str(patch)])
    run(["git", "-C", str(sdk), "apply", str(patch)])
    overlay = output / "source"
    shutil.copytree(source, overlay, ignore=shutil.ignore_patterns(".git", "target", "node_modules", ".codex-tmp", "__pycache__"))
    manifest = overlay / "hivezilla/ledger-archive/Cargo.toml"
    text = manifest.read_text()
    for name, folder in AGAVE.items():
        needle = f'{name} = {{ git = "https://github.com/anza-xyz/agave", tag = "v4.4.0-rc.1"'
        if text.count(needle) != 1:
            raise SystemExit(f"unexpected direct Agave dependency: {name}")
        text = text.replace(needle, f"{name} = {{ path = {json.dumps(str(sdk / folder))}")
    manifest.write_text(text)
    lock = manifest.with_name("Cargo.lock")
    before_registry = registry_packages(package / "Cargo.lock")
    # Retain the existing lock selections. Resolve only the changed path
    # sources, with network access disabled, before the locked build starts.
    cargo = [args.cargo, "+1.98.1", "metadata", "--offline", "--format-version", "1", "--manifest-path", str(manifest), "--features", "bounded-ledger-read"]
    with (output / "metadata.log").open("w") as log:
        resolved = subprocess.run(cargo, stdout=subprocess.DEVNULL, stderr=log, text=True)
    after_registry = registry_packages(lock)
    if before_registry != after_registry:
        raise SystemExit("the overlay changed registry package versions or sources")
    original_packages = tomllib.loads((package / "Cargo.lock").read_text())["package"]
    overlay_packages = tomllib.loads(lock.read_text())["package"]
    agave_git = "git+https://github.com/anza-xyz/agave?"
    migrated = sorted(p["name"] for p in original_packages if p.get("source", "").startswith(agave_git))
    if any(p.get("source", "").startswith(agave_git) for p in overlay_packages):
        raise SystemExit("the overlay still has split Agave git and path sources")
    if resolved.returncode:
        if not args.allow_fetch:
            raise SystemExit("metadata needs cached archives; see metadata.log or use --allow-fetch")
        with (output / "fetch.log").open("w") as log:
            run([args.cargo, "+1.98.1", "fetch", "--locked", "--manifest-path", str(manifest)], stdout=log, stderr=subprocess.STDOUT)
    run(cargo + ["--locked"], stdout=subprocess.DEVNULL)
    receipt = {
        "version": 1, "agave_revision": BASE, "patch_sha256": sha(patch),
        "original_manifest_sha256": sha(package / "Cargo.toml"),
        "overlay_manifest_sha256": sha(manifest), "overlay_lock_sha256": sha(lock),
        "registry_packages_unchanged": True, "feature": "bounded-ledger-read",
        "locked_fetch_allowed": args.allow_fetch,
        "read_only_max_open_files": 64, "sdk": str(sdk), "manifest": str(manifest),
        "agave_direct_dependency_paths": {name: str(sdk / folder) for name, folder in AGAVE.items()},
        "agave_packages_moved_to_isolated_path": migrated,
        "sdk_diff": run(["git", "-C", str(sdk), "diff", "--stat"], capture_output=True).stdout,
    }
    (output / "PREPARED.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
