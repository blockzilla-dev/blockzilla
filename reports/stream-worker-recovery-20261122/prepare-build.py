#!/usr/bin/env python3
"""Freeze only the existing consumer build closure. No data or credentials."""
import hashlib
import json
import argparse
import re
from pathlib import Path
import shutil
import tarfile

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / ".codex/reports/ferno-compact-only-20261122/build-20261122T134831Z/INPUT-SOURCE-FILES.json"
PINNED = {"Cargo.toml", "hivezilla/stream-relay/decoder/src/lib.rs",
          "hivezilla/stream-relay/decoder/src/tests.rs"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="linux-build")
    args = parser.parse_args()
    assert re.fullmatch("linux-[a-z0-9-]+", args.name)
    WORK = ROOT / ".codex-tmp/stream-worker-recovery-20261122" / args.name
    assert not WORK.exists(), "use a new build directory after a frozen build"
    previous = json.loads(OLD.read_text())
    names = {p for p in previous if (ROOT / p).is_file()
             and "/benches/fixtures/" not in p}
    for name in previous:
        if name.endswith("Cargo.toml") and name != "Cargo.toml":
            package = (ROOT / name).parent
            for folder in ["src", "tests", "examples"]:
                names.update(str(p.relative_to(ROOT)) for p in (package / folder).rglob("*.rs"))
    source = WORK / "source"
    source.mkdir(parents=True)
    manifest = {}
    for name in sorted(names):
        path = ROOT / name
        if name in PINNED:
            path = OLD.parent / "source" / name
            assert hashlib.sha256(path.read_bytes()).hexdigest() == previous[name]["sha256"]
        assert not path.is_symlink() and path.stat().st_size < 2 * 1024 * 1024
        dest = source / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        manifest[name] = {"bytes": path.stat().st_size,
                          "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()}
    (WORK / "SOURCE-FILES.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (WORK / "PINNED-DEPENDENCIES.json").write_text(json.dumps({"source": str(OLD),
        "files": sorted(PINNED), "reason": "Keep the deployed decoder; concurrent wallet changes stay outside this release."}, indent=2) + "\n")
    with tarfile.open(WORK / "source.tar.gz", "w:gz") as archive:
        archive.add(source, arcname="source")
    print(json.dumps({"files": len(manifest), "tar_sha256": hashlib.sha256((WORK / "source.tar.gz").read_bytes()).hexdigest(), "directory": str(WORK)}))


if __name__ == "__main__":
    main()
