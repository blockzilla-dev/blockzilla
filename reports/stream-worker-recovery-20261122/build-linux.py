#!/usr/bin/env python3
"""Build a frozen client source closure on Foundation with two CPU cores."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

JOB = Path(__file__).resolve().parent
SOURCE = JOB / "source"
RESULTS = JOB / "results"
RESULTS.mkdir(mode=0o700, exist_ok=False)
TARGET = Path("/home/ubuntu/live/hivezilla-validator-20260930/jobs/native-client-pipe-20261122/target")
os.environ.update(CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
                  RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+sse2", MALLOC_ARENA_MAX="4")
RECEIPT = {"schema": "blockzilla-worker-recovery-linux-build-v1", "state": "RUNNING",
           "started_at_unix_ms": time.time_ns() // 1000000, "commands": [],
           "production_services_changed": False, "build_jobs": 2}


def save():
    p = RESULTS / "BUILD.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(RECEIPT, indent=2) + "\n")
    tmp.replace(p)


def run(name, args, cwd):
    phase = {"phase": name, "argv": args, "started_at_unix_ms": time.time_ns() // 1000000}
    RECEIPT["commands"].append(phase)
    save()
    with (RESULTS / (name + ".log")).open("w") as log:
        result = subprocess.run(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
    phase.update(returncode=result.returncode, finished_at_unix_ms=time.time_ns() // 1000000)
    if result.returncode:
        RECEIPT["state"] = "FAILED"
    save()
    if result.returncode:
        raise SystemExit(result.returncode)


save()
cargo = ["/home/ubuntu/.cargo/bin/cargo", "+1.98.0"]
run("sdk-tests", cargo + ["test", "--release", "--locked"], SOURCE / "crates/blockzilla-bank-client")
run("sdk-probe", cargo + ["build", "--release", "--locked", "--example", "worker_recovery_probe"], SOURCE / "crates/blockzilla-bank-client")
if "--sdk-only" not in sys.argv:
    run("sidecar-tests", cargo + ["test", "--release", "--locked"], SOURCE / "hivezilla/stream-sidecar")
    fixture = Path("/home/ubuntu/live/hivezilla-validator-20260930/jobs/native-deploy-20261121/live-r5/transport-fresh/frames/2cac53af86778406175e09b43f104ee479c6745d3d4fc4c97932e295c41f5aee.bin")
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == "2cac53af86778406175e09b43f104ee479c6745d3d4fc4c97932e295c41f5aee"
    os.environ["BLOCKZILLA_SIDECAR_FRAME"] = str(fixture)
    run("automatic-recovery-fixture", cargo + ["test", "--release", "--locked",
        "automatic_worker_recovery_commits_once_after_disconnect_and_restart", "--", "--ignored", "--nocapture"], SOURCE / "hivezilla/stream-sidecar")
    run("sidecar-release", cargo + ["build", "--release", "--locked"], SOURCE / "hivezilla/stream-sidecar")
artifacts = {}
paths = [TARGET / "release/examples/worker_recovery_probe"]
if "--sdk-only" not in sys.argv:
    paths.append(TARGET / "release/blockzilla-stream-sidecar")
for path in paths:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    dest = JOB / "candidate" / digest / path.name
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(path, dest)
    dest.chmod(0o500)
    artifacts[path.name] = {"path": str(dest), "bytes": dest.stat().st_size, "sha256": digest}
RECEIPT.update(state="PASSED", artifacts=artifacts, finished_at_unix_ms=time.time_ns() // 1000000)
save()
print(json.dumps(RECEIPT))
