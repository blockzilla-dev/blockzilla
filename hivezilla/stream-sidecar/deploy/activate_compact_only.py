#!/usr/bin/env python3
"""Activate a tested sidecar artifact on the current Hetzner host.

Run as root on the consumer host. This changes only the sidecar service. A
failed activation restores the pre-migration database and its prior service
configuration. It never changes the validator or application containers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import time
import urllib.request


UNIT = "blockzilla-client-pipe.service"
DATABASE = Path("/var/lib/blockzilla-client-pipe/client.sqlite")
DROPIN = Path("/etc/systemd/system/" + UNIT + ".d/40-compact-only.conf")
BACKUPS = Path("/var/backups/blockzilla-client-pipe")
RELEASES = Path("/opt/blockzilla-client-pipe-20261122/releases")
RESOURCE_KEYS = ("CPUQuotaPerSecUSec", "MemoryHigh", "MemoryMax", "MemorySwapMax", "TasksMax")


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def properties():
    values = command("systemctl", "show", UNIT, "-pMainPID", "-pActiveState",
                     *("-p" + key for key in RESOURCE_KEYS))
    return dict(line.split("=", 1) for line in values.splitlines())


def digest(path):
    with Path(path).open("rb") as source:
        result = hashlib.file_digest(source, "sha256").hexdigest()
    return result


def head():
    token = Path("/etc/blockzilla-client-pipe/reader-token").read_text().strip()
    request = urllib.request.Request("http://127.0.0.1:18890/v1/head",
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.load(response)
    fields = ("source", "input", "error", "signingReady", "payloadMode",
              "beamCommittedCursor", "beamSourceObservedAtMs", "sampledAtMs", "outputCursor")
    return {field: value.get(field) for field in fields}


def containers():
    ids = command("docker", "ps", "-q").splitlines()
    if not ids:
        return {}
    rows = json.loads(command("docker", "inspect", *ids))
    return {row["Id"]: {"name": row["Name"], "image": row["Image"],
                         "startedAt": row["State"]["StartedAt"]} for row in rows}


def position(cursor, marker):
    if not cursor:
        raise ValueError("cursor is missing")
    field = cursor.split(":")[1]
    if not field.startswith(marker):
        raise ValueError("wrong cursor kind")
    return int(field[1:])


def save(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def restore_database(backup, ownership):
    # Both writer and SQLite readers belong to this stopped service. Remove
    # only its side files before restoring the consistent backup image.
    for suffix in ("-wal", "-shm"):
        Path(str(DATABASE) + suffix).unlink(missing_ok=True)
    staged = DATABASE.with_name(DATABASE.name + ".restore")
    shutil.copyfile(backup / "client.sqlite", staged)
    os.chown(staged, ownership[0], ownership[1])
    staged.chmod(ownership[2])
    with staged.open("rb") as source:
        os.fsync(source.fileno())
    staged.replace(DATABASE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--previous-sha256", required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run on the consumer host as root")
    if any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
           for value in (args.sha256, args.previous_sha256)):
        parser.error("invalid artifact digest")
    build = json.loads(args.build_receipt.read_text())
    assert build["state"] == "PASSED" and build["sha256"] == args.sha256
    assert digest(args.candidate) == args.sha256
    assert not DROPIN.exists(), "existing compact-only override requires review"
    before = properties()
    pid = int(before["MainPID"])
    assert pid > 0 and before["ActiveState"] == "active"
    assert digest(f"/proc/{pid}/exe") == args.previous_sha256
    argv = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    assert "--payload-mode" not in argv, "payload mode is already configured"
    assert all(not any(c in arg for c in ("%", "$", "\n", "\r")) for arg in argv)
    before_head = head()
    before_containers = containers()
    database_stat = DATABASE.stat()
    ownership = (database_stat.st_uid, database_stat.st_gid, database_stat.st_mode & 0o777)
    assert before_head["source"] and before_head["beamCommittedCursor"]
    assert shutil.disk_usage(BACKUPS.parent).free >= 1024 ** 3, "backup headroom is too small"
    backup = BACKUPS / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + args.sha256[:12])
    backup.mkdir(parents=True, mode=0o700)
    receipt_path = backup / "activation.json"
    release = RELEASES / args.sha256
    release.mkdir(parents=True, mode=0o755)
    binary = release / "blockzilla-stream-sidecar"
    shutil.copyfile(args.candidate, binary)
    binary.chmod(0o555)
    assert digest(binary) == args.sha256
    (backup / "previous-systemd.txt").write_text(command("systemctl", "cat", UNIT) + "\n")
    (backup / "previous-systemd.txt").chmod(0o600)
    receipt = {"schema": "blockzilla-compact-only-activation-v1", "state": "PREPARED",
               "startedAtMs": time.time_ns() // 1_000_000, "sha256": args.sha256,
               "previousSha256": args.previous_sha256, "backup": str(backup),
               "buildReceiptSha256": digest(args.build_receipt), "before": before,
               "activationToolSha256": digest(__file__),
               "beforeHead": before_head, "beforeContainers": before_containers}
    save(receipt_path, receipt)
    backup_complete = False
    try:
        command("systemctl", "stop", UNIT)
        assert int(properties()["MainPID"]) == 0
        backup_deadline = time.monotonic() + 20
        def backup_progress(status, remaining, total):
            if time.monotonic() > backup_deadline:
                raise TimeoutError("stopped database backup exceeded its deadline")
        with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True, timeout=5) as source:
            stopped_cursor = source.execute(
                "SELECT cursor,output_cursor FROM checkpoint WHERE id=1").fetchone()
            assert stopped_cursor and all(stopped_cursor)
            with sqlite3.connect(backup / "client.sqlite") as destination:
                source.backup(destination, pages=256, sleep=0.01, progress=backup_progress)
                assert destination.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        (backup / "client.sqlite").chmod(0o600)
        backup_complete = True
        receipt["stoppedCheckpoint"] = {"sourceCursor": stopped_cursor[0], "outputCursor": stopped_cursor[1]}
        save(receipt_path, receipt)
        DROPIN.parent.mkdir(parents=True, exist_ok=True)
        DROPIN.write_text("[Service]\nExecStart=\nExecStart=" +
                          shlex.join([str(binary), *argv[1:], "--payload-mode", "compact-only"]) + "\n")
        DROPIN.chmod(0o644)
        command("systemctl", "daemon-reload")
        command("systemctl", "restart", UNIT)
        deadline = time.monotonic() + 45
        after_head = None
        fresh_samples = 0
        while time.monotonic() < deadline:
            try:
                after_head = head()
                sample_time = after_head.get("sampledAtMs")
                observed = after_head.get("beamSourceObservedAtMs")
                fresh = (after_head.get("payloadMode") == "compact-only"
                         and after_head.get("beamCommittedCursor")
                         and after_head.get("input") == "live"
                         and after_head.get("signingReady") is True
                         and isinstance(sample_time, int) and isinstance(observed, int)
                         and -1000 <= sample_time - observed <= 5000
                         and abs(time.time_ns() // 1_000_000 - sample_time) <= 2000)
                fresh_samples = fresh_samples + 1 if fresh else 0
                if fresh_samples >= 3:
                    break
            except (OSError, ValueError):
                fresh_samples = 0
            time.sleep(0.25)
        assert after_head and after_head["payloadMode"] == "compact-only"
        assert fresh_samples >= 3, "candidate did not establish fresh live signing data"
        assert after_head["source"] == before_head["source"]
        assert after_head["error"] is None and after_head["input"] != "failed"
        assert position(after_head["beamCommittedCursor"], "p") >= position(stopped_cursor[0], "p")
        assert position(after_head["outputCursor"], "o") >= position(stopped_cursor[1], "o")
        after = properties()
        assert int(after["MainPID"]) > 0 and after["MainPID"] != before["MainPID"]
        assert digest(f"/proc/{after['MainPID']}/exe") == args.sha256
        assert all(after[key] == before[key] for key in RESOURCE_KEYS)
        after_containers = containers()
        assert all(after_containers.get(key) == value for key, value in before_containers.items())
        with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            assert db.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
            count, projection_bytes, accounted, native = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(projection)),0),COALESCE(SUM(bytes),0),"
                "COALESCE(SUM(length(wire)),0) FROM payloads").fetchone()
            assert count > 0 and projection_bytes == 0 and accounted == native
        receipt.update(state="ACTIVATED", finishedAtMs=time.time_ns() // 1_000_000,
                       after=after, afterHead=after_head, afterContainers=after_containers,
                       resourcesUnchanged=True, existingContainersUnchanged=True,
                       freshSigningAtActivation=True,
                       compactPayloads=count, projectionBytes=projection_bytes, nativeWireBytes=native)
    except BaseException as error:
        command("systemctl", "stop", UNIT)
        DROPIN.unlink(missing_ok=True)
        if backup_complete:
            restore_database(backup, ownership)
        command("systemctl", "daemon-reload")
        command("systemctl", "restart", UNIT)
        receipt.update(state="ROLLED_BACK", failureType=type(error).__name__,
                       finishedAtMs=time.time_ns() // 1_000_000)
        save(receipt_path, receipt)
        raise
    save(receipt_path, receipt)
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
