#!/usr/bin/env python3
"""Read provider freshness, resource use and actual replay storage on its host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import urllib.request


def sample(token, previous):
    started = time.monotonic()
    props = dict(line.split("=", 1) for line in subprocess.check_output(
        ["systemctl", "show", "blockzilla-client-pipe.service", "-pMainPID", "-pActiveState"],
        text=True).splitlines())
    pid = int(props["MainPID"])
    row = {"sampledAtMs": time.time_ns() // 1_000_000, "pid": pid,
           "activeState": props["ActiveState"], "rootFreeBytes": shutil.disk_usage("/").free}
    if pid:
        proc = Path(f"/proc/{pid}")
        stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        cpu = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
        row["rssBytes"] = int(stat[21]) * os.sysconf("SC_PAGE_SIZE")
        if previous and previous[0] == pid:
            row["cpuCores"] = (cpu - previous[1]) / (started - previous[2])
            row["artifactSha256"] = previous[3]
        else:
            with (proc / "exe").open("rb") as source:
                row["artifactSha256"] = hashlib.file_digest(source, "sha256").hexdigest()
        previous = (pid, cpu, started, row["artifactSha256"])
    request = urllib.request.Request("http://127.0.0.1:18890/v1/head",
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=3) as response:
        head = json.load(response)
    fields = ("source", "input", "error", "signingReady", "payloadMode", "beamCommittedCursor",
              "beamSourceObservedAtMs", "beamLastFrameAgeMs", "sampledAtMs", "outputCursor", "payloadCache")
    row["head"] = {field: head.get(field) for field in fields}
    if isinstance(head.get("beamSourceObservedAtMs"), int) and isinstance(head.get("sampledAtMs"), int):
        row["sourceAgeMs"] = head["sampledAtMs"] - head["beamSourceObservedAtMs"]
    with sqlite3.connect("file:/var/lib/blockzilla-client-pipe/client.sqlite?mode=ro", uri=True, timeout=0.5) as db:
        db.execute("PRAGMA query_only=ON")
        has_covering_index = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='payloads_wire_bytes'"
        ).fetchone() is not None
        count, stored, wire = db.execute(
            "SELECT COUNT(*),COALESCE(SUM(bytes),0),COALESCE(SUM(length(wire)),0) "
            "FROM payloads" + (" INDEXED BY payloads_wire_bytes" if has_covering_index else "")
        ).fetchone()
        projection = stored - wire
        first = db.execute("SELECT cursor,event FROM updates ORDER BY sequence LIMIT 1").fetchone()
        last = db.execute("SELECT cursor,event FROM updates ORDER BY sequence DESC LIMIT 1").fetchone()
        replay = {"payloads": count, "accountedBytes": stored, "nativeWireBytes": wire,
                  "projectionBytes": projection, "updates": db.execute("SELECT COUNT(*) FROM updates").fetchone()[0],
                  "databasePageBytes": db.execute("PRAGMA page_count").fetchone()[0] * db.execute("PRAGMA page_size").fetchone()[0]}
        if first and last:
            replay.update(oldestOutputCursor=first[0], newestOutputCursor=last[0])
            old_time = json.loads(first[1]).get("observed_at_unix_ms")
            new_time = json.loads(last[1]).get("observed_at_unix_ms")
            if isinstance(old_time, int) and isinstance(new_time, int):
                replay.update(oldestNativeObservedAtMs=old_time, newestNativeObservedAtMs=new_time,
                              nativeObservationSpanMs=new_time - old_time)
        row["replay"] = replay
    row["probeDurationMs"] = round((time.monotonic() - started) * 1000, 3)
    return row, previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=300)
    parser.add_argument("--interval-seconds", type=float, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.duration_seconds <= 3600 or not 1 <= args.interval_seconds <= 60:
        parser.error("duration must be 1..3600; interval must be 1..60")
    if not args.output.is_absolute():
        parser.error("output must be an absolute private path outside the replay volume")
    if args.output.is_relative_to(Path("/var/lib/blockzilla-client-pipe")):
        parser.error("do not put evidence in the bounded replay volume")
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = Path("/etc/blockzilla-client-pipe/reader-token").read_text().strip()
    deadline = time.monotonic() + args.duration_seconds
    previous = None
    samples = ready = failures = 0
    with args.output.open("x") as output:
        os.fchmod(output.fileno(), 0o600)
        while time.monotonic() < deadline:
            started = time.monotonic()
            try:
                row, previous = sample(token, previous)
                ready += int(row["head"].get("signingReady") is True)
            except (OSError, ValueError, sqlite3.Error) as error:
                row = {"sampledAtMs": time.time_ns() // 1_000_000, "errorType": type(error).__name__}
                failures += 1
            output.write(json.dumps(row, separators=(",", ":")) + "\n")
            output.flush()
            samples += 1
            remaining = min(args.interval_seconds - (time.monotonic() - started), deadline - time.monotonic())
            if remaining > 0:
                time.sleep(remaining)
    print(json.dumps({"evidence": str(args.output), "samples": samples, "readySamples": ready,
                      "failedSamples": failures}))


if __name__ == "__main__":
    main()
