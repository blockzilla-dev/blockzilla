#!/usr/bin/env python3
"""Run on Foundation. Keep keys and native frame bodies in RAM only."""

import argparse
import hashlib
import http.client
import json
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path

MAX_FRAME = 16 + 65536 + 16 * 1024 * 1024


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private_key(path):
    value = path.read_text().strip()
    require(32 <= len(value) <= 256 and all(33 <= ord(c) <= 126 for c in value), "invalid private key file")
    return value


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=8)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(8)
        self.sock.connect(str(self.path))


def request(path, key, limit, host="stream.blockzilla.dev", unix=None, method="GET"):
    connection = UnixHTTP(unix) if unix else http.client.HTTPSConnection(host, timeout=8)
    headers = {"Accept-Encoding": "identity"}
    if key is not None:
        headers["Authorization"] = "Bearer " + key
    started = time.monotonic()
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = response.read(limit + 1)
    require(len(body) <= limit, "HTTP response exceeded its byte limit")
    result = (response.status, dict((k.lower(), v) for k, v in response.getheaders()), body, round((time.monotonic() - started) * 1000, 3))
    connection.close()
    return result


def exact(response, length):
    output = bytearray()
    while len(output) < length:
        part = response.read(length - len(output))
        require(part, "native stream ended inside a frame")
        output.extend(part)
    return bytes(output)


def frame(wire, source):
    require(len(wire) >= 16 and wire[:8] == b"BZSTRM01", "invalid frame magic")
    metadata_length = int.from_bytes(wire[8:12], "little")
    payload_length = int.from_bytes(wire[12:16], "little")
    require(0 < metadata_length <= 65536 and payload_length <= 16 * 1024 * 1024, "frame bounds differ")
    require(len(wire) == 16 + metadata_length + payload_length, "frame length differs")
    envelope = json.loads(wire[16:16 + metadata_length])
    require(envelope["schema"] == "blockzilla-stream-envelope-v2" and envelope["profile"] == "native-bank-compact-v2", "frame profile differs")
    marker = envelope["marker"]
    require(all(marker[k] == source[k] for k in ["genesis_hash", "node_identity", "agave_revision", "session_id"]), "frame source differs")
    offset = 0
    names = set()
    payload = memoryview(wire)[16 + metadata_length:]
    for item in envelope["objects"]:
        require(item["path"] not in names and item["offset"] == offset, "frame object order differs")
        names.add(item["path"])
        end = offset + item["bytes"]
        require(end <= len(payload) and hashlib.sha256(payload[offset:end]).hexdigest() == item["sha256"], "frame object hash differs")
        offset = end
    require(offset == len(payload), "frame has unindexed payload bytes")
    digest = hashlib.sha256(wire).hexdigest()
    event = envelope["event"]
    cursor = f"{source['session_id']}:p{event['sequence']}:{digest}"
    return {"sha256": digest, "cursor": cursor, "sequence": event["sequence"], "kind": event["kind"], "slot": event["bank"]["slot"], "bytes": len(wire), "objects_checked": len(names)}, event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/home/ubuntu/live/hivezilla-validator-20260930"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    job = root / "jobs/public-native-stream-20261122"
    before = json.loads((job / "PREFLIGHT.json").read_text())
    current = private_key(root / f"jobs/native-continuous-20261121/runs/{before['generation']}/origin-token")
    legacy = private_key(root / "config/stream-20261004/client-api.key")
    receipt = {"status": "RUNNING", "block_payload_persisted": False, "keys_printed_or_copied": False}
    try:
        auth = []
        for label, key, expected, path in [("missing", None, 401, "/v2/banks/head"), ("wrong", "invalid-key", 401, "/v2/banks/head"), ("legacy", legacy, 401, "/v2/banks/head"), ("current", current, 200, "/v2/banks/head"), ("url-key-rejected", current, 401, "/v2/banks/head?api_key=invalid-key")]:
            status, headers, body, elapsed = request(path, key, 65536)
            require(status == expected, "public authentication result differs")
            require("no-store" in headers.get("cache-control", ""), "public native response is cacheable")
            auth.append({"credential": label, "status": status, "wall_ms": elapsed})
            if label == "current":
                head = json.loads(body)
        receipt["auth"] = auth
        require(head["status"] == "live", "public head is not live")
        expected_session = "000000000000000018ea5078fdda19df-13e843"
        require(head["source"]["session_id"] == expected_session, "public source session changed")
        source = head["source"]
        after = head["cursor"]
        sequence = int(after.split(":")[1][1:])
        connection = http.client.HTTPSConnection("stream.blockzilla.dev", timeout=8)
        connection.request("GET", "/v2/banks/beam?after=" + urllib.parse.quote(after, safe=""), headers={"Authorization": "Bearer " + current, "Accept-Encoding": "identity"})
        response = connection.getresponse()
        require(response.status == 200 and response.getheader("x-blockzilla-start-cursor") == after, "beam start cursor differs")
        require(response.getheader("content-type") == "application/vnd.blockzilla.stream.v2", "beam content type differs")
        frames = []
        rooted_slot = None
        for _ in range(6):
            header = exact(response, 16)
            length = 16 + int.from_bytes(header[8:12], "little") + int.from_bytes(header[12:16], "little")
            require(header[:8] == b"BZSTRM01" and 16 < length <= MAX_FRAME, "beam frame bounds differ")
            wire = header + exact(response, length - 16)
            row, event = frame(wire, source)
            require(row["sequence"] == sequence + 1, "beam cursor has a gap or duplicate")
            original_status, _, original_wire, _ = request("/v2/banks/chunks/" + row["sha256"], current, MAX_FRAME, unix=root / "runtime/live/origin.sock")
            require(original_status == 200 and wire == original_wire, "beam frame differs from the original origin")
            row["original_bytes_equal"] = True
            sequence = row["sequence"]
            frames.append(row)
            if event["kind"] == "root":
                rooted_slot = event["bank"]["slot"]
                break
        connection.close()
        receipt["beam"] = {"start_cursor": after, "frames": frames, "exact_next_sequences": True}
        digest = head["latest_confirmed"]["payload_frame_sha256"]
        status, headers, public_wire, elapsed = request("/v2/banks/chunks/" + digest, current, MAX_FRAME)
        require(status == 200 and hashlib.sha256(public_wire).hexdigest() == digest, "public finite chunk identity differs")
        chunk, _ = frame(public_wire, source)
        direct_status, _, direct_wire, _ = request("/v2/banks/chunks/" + digest, current, MAX_FRAME, unix=root / "runtime/live/origin.sock")
        require(direct_status == 200 and public_wire == direct_wire, "public finite chunk differs from the original origin")
        receipt["chunk"] = {**chunk, "wall_ms": elapsed, "original_bytes_equal": True}
        private_routes = []
        for path in ["/v2/banks/state", "/v2/banks/ack", "/v2/banks/coverage-gaps", "/v2/banks/finalized/events", "/health"]:
            status, _, _, _ = request(path, current, 4096)
            require(status == 404, "origin-only public path is not closed")
            private_routes.append({"path": path, "status": status})
        receipt["private_origin_paths"] = private_routes
        require(rooted_slot is not None, "bounded beam did not contain a root for getBlock check")
        status, headers, body, elapsed = request(f"/block/{rooted_slot}.json?rewards=false&profile=1", None, 16 * 1024 * 1024, host="archive.blockzilla.dev")
        require(status == 200 and "result" in json.loads(body), "current public getBlock failed after private route change")
        require(headers.get("x-blockzilla-foundation-result") == "NATIVE_RECENT", "getBlock did not use the original native private path")
        receipt["getblock"] = {"slot": rooted_slot, "status": status, "foundation": headers.get("x-blockzilla-foundation-result"), "r2_gets": headers.get("x-blockzilla-r2-gets"), "s3_gets": headers.get("x-blockzilla-s3-gets"), "body_sha256": hashlib.sha256(body).hexdigest(), "wall_ms": elapsed}
        after_units = {}
        for unit, expected in before["units"].items():
            raw = subprocess.run(["systemctl", "show", unit, "-p", "MainPID", "-p", "InvocationID", "-p", "NRestarts", "-p", "ActiveState"], capture_output=True, text=True, check=True).stdout
            actual = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
            require(all(actual[k] == expected[k] for k in actual), "protected process pin changed")
            after_units[unit] = actual
        receipt["protected_units"] = after_units
        authority = Path(before["authority"]["path"])
        require(hashlib.sha256(authority.read_bytes()).hexdigest() == before["authority"]["sha256"], "retention authority changed")
        require((root / "runtime/live/origin.sock").stat().st_mode & 0o777 == 0o600, "origin socket mode changed")
        receipt["retention_authority_unchanged"] = True
        receipt["origin_socket_mode_unchanged"] = True
        raw = subprocess.run(["systemctl", "show", "hivezilla-native-stream-proxy.service", "-p", "MainPID", "-p", "MemoryCurrent", "-p", "MemoryPeak", "-p", "MemoryMax", "-p", "LimitNOFILE", "-p", "PrivateNetwork", "-p", "ProtectHome", "-p", "NRestarts"], capture_output=True, text=True, check=True).stdout
        proxy = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        require(proxy["MemoryMax"] == "67108864" and proxy["LimitNOFILE"] == "512", "proxy limits differ")
        pid = proxy["MainPID"]
        status_lines = (Path("/proc") / pid / "status").read_text().splitlines()
        proxy["rss_kib"] = int(next(line for line in status_lines if line.startswith("VmRSS:")).split()[1])
        proxy["open_fds"] = len(list((Path("/proc") / pid / "fd").iterdir()))
        receipt["proxy"] = proxy
        receipt["status"] = "PASS"
    except Exception as error:
        receipt["status"] = "FAIL"
        receipt["reason"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    raise SystemExit(0 if receipt["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
