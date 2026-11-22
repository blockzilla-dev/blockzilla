#!/usr/bin/env python3
"""Check HTTPS, authentication and an original archive digest without saving bodies."""
import datetime
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess

HOST = "getblock.blockzilla.dev"
REPORT = Path(__file__).resolve().parent
ROOT = REPORT.parent.parent


class Connection(http.client.HTTPSConnection):
    def __init__(self, address):
        super().__init__(HOST, timeout=30, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, 443), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=HOST)


def main():
    # Use a public resolver for this check; macOS may retain the prior NXDOMAIN.
    addresses = subprocess.check_output(["dig", "@1.1.1.1", HOST, "A", "+short"], text=True).splitlines()
    assert addresses
    key = (ROOT / ".codex-tmp/get-block-deploy-20261121/private/worker-api-key.txt").read_text().strip()
    cases = [("info", "/info", False, 200, None),
             ("unauthenticated", "/block/470555971.bin", False, 401, None),
             ("archive-bytes", "/block/470555971.bin?profile=1", True, 200,
              "c0fc8383e217705dde28612195cc165e95b2163c73743e5cb1586aab220c8415"),
             ("missing-recovery-pins", "/block/470555971.compact", True, 400, None)]
    rows = []
    for label, path, authenticated, expected_status, expected_digest in cases:
        conn = Connection(addresses[0])
        headers = {"User-Agent": "blockzilla-get-block/1.0", "Accept-Encoding": "identity"}
        if authenticated:
            headers["Authorization"] = "Bearer " + key
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        digest, size = hashlib.sha256(), 0
        while data := response.read(65536):
            size += len(data)
            assert size <= 4 * 1024 * 1024
            digest.update(data)
        row = {"case": label, "status": response.status, "bytes": size,
               "sha256": digest.hexdigest(), "expected_status": expected_status,
               "content_type": response.getheader("content-type"),
               "archive_gets": {h: response.getheader(h) for h in
                                ["X-Blockzilla-R2-GETs", "X-Blockzilla-S3-GETs"]}}
        row["passed"] = response.status == expected_status and (expected_digest is None or digest.hexdigest() == expected_digest)
        rows.append(row)
        conn.close()
    report = {"schema": "blockzilla-domain-check-v1", "host": HOST,
              "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "resolver": "1.1.1.1", "addresses": addresses,
              "tls_hostname_verified": True, "payload_files_written": False,
              "checks": rows, "passed": all(r["passed"] for r in rows)}
    (REPORT / "domain-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    assert report["passed"]


if __name__ == "__main__":
    main()
