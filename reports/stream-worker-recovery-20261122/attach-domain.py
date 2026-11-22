#!/usr/bin/env python3
"""Attach only the getBlock hostname; never upload or change Worker code."""
import json
import pathlib
import tomllib
import urllib.error
import urllib.request

ACCOUNT = "8df0426c80fcd1a04ed439f441db9ff8"
ZONE = "fe1afd69f777e57eca0a230722f77da2"
HOST = "getblock.blockzilla.dev"
SERVICE = "blockzilla-get-block"
REPORT = pathlib.Path(__file__).resolve().parent


def main():
    config = pathlib.Path.home() / "Library/Preferences/.wrangler/config/default.toml"
    token = tomllib.loads(config.read_text())["oauth_token"]
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers/domains"
    headers = {"Authorization": "Bearer " + token,
               "Content-Type": "application/json", "User-Agent": "blockzilla-deployment/1.0"}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        before = json.load(r)
    assert before["success"]
    current = [v for v in before["result"] if v["hostname"] == HOST]
    assert not current or all(v["service"] == SERVICE and v["zone_id"] == ZONE for v in current)
    body = {"hostname": HOST, "service": SERVICE, "zone_id": ZONE,
            "enabled": True, "previews_enabled": False}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            result = json.load(r)
    except urllib.error.HTTPError as e:
        result = {"success": False, "status": e.code, "response": json.loads(e.read())}
    (REPORT / "domain-attachment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    assert result["success"], "Custom domain attach failed; see report"
    attached = result["result"]
    assert attached["hostname"] == HOST and attached["service"] == SERVICE


if __name__ == "__main__":
    main()
