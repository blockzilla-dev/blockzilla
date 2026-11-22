"""Private SSH fields stay in process. All calls keep strict host checks."""
from pathlib import Path
import shlex
import subprocess


def connection(host):
    if host == "foundation":
        return ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=12"], "ubuntu@213.239.141.61"
    assert host == "consumer"
    values = {}
    for line in (Path.home() / ".config/ferno/hetzner-production.env").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = shlex.split(line.removeprefix("export "), comments=True)
        if len(fields) == 1 and "=" in fields[0]:
            key, value = fields[0].split("=", 1)
            if key in {"SSH_HOST", "SSH_USER", "SSH_PORT", "SSH_IDENTITY_FILE"}:
                values[key] = value
    assert values["SSH_HOST"] == "188.245.147.127"
    return ["-o", "UseKeychain=yes", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=12",
            "-i", values["SSH_IDENTITY_FILE"], "-p", values.get("SSH_PORT", "22")], \
        values["SSH_USER"] + "@" + values["SSH_HOST"]


def ssh(host, command, data=None, timeout=60, check=True):
    options, target = connection(host)
    return subprocess.run(["ssh", *options, target, command], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=check)


def put(host, local, remote):
    # Remote path is fixed by the caller; a single SSH stream avoids scp path rules.
    path = Path(local)
    return ssh(host, "umask 077; cat > " + shlex.quote(remote), path.read_bytes())
