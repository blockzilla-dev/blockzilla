#!/usr/bin/env python3
"""Restrict one relay SSH key to the pinned raw stream adapter.

Use as an authorized_keys forced command with restrict. No shell command from
the peer is executed. Existing owner SSH access is separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def admitted(original, gateway, job):
    if not original or len(original) > 16384:
        raise ValueError('missing_or_large_command')
    argv = shlex.split(original)
    if argv[:4] != ['/usr/bin/python3', '-u', '-B', gateway] or len(argv[4:]) % 2:
        raise ValueError('unapproved_command')
    options = {}
    for key, value in zip(argv[4::2], argv[5::2]):
        if key in options or key not in ('--job', '--mode', '--generation', '--source-json', '--after', '--until', '--max-events', '--digest', '--block-id', '--anchor-id', '--max-blocks', '--max-wire-bytes'):
            raise ValueError('unapproved_option')
        options[key] = value
    if options.get('--job') != job:
        raise ValueError('unapproved_job')
    mode = options.get('--mode')
    common = {'--job', '--mode', '--generation', '--source-json'}
    allowed = {'head': common, 'stream': common | {'--after'}, 'frame': common | {'--digest'},
               'recovery-plan': common | {'--after', '--until', '--max-events'},
               'finalized-block': common | {'--block-id'},
               'finalized-path': common | {'--block-id', '--anchor-id', '--max-blocks', '--max-wire-bytes'},
               'clock': {'--job', '--mode'}}
    if mode not in allowed or not set(options) <= allowed[mode]:
        raise ValueError('unapproved_mode')
    if mode in ('stream', 'frame', 'finalized-block', 'finalized-path', 'recovery-plan') and not {'--generation', '--source-json'} <= set(options):
        raise ValueError('missing_source_pins')
    if mode == 'stream' and '--after' not in options or mode == 'frame' and '--digest' not in options:
        raise ValueError('missing_position')
    if mode == 'finalized-block' and '--block-id' not in options:
        raise ValueError('missing_position')
    if mode == 'finalized-path' and not {'--block-id', '--anchor-id', '--max-blocks', '--max-wire-bytes'} <= set(options):
        raise ValueError('missing_position')
    if mode == 'recovery-plan' and not {'--after', '--until', '--max-events'} <= set(options):
        raise ValueError('missing_position')
    return ['/usr/bin/python3', '-I', '-u', '-B', gateway] + argv[4:]


def selected_gateway(original, pins):
    """Allow only complete file paths with exact content pins during rollout."""
    if not original or len(original) > 16384:
        raise ValueError('missing_or_large_command')
    argv = shlex.split(original)
    expected = {}
    for gateway, digest in pins:
        if (gateway in expected or not Path(gateway).is_absolute()
                or str(Path(gateway)) != gateway):
            raise ValueError('invalid_adapter_pins')
        expected[gateway] = digest
    if len(argv) < 4 or argv[3] not in expected:
        raise ValueError('unapproved_adapter')
    path = Path(argv[3])
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected[str(path)]:
        raise ValueError('adapter_pin_changed')
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--gateway-sha', required=True)
    parser.add_argument('--allow-gateway', nargs=2, action='append', default=[], metavar=('PATH', 'SHA256'))
    parser.add_argument('--job', required=True)
    args = parser.parse_args()
    try:
        original = os.environ.get('SSH_ORIGINAL_COMMAND', '')
        gateway = selected_gateway(original, [(args.gateway, args.gateway_sha), *args.allow_gateway])
        command = admitted(original, gateway, args.job)
        return subprocess.call(command)
    except (ValueError, OSError):
        print(json.dumps({'schema': 'blockzilla-ssh-beam-v1', 'status': 403, 'error': 'restricted_stream_key'}))
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
