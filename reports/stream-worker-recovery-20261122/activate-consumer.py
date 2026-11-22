#!/usr/bin/env python3
"""Activate the tested recovery client on the existing consumer database.

Run as root on the Hetzner consumer. This makes one controlled stop/start.
It copies code only. Rollback restores only the new systemd override and
starts the old binary on the current database. It never restores a database
or moves a cursor backward. No fault is injected by this script.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.request


UNIT = 'blockzilla-client-pipe.service'
PREVIOUS_SHA = 'fd246ddb77e3fa478de8809c374499ddde11811da64996eb8167028767c1fc14'
RELEASES = Path('/opt/blockzilla-client-pipe-20261122/releases')
DATABASE = Path('/var/lib/blockzilla-client-pipe/client.sqlite')
DROPIN = Path('/etc/systemd/system/' + UNIT + '.d/50-worker-recovery.conf')
SOURCE_FILE = Path('/etc/blockzilla-client-pipe/SOURCE.json')
WORKER_KEY = Path('/etc/blockzilla-client-pipe/worker-api-key')
WORKER_URL = 'https://getblock.blockzilla.dev'
RUNTIME = 'c1739ce6fcee61291f41548b1960aa27'
PRODUCER = '4aaf2462131201579e55e0679f31f4a992d2c85d4e3c4891f682537625e88900'
FOUNDATION = '/home/ubuntu/live/hivezilla-validator-20260930'
OLD_HELPER = FOUNDATION + '/releases/native-relay-access-20261122-c74ca0aa24f762ed/beam_ssh_gateway.py'
NEW_HELPER = FOUNDATION + '/releases/native-relay-recovery-20261122-93ef3aef5593c417/beam_ssh_gateway.py'
EXPECTED_SOURCE = {
    'agave_revision': 'agave-4.4.0-source-251b5d923155da2673dadaeed777994cbfe2f5176b33948d19b608be94686b6d',
    'genesis_hash': '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
    'node_identity': 'J7qpvCEWhdBgPdYRV3s3btWPrRVXa2qnAzgvxWTvtbrQ',
    'session_id': '000000000000000018ea5078fdda19df-13e843',
}
EXPECTED_ARGV = [str(RELEASES / PREVIOUS_SHA / 'blockzilla-stream-sidecar'),
    '--source-file', str(SOURCE_FILE), '--producer-generation', PRODUCER,
    '--runtime-generation', RUNTIME, '--upstream-ssh-host', 'ubuntu@213.239.141.61',
    '--upstream-ssh-helper', OLD_HELPER, '--upstream-ssh-job', FOUNDATION + '/jobs/native-continuous-20261121',
    '--token-file', '/etc/blockzilla-client-pipe/admin-token',
    '--reader-token-file', '/etc/blockzilla-client-pipe/reader-token',
    '--database', str(DATABASE), '--join-head', '--replay-mib', '128',
    '--replay-events', '8192', '--database-mib', '320', '--disk-reserve-mib', '64',
    '--max-clients', '4', '--bind', '127.0.0.1:18890', '--payload-mode', 'compact-only']
RESOURCE_KEYS = ('CPUQuotaPerSecUSec', 'CPUWeight', 'MemoryHigh', 'MemoryMax', 'MemorySwapMax',
                 'TasksMax', 'LimitNOFILE', 'TimeoutStopUSec', 'RestartUSec', 'User', 'Group',
                 'ProtectSystem', 'ProtectHome', 'ReadWritePaths')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def command(*argv):
    return subprocess.check_output(argv, text=True, timeout=45).strip()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def regular(path):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_regular_file:' + str(path))
    return info


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def properties():
    raw = command('systemctl', 'show', UNIT, '-pMainPID', '-pActiveState', '-pInvocationID',
                  '-pNRestarts', '-pFragmentPath', '-pDropInPaths', *('-p' + key for key in RESOURCE_KEYS))
    return dict(line.split('=', 1) for line in raw.splitlines())


def unit_files(props):
    paths = [props['FragmentPath'], *shlex.split(props['DropInPaths'])]
    return {path: digest(path) for path in paths if Path(path) != DROPIN}


def service_invocations():
    names = [line.split()[0] for line in command('systemctl', 'list-units', '--type=service',
              '--state=running', '--no-pager', '--plain', '--no-legend').splitlines() if line.strip()]
    names = [name for name in names if name != UNIT]
    if not names:
        return {}
    raw = command('systemctl', 'show', *names, '-pId', '-pInvocationID', '-pMainPID', '-pActiveState')
    result = {}
    for item in raw.split('\n\n'):
        fields = dict(line.split('=', 1) for line in item.splitlines() if '=' in line)
        if fields.get('Id') in names:
            result[fields['Id']] = {key: fields[key] for key in ('InvocationID', 'MainPID', 'ActiveState')}
    require(len(result) == len(names), 'service_inventory_incomplete')
    return result


def containers():
    ids = command('docker', 'ps', '-q').splitlines()
    if not ids:
        return {}
    rows = json.loads(command('docker', 'inspect', *ids))
    return {row['Id']: {'name': row['Name'], 'image': row['Image'],
                       'startedAt': row['State']['StartedAt']} for row in rows}


def position(cursor, kind):
    require(isinstance(cursor, str), 'missing_cursor')
    fields = cursor.split(':')
    require(len(fields) == 3 and fields[0] == EXPECTED_SOURCE['session_id']
            and re.fullmatch(re.escape(kind) + r'(0|[1-9][0-9]*)', fields[1])
            and (fields[2] == '-' or re.fullmatch('[0-9a-f]{64}', fields[2])), 'invalid_cursor')
    return int(fields[1][1:])


def checkpoint_not_before(current, previous, strict=False):
    for key, kind in [('sourceCursor', 'p'), ('outputCursor', 'o')]:
        a, b = position(current[key], kind), position(previous[key], kind)
        require(a > b if strict else a >= b, 'checkpoint_regressed_or_not_advanced:' + key)
        require(a != b or current[key] == previous[key], 'checkpoint_hash_changed:' + key)


def database():
    info = regular(DATABASE)
    others = sorted(str(path) for path in DATABASE.parent.glob('*.sqlite'))
    require(others == [str(DATABASE)], 'unexpected_additional_sqlite_database')
    with closing(sqlite3.connect(DATABASE.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
        version = db.execute('PRAGMA user_version').fetchone()[0]
        config = db.execute('SELECT source,targets,producer_generation FROM config WHERE id=1').fetchone()
        runtime = db.execute('SELECT runtime_generation FROM beam_input WHERE id=1').fetchone()
        row = db.execute('SELECT cursor,output_cursor,bootstrap_boundary FROM checkpoint WHERE id=1').fetchone()
        require(config and json.loads(config[0]) == EXPECTED_SOURCE and config[2] == PRODUCER,
                'database_source_or_producer_changed')
        require(runtime == (RUNTIME,), 'database_runtime_changed')
        require(row and all(row), 'database_checkpoint_missing')
        require(db.execute('SELECT COUNT(*) FROM payloads WHERE length(projection)>0').fetchone()[0] == 0,
                'database_has_expanded_projection')
    result = {'device': info.st_dev, 'inode': info.st_ino, 'userVersion': version,
              'schemaSha256': sha(json.dumps(schema, separators=(',', ':')).encode()),
              'configSha256': sha(json.dumps(config, separators=(',', ':')).encode()),
              'runtimeGeneration': runtime[0], 'bootstrapBoundary': row[2],
              'sourceCursor': row[0], 'outputCursor': row[1], 'database': str(DATABASE),
              'databaseCount': 1, 'projectionBytes': 0}
    position(row[0], 'p')
    position(row[1], 'o')
    return result


def same_database(before, after):
    for key in ('device', 'inode', 'userVersion', 'schemaSha256', 'configSha256',
                'runtimeGeneration', 'bootstrapBoundary', 'database', 'databaseCount'):
        require(before[key] == after[key], 'database_identity_or_schema_changed:' + key)
    checkpoint_not_before(after, before)


def head():
    token = Path('/etc/blockzilla-client-pipe/reader-token').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:18890/v1/head',
                                     headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.load(response)
    keys = ('source', 'producerGeneration', 'runtimeGeneration', 'inputMode', 'input', 'error',
            'signingReady', 'payloadMode', 'beamCommittedCursor', 'beamSourceObservedAtMs',
            'beamLastFrameAgeMs', 'beamReconcileError', 'sampledAtMs', 'outputCursor', 'workerRecovery')
    return {key: value.get(key) for key in keys}


def fresh_head(value, recovery):
    sampled, observed = value.get('sampledAtMs'), value.get('beamSourceObservedAtMs')
    age = value.get('beamLastFrameAgeMs')
    recovery_status = value.get('workerRecovery') or {}
    return (value.get('source') == EXPECTED_SOURCE and value.get('producerGeneration') == PRODUCER
            and value.get('runtimeGeneration') == RUNTIME and value.get('inputMode') == 'raw_ssh'
            and value.get('payloadMode') == 'compact-only' and value.get('input') == 'live'
            and value.get('signingReady') is True and value.get('error') is None
            and value.get('beamReconcileError') is None
            and isinstance(sampled, int) and isinstance(observed, int)
            and -1000 <= sampled - observed <= 5000
            and abs(time.time_ns() // 1_000_000 - sampled) <= 2000
            and isinstance(age, int) and 0 <= age <= 5000
            and (not recovery or (isinstance(recovery_status, dict)
                                  and recovery_status.get('enabled') is True
                                  and recovery_status.get('active') is False)))


def wait_live(minimum, recovery, seconds=60):
    deadline, consecutive, last = time.monotonic() + seconds, 0, None
    while time.monotonic() < deadline:
        try:
            last = head()
            current = {'sourceCursor': last['beamCommittedCursor'], 'outputCursor': last['outputCursor']}
            checkpoint_not_before(current, minimum, strict=True)
            consecutive = consecutive + 1 if fresh_head(last, recovery) else 0
            if consecutive >= 3:
                return last
        except (OSError, ValueError, KeyError):
            consecutive = 0
        time.sleep(0.25)
    raise TimeoutError('consumer_did_not_resume_fresh_live_data')


def candidate_argv(binary, previous):
    require(previous == EXPECTED_ARGV, 'current_argv_changed')
    result = [str(binary), *previous[1:]]
    result[result.index('--upstream-ssh-helper') + 1] = NEW_HELPER
    result += ['--recovery-worker-url', WORKER_URL, '--recovery-worker-api-key-file', str(WORKER_KEY)]
    require(all(not any(c in item for c in ('%', '$', '\n', '\r', '\0')) for item in result),
            'unsafe_systemd_argument')
    return result


def install_binary(candidate, expected):
    regular(candidate)
    require(digest(candidate) == expected, 'candidate_sha_mismatch')
    require(RELEASES.is_dir() and not RELEASES.is_symlink(), 'unsafe_release_root')
    require(shutil.disk_usage(RELEASES).free > candidate.stat().st_size * 2 + 16 * 1024 * 1024,
            'insufficient_code_install_space')
    release = RELEASES / expected
    binary = release / 'blockzilla-stream-sidecar'
    if release.exists():
        require(not release.is_symlink() and set(path.name for path in release.iterdir()) == {binary.name},
                'existing_release_file_set_changed')
        regular(binary)
        require(digest(binary) == expected and binary.stat().st_mode & 0o777 == 0o555,
                'existing_release_content_or_mode_changed')
        return binary
    staged = Path(tempfile.mkdtemp(prefix='.worker-recovery-', dir=RELEASES))
    try:
        dest = staged / binary.name
        with candidate.open('rb') as source, dest.open('xb') as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        dest.chmod(0o555)
        require(digest(dest) == expected, 'installed_binary_sha_mismatch')
        staged.chmod(0o555)
        staged.rename(release)
    except BaseException:
        if staged.exists():
            staged.chmod(0o700)
            shutil.rmtree(staged)
        raise
    return binary


def write_dropin(argv):
    DROPIN.parent.mkdir(parents=True, exist_ok=True)
    require(not DROPIN.exists() and not DROPIN.is_symlink(), 'recovery_override_already_exists')
    raw = ('[Service]\nExecStart=\nExecStart=' + shlex.join(argv) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.50-worker-recovery-', dir=DROPIN.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, DROPIN)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return sha(raw)


def activate(args):
    require(os.geteuid() == 0, 'run_as_root_on_consumer')
    require(re.fullmatch('[0-9a-f]{64}', args.sha256), 'invalid_candidate_sha')
    require(not args.receipt.exists(), 'receipt_already_exists')
    regular(args.build_receipt)
    build = json.loads(args.build_receipt.read_text())
    require(build.get('state') == 'PASSED'
            and build.get('artifacts', {}).get('blockzilla-stream-sidecar', {}).get('sha256') == args.sha256,
            'tested_build_receipt_mismatch')
    phases = {phase['phase']: phase.get('returncode') for phase in build.get('commands', [])}
    require(all(phases.get(name) == 0 for name in
                ('sdk-tests', 'sidecar-tests', 'automatic-recovery-fixture', 'sidecar-release')),
            'required_build_checks_missing')
    require(json.loads(SOURCE_FILE.read_text()) == EXPECTED_SOURCE, 'source_file_changed')
    key = regular(WORKER_KEY)
    require(key.st_uid == pwd.getpwnam('blockzilla-pipe').pw_uid
            and key.st_mode & 0o777 == 0o600 and 32 <= key.st_size <= 4096,
            'worker_api_key_not_service_private')
    before = properties()
    require(before['ActiveState'] == 'active' and int(before['MainPID']) > 0, 'consumer_not_active')
    pid = before['MainPID']
    require(digest('/proc/' + pid + '/exe') == PREVIOUS_SHA, 'previous_binary_sha_changed')
    argv = Path('/proc/' + pid + '/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    require(argv == EXPECTED_ARGV, 'previous_compact_only_argv_changed')
    require(not DROPIN.exists() and not DROPIN.is_symlink(), 'recovery_dropin_already_exists')
    old_files, old_services, old_containers = unit_files(before), service_invocations(), containers()
    before_db, before_head = database(), head()
    require(fresh_head(before_head, recovery=False), 'previous_consumer_not_fresh_live')
    binary = install_binary(args.candidate, args.sha256)
    new_argv = candidate_argv(binary, argv)
    receipt = {'schema': 'blockzilla-worker-recovery-consumer-activation-v1', 'state': 'PREPARED',
        'startedAtMs': time.time_ns() // 1_000_000, 'sha256': args.sha256, 'previousSha256': PREVIOUS_SHA,
        'activationToolSha256': digest(__file__), 'buildReceiptSha256': digest(args.build_receipt),
        'before': before, 'beforeHead': before_head, 'beforeDatabase': before_db,
        'beforeUnitFiles': old_files, 'beforeOtherServices': old_services,
        'beforeContainers': old_containers, 'newArgv': new_argv,
        'databaseBackupCreated': False, 'databaseRestoreUsed': False,
        'blockFilesCopied': 0, 'faultInjected': False, 'controlledStopStartCycles': 0}
    save(args.receipt, receipt)
    stopped = None
    dropin_written = False
    stop_attempted = False
    try:
        # No database copy or migration. The stopped checkpoint is the exact
        # old-process boundary that the new process must continue.
        stop_attempted = True
        command('systemctl', 'stop', UNIT)
        require(int(properties()['MainPID']) == 0, 'old_consumer_did_not_stop')
        stopped = database()
        same_database(before_db, stopped)
        receipt['stoppedCheckpoint'] = stopped
        save(args.receipt, receipt)
        receipt['recoveryDropinSha256'] = write_dropin(new_argv)
        dropin_written = True
        command('systemctl', 'daemon-reload')
        require(unit_files(properties()) == old_files, 'existing_unit_files_changed')
        command('systemctl', 'start', UNIT)
        receipt['controlledStopStartCycles'] = 1
        after_head = wait_live(stopped, recovery=True)
        after, after_db = properties(), database()
        same_database(stopped, after_db)
        checkpoint_not_before(after_db, stopped, strict=True)
        require(after['ActiveState'] == 'active' and after['InvocationID'] != before['InvocationID'],
                'new_consumer_invocation_missing')
        require(after['NRestarts'] == '0', 'candidate_had_automatic_restarts')
        require(digest('/proc/' + after['MainPID'] + '/exe') == args.sha256, 'new_process_binary_mismatch')
        require(Path('/proc/' + after['MainPID'] + '/cmdline').read_bytes().rstrip(b'\0').decode().split('\0') == new_argv,
                'new_process_argv_mismatch')
        require(all(before[key] == after[key] for key in RESOURCE_KEYS), 'resource_or_security_limits_changed')
        require(unit_files(after) == old_files, 'existing_unit_files_changed')
        after_services, after_containers = service_invocations(), containers()
        require(all(after_services.get(key) == value for key, value in old_services.items()), 'other_service_changed')
        require(after_containers == old_containers, 'existing_containers_changed')
        receipt.update(state='ACTIVATED', after=after, afterHead=after_head, afterDatabase=after_db,
            afterOtherServices=after_services, afterContainers=after_containers,
            existingUnitFilesUnchanged=True, resourceAndSecurityLimitsUnchanged=True,
            existingServicesUnchanged=True, existingContainersUnchanged=True,
            oneDatabaseResumedWithoutSchemaChange=True, sourceAndOutputAdvanced=True,
            freshRawLiveSigning=True, workerRecoveryEnabled=True,
            finishedAtMs=time.time_ns() // 1_000_000)
    except BaseException as error:
        receipt.update(state='ACTIVATION_FAILED', failureType=type(error).__name__, failure=str(error))
        save(args.receipt, receipt)
        if stop_attempted:
            try:
                command('systemctl', 'stop', UNIT)
                rollback_db = database()
                same_database(stopped or before_db, rollback_db)
                # Restore configuration only. Keep all commits made by either
                # binary. Never restore an old database image or checkpoint.
                if dropin_written:
                    require(digest(DROPIN) == receipt['recoveryDropinSha256'], 'recovery_dropin_changed')
                    DROPIN.unlink()
                command('systemctl', 'daemon-reload')
                command('systemctl', 'start', UNIT)
                rollback_head = wait_live(rollback_db, recovery=False)
                restored, final_db = properties(), database()
                require(digest('/proc/' + restored['MainPID'] + '/exe') == PREVIOUS_SHA, 'rollback_binary_mismatch')
                same_database(rollback_db, final_db)
                checkpoint_not_before(final_db, rollback_db, strict=True)
                require(unit_files(restored) == old_files, 'rollback_unit_files_changed')
                require(all(before[key] == restored[key] for key in RESOURCE_KEYS), 'rollback_limits_changed')
                rollback_services, rollback_containers = service_invocations(), containers()
                require(all(rollback_services.get(key) == value for key, value in old_services.items()),
                        'rollback_other_service_changed')
                require(rollback_containers == old_containers, 'rollback_containers_changed')
                receipt.update(state='ROLLED_BACK_SAME_DATABASE', rollbackHead=rollback_head,
                               rollbackDatabase=final_db, rollback=restored,
                               rollbackStartCheckpoint=rollback_db, cursorRollbackUsed=False,
                               rollbackStopStartCycles=1, rollbackOtherServices=rollback_services,
                               rollbackContainers=rollback_containers)
            except BaseException as rollback_error:
                receipt.update(state='ROLLBACK_NEEDS_ATTENTION', rollbackFailureType=type(rollback_error).__name__,
                               rollbackFailure=str(rollback_error))
        receipt['finishedAtMs'] = time.time_ns() // 1_000_000
        save(args.receipt, receipt)
        raise
    save(args.receipt, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(activate(args), sort_keys=True))


if __name__ == '__main__':
    main()
