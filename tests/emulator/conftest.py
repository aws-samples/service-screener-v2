"""
Shared fixtures for checks tested against the local AWS Emulator.

Tests here never reach AWS: the session is built from the emulator's own
credential files, real-credential env vars are removed, and every client is
asserted to point at https://127.0.0.1:<port>. If the emulator is not running
the tests are skipped.

Start the emulator (Docker or Finch), published on loopback only:
    docker run --rm -p 127.0.0.1:9297:9297 -e HOME="$HOME" \
      -v "$HOME/.aws/emulator:$HOME/.aws/emulator" aws-emulator -p 9297
See https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-docker.html
"""
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import uuid

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

from utils.CheckRunner import CheckRunner, emulatorFiles, emulatorSession, assertEmulatorOnly  # noqa: E402

PORT = int(os.environ.get('SS_EMULATOR_PORT', '9297'))
REGION = 'us-east-1'


def _healthy(port=PORT):
    f = emulatorFiles(port)
    if not os.path.exists(f['ca']):
        return False
    try:
        ctx = ssl.create_default_context(cafile=f['ca'])
        with urllib.request.urlopen(f"{f['endpoint']}/__admin/health", context=ctx, timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


@pytest.fixture(scope='session')
def emu():
    if not _healthy():
        pytest.skip(f'AWS Emulator not running on 127.0.0.1:{PORT}')
    sess = emulatorSession(port=PORT, region=REGION)
    assertEmulatorOnly(sess)
    return sess


@pytest.fixture
def emu_fresh():
    """A brand-new emulator (empty account) for tests of ACCOUNT-WIDE checks,
    whose result depends on every resource in the account and would be
    polluted by resources other tests leave behind. Starts a container on a
    free loopback port with docker or finch, image SS_EMULATOR_IMAGE (default
    'aws-emulator', see tests/emulator/Dockerfile); skips if unavailable."""
    runtime = shutil.which('docker') or shutil.which('finch')
    if not runtime:
        pytest.skip('docker/finch not available for an isolated emulator')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    home = os.path.expanduser('~')
    os.makedirs(os.path.join(home, '.aws', 'emulator'), exist_ok=True)
    name = f'ss-emu-fresh-{port}'
    image = os.environ.get('SS_EMULATOR_IMAGE', 'aws-emulator')
    run = subprocess.run([runtime, 'run', '-d', '--name', name, '--memory=1g',
                          '-p', f'127.0.0.1:{port}:{port}', '-e', f'HOME={home}', '-e', 'EMULATOR_TELEMETRY=off',
                          '-v', f'{home}/.aws/emulator:{home}/.aws/emulator', image, '-p', str(port),
                          '--idle-timeout', '900'], capture_output=True, text=True)
    if run.returncode != 0:
        pytest.skip(f'could not start isolated emulator: {run.stderr.strip()[:200]}')
    saved = dict(os.environ)
    try:
        for _ in range(240):
            if _healthy(port):
                break
            time.sleep(0.5)
        else:
            pytest.skip('isolated emulator did not become healthy')
        sess = emulatorSession(port=port, region=REGION)
        assertEmulatorOnly(sess)
        yield sess
    finally:
        os.environ.clear()
        os.environ.update(saved)
        subprocess.run([runtime, 'rm', '-f', name], capture_output=True)


@pytest.fixture
def uid():
    """Short unique suffix so tests never collide on resource names."""
    return uuid.uuid4().hex[:8]


def runCheck(emu, service, check, resource=None):
    return CheckRunner.run(service, check, region=REGION, session=emu, resource=resource, emulator=True)


def assertFlagFixCycle(emu, service, check, resource, misconfigure, fix):
    """The standard test for every new check:
    1. misconfigure() -> check must return -1 for `resource`
    2. fix()          -> re-run; check must NOT return -1 for `resource`
    """
    misconfigure()
    before = runCheck(emu, service, check, resource).statuses()
    assert before, f'{service}.{check}: no result for {resource} (errors: {runCheck(emu, service, check, resource).errors[:1]})'
    assert all(s == -1 for s in before.values()), f'{service}.{check} expected -1 after misconfigure, got {before}'
    fix()
    after = runCheck(emu, service, check, resource).statuses()
    assert after, f'{service}.{check}: no result for {resource} after fix'
    assert all(s != -1 for s in after.values()), f'{service}.{check} still -1 after fix: {after}'
    return before, after
