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
import ssl
import sys
import urllib.request
import uuid

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
os.chdir(ROOT)
sys.path.insert(0, ROOT)

from utils.CheckRunner import CheckRunner, emulatorFiles, emulatorSession, assertEmulatorOnly  # noqa: E402

PORT = int(os.environ.get('SS_EMULATOR_PORT', '9297'))
REGION = 'us-east-1'


def _healthy():
    f = emulatorFiles(PORT)
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
