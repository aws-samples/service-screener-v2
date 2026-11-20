"""
Lightweight runner for one service / one check, without the full scan
bootstrap (no forking, frameworks, HTML output, custom pages or
cross-account handling). It drives the real Service and driver classes, so a
check behaves exactly as it does in a full scan.

Typical uses
- Developing a check:   python3 run_check.py --service s3 --check PublicReadAccessBlock
- Tests (flag -> fix -> re-run) against the local AWS Emulator:
      from utils.CheckRunner import CheckRunner, emulatorSession
      sess = emulatorSession()
      res = CheckRunner.run('s3', 'PublicReadAccessBlock', region='us-east-1', session=sess)
      assert res.statuses() == {'my-bucket': -1}

`check` may be a result key (e.g. 'PublicReadAccessBlock') or a driver method
name without the '_check' prefix (e.g. 'Access'). When it matches a method,
only that method runs; otherwise every check of the service runs and the
results are filtered to that key.
"""
import gc
import importlib
import os
import shutil
import tempfile

import boto3

import constants as _C
from utils.Config import Config

EMULATOR_HOST = '127.0.0.1'
_REAL_CRED_VARS = ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                   'AWS_SECURITY_TOKEN', 'AWS_PROFILE', 'AWS_DEFAULT_PROFILE')


def emulatorFiles(port=9297):
    base = os.path.expanduser(f'~/.aws/emulator/{port}')
    return {
        'endpoint': f'https://{EMULATOR_HOST}:{port}',
        'credentials': os.path.join(base, 'emulator_credentials'),
        'config': os.path.join(base, 'config'),
        'ca': os.path.join(base, 'ca.pem'),
    }


def emulatorSession(port=9297, region='us-east-1'):
    """Return a boto3 Session that can only talk to the local AWS Emulator.

    Removes any real-credential environment variables from this process and
    points every client at https://127.0.0.1:<port>. Raises if the emulator's
    credential files are missing (emulator not started)."""
    f = emulatorFiles(port)
    for k in ('credentials', 'config', 'ca'):
        if not os.path.exists(f[k]):
            raise RuntimeError(f"AWS Emulator files not found at {f[k]}; start the emulator on port {port}")
    for v in _REAL_CRED_VARS:
        os.environ.pop(v, None)
    os.environ.update({
        'AWS_ENDPOINT_URL': f['endpoint'],
        'AWS_SHARED_CREDENTIALS_FILE': f['credentials'],
        'AWS_CONFIG_FILE': f['config'],
        'AWS_CA_BUNDLE': f['ca'],
        'AWS_EC2_METADATA_DISABLED': 'true',
        'AWS_DISABLE_HOST_PREFIX_INJECTION': 'true',
        'AWS_REGION': region,
        'AWS_DEFAULT_REGION': region,
    })
    return boto3.session.Session(region_name=region)


def resourceIdMatches(rid, resource):
    """True when `resource` names this resource exactly: the whole id, the
    part after 'Driver::', or the last ARN/path segment of it. 'bucket-1'
    does not match 'Bucket::bucket-10'."""
    rid = str(rid)
    name = rid.split('::', 1)[-1]
    return resource in (rid, name) or name.endswith('/' + resource) or name.endswith(':' + resource)


def assertEmulatorOnly(session):
    """Fail closed if a client from this session would reach anything other
    than the local emulator."""
    endpoint = session.client('sts').meta.endpoint_url
    if not endpoint.startswith(f'https://{EMULATOR_HOST}:'):
        raise RuntimeError(f"Refusing to run: session endpoint is {endpoint}, not the local emulator")


class CheckResult:
    def __init__(self, service, region, check, results, errors):
        self.service = service
        self.region = region
        self.check = check
        self.results = results      # {resourceId: {checkKey: [status, msg]}}
        self.errors = errors

    def statuses(self, check=None):
        """{resourceId: status} for one check key (defaults to the requested check)."""
        key = (check or self.check or '').lower()
        out = {}
        for rid, res in self.results.items():
            for k, v in res.items():
                if k.lower() == key and isinstance(v, (list, tuple)) and v:
                    out[rid] = v[0]
        return out

    def allStatuses(self):
        """{(resourceId, checkKey): status} over every key in results. After
        run(), results only hold the requested key or, when `check` is a method
        name, every key that method returned."""
        return {(rid, k): v[0] for rid, res in self.results.items() for k, v in res.items()
                if isinstance(v, (list, tuple)) and v}

    def flagged(self, check=None):
        return sorted(rid for rid, s in self.statuses(check).items() if s == -1)

    def toDict(self):
        return {'service': self.service, 'region': self.region, 'check': self.check,
                'results': self.results, 'errors': self.errors}


class CheckRunner:
    @staticmethod
    def _serviceClass(service):
        folder = service + '_' if service in Config.KEYWORD_SERVICES else service
        className = service.title()
        return getattr(importlib.import_module(f'services.{folder}.{className}'), className)

    @staticmethod
    def _methodNames(serviceObj):
        """All _check* method names across the drivers imported by the service module."""
        names = set()
        mod = importlib.import_module(type(serviceObj).__module__)
        for obj in vars(mod).values():
            if isinstance(obj, type):
                names |= {m[6:].lower() for m in dir(obj) if m.startswith('_check')}
        return names

    @staticmethod
    def _defaultParams():
        from utils.ArguParser import ArguParser
        params = {k: v.get('default') for k, v in ArguParser.CLI_ARGUMENT_RULES.items()}
        params.setdefault('crossAccounts', False)
        return params

    @staticmethod
    def run(service, check=None, region='us-east-1', session=None, resource=None,
            emulator=False, debug=False):
        service = service.lower()
        if session is None:
            session = emulatorSession(region=region) if emulator else boto3.session.Session(region_name=region)
        if emulator:
            assertEmulatorOnly(session)

        forkDir = tempfile.mkdtemp(prefix='ss-check-')
        saved = (_C.FORK_DIR, _C.API_JSON)
        from utils.Checkpoint import Checkpoint
        savedCp = (Checkpoint.CHECKPOINT_DIR, Checkpoint.MANIFEST_PATH, Checkpoint._cache)
        try:
            _C.FORK_DIR = forkDir
            _C.API_JSON = forkDir + '/api.json'
            Checkpoint.CHECKPOINT_DIR = forkDir + '/checkpoint'
            Checkpoint.MANIFEST_PATH = Checkpoint.CHECKPOINT_DIR + '/manifest.json'
            Checkpoint._cache = {}

            Config.init()
            Config.set('DEBUG', debug)
            Config.set('_SS_PARAMS', CheckRunner._defaultParams())
            Config.set('ssBoto', session)
            Config.set('ssBotoKwargs', None)
            Config.set('REGIONS_SELECTED', [region])
            Config.set('stsInfo', session.client('sts').get_caller_identity())
            Config.set('scanned_' + service, {'resources': 0, 'rules': 0, 'exceptions': 0, 'timespent': 0})

            reg = 'us-east-1' if service in Config.GLOBAL_SERVICES else region
            from services.Cloudwatch import Cloudwatch
            Config.set('CWClient', Cloudwatch(reg).getClient())
            Config.set(Config.getDriversClassPrefix(service), reg)

            serv = CheckRunner._serviceClass(service)(reg)
            if check and check.lower() in CheckRunner._methodNames(serv):
                serv.setRules(check)

            resp = serv.advise() or {}
            results = {}
            for rid, obj in resp.items():
                if resource and resource not in str(rid):
                    continue
                res = obj.get('results', {}) if isinstance(obj, dict) else {}
                if check:
                    res = {k: v for k, v in res.items() if k.lower() == check.lower()} or \
                          (res if check.lower() in CheckRunner._methodNames(serv) else {})
                results[str(rid)] = res

            del serv, resp
            gc.collect()

            errors = []
            errPath = os.path.join(forkDir, 'error.txt')
            if os.path.exists(errPath):
                errors = [e for e in open(errPath).read().split('\n\n') if e.strip()]
            return CheckResult(service, reg, check, results, errors)
        finally:
            _C.FORK_DIR, _C.API_JSON = saved
            Checkpoint.CHECKPOINT_DIR, Checkpoint.MANIFEST_PATH, Checkpoint._cache = savedCp
            shutil.rmtree(forkDir, ignore_errors=True)
