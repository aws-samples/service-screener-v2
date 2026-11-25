"""Stubber tests for ecrImageSigningNotConfigured "Unable to evaluate" paths.

The emulator cannot simulate AccessDenied for get_signing_configuration /
signer.list_signing_profiles (IAM is not evaluated), so these paths are driven
with real boto3 clients wrapped by botocore.stub.Stubber (real API shapes).
The FLAG -> FIX -> RE-RUN cycle itself is covered by tests/emulator/test_emu_ecr.py.
"""
import os
import sys
import types

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.ecr.Ecr import Ecr  # noqa: E402
from services.ecr.drivers.EcrCommon import EcrCommon  # noqa: E402

KEY = 'ecrImageSigningNotConfigured'


def _clients():
    kw = dict(region_name='us-east-1', aws_access_key_id='x', aws_secret_access_key='x')
    return boto3.client('ecr', **kw), boto3.client('signer', **kw)


def _fakeService(ecr, signer):
    svc = types.SimpleNamespace(ecrClient=ecr, bConfig=None, _logClientError=lambda *a: None)
    svc.ssBoto = types.SimpleNamespace(client=lambda name, config=None: signer)
    return svc


def _evaluate(ecr, signer):
    svc = _fakeService(ecr, signer)
    repo = {'repositoryName': 'r', '_reportRegistryChecks': True,
            '_signingConfig': Ecr._getSigningConfiguration(svc),
            '_notationProfiles': Ecr._listNotationSigningProfiles(svc)}
    d = EcrCommon(repo, ecr)
    d._checkEcrImageSigningNotConfigured()
    return d.results[KEY]


def test_flag_then_fix_with_stubbed_responses():
    ecr, signer = _clients()
    with Stubber(ecr) as se, Stubber(signer) as ss:
        se.add_client_error('get_signing_configuration', 'SigningConfigurationNotFoundException')
        ss.add_response('list_signing_profiles', {'profiles': [
            {'profileName': 'lam', 'platformId': 'AWSLambda-SHA384-ECDSA', 'status': 'Active'}]})
        assert _evaluate(ecr, signer)[0] == -1
        se.add_response('get_signing_configuration', {'registryId': '123456789012', 'signingConfiguration': {
            'rules': [{'signingProfileArn': 'arn:aws:signer:us-east-1:123456789012:/signing-profiles/p'}]}})
        ss.add_response('list_signing_profiles', {'profiles': []})
        assert _evaluate(ecr, signer)[0] == 1


def test_access_denied_is_not_evaluable():
    ecr, signer = _clients()
    with Stubber(ecr) as se, Stubber(signer) as ss:
        se.add_client_error('get_signing_configuration', 'AccessDeniedException')
        ss.add_response('list_signing_profiles', {'profiles': []})
        r = _evaluate(ecr, signer)
        assert r[0] == 0 and 'Unable to evaluate' in r[1] and 'AccessDeniedException' in r[1]

        se.add_client_error('get_signing_configuration', 'SigningConfigurationNotFoundException')
        ss.add_client_error('list_signing_profiles', 'AccessDeniedException')
        r = _evaluate(ecr, signer)
        assert r[0] == 0 and 'signer:AccessDeniedException' in r[1]


def test_signer_denied_but_managed_signing_present_passes():
    ecr, signer = _clients()
    with Stubber(ecr) as se, Stubber(signer) as ss:
        se.add_response('get_signing_configuration', {'registryId': '123456789012', 'signingConfiguration': {
            'rules': [{'signingProfileArn': 'arn:aws:signer:us-east-1:123456789012:/signing-profiles/p'}]}})
        ss.add_client_error('list_signing_profiles', 'AccessDeniedException')
        assert _evaluate(ecr, signer)[0] == 1


def test_non_anchor_repo_is_info():
    ecr, _ = _clients()
    d = EcrCommon({'repositoryName': 'r2', '_reportRegistryChecks': False}, ecr)
    d._checkEcrImageSigningNotConfigured()
    assert d.results[KEY][0] == 0
