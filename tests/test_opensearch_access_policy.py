"""Offline edge-case tests for OpensearchCommon._checkAccessPolicyPublic.

The emulator flag/fix cycle lives in tests/emulator/test_emu_opensearch.py. These
cases cover inputs the emulator cannot produce (a VPC domain with real VPCOptions,
an unparseable AccessPolicies string, FGAC anonymous-auth domains). The check reads only
the DomainStatus returned by describe_domain, so the driver is built without its
constructor (which makes unrelated list_versions / describe_domain_config calls).
"""
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.opensearch.drivers.OpensearchCommon import OpensearchCommon  # noqa: E402

# Evaluator.__del__ writes to __fork/error.txt, which only exists in a full scan run.
pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

ARN = 'arn:aws:es:us-east-1:111122223333:domain/d/*'


def _run(status):
    obj = OpensearchCommon.__new__(OpensearchCommon)
    obj.results = {}
    obj.attribute = {'DomainStatus': status}
    obj._checkAccessPolicyPublic()
    return obj.results['AccessPolicyPublic']


def _pol(**stmt):
    base = {'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'es:*', 'Resource': ARN}
    base.update(stmt)
    return json.dumps({'Version': '2012-10-17', 'Statement': [base]})


def test_public_wildcard_flagged_then_ip_scoped_passes():
    assert _run({'AccessPolicies': _pol()})[0] == -1
    assert _run({'AccessPolicies': _pol(Condition={'IpAddress': {'aws:SourceIp': ['10.0.0.0/8']}})})[0] == 1


def test_list_form_principal_without_fgac_flagged():
    r = _run({'AccessPolicies': _pol(Principal={'AWS': ['*']}),
              'AdvancedSecurityOptions': {'Enabled': False}})
    assert r[0] == -1 and 'not enabled' in r[1]
    # AdvancedSecurityOptions absent -> no FGAC -> still flagged.
    assert _run({'AccessPolicies': _pol(Principal={'AWS': ['*']})})[0] == -1


def test_fgac_open_policy_is_info_not_high_fail():
    """AWS's documented FGAC setup (open es:ESHttp* policy + FGAC, anonymous auth off):
    every request authenticates, so it is not 'anyone can read/write/delete' (-1/H).
    Network exposure is still surfaced as INFO, never PASS."""
    for aso in ({'Enabled': True, 'InternalUserDatabaseEnabled': True, 'AnonymousAuthEnabled': False},
                {'Enabled': True, 'InternalUserDatabaseEnabled': False}):
        r = _run({'AccessPolicies': _pol(Principal={'AWS': '*'}, Action='es:ESHttp*'),
                  'AdvancedSecurityOptions': aso})
        assert r[0] == 0, r
        assert 'authentication' in r[1] and 'reachable from the internet' in r[1]


def test_fgac_with_anonymous_auth_still_flagged():
    r = _run({'AccessPolicies': _pol(Action='es:ESHttp*'),
              'AdvancedSecurityOptions': {'Enabled': True, 'InternalUserDatabaseEnabled': True,
                                          'AnonymousAuthEnabled': True}})
    assert r[0] == -1 and 'anonymous authentication enabled' in r[1]


def test_slash_zero_and_negated_ip_not_restrictive():
    assert _run({'AccessPolicies': _pol(Condition={'IpAddress': {'aws:SourceIp': '::/0'}})})[0] == -1
    assert _run({'AccessPolicies': _pol(Condition={'NotIpAddress': {'aws:SourceIp': '10.0.0.0/8'}})})[0] == -1


def test_vpce_scoping_and_named_principal_pass():
    assert _run({'AccessPolicies': _pol(Condition={'StringEquals': {'aws:SourceVpce': 'vpce-0123'}})})[0] == 1
    assert _run({'AccessPolicies': _pol(Principal={'AWS': 'arn:aws:iam::111122223333:role/app'})})[0] == 1


def test_deny_and_config_only_actions_not_flagged():
    assert _run({'AccessPolicies': _pol(Effect='Deny')})[0] == 1
    assert _run({'AccessPolicies': _pol(Action='es:DescribeDomain')})[0] == 1


def test_vpc_domain_passes_even_with_wildcard_policy():
    r = _run({'AccessPolicies': _pol(), 'VPCOptions': {'VPCId': 'vpc-1', 'SubnetIds': ['subnet-1']}})
    assert r[0] == 1


def test_no_policy_passes_and_unparseable_is_info():
    assert _run({'AccessPolicies': ''})[0] == 1
    assert _run({})[0] == 1
    assert _run({'AccessPolicies': '{not json'}) == [0, 'Unable to evaluate (UnparseableAccessPolicy)']
