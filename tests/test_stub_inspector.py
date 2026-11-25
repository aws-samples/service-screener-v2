"""Stubber-based flag -> fix tests for Amazon Inspector checks.

Why Stubber and not the emulator: the AWS Emulator returns NotImplemented for
inspector2.list_findings, describe_organization_configuration and
list_members, and the emulator is a single standalone account (no Inspector
delegated administrator). These tests drive services.inspector.drivers.
InspectorCommon directly with a real boto3 inspector2 client wrapped in
botocore.stub.Stubber, so request/response shapes are validated against the
real API model. No network call is made: the client points at 127.0.0.1 with
dummy credentials and every call is answered by the Stubber.
"""
import datetime
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber, ANY

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.inspector.drivers.InspectorCommon import InspectorCommon  # noqa: E402
from utils.Config import Config  # noqa: E402


def _client():
    return boto3.session.Session(
        aws_access_key_id='testing', aws_secret_access_key='testing',
        region_name='us-east-1').client('inspector2', endpoint_url='https://127.0.0.1:1')


def _driver(client, enabled=True):
    detail = {
        '_region': 'us-east-1',
        '_accountStatus': {'accountId': '111111111111',
                           'state': {'status': 'ENABLED' if enabled else 'DISABLED'},
                           'resourceState': {}},
    }
    return InspectorCommon(detail, client)


def _finding(sev, days_old):
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        'findingArn': 'arn:aws:inspector2:us-east-1:111111111111:finding/abc',
        'awsAccountId': '111111111111', 'type': 'PACKAGE_VULNERABILITY',
        'description': 'd', 'severity': sev,
        'firstObservedAt': now - datetime.timedelta(days=days_old),
        'lastObservedAt': now, 'status': 'ACTIVE',
        'remediation': {}, 'resources': [{'type': 'AWS_EC2_INSTANCE', 'id': 'i-1'}],
    }


def _run(drv, method, key):
    getattr(drv, method)()
    return drv.results[key][0]


# ---------------------------------------------------------------- aged findings
def _stub_aged(stub, critical, high):
    for sev, findings in (('CRITICAL', critical), ('HIGH', high)):
        stub.add_response('list_findings', {'findings': findings}, {
            'filterCriteria': {
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}],
                'severity': [{'comparison': 'EQUALS', 'value': sev}],
                'firstObservedAt': [{'endInclusive': ANY}],
            },
            'maxResults': 100,
        })


def test_findings_aged_flag_fix():
    c = _client()
    with Stubber(c) as stub:
        _stub_aged(stub, [_finding('CRITICAL', 40)], [])
        d = _driver(c)
        assert _run(d, '_checkInspectorFindingsAged', 'inspectorFindingsAged') == -1
        assert 'CRITICAL' in d.results['inspectorFindingsAged'][1]
        stub.assert_no_pending_responses()
    ## fix: the aged finding has been remediated (no longer ACTIVE past SLA)
    c = _client()
    with Stubber(c) as stub:
        _stub_aged(stub, [], [])
        assert _run(_driver(c), '_checkInspectorFindingsAged', 'inspectorFindingsAged') == 1


def test_findings_aged_high_and_custom_sla():
    Config.set('INSPECTOR_FINDING_SLA_DAYS', {'HIGH': 7})
    try:
        c = _client()
        with Stubber(c) as stub:
            _stub_aged(stub, [], [_finding('HIGH', 10)])
            d = _driver(c)
            assert _run(d, '_checkInspectorFindingsAged', 'inspectorFindingsAged') == -1
            assert 'open > 7d' in d.results['inspectorFindingsAged'][1]
    finally:
        Config.set('INSPECTOR_FINDING_SLA_DAYS', None)


def test_findings_aged_access_denied_and_disabled():
    c = _client()
    with Stubber(c) as stub:
        stub.add_client_error('list_findings', 'AccessDeniedException', 'denied')
        d = _driver(c)
        assert _run(d, '_checkInspectorFindingsAged', 'inspectorFindingsAged') == 0
        assert 'Unable to evaluate (AccessDeniedException)' in d.results['inspectorFindingsAged'][1]
    c = _client()
    with Stubber(c):
        assert _run(_driver(c, enabled=False), '_checkInspectorFindingsAged', 'inspectorFindingsAged') == 0


# ------------------------------------------------------------ org auto-enable
ALL_ON = {'ec2': True, 'ecr': True, 'lambda': True, 'lambdaCode': True, 'codeRepository': True}


def _stub_org(stub, auto, members, limit=False):
    stub.add_response('describe_organization_configuration',
                      {'autoEnable': auto, 'maxAccountLimitReached': limit}, {})
    stub.add_response('list_members', {'members': members}, {'onlyAssociated': False})


def test_org_auto_enable_flag_fix():
    k = 'inspectorOrgAutoEnableIncomplete'
    c = _client()
    with Stubber(c) as stub:
        _stub_org(stub, dict(ALL_ON, ec2=False),
                  [{'accountId': '222222222222', 'relationshipStatus': 'ENABLED'}])
        d = _driver(c)
        assert _run(d, '_checkInspectorOrgAutoEnableIncomplete', k) == -1
        assert 'ec2' in d.results[k][1]
    c = _client()
    with Stubber(c) as stub:
        _stub_org(stub, ALL_ON,
                  [{'accountId': '222222222222', 'relationshipStatus': 'ENABLED'},
                   {'accountId': '333333333333', 'relationshipStatus': 'ACCOUNT_SUSPENDED'}])
        assert _run(_driver(c), '_checkInspectorOrgAutoEnableIncomplete', k) == 1


def test_org_member_not_enabled_and_advisory():
    k = 'inspectorOrgAutoEnableIncomplete'
    c = _client()
    with Stubber(c) as stub:
        _stub_org(stub, ALL_ON, [{'accountId': '222222222222', 'relationshipStatus': 'DISABLED'}])
        d = _driver(c)
        assert _run(d, '_checkInspectorOrgAutoEnableIncomplete', k) == -1
        assert '222222222222=DISABLED' in d.results[k][1]
    ## lambdaCode/codeRepository off only -> advisory, not a finding
    c = _client()
    with Stubber(c) as stub:
        _stub_org(stub, dict(ALL_ON, lambdaCode=False, codeRepository=False), [])
        d = _driver(c)
        assert _run(d, '_checkInspectorOrgAutoEnableIncomplete', k) == 1
        assert 'advisory' in d.results[k][1]
    c = _client()
    with Stubber(c) as stub:
        _stub_org(stub, ALL_ON, [], limit=True)
        assert _run(_driver(c), '_checkInspectorOrgAutoEnableIncomplete', k) == -1


def test_org_not_admin():
    k = 'inspectorOrgAutoEnableIncomplete'
    c = _client()
    with Stubber(c) as stub:
        stub.add_client_error('describe_organization_configuration', 'AccessDeniedException',
                              'Invoking account is not the delegated administrator')
        d = _driver(c)
        assert _run(d, '_checkInspectorOrgAutoEnableIncomplete', k) == 0
        assert d.results[k][1].startswith('Not evaluable from member account')


# ----------------------------------------------------------- suppression rules
def _filter(criteria, action='SUPPRESS', name='f1'):
    now = datetime.datetime.now(datetime.timezone.utc)
    return {'arn': 'arn:aws:inspector2:us-east-1:111111111111:owner/111111111111/filter/1',
            'ownerId': '111111111111', 'name': name, 'criteria': criteria,
            'action': action, 'createdAt': now, 'updatedAt': now}


SEV = lambda *v: [{'comparison': 'EQUALS', 'value': x} for x in v]  # noqa: E731


@pytest.mark.parametrize('criteria,expected', [
    ({'severity': SEV('LOW', 'MEDIUM')}, -1),
    ({'resourceType': SEV('AWS_EC2_INSTANCE')}, -1),
    ({'severity': SEV('HIGH'), 'resourceType': SEV('AWS_LAMBDA_FUNCTION')}, -1),
    ({'severity': [{'comparison': 'NOT_EQUALS', 'value': 'CRITICAL'}]}, -1),
    ({}, -1),
    ({'severity': SEV('INFORMATIONAL')}, 1),
    ({'severity': SEV('LOW'), 'vulnerabilityId': SEV('CVE-2023-0001')}, 1),
    ({'resourceType': SEV('AWS_EC2_INSTANCE'),
      'resourceTags': [{'comparison': 'EQUALS', 'key': 'env', 'value': 'sandbox'}]}, 1),
    ({'resourceId': SEV('i-0123')}, 1),
])
def test_suppression_broad(criteria, expected):
    c = _client()
    with Stubber(c) as stub:
        stub.add_response('list_filters', {'filters': [_filter(criteria)]}, {'action': 'SUPPRESS'})
        assert _run(_driver(c), '_checkInspectorSuppressionBroad', 'inspectorSuppressionBroad') == expected


def test_suppression_unreadable():
    c = _client()
    with Stubber(c) as stub:
        stub.add_client_error('list_filters', 'AccessDeniedException', 'denied')
        d = _driver(c)
        assert _run(d, '_checkInspectorSuppressionBroad', 'inspectorSuppressionBroad') == 0
        assert d.results['inspectorSuppressionBroad'][1].startswith('Unable to evaluate')
