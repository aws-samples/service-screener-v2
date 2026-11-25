"""Stubber tests for the AWS Config rule checks.

The emulator tests (tests/emulator/test_emu_config.py) cover the flag -> fix
cycle against a live API. These tests cover what the emulator cannot produce on
demand: AccessDenied on describe_config_rules / describe_remediation_configurations.
The checks must then record 'Unable to evaluate (<code>)' (status 0) instead
of treating the unreadable list as empty (a false FAIL) or as clean (a false
PASS). They also repeat the flag/fix cycle on real API response shapes.

The service hydration (services/config/Config.py getResources) is driven with a
real boto3 config client wrapped by botocore.stub.Stubber, using dummy
credentials; Stubber refuses any un-stubbed call, so nothing leaves the process.
"""
import os
import sys

import boto3
import pytest
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.config.Config import Config  # noqa: E402
from services.config.drivers.ConfigCommon import ConfigCommon  # noqa: E402

class _StubConfig(Config):
    """Config built without Service.__init__ (no session); skip the report-time
    teardown in Service.__del__, which needs state __init__ would have set."""
    def __del__(self):
        pass


NEW_KEYS = ('configNoProactiveRules', 'configDataProtectionRulesMissing',
            'configRemediationManualOnly')


def _client():
    return boto3.session.Session(
        aws_access_key_id='AKIDSTUBBER', aws_secret_access_key='stub',
        region_name='us-east-1').client('config')


def _rule(name, ident, modes=None, owner='AWS', state='ACTIVE'):
    r = {'ConfigRuleName': name, 'ConfigRuleState': state,
         'Source': {'Owner': owner, 'SourceIdentifier': ident}}
    if modes:
        r['EvaluationModes'] = [{'Mode': m} for m in modes]
    return r


def _remediation(name, automatic):
    return {'ConfigRuleName': name, 'TargetType': 'SSM_DOCUMENT',
            'TargetId': 'AWS-ConfigureS3BucketVersioning', 'Automatic': automatic}


def _run(rules=None, rulesError=None, remediations=None, remediationError=None):
    """Hydrate via Config.getResources() on a stubbed client, then run the driver."""
    client = _client()
    st = Stubber(client)
    st.add_response('describe_configuration_recorders', {'ConfigurationRecorders': []})
    st.add_response('describe_configuration_recorder_status', {'ConfigurationRecordersStatus': []})
    st.add_response('describe_delivery_channels', {'DeliveryChannels': []})
    if rulesError:
        st.add_client_error('describe_config_rules', service_error_code=rulesError,
                            http_status_code=400)
    else:
        st.add_response('describe_config_rules', {'ConfigRules': rules or []})
    st.add_response('describe_compliance_by_config_rule', {'ComplianceByConfigRules': []})
    st.add_response('describe_retention_configurations', {'RetentionConfigurations': []})
    st.add_response('describe_configuration_aggregators', {'ConfigurationAggregators': []})
    if not rulesError and rules:
        if remediationError:
            st.add_client_error('describe_remediation_configurations',
                                service_error_code=remediationError, http_status_code=400)
        else:
            st.add_response('describe_remediation_configurations',
                            {'RemediationConfigurations': remediations or []},
                            {'ConfigRuleNames': [r['ConfigRuleName'] for r in rules]})

    svc = _StubConfig.__new__(_StubConfig)
    svc.region = 'us-east-1'
    svc.configClient = client
    with st:
        detail = svc.getResources()
        st.assert_no_pending_responses()
    drv = ConfigCommon(detail, client)
    for m in ('_checkConfigNoProactiveRules', '_checkConfigDataProtectionRulesMissing',
              '_checkConfigRemediationManualOnly', '_checkConfigNoRules',
              '_checkConfigRulesNonCompliant', '_checkConfigNoRemediationActions'):
        getattr(drv, m)()
    return drv.results


def test_rules_access_denied_is_not_evaluable():
    res = _run(rulesError='AccessDeniedException')
    for k in NEW_KEYS + ('configNoRules', 'configRulesNonCompliant'):
        assert res[k][0] == 0, (k, res[k])
        assert 'Unable to evaluate (AccessDeniedException)' in res[k][1]


def test_remediation_access_denied_is_not_evaluable():
    res = _run(rules=[_rule('r1', 'S3_BUCKET_VERSIONING_ENABLED')],
               remediationError='AccessDeniedException')
    assert res['configRemediationManualOnly'][0] == 0
    assert 'Unable to evaluate' in res['configRemediationManualOnly'][1]


def test_proactive_flag_fix():
    bad = _run(rules=[_rule('r1', 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED', ['DETECTIVE'])])
    assert bad['configNoProactiveRules'][0] == -1
    good = _run(rules=[_rule('r1', 'S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED',
                             ['DETECTIVE', 'PROACTIVE'])])
    assert good['configNoProactiveRules'][0] == 1


def test_proactive_ignores_deleting_rules_and_no_rules():
    res = _run(rules=[_rule('r1', 'X', ['PROACTIVE'], state='DELETING')])
    assert res['configNoProactiveRules'][0] == 0  # no live rule -> see configNoRules
    assert _run(rules=[])['configNoProactiveRules'][0] == 0


def test_data_protection_flag_fix():
    bad = _run(rules=[_rule('r1', 'S3_BUCKET_VERSIONING_ENABLED')])
    assert bad['configDataProtectionRulesMissing'][0] == -1
    good = _run(rules=[_rule('r1', 'S3_BUCKET_VERSIONING_ENABLED'),
                       _rule('securityhub-encrypted-volumes-abc', 'ENCRYPTED_VOLUMES')])
    assert good['configDataProtectionRulesMissing'][0] == 1


def test_data_protection_custom_rules_are_review_not_fail():
    res = _run(rules=[_rule('custom', 'arn:aws:lambda:us-east-1:111122223333:function:f',
                            owner='CUSTOM_LAMBDA')])
    assert res['configDataProtectionRulesMissing'][0] == 0


def test_remediation_manual_only_flag_fix():
    rules = [_rule('r1', 'S3_BUCKET_VERSIONING_ENABLED'), _rule('r2', 'ENCRYPTED_VOLUMES')]
    bad = _run(rules=rules, remediations=[_remediation('r1', False), _remediation('r2', False)])
    assert bad['configRemediationManualOnly'][0] == -1
    good = _run(rules=rules, remediations=[_remediation('r1', False), _remediation('r2', True)])
    assert good['configRemediationManualOnly'][0] == 1
    none = _run(rules=rules, remediations=[])
    assert none['configRemediationManualOnly'][0] == 0


@pytest.mark.parametrize('n', [26, 51])
def test_remediation_query_batches_25(n):
    """describe_remediation_configurations caps ConfigRuleNames at 25."""
    client = _client()
    svc = _StubConfig.__new__(_StubConfig)
    svc.configClient = client
    names = [f'r{i}' for i in range(n)]
    st = Stubber(client)
    for i in range(0, n, 25):
        st.add_response('describe_remediation_configurations',
                        {'RemediationConfigurations': [_remediation(names[i], True)]},
                        {'ConfigRuleNames': names[i:i + 25]})
    with st:
        out = svc._describeRemediationConfigurations(names)
        st.assert_no_pending_responses()
    assert len(out) == len(range(0, n, 25))
