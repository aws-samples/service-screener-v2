"""Stubber-based tests for WAFS2027 Security Hub checks.

Why Stubber here: the emulator cannot produce a control that is DISABLED with
no DisabledReason (UpdateStandardsControl requires a reason and
BatchUpdateStandardsControlAssociations is NotImplemented), cannot disable the
new Security Hub once enabled (DisableSecurityHubV2 is NotImplemented), and
cannot return AccessDenied. These tests drive SecurityhubCommon directly with
real boto3 clients wrapped by botocore Stubber, so request and response shapes
are validated against the real API models.
"""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.securityhub.drivers.SecurityhubCommon import SecurityhubCommon  # noqa: E402

ACCT = '123456789012'
FSBP = 'arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0'
CIS = 'arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/3.0.0'


def _sub(arn, status='READY'):
    name = arn.split('standards/')[1]
    return {'StandardsSubscriptionArn': f'arn:aws:securityhub:us-east-1:{ACCT}:subscription/{name}',
            'StandardsArn': arn, 'StandardsInput': {}, 'StandardsStatus': status}


def _clients():
    s = boto3.session.Session(aws_access_key_id='x', aws_secret_access_key='x', region_name='us-east-1')
    return s.client('securityhub'), s.client('ssm'), s.client('events')


def _driver(sh, standards=(), enabled=True, standardsError=None, ssm=None, ev=None,
            aggregators=(), aggregatorsError=None, region='us-east-1'):
    detail = {'_region': region, '_enabled': enabled,
              '_hub': {'HubArn': 'h', 'AutoEnableControls': True} if enabled else None,
              '_standards': list(standards), '_standardsError': standardsError,
              '_aggregators': list(aggregators), '_aggregatorsError': aggregatorsError,
              '_products': [], '_unprocessedFindings': 0}
    d = SecurityhubCommon(detail, sh, 'cis-aws-foundations-benchmark', eventsClient=ev)
    ## Older drivers read SSM Automation documents as evidence; keep the client
    ## attached so these tests prove such documents no longer count.
    d.ssmClient = ssm
    return d


# ---- shubFsbpStandardDisabled --------------------------------------------- #

def test_fsbp_flag_then_fix():
    sh, _, _ = _clients()
    d = _driver(sh, [_sub(CIS)])
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'][0] == -1
    d = _driver(sh, [_sub(CIS), _sub(FSBP)])
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'][0] == 1


def test_fsbp_failed_subscription_flags():
    sh, _, _ = _clients()
    d = _driver(sh, [_sub(FSBP, 'FAILED')])
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'][0] == -1
    d = _driver(sh, [_sub(FSBP, 'INCOMPLETE')])
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'][0] == 1


def test_fsbp_unreadable_and_not_enabled_are_info():
    sh, _, _ = _clients()
    d = _driver(sh, standardsError='AccessDeniedException')
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'] == [0, 'Unable to evaluate (AccessDeniedException)']
    d = _driver(sh, enabled=False)
    d._checkShubFsbpStandardDisabled()
    assert d.results['shubFsbpStandardDisabled'][0] == 0


# ---- securityHubV2NotEnabled ---------------------------------------------- #

def test_v2_flag_then_fix():
    sh, _, _ = _clients()
    with Stubber(sh) as st:
        st.add_client_error('describe_security_hub_v2', 'ResourceNotFoundException', http_status_code=404)
        d = _driver(sh, enabled=False)
        d._checkSecurityHubV2NotEnabled()
        assert d.results['securityHubV2NotEnabled'][0] == -1
    with Stubber(sh) as st:
        st.add_response('describe_security_hub_v2', {
            'HubV2Arn': f'arn:aws:securityhub:us-east-1:{ACCT}:hubv2/default', 'SubscribedAt': '2026-01-01T00:00:00Z'})
        d = _driver(sh)
        d._checkSecurityHubV2NotEnabled()
        assert d.results['securityHubV2NotEnabled'][0] == 1


def test_v2_access_denied_is_info():
    sh, _, _ = _clients()
    with Stubber(sh) as st:
        st.add_client_error('describe_security_hub_v2', 'AccessDeniedException', http_status_code=403)
        d = _driver(sh)
        d._checkSecurityHubV2NotEnabled()
        assert d.results['securityHubV2NotEnabled'] == [0, 'Unable to evaluate (AccessDeniedException)']


# ---- shubControlsDisabledNoReason ----------------------------------------- #

def _ctl(cid, status, reason=None):
    c = {'StandardsControlArn': f'arn:aws:securityhub:us-east-1:{ACCT}:control/aws-foundational-security-best-practices/v/1.0.0/{cid}',
         'ControlStatus': status, 'ControlId': cid}
    if reason is not None:
        c['DisabledReason'] = reason
    return c


def test_controls_flag_then_fix():
    sh, _, _ = _clients()
    sub = _sub(FSBP)
    req = {'StandardsSubscriptionArn': sub['StandardsSubscriptionArn']}
    with Stubber(sh) as st:
        st.add_response('describe_standards_controls',
                        {'Controls': [_ctl('IAM.1', 'ENABLED'), _ctl('EC2.2', 'DISABLED')], 'NextToken': 't'}, req)
        st.add_response('describe_standards_controls',
                        {'Controls': [_ctl('S3.1', 'DISABLED', 'Handled by SCP')]},
                        dict(req, NextToken='t'))
        d = _driver(sh, [sub])
        d._checkShubControlsDisabledNoReason()
        r = d.results['shubControlsDisabledNoReason']
        assert r[0] == -1 and 'EC2.2' in r[1] and 'S3.1' not in r[1]
    with Stubber(sh) as st:
        st.add_response('describe_standards_controls',
                        {'Controls': [_ctl('EC2.2', 'DISABLED', 'Default VPC deleted'),
                                      _ctl('S3.1', 'DISABLED', 'Handled by SCP')]}, req)
        d = _driver(sh, [sub])
        d._checkShubControlsDisabledNoReason()
        assert d.results['shubControlsDisabledNoReason'][0] == 1


def test_controls_access_denied_is_info():
    sh, _, _ = _clients()
    sub = _sub(FSBP)
    with Stubber(sh) as st:
        st.add_client_error('describe_standards_controls', 'AccessDeniedException', http_status_code=403)
        d = _driver(sh, [sub])
        d._checkShubControlsDisabledNoReason()
        assert d.results['shubControlsDisabledNoReason'] == [0, 'Unable to evaluate (AccessDeniedException)']


def test_controls_pending_only_is_info():
    sh, _, _ = _clients()
    d = _driver(sh, [_sub(FSBP, 'PENDING')])
    d._checkShubControlsDisabledNoReason()
    assert d.results['shubControlsDisabledNoReason'][0] == 0


# ---- securityHubNoAutomationRules ----------------------------------------- #
## Real request shapes: list_rules / list_targets_by_rule on the default bus,
## get_administrator_account, get_finding_aggregator.

SH_RULE = 'securityHubNoAutomationRules'
TARGET = [{'Id': 't1', 'Arn': 'arn:aws:sqs:us-east-1:123456789012:soar'}]
SSM_FILTERS = {'Filters': [{'Key': 'Owner', 'Values': ['Self']},
                           {'Key': 'DocumentType', 'Values': ['Automation']}]}


def _noRules(a):
    a.add_response('list_automation_rules', {'AutomationRulesMetadata': []}, {'MaxResults': 100})


def _ebRules(b, rules, targets=()):
    b.add_response('list_rules', {'Rules': rules}, {'EventBusName': 'default'})
    for name, t in targets:
        b.add_response('list_targets_by_rule', {'Targets': list(t)} if t else {},
                       {'Rule': name, 'EventBusName': 'default'})


def _notMember(a):
    a.add_response('get_administrator_account', {}, {})


def _run(d):
    d._checkSecurityHubNoAutomationRules()
    return d.results[SH_RULE]


def test_automation_flag_then_fix_eventbridge():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a); _ebRules(b, []); _notMember(a)
        assert _run(_driver(sh, ev=ev))[0] == -1
    with Stubber(sh) as a, Stubber(ev) as b:
        a.add_response('list_automation_rules', {'AutomationRulesMetadata': [
            {'RuleName': 'old', 'RuleStatus': 'DISABLED'}]}, {'MaxResults': 100})
        _ebRules(b, [{'Name': 'sh-to-soar', 'State': 'ENABLED',
                      'EventPattern': '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}'}],
                 [('sh-to-soar', TARGET)])
        r = _run(_driver(sh, ev=ev))
        assert r[0] == 1 and 'sh-to-soar' in r[1]


def test_automation_enabled_rule_passes():
    sh, _, ev = _clients()
    with Stubber(sh) as a:
        a.add_response('list_automation_rules', {'AutomationRulesMetadata': [
            {'RuleName': 'suppress-low', 'RuleStatus': 'ENABLED'}]}, {'MaxResults': 100})
        r = _run(_driver(sh, ev=ev))
        assert r[0] == 1 and 'suppress-low' in r[1]


def test_automation_disabled_rule_only_still_flags():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        a.add_response('list_automation_rules', {'AutomationRulesMetadata': [
            {'RuleName': 'old', 'RuleStatus': 'DISABLED'}]}, {'MaxResults': 100})
        _ebRules(b, [{'Name': 'gd', 'State': 'ENABLED', 'EventPattern': '{"source":["aws.guardduty"]}'}])
        _notMember(a)
        assert _run(_driver(sh, ev=ev))[0] == -1


def test_unrelated_ssm_runbook_is_not_evidence():
    """A self-owned patching runbook does not respond to findings (was a false PASS)."""
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b, Stubber(ssm) as c:
        _noRules(a)
        _ebRules(b, [])
        _notMember(a)
        c.add_response('list_documents', {'DocumentIdentifiers': [
            {'Name': 'PatchFleet', 'DocumentType': 'Automation', 'Owner': '123456789012'}]}, SSM_FILTERS)
        r = _run(_driver(sh, ssm=ssm, ev=ev))
        assert r[0] == -1, r


def test_custom_action_without_rule_is_not_evidence():
    """A custom action does nothing unless an EventBridge rule routes it (was a false PASS).

    The custom action exists (describe_action_targets would list it) but the
    driver must not read it as evidence; only the rule lookups below happen."""
    sh, _, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a)
        _ebRules(b, [])
        _notMember(a)
        r = _run(_driver(sh, ev=ev))
        assert r[0] == -1, r


def test_custom_action_with_routed_rule_passes():
    sh, _, ev = _clients()
    pattern = ('{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Custom Action"],'
               '"resources":["arn:aws:securityhub:us-east-1:123456789012:action/custom/soar"]}')
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a)
        _ebRules(b, [{'Name': 'soar', 'State': 'ENABLED', 'EventPattern': pattern}], [('soar', TARGET)])
        r = _run(_driver(sh, ev=ev))
        assert r[0] == 1 and 'soar' in r[1]


def test_eventbridge_rule_must_match_and_have_a_target():
    """anything-but aws.securityhub (substring match), zero targets, and CloudTrail-only
    rules were false PASSes."""
    sh, _, ev = _clients()
    rules = [
        {'Name': 'not-sh', 'State': 'ENABLED',
         'EventPattern': '{"source":[{"anything-but":["aws.securityhub"]}],"detail-type":["x"]}'},
        {'Name': 'no-target', 'State': 'ENABLED',
         'EventPattern': '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}'},
        {'Name': 'api-calls', 'State': 'ENABLED',
         'EventPattern': '{"source":["aws.securityhub"],"detail-type":["AWS API Call via CloudTrail"]}'},
        {'Name': 'off', 'State': 'DISABLED', 'EventPattern': '{"source":["aws.securityhub"]}'},
    ]
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a)
        _ebRules(b, rules, [('no-target', [])])
        _notMember(a)
        r = _run(_driver(sh, ev=ev))
        assert r[0] == -1, r


def test_member_account_is_info():
    sh, _, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        a.add_client_error('list_automation_rules', 'AccessDeniedException', http_status_code=403)
        _ebRules(b, [])
        a.add_response('get_administrator_account', {'Administrator': {
            'AccountId': '210987654321', 'InvitationId': 'i', 'MemberStatus': 'Enabled'}}, {})
        r = _run(_driver(sh, ev=ev))
        assert r[0] == 0 and '210987654321' in r[1], r


def test_linked_region_is_info_and_unlinked_region_flags():
    sh, _, ev = _clients()
    arn = 'arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/abc'
    for mode, regions, expected in [('ALL_REGIONS', [], 0),
                                    ('SPECIFIED_REGIONS', ['eu-west-1'], 0),
                                    ('SPECIFIED_REGIONS', ['ap-southeast-1'], -1),
                                    ('ALL_REGIONS_EXCEPT_SPECIFIED', ['eu-west-1'], -1)]:
        with Stubber(sh) as a, Stubber(ev) as b:
            _noRules(a); _ebRules(b, []); _notMember(a)
            resp = {'FindingAggregatorArn': arn, 'FindingAggregationRegion': 'us-east-1',
                    'RegionLinkingMode': mode}
            if regions:
                resp['Regions'] = regions
            a.add_response('get_finding_aggregator', resp, {'FindingAggregatorArn': arn})
            d = _driver(sh, ev=ev, region='eu-west-1', aggregators=[{'FindingAggregatorArn': arn}])
            r = _run(d)
            assert r[0] == expected, (mode, regions, r)


def test_aggregation_region_itself_is_evaluated():
    sh, _, ev = _clients()
    arn = 'arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/abc'
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a); _ebRules(b, []); _notMember(a)
        a.add_response('get_finding_aggregator', {'FindingAggregatorArn': arn, 'FindingAggregationRegion': 'us-east-1',
                                                  'RegionLinkingMode': 'ALL_REGIONS'}, {'FindingAggregatorArn': arn})
        assert _run(_driver(sh, ev=ev, aggregators=[{'FindingAggregatorArn': arn}]))[0] == -1


def test_membership_unreadable_without_evidence_is_info():
    sh, _, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a); _ebRules(b, [])
        a.add_client_error('get_administrator_account', 'AccessDeniedException', http_status_code=403)
        r = _run(_driver(sh, ev=ev))
        assert r[0] == 0 and r[1].startswith('Unable to evaluate (get_administrator_account: AccessDeniedException)'), r


def test_aggregators_unreadable_without_evidence_is_info():
    sh, _, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        _noRules(a); _ebRules(b, []); _notMember(a)
        r = _run(_driver(sh, ev=ev, aggregatorsError='AccessDeniedException'))
        assert r[0] == 0 and 'list_finding_aggregators: AccessDeniedException' in r[1], r


def test_automation_access_denied_without_evidence_is_info():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b:
        a.add_client_error('list_automation_rules', 'AccessDeniedException', http_status_code=403)
        _ebRules(b, [])
        _notMember(a)
        assert _run(_driver(sh, ev=ev)) == [0, 'Unable to evaluate (AccessDeniedException)']


# ---- shubFindingAggregatorMissing: unreadable list is not "missing" ------- #

def test_aggregator_list_unreadable_is_info_not_fail():
    sh, _, _ = _clients()
    d = _driver(sh, aggregatorsError='AccessDeniedException')
    d._checkShubFindingAggregatorMissing()
    assert d.results['shubFindingAggregatorMissing'] == [0, 'Unable to evaluate (AccessDeniedException)']
    d = _driver(sh)
    d._checkShubFindingAggregatorMissing()
    assert d.results['shubFindingAggregatorMissing'][0] == -1


def test_service_records_aggregator_read_error():
    from services.securityhub.Securityhub import Securityhub
    sh, _, _ = _clients()
    import types
    ## Unbound call: a real Service instance writes report files on __del__.
    svc = types.SimpleNamespace(shClient=sh, _logClientError=lambda *a: None)
    with Stubber(sh) as a:
        a.add_client_error('list_finding_aggregators', 'AccessDeniedException', http_status_code=403)
        assert Securityhub._listFindingAggregators(svc) == ([], 'AccessDeniedException')
    with Stubber(sh) as a:
        a.add_response('list_finding_aggregators', {'FindingAggregators': []}, {})
        assert Securityhub._listFindingAggregators(svc) == ([], None)
