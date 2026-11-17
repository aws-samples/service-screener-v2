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


def _driver(sh, standards=(), enabled=True, standardsError=None, ssm=None, ev=None):
    detail = {'_region': 'us-east-1', '_enabled': enabled,
              '_hub': {'HubArn': 'h', 'AutoEnableControls': True} if enabled else None,
              '_standards': list(standards), '_standardsError': standardsError,
              '_aggregators': [], '_products': [], '_unprocessedFindings': 0}
    return SecurityhubCommon(detail, sh, 'cis-aws-foundations-benchmark', ssmClient=ssm, eventsClient=ev)


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

def _emptyAutomation(st_sh, st_ev, st_ssm):
    st_sh.add_response('list_automation_rules', {'AutomationRulesMetadata': []}, {'MaxResults': 100})
    st_sh.add_response('describe_action_targets', {'ActionTargets': []}, {})
    st_ev.add_response('list_rules', {'Rules': []}, {})
    st_ssm.add_response('list_documents', {'DocumentIdentifiers': []}, {'Filters': [
        {'Key': 'Owner', 'Values': ['Self']}, {'Key': 'DocumentType', 'Values': ['Automation']}]})


def test_automation_flag_then_fix_eventbridge():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b, Stubber(ssm) as c:
        _emptyAutomation(a, b, c)
        d = _driver(sh, ssm=ssm, ev=ev)
        d._checkSecurityHubNoAutomationRules()
        assert d.results['securityHubNoAutomationRules'][0] == -1
    with Stubber(sh) as a, Stubber(ev) as b:
        a.add_response('list_automation_rules', {'AutomationRulesMetadata': [
            {'RuleName': 'old', 'RuleStatus': 'DISABLED'}]}, {'MaxResults': 100})
        a.add_response('describe_action_targets', {'ActionTargets': []}, {})
        b.add_response('list_rules', {'Rules': [
            {'Name': 'sh-to-soar', 'State': 'ENABLED',
             'EventPattern': '{"source":["aws.securityhub"],"detail-type":["Security Hub Findings - Imported"]}'}]}, {})
        d = _driver(sh, ssm=ssm, ev=ev)
        d._checkSecurityHubNoAutomationRules()
        r = d.results['securityHubNoAutomationRules']
        assert r[0] == 1 and 'sh-to-soar' in r[1]


def test_automation_disabled_rule_only_still_flags():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b, Stubber(ssm) as c:
        a.add_response('list_automation_rules', {'AutomationRulesMetadata': [
            {'RuleName': 'old', 'RuleStatus': 'DISABLED'}]}, {'MaxResults': 100})
        a.add_response('describe_action_targets', {'ActionTargets': []}, {})
        b.add_response('list_rules', {'Rules': [
            {'Name': 'gd', 'State': 'ENABLED', 'EventPattern': '{"source":["aws.guardduty"]}'}]}, {})
        c.add_response('list_documents', {'DocumentIdentifiers': []})
        d = _driver(sh, ssm=ssm, ev=ev)
        d._checkSecurityHubNoAutomationRules()
        assert d.results['securityHubNoAutomationRules'][0] == -1


def test_automation_access_denied_without_evidence_is_info():
    sh, ssm, ev = _clients()
    with Stubber(sh) as a, Stubber(ev) as b, Stubber(ssm) as c:
        a.add_client_error('list_automation_rules', 'AccessDeniedException', http_status_code=403)
        a.add_response('describe_action_targets', {'ActionTargets': []}, {})
        b.add_response('list_rules', {'Rules': []}, {})
        c.add_response('list_documents', {'DocumentIdentifiers': []})
        d = _driver(sh, ssm=ssm, ev=ev)
        d._checkSecurityHubNoAutomationRules()
        assert d.results['securityHubNoAutomationRules'] == [0, 'Unable to evaluate (AccessDeniedException)']
