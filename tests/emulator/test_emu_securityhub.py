"""Flag -> fix -> re-run tests for the WAFS2027 Security Hub checks.

Security Hub state is account/region-wide in the emulator, so every test
enables Security Hub CSPM itself and disables it in finally (which also drops
standards, automation rules and action targets). The emulator cannot disable
the new Security Hub (DisableSecurityHubV2 is NotImplemented), so the v2 test
skips if v2 is already on; its FAIL path is also covered in
tests/test_stub_securityhub.py.

shubControlsDisabledNoReason: the emulator (like real UpdateStandardsControl)
rejects disabling a control without a DisabledReason, and
BatchUpdateStandardsControlAssociations is NotImplemented, so only the PASS
path (control disabled with a reason) is exercised here; the FAIL path is in
the Stubber test.
"""
import time

import pytest
from botocore.exceptions import ClientError

from tests.emulator.conftest import assertFlagFixCycle, runCheck

RES = 'Account'


def _fsbpArn(sh):
    return [s['StandardsArn'] for s in sh.describe_standards()['Standards']
            if 'aws-foundational-security-best-practices' in s['StandardsArn']][0]


CIS_ARN = 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0'


def _enable(sh):
    try:
        sh.describe_hub()
        pytest.skip('Security Hub CSPM already enabled in the emulator; not touching shared state')
    except ClientError:
        pass
    sh.enable_security_hub(EnableDefaultStandards=False)


def _disable(sh):
    try:
        sh.disable_security_hub()
    except ClientError:
        pass


def test_shub_fsbp_standard_disabled(emu):
    sh = emu.client('securityhub')
    _enable(sh)
    try:
        def misconfigure():
            sh.batch_enable_standards(StandardsSubscriptionRequests=[{'StandardsArn': CIS_ARN}])

        def fix():
            sh.batch_enable_standards(StandardsSubscriptionRequests=[{'StandardsArn': _fsbpArn(sh)}])

        assertFlagFixCycle(emu, 'securityhub', 'shubFsbpStandardDisabled', RES, misconfigure, fix)
    finally:
        _disable(sh)


def test_security_hub_v2_not_enabled(emu):
    sh = emu.client('securityhub')
    try:
        sh.describe_security_hub_v2()
        pytest.skip('Security Hub v2 already enabled and cannot be disabled in the emulator')
    except ClientError as e:
        assert e.response['Error']['Code'] == 'ResourceNotFoundException'

    assertFlagFixCycle(emu, 'securityhub', 'securityHubV2NotEnabled', RES,
                       lambda: None, lambda: sh.enable_security_hub_v2())
    ## No restore: DisableSecurityHubV2 is NotImplemented in the emulator.


def test_shub_controls_disabled_with_reason_passes(emu):
    sh = emu.client('securityhub')
    _enable(sh)
    try:
        sh.batch_enable_standards(StandardsSubscriptionRequests=[{'StandardsArn': CIS_ARN}])
        sub = None
        for _ in range(10):
            subs = sh.get_enabled_standards()['StandardsSubscriptions']
            sub = next((s for s in subs if s['StandardsStatus'] == 'READY'), None)
            if sub:
                break
            time.sleep(0.5)
        assert sub, 'CIS subscription never became READY'
        ctl = sh.describe_standards_controls(
            StandardsSubscriptionArn=sub['StandardsSubscriptionArn'])['Controls'][0]
        before = runCheck(emu, 'securityhub', 'shubControlsDisabledNoReason', RES).statuses()
        assert before and all(s == 1 for s in before.values()), before
        sh.update_standards_control(StandardsControlArn=ctl['StandardsControlArn'],
                                    ControlStatus='DISABLED', DisabledReason='Compensating control: SCP')
        after = runCheck(emu, 'securityhub', 'shubControlsDisabledNoReason', RES).statuses()
        assert after and all(s == 1 for s in after.values()), after
    finally:
        _disable(sh)


def test_security_hub_no_automation_rules(emu, uid):
    sh = emu.client('securityhub')
    _enable(sh)
    created = {}
    try:
        def misconfigure():
            pass  # fresh hub: no automation rules, action targets, EventBridge rules or runbooks

        def fix():
            r = sh.create_automation_rule(
                RuleName=f'ss-test-{uid}', RuleOrder=1, Description='suppress low',
                Criteria={'SeverityLabel': [{'Value': 'LOW', 'Comparison': 'EQUALS'}]},
                Actions=[{'Type': 'FINDING_FIELDS_UPDATE',
                          'FindingFieldsUpdate': {'Workflow': {'Status': 'SUPPRESSED'}}}])
            created['rule'] = r['RuleArn']

        assertFlagFixCycle(emu, 'securityhub', 'securityHubNoAutomationRules', RES, misconfigure, fix)
    finally:
        if created.get('rule'):
            try:
                sh.batch_delete_automation_rules(AutomationRulesArns=[created['rule']])
            except ClientError:
                pass
        _disable(sh)


def test_security_hub_custom_action_counts_as_automation(emu, uid):
    sh = emu.client('securityhub')
    _enable(sh)
    arn = None
    try:
        def fix():
            nonlocal arn
            arn = sh.create_action_target(Name='Send to SOAR', Description='d',
                                          Id=f'ss{uid}')['ActionTargetArn']

        assertFlagFixCycle(emu, 'securityhub', 'securityHubNoAutomationRules', RES, lambda: None, fix)
    finally:
        if arn:
            try:
                sh.delete_action_target(ActionTargetArn=arn)
            except ClientError:
                pass
        _disable(sh)
