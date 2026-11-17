"""Flag -> fix -> re-run tests (AWS Emulator) for the WAFS2027 IAM identity
checks of chunk 2 that the emulator can drive end to end:

- rolesAnywhereTrustAnchorCertExpiring (CERTIFICATE_BUNDLE source, CRLs)
- workloadRoleCanEscalate
- accountMixesEnvironments
- budgetNoActions

iamUserTwoActiveKeys, rootVirtualMfaOnly, healthOrgViewDisabled and
auditManagerNoActiveAssessment are tested with botocore Stubber in
tests/test_stub_iam_identity2.py (credential report is cached by the
emulator; root MFA cannot be assigned through the IAM API; Health org status
and Audit Manager GetAccountStatus are not implemented by the emulator).
"""
import json
import shutil
import subprocess
import tempfile

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ACCOUNT = '000000000000'


def _doc(statements):
    return json.dumps({'Version': '2012-10-17', 'Statement': statements})


def _deleteRole(iam, name):
    try:
        for p in iam.list_role_policies(RoleName=name).get('PolicyNames', []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        for p in iam.list_attached_role_policies(RoleName=name).get('AttachedPolicies', []):
            iam.detach_role_policy(RoleName=name, PolicyArn=p['PolicyArn'])
        iam.delete_role(RoleName=name)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# rolesAnywhereTrustAnchorCertExpiring
# --------------------------------------------------------------------------- #
def _caCert(days):
    exe = shutil.which('openssl')
    if not exe:
        pytest.skip('openssl not available to create a test CA certificate')
    d = tempfile.mkdtemp(prefix='ss-ra-')
    try:
        subprocess.run([exe, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/k.pem',
                        '-out', d + '/c.pem', '-subj', '/CN=ss-test-ca', '-days', str(days),
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
                       check=True, capture_output=True)
        return open(d + '/c.pem').read()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _bundle(pem):
    return {'sourceType': 'CERTIFICATE_BUNDLE', 'sourceData': {'x509CertificateData': pem}}


def test_roles_anywhere_bundle_expiring(emu, uid):
    ra = emu.client('rolesanywhere')
    anchorId = None
    try:
        def misconfigure():
            nonlocal anchorId
            anchorId = ra.create_trust_anchor(name=f'ss-test-ta-{uid}', enabled=True,
                                              source=_bundle(_caCert(10)))['trustAnchor']['trustAnchorId']

        def fix():
            ra.update_trust_anchor(trustAnchorId=anchorId, source=_bundle(_caCert(3650)))

        before, after = assertFlagFixCycle(emu, 'iam', 'rolesAnywhereTrustAnchorCertExpiring', 'Account',
                                           misconfigure, fix)
        assert list(after.values()) == [1], after
    finally:
        if anchorId:
            ra.delete_trust_anchor(trustAnchorId=anchorId)


def test_roles_anywhere_disabled_crl(emu, uid):
    ra = emu.client('rolesanywhere')
    ta = ra.create_trust_anchor(name=f'ss-test-tacrl-{uid}', enabled=True,
                                source=_bundle(_caCert(3650)))['trustAnchor']
    crlId = None
    try:
        def misconfigure():
            nonlocal crlId
            crlId = ra.import_crl(name=f'ss-test-crl-{uid}', crlData=b'ss-test-crl', enabled=False,
                                  trustAnchorArn=ta['trustAnchorArn'])['crl']['crlId']

        def fix():
            # EnableCrl is not implemented by the emulator: replace the
            # disabled CRL with an enabled one (same end state).
            nonlocal crlId
            ra.delete_crl(crlId=crlId)
            crlId = ra.import_crl(name=f'ss-test-crl-{uid}', crlData=b'ss-test-crl', enabled=True,
                                  trustAnchorArn=ta['trustAnchorArn'])['crl']['crlId']

        assertFlagFixCycle(emu, 'iam', 'rolesAnywhereTrustAnchorCertExpiring', 'Account', misconfigure, fix)
    finally:
        if crlId:
            ra.delete_crl(crlId=crlId)
        ra.delete_trust_anchor(trustAnchorId=ta['trustAnchorId'])


def test_roles_anywhere_disabled_anchor_not_flagged(emu, uid):
    """A disabled trust anchor cannot authenticate anyone: noted, not a finding."""
    ra = emu.client('rolesanywhere')
    ta = ra.create_trust_anchor(name=f'ss-test-tadis-{uid}', enabled=False,
                                source=_bundle(_caCert(10)))['trustAnchor']
    try:
        res = runCheck(emu, 'iam', 'rolesAnywhereTrustAnchorCertExpiring', 'Account').statuses()
        assert res and all(v != -1 for v in res.values()), res
    finally:
        ra.delete_trust_anchor(trustAnchorId=ta['trustAnchorId'])


# --------------------------------------------------------------------------- #
# workloadRoleCanEscalate
# --------------------------------------------------------------------------- #
def _serviceTrust(service):
    return _doc([{'Effect': 'Allow', 'Principal': {'Service': service}, 'Action': 'sts:AssumeRole'}])


@pytest.mark.parametrize('service,path,bad,good', [
    ('lambda.amazonaws.com', '/',
     {'Effect': 'Allow', 'Action': 'iam:AttachRolePolicy', 'Resource': '*'},
     {'Effect': 'Allow', 'Action': 'iam:AttachRolePolicy', 'Resource': f'arn:aws:iam::{ACCOUNT}:role/app-worker'}),
    ('ecs-tasks.amazonaws.com', '/service-role/',
     {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': f'arn:aws:iam::{ACCOUNT}:role/*'},
     {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': '*',
      'Condition': {'StringEquals': {'iam:PassedToService': 'ecs-tasks.amazonaws.com'}}}),
    ('codebuild.amazonaws.com', '/',
     {'Effect': 'Allow', 'Action': ['iam:Put*', 's3:GetObject'], 'Resource': '*'},
     {'Effect': 'Allow', 'Action': ['iam:Get*', 's3:GetObject'], 'Resource': '*'}),
])
def test_workload_role_can_escalate_inline(emu, uid, service, path, bad, good):
    iam = emu.client('iam')
    role = f'ss-test-esc-{uid}'
    iam.create_role(RoleName=role, Path=path, AssumeRolePolicyDocument=_serviceTrust(service))
    try:
        def misconfigure():
            iam.put_role_policy(RoleName=role, PolicyName='p', PolicyDocument=_doc([bad]))

        def fix():
            iam.put_role_policy(RoleName=role, PolicyName='p', PolicyDocument=_doc([good]))

        misconfigure()
        res = runCheck(emu, 'iam', 'workloadRoleCanEscalate', 'Account').results
        assert any(role in str(v.get('workloadRoleCanEscalate')) for v in res.values()), res
        assertFlagFixCycle(emu, 'iam', 'workloadRoleCanEscalate', 'Account', misconfigure, fix)
    finally:
        _deleteRole(iam, role)


def test_workload_role_can_escalate_managed_and_boundary(emu, uid):
    """Customer managed policy grants iam:CreatePolicyVersion on all policies;
    the fix is a permissions boundary that does not allow IAM writes."""
    iam = emu.client('iam')
    role = f'ss-test-escm-{uid}'
    pol = iam.create_policy(PolicyName=f'ss-test-escp-{uid}', PolicyDocument=_doc(
        [{'Effect': 'Allow', 'Action': ['iam:CreatePolicyVersion', 'logs:*'], 'Resource': '*'}]))['Policy']['Arn']
    boundary = iam.create_policy(PolicyName=f'ss-test-escb-{uid}', PolicyDocument=_doc(
        [{'Effect': 'Allow', 'Action': 'logs:*', 'Resource': '*'}]))['Policy']['Arn']
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=_serviceTrust('ec2.amazonaws.com'))
    try:
        def misconfigure():
            iam.attach_role_policy(RoleName=role, PolicyArn=pol)

        def fix():
            iam.put_role_permissions_boundary(RoleName=role, PermissionsBoundary=boundary)

        assertFlagFixCycle(emu, 'iam', 'workloadRoleCanEscalate', 'Account', misconfigure, fix)
    finally:
        try:
            iam.delete_role_permissions_boundary(RoleName=role)
        except Exception:
            pass
        _deleteRole(iam, role)
        iam.delete_policy(PolicyArn=pol)
        iam.delete_policy(PolicyArn=boundary)


def test_workload_role_full_admin_and_human_roles_not_flagged(emu, uid):
    iam = emu.client('iam')
    admin = f'ss-test-escadm-{uid}'
    human = f'ss-test-eschum-{uid}'
    iam.create_role(RoleName=admin, AssumeRolePolicyDocument=_serviceTrust('lambda.amazonaws.com'))
    iam.put_role_policy(RoleName=admin, PolicyName='p', PolicyDocument=_doc(
        [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]))
    iam.create_role(RoleName=human, AssumeRolePolicyDocument=_doc(
        [{'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:root'}, 'Action': 'sts:AssumeRole'}]))
    iam.put_role_policy(RoleName=human, PolicyName='p', PolicyDocument=_doc(
        [{'Effect': 'Allow', 'Action': 'iam:AttachRolePolicy', 'Resource': '*'}]))
    try:
        res = runCheck(emu, 'iam', 'workloadRoleCanEscalate', 'Account').statuses()
        assert res and all(v != -1 for v in res.values()), res
    finally:
        _deleteRole(iam, admin)
        _deleteRole(iam, human)


# --------------------------------------------------------------------------- #
# accountMixesEnvironments
# --------------------------------------------------------------------------- #
def test_account_mixes_environments(emu, uid):
    sqs = emu.client('sqs')
    prod = sqs.create_queue(QueueName=f'ss-test-envp-{uid}', tags={'Environment': 'Production'})['QueueUrl']
    dev = None
    try:
        def misconfigure():
            nonlocal dev
            dev = sqs.create_queue(QueueName=f'ss-test-envd-{uid}', tags={'Environment': 'dev'})['QueueUrl']

        def fix():
            sqs.untag_queue(QueueUrl=dev, TagKeys=['Environment'])

        assertFlagFixCycle(emu, 'iam', 'accountMixesEnvironments', 'Account', misconfigure, fix)
    finally:
        sqs.delete_queue(QueueUrl=prod)
        if dev:
            sqs.delete_queue(QueueUrl=dev)


# --------------------------------------------------------------------------- #
# budgetNoActions
# --------------------------------------------------------------------------- #
def test_budget_no_actions(emu, uid):
    budgets = emu.client('budgets')
    iam = emu.client('iam')
    name = f'ss-test-budget-{uid}'
    execRole = f'ss-test-budgetx-{uid}'
    target = f'ss-test-budgett-{uid}'
    deny = iam.create_policy(PolicyName=f'ss-test-budgetp-{uid}', PolicyDocument=_doc(
        [{'Effect': 'Deny', 'Action': 'ec2:RunInstances', 'Resource': '*'}]))['Policy']['Arn']
    execArn = iam.create_role(RoleName=execRole, AssumeRolePolicyDocument=_serviceTrust('budgets.amazonaws.com'))['Role']['Arn']
    iam.create_role(RoleName=target, AssumeRolePolicyDocument=_serviceTrust('ec2.amazonaws.com'))
    actionId = None
    try:
        def misconfigure():
            budgets.create_budget(AccountId=ACCOUNT, Budget={
                'BudgetName': name, 'BudgetLimit': {'Amount': '100', 'Unit': 'USD'},
                'TimeUnit': 'MONTHLY', 'BudgetType': 'COST'})

        def fix():
            nonlocal actionId
            actionId = budgets.create_budget_action(
                AccountId=ACCOUNT, BudgetName=name, NotificationType='ACTUAL', ActionType='APPLY_IAM_POLICY',
                ActionThreshold={'ActionThresholdValue': 100, 'ActionThresholdType': 'PERCENTAGE'},
                Definition={'IamActionDefinition': {'PolicyArn': deny, 'Roles': [target]}},
                ExecutionRoleArn=execArn, ApprovalModel='MANUAL',
                Subscribers=[{'SubscriptionType': 'EMAIL', 'Address': 'ops@example.com'}])['ActionId']

        assertFlagFixCycle(emu, 'iam', 'budgetNoActions', 'Account', misconfigure, fix)
    finally:
        if actionId:
            try:
                budgets.delete_budget_action(AccountId=ACCOUNT, BudgetName=name, ActionId=actionId)
            except Exception:
                pass
        try:
            budgets.delete_budget(AccountId=ACCOUNT, BudgetName=name)
        except Exception:
            pass
        _deleteRole(iam, execRole)
        _deleteRole(iam, target)
        iam.delete_policy(PolicyArn=deny)


def test_enable_cost_budget_empty_list_flags(emu):
    """enableCostBudget gap fix: an empty Budgets list must not PASS."""
    budgets = emu.client('budgets')
    if budgets.describe_budgets(AccountId=ACCOUNT).get('Budgets'):
        pytest.skip('budgets already present in emulator')
    res = runCheck(emu, 'iam', 'enableCostBudget', 'Account').statuses()
    assert list(res.values()) == [-1], res
