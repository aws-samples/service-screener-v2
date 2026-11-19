"""EC2 caches kept in utils.Config must be scoped to the account being scanned.

main.py calls Config.init() once, before the account loop, and with
--sequential --crossAccounts every account is scanned in the same process. A
cache keyed only by region (or not at all) would hand account A's route
tables / organization / AMIs / security groups / run-once flags to account B:
  - vpcNoGatewayEndpoints: B's VPC not found in A's subnetVpc -> false PASS
  - vpcPeeringFullRoute: A's route tables reused for B -> false PASS
  - ebsSnapshotSharedExternally / ec2AmiSharedExternally: B judged against A's org
  - compute optimizer / cost explorer recommendations silently skipped for B
Each test below scans "account A" then "account B" in one process and fails on
the old (account-agnostic) cache keys.
"""
import datetime as _dt
import os
import re
import sys
import types
from unittest import mock

import botocore.session
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.Evaluator import Evaluator  # noqa: E402
from services.ec2.acctCache import acctKey  # noqa: E402
from services.ec2.Ec2 import Ec2  # noqa: E402
from services.ec2.drivers.Ec2NetworkInterface import getSubnetRouting  # noqa: E402
from services.ec2.drivers.Ec2Instance import Ec2Instance  # noqa: E402

ACCT_A = '111111111111'
ACCT_B = '333333333333'
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def _client(service):
    return botocore.session.get_session().create_client(
        service, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
        aws_access_key_id='testing', aws_secret_access_key='testing')


@pytest.fixture
def accounts():
    """Switch the scanned account like main.py does (Config.setAccountInfo -> stsInfo),
    without resetting the rest of Config."""
    saved = Config.get('stsInfo', None)

    def use(acct):
        Config.set('stsInfo', {'Account': acct})
    try:
        yield use
    finally:
        Config.set('stsInfo', saved)


def test_acct_key_differs_per_account(accounts):
    accounts(ACCT_A)
    a = acctKey('ec2::orgContext')
    accounts(ACCT_B)
    b = acctKey('ec2::orgContext')
    assert a != b and ACCT_A in a and ACCT_B in b


def _rt(rtId, vpc, subnet):
    return {'RouteTableId': rtId, 'VpcId': vpc, 'Routes': [],
            'Associations': [{'RouteTableAssociationId': 'rtbassoc-' + rtId[4:], 'RouteTableId': rtId,
                              'Main': False, 'SubnetId': subnet, 'AssociationState': {'State': 'associated'}}]}


def _routingFor(vpc, subnet, rtId):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_route_tables', {'RouteTables': [_rt(rtId, vpc, subnet)]})
        st.add_response('describe_subnets', {'Subnets': [{'SubnetId': subnet, 'VpcId': vpc}]})
        ctx = getSubnetRouting(ec2)
        # account B must read its own route tables, not reuse account A's
        st.assert_no_pending_responses()
    return ctx


def test_subnet_routing_not_reused_across_accounts(accounts):
    for acct in (ACCT_A, ACCT_B):
        accounts(acct)
        Config.set(acctKey('ec2::subnetRouting::us-east-1'), None)
    try:
        accounts(ACCT_A)
        a = _routingFor('vpc-aaaa', 'subnet-aaaa', 'rtb-aaaa')
        accounts(ACCT_B)
        b = _routingFor('vpc-bbbb', 'subnet-bbbb', 'rtb-bbbb')
        assert b['subnetVpc'] == {'subnet-bbbb': 'vpc-bbbb'}
        assert [r['RouteTableId'] for r in b['_routeTables']] == ['rtb-bbbb']
        # A's entry is still A's
        accounts(ACCT_A)
        assert Config.get(acctKey('ec2::subnetRouting::us-east-1'), None) is a
    finally:
        for acct in (ACCT_A, ACCT_B):
            accounts(acct)
            Config.set(acctKey('ec2::subnetRouting::us-east-1'), None)


def _orgFor(orgId, members):
    org = _client('organizations')
    with Stubber(org) as st:
        if orgId is None:
            st.add_client_error('describe_organization', service_error_code='AWSOrganizationsNotInUseException',
                                http_status_code=400)
        else:
            st.add_response('describe_organization', {'Organization': {'Id': orgId, 'FeatureSet': 'ALL'}})
            st.add_response('list_accounts', {'Accounts': [{'Id': m} for m in members]})
        ctx = Ec2.getOrgContext(types.SimpleNamespace(orgClient=org))
        st.assert_no_pending_responses()
    return ctx


def test_org_context_not_reused_across_accounts(accounts):
    for acct in (ACCT_A, ACCT_B):
        accounts(acct)
        Config.set(acctKey('ec2::orgContext'), None)
    try:
        accounts(ACCT_A)
        a = _orgFor('o-aaaaaaaaaa', [ACCT_A, '222222222222'])
        assert a['inOrg'] is True
        accounts(ACCT_B)
        b = _orgFor(None, [])   # B is a standalone account
        assert b['inOrg'] is False and b['accounts'] is None
    finally:
        for acct in (ACCT_A, ACCT_B):
            accounts(acct)
            Config.set(acctKey('ec2::orgContext'), None)


def _instance(imageId):
    return {'InstanceId': 'i-0123456789abcdef0', 'ImageId': imageId, 'InstanceType': 'm5.large',
            'State': {'Name': 'running'}, 'LaunchTime': _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)}


def test_source_ami_lookup_not_reused_across_accounts(accounts):
    """The same AMI ID can be visible to account A (shared with it) and not to B."""
    imageId = 'ami-0acc0acc0acc0acc0'
    keys = ('ec2::image::' + imageId, 'ec2::imagestatus::' + imageId)
    for acct in (ACCT_A, ACCT_B):
        accounts(acct)
        for k in keys:
            Config.set(acctKey(k), '__unset__')
    params = {'ImageIds': [imageId], 'IncludeDeprecated': True, 'IncludeDisabled': True}
    try:
        accounts(ACCT_A)
        ec2 = _client('ec2')
        with Stubber(ec2) as st:
            st.add_response('describe_images', {'Images': [{'ImageId': imageId, 'OwnerId': '444444444444',
                                                             'State': 'available'}]}, params)
            a = Ec2Instance(_instance(imageId), ec2, None)
            st.assert_no_pending_responses()
        assert a.ec2ImageStatus == 'found'

        accounts(ACCT_B)
        ec2 = _client('ec2')
        with Stubber(ec2) as st:
            st.add_response('describe_images', {'Images': []}, params)
            b = Ec2Instance(_instance(imageId), ec2, None)
            st.assert_no_pending_responses()
        assert b.ec2ImageStatus == 'missing' and b.ec2ImageInfo is None
    finally:
        for acct in (ACCT_A, ACCT_B):
            accounts(acct)
            for k in keys:
                Config.set(acctKey(k), '__unset__')


def _mockService():
    svc = mock.MagicMock()
    svc._ruleSelected.side_effect = lambda r: False
    for m in ('getResources', 'getEBSResources', 'getELB', 'getELBClassic', 'getASG', 'getEIPResources',
              'getVpcs', 'getNetworkACLs', 'getKeyPairs', 'getSelfImages', 'getLaunchTemplates',
              'getNetworkInterfaces'):
        getattr(svc, m).return_value = []
    svc.region = 'us-east-1'
    svc.ec2Client.meta.region_name = 'us-east-1'
    svc.ssmClient.get_parameters_by_path.return_value = {'Parameters': [{'Name': 'compute-optimizer'}]}
    svc.getChartGenCost.return_value = {}
    return svc


def test_run_once_recommendations_run_for_every_account(accounts):
    """Compute Optimizer / Cost Explorer recommendations run once per ACCOUNT, not once per process."""
    for acct in (ACCT_A, ACCT_B):
        accounts(acct)
        Config.set(acctKey('EC2_HasRunComputeOpt'), False)
        Config.set(acctKey('EC2_HasRunRISP'), False)
    try:
        with mock.patch.object(Evaluator, 'run', lambda *a, **k: None), \
                mock.patch('services.ec2.Ec2.Ec2CompOpt') as compOpt, \
                mock.patch('services.ec2.Ec2.Ec2CostExplorerRecs') as ceRecs:
            for acct in (ACCT_A, ACCT_A, ACCT_B):     # second region of A, then account B
                accounts(acct)
                Ec2.advise(_mockService())
        assert compOpt.call_count == 2
        assert ceRecs.call_count == 2
    finally:
        for acct in (ACCT_A, ACCT_B):
            accounts(acct)
            Config.set(acctKey('EC2_HasRunComputeOpt'), False)
            Config.set(acctKey('EC2_HasRunRISP'), False)


def test_no_account_agnostic_ec2_cache_keys_in_source():
    """Every 'ec2::' / 'EC2_HasRun' cache key in services/ec2 is built through acctKey()."""
    offenders = []
    for dirpath, _, files in os.walk(os.path.join(ROOT, 'services', 'ec2')):
        for f in files:
            if not f.endswith('.py'):
                continue
            path = os.path.join(dirpath, f)
            for n, line in enumerate(open(path, encoding='utf-8'), 1):
                if re.search(r"['\"](ec2::|EC2_HasRun)", line) and 'acctKey(' not in line:
                    offenders.append(f'{os.path.relpath(path, ROOT)}:{n}: {line.strip()}')
    assert not offenders, '\n'.join(offenders)
