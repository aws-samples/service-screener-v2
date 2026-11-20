"""Regression tests for the low-severity ec2 review findings (branch low/ec2).

1. Transient errors (throttling / 5xx) are not cached for the rest of the scan by
   getSubnetRouting, Ec2.getOrgContext, Ec2Instance.getImageInfo and
   Ec2ElbCommon._getTrustStore; non-transient errors (AccessDenied) still are.
2. naclAllowAllIngress: a narrow deny rule before an allow-all rule is not a PASS.
3. ssmVpcEndpointsMissing: isolated instances whose SSM Agent is Online (centralized
   endpoints in a hub VPC) are not a FAIL when 'ssm' has no in-VPC endpoint; Online
   never proves ssmmessages (INFO when it is also missing, FAIL when only it is).
4. selfManagedDataStoreOnEc2: unreadable security groups -> 'Unable to evaluate';
   an SSM lookup failure is not reported as 'not SSM-managed'.
5. selfManagedDataStoreOnEc2 pages the whole AWS:Application inventory (locked:
   a server package on a later page must still be found).

Every client is a real botocore client wrapped by botocore.stub.Stubber, pointed at an
unroutable loopback endpoint with dummy credentials: no request can leave the process.
"""
import datetime as _dt
import os
import sys
import types

import botocore.session
import pytest
from botocore.stub import Stubber

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.ec2.acctCache import acctKey  # noqa: E402
from services.ec2.Ec2 import Ec2  # noqa: E402
from services.ec2.drivers.Ec2NetworkInterface import getSubnetRouting  # noqa: E402
from services.ec2.drivers.Ec2Instance import Ec2Instance  # noqa: E402
from services.ec2.drivers.Ec2ElbCommon import Ec2ElbCommon  # noqa: E402
from services.ec2.drivers.Ec2NACL import Ec2NACL  # noqa: E402
from services.ec2.drivers.Ec2Vpc import Ec2Vpc  # noqa: E402
from services.ec2.drivers.Ec2SSM import Ec2SSM  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

SELF = '111111111111'
IID = 'i-0123456789abcdef0'


def _client(service):
    return botocore.session.get_session().create_client(
        service, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
        aws_access_key_id='testing', aws_secret_access_key='testing')


def _run(driver, method):
    getattr(driver, method)()
    return driver.results


@pytest.fixture(autouse=True)
def _account():
    Config.set('stsInfo', {'Account': SELF})
    yield


# --------------------------------------------------------------------------- #
# 1. transient errors are not cached
# --------------------------------------------------------------------------- #
ROUTING_KEY = 'ec2::subnetRouting::us-east-1'
_RT = {'RouteTableId': 'rtb-1', 'VpcId': 'vpc-1', 'Routes': [],
       'Associations': [{'RouteTableAssociationId': 'rtbassoc-1', 'RouteTableId': 'rtb-1', 'Main': True,
                         'AssociationState': {'State': 'associated'}}]}


@pytest.fixture
def routingKey():
    Config.set(acctKey(ROUTING_KEY), None)
    yield
    Config.set(acctKey(ROUTING_KEY), None)


def test_subnet_routing_throttle_not_cached(routingKey):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_client_error('describe_route_tables', service_error_code='RequestLimitExceeded', http_status_code=503)
        first = getSubnetRouting(ec2)
        st.add_response('describe_route_tables', {'RouteTables': [_RT]})
        st.add_response('describe_subnets', {'Subnets': [{'SubnetId': 'subnet-a', 'VpcId': 'vpc-1'}]})
        second = getSubnetRouting(ec2)       # retried, not the cached throttle
        st.assert_no_pending_responses()
    assert first['error'] == 'RequestLimitExceeded'
    assert second['error'] is None and second['subnets']['subnet-a']['routeTableId'] == 'rtb-1'


def test_subnet_routing_access_denied_cached(routingKey):
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_client_error('describe_route_tables', service_error_code='UnauthorizedOperation', http_status_code=403)
        first = getSubnetRouting(ec2)
        second = getSubnetRouting(ec2)       # no second API call: denial is cached
        st.assert_no_pending_responses()
    assert first['error'] == second['error'] == 'UnauthorizedOperation'


@pytest.fixture
def orgKey():
    Config.set(acctKey('ec2::orgContext'), None)
    yield
    Config.set(acctKey('ec2::orgContext'), None)


def _org(stubs):
    org = _client('organizations')
    out = []
    with Stubber(org) as st:
        for batch in stubs:
            for kind, op, arg in batch:
                if kind == 'err':
                    st.add_client_error(op, service_error_code=arg, http_status_code=400 if 'Denied' in arg else 500)
                else:
                    st.add_response(op, arg)
            out.append(Ec2.getOrgContext(types.SimpleNamespace(orgClient=org)))
        st.assert_no_pending_responses()
    return out


ORG_OK = ('ok', 'describe_organization', {'Organization': {'Id': 'o-abc123defg', 'FeatureSet': 'ALL'}})
ACCTS_OK = ('ok', 'list_accounts', {'Accounts': [{'Id': SELF}]})


def test_org_context_throttle_not_cached(orgKey):
    a, b = _org([[('err', 'describe_organization', 'TooManyRequestsException')], [ORG_OK, ACCTS_OK]])
    assert a['error'] == 'TooManyRequestsException'
    assert b['inOrg'] is True and SELF in b['accounts']


def test_org_context_list_accounts_throttle_not_cached(orgKey):
    a, b = _org([[ORG_OK, ('err', 'list_accounts', 'TooManyRequestsException')], [ORG_OK, ACCTS_OK]])
    assert a['accountsError'] == 'TooManyRequestsException'
    assert not b.get('accountsError') and SELF in b['accounts']


def test_org_context_access_denied_cached(orgKey):
    a, b = _org([[ORG_OK, ('err', 'list_accounts', 'AccessDeniedException')], []])
    assert a['accountsError'] == b['accountsError'] == 'AccessDeniedException'


def _instance(imageId):
    return {'InstanceId': IID, 'ImageId': imageId, 'InstanceType': 't3.micro', 'State': {'Name': 'running'},
            'LaunchTime': _dt.datetime.now(_dt.timezone.utc)}


def _resetImage(imageId):
    for k in ('ec2::image::' + imageId, 'ec2::imagestatus::' + imageId):
        Config.set(acctKey(k), '__unset__')


def test_image_info_throttle_not_cached():
    imageId = 'ami-0low000000000001'
    _resetImage(imageId)
    params = {'ImageIds': [imageId], 'IncludeDeprecated': True, 'IncludeDisabled': True}
    ec2 = _client('ec2')
    try:
        with Stubber(ec2) as st:
            st.add_client_error('describe_images', service_error_code='RequestLimitExceeded',
                                http_status_code=503, expected_params=params)
            first = Ec2Instance(_instance(imageId), ec2, None)
            st.add_response('describe_images', {'Images': [{'ImageId': imageId, 'OwnerId': SELF, 'State': 'available'}]}, params)
            second = Ec2Instance(_instance(imageId), ec2, None)      # retried
            st.assert_no_pending_responses()
    finally:
        _resetImage(imageId)
    assert first.ec2ImageStatus == 'error:RequestLimitExceeded'
    assert second.ec2ImageStatus == 'found'


def test_image_info_access_denied_cached():
    imageId = 'ami-0low000000000002'
    _resetImage(imageId)
    ec2 = _client('ec2')
    try:
        with Stubber(ec2) as st:
            st.add_client_error('describe_images', service_error_code='UnauthorizedOperation', http_status_code=403)
            first = Ec2Instance(_instance(imageId), ec2, None)
            second = Ec2Instance(_instance(imageId), ec2, None)      # cached, no API call
            st.assert_no_pending_responses()
    finally:
        _resetImage(imageId)
    assert first.ec2ImageStatus == second.ec2ImageStatus == 'error:UnauthorizedOperation'


TS_ARN = 'arn:aws:elasticloadbalancing:us-east-1:111111111111:truststore/ts/0123456789abcdef'
ALB = {'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a/1',
       'LoadBalancerName': 'a', 'Type': 'application', 'Scheme': 'internal'}


def test_trust_store_throttle_not_cached():
    key = acctKey('ec2::elbv2TrustStores::us-east-1')
    Config.set(key, None)
    elbv2 = _client('elbv2')
    try:
        with Stubber(elbv2) as st:
            d = Ec2ElbCommon(ALB, [], elbv2, None)
            st.add_client_error('describe_trust_stores', service_error_code='Throttling', http_status_code=400)
            first = d._getTrustStore(TS_ARN)
            st.add_response('describe_trust_stores', {'TrustStores': [{'TrustStoreArn': TS_ARN, 'Status': 'ACTIVE'}]},
                            {'TrustStoreArns': [TS_ARN]})
            second = d._getTrustStore(TS_ARN)
            st.assert_no_pending_responses()
    finally:
        Config.set(key, None)
    assert first == {'_error': 'Throttling'}
    assert second.get('Status') == 'ACTIVE'


# --------------------------------------------------------------------------- #
# 2. naclAllowAllIngress
# --------------------------------------------------------------------------- #
def _entry(num, action, proto='-1', cidr='0.0.0.0/0', v6=False):
    e = {'RuleNumber': num, 'RuleAction': action, 'Protocol': proto, 'Egress': False}
    e['Ipv6CidrBlock' if v6 else 'CidrBlock'] = cidr
    return e


IMPLICIT = [_entry(32767, 'deny'), _entry(32768, 'deny', cidr='::/0', v6=True)]


def _nacl(entries, default=False):
    nacl = {'NetworkAclId': 'acl-1', 'IsDefault': default, 'Entries': entries + IMPLICIT,
            'Associations': [{'SubnetId': 'subnet-a'}]}
    return _run(Ec2NACL(nacl, None), '_checkNaclAllowAllIngress')['naclAllowAllIngress']


def test_nacl_narrow_deny_before_allow_all_not_pass():
    # finding scenario: deny tcp 22 from one host, then allow all from the internet
    res = _nacl([_entry(50, 'deny', proto='6', cidr='203.0.113.7/32'), _entry(100, 'allow')])
    assert res[0] == 0 and 'rule 100' in res[1] and '50' in res[1]
    # deny of one protocol from everywhere is still narrow (all other protocols allowed)
    assert _nacl([_entry(50, 'deny', proto='6'), _entry(100, 'allow')])[0] == 0
    # deny of all protocols from one range is narrow too
    assert _nacl([_entry(50, 'deny', cidr='198.51.100.0/24'), _entry(100, 'allow')])[0] == 0


def test_nacl_full_deny_before_allow_all_passes():
    assert _nacl([_entry(50, 'deny'), _entry(100, 'allow')])[0] == 1
    assert _nacl([_entry(50, 'deny', cidr='::/0', v6=True), _entry(100, 'allow', cidr='::/0', v6=True)])[0] == 1


def test_nacl_split_denies_covering_family_pass():
    # all-protocol denies 0.0.0.0/1 + 128.0.0.0/1 together deny all IPv4 before the allow-all
    assert _nacl([_entry(50, 'deny', cidr='0.0.0.0/1'), _entry(51, 'deny', cidr='128.0.0.0/1'),
                  _entry(100, 'allow')])[0] == 1
    assert _nacl([_entry(50, 'deny', cidr='::/1', v6=True), _entry(51, 'deny', cidr='8000::/1', v6=True),
                  _entry(100, 'allow', cidr='::/0', v6=True)])[0] == 1
    # a gap in coverage keeps it INFO
    assert _nacl([_entry(50, 'deny', cidr='0.0.0.0/1'), _entry(51, 'deny', cidr='128.0.0.0/2'),
                  _entry(100, 'allow')])[0] == 0
    # one half denied for one protocol only does not complete coverage
    assert _nacl([_entry(50, 'deny', cidr='0.0.0.0/1'), _entry(51, 'deny', proto='6', cidr='128.0.0.0/1'),
                  _entry(100, 'allow')])[0] == 0
    # coverage completed only after the allow-all does not count
    assert _nacl([_entry(50, 'deny', cidr='0.0.0.0/1'), _entry(100, 'allow'),
                  _entry(150, 'deny', cidr='128.0.0.0/1')])[0] == 0


def test_nacl_mixed_families():
    # IPv4: allow-all behind a narrow deny; IPv6: unfiltered -> FAIL listing the open family
    res = _nacl([_entry(50, 'deny', proto='6'), _entry(100, 'allow'), _entry(101, 'allow', cidr='::/0', v6=True)])
    assert res[0] == -1 and 'rule 101 allows all traffic from ::/0 with no preceding deny rule' in res[1]
    assert 'rule 100 allows all traffic from 0.0.0.0/0 behind only narrow deny rule(s) 50' in res[1]
    # unchanged: plain allow-all fails, narrow allows pass, default NACL INFO
    assert _nacl([_entry(100, 'allow')])[0] == -1
    assert _nacl([_entry(100, 'allow', proto='6')])[0] == 1
    assert _nacl([_entry(50, 'deny', proto='6'), _entry(100, 'allow')], default=True)[0] == 0


# --------------------------------------------------------------------------- #
# 3. ssmVpcEndpointsMissing with centralized endpoints
# --------------------------------------------------------------------------- #
def _isolatedRouting():
    return {'error': None, 'subnets': {'subnet-a': {'routeTableId': 'rtb-1', 'igwRoutes': [], 'defaultRoutes': []}},
            'subnetVpc': {'subnet-a': 'vpc-1'}}


def _iface(svc, dns=True):
    return {'VpcEndpointId': f'vpce-{svc}', 'VpcId': 'vpc-1', 'VpcEndpointType': 'Interface',
            'State': 'available', 'ServiceName': f'com.amazonaws.us-east-1.{svc}', 'PrivateDnsEnabled': dns}


def _ssmEp(ping, endpoints=()):
    inst = [{'InstanceId': IID, 'VpcId': 'vpc-1', 'SubnetId': 'subnet-a', 'State': {'Name': 'running'}},
            {'InstanceId': 'i-0second0000000000', 'VpcId': 'vpc-1', 'SubnetId': 'subnet-a', 'State': {'Name': 'running'}}]
    obj = Ec2Vpc({'VpcId': 'vpc-1', 'OwnerId': SELF}, [], None, _isolatedRouting(), list(endpoints), None, SELF, inst,
                 None, ping)
    return _run(obj, '_checkSsmVpcEndpointsMissing')['ssmVpcEndpointsMissing']


ALL_ONLINE = {IID: 'Online', 'i-0second0000000000': 'Online'}


def test_ssm_endpoints_centralized_all_online_ssmmessages_unproven_info():
    # no in-VPC ssm nor ssmmessages: Online proves ssm only -> INFO, never PASS
    res = _ssmEp(ALL_ONLINE)
    assert res[0] == 0 and 'centralized' in res[1] and 'not proven' in res[1]


def test_ssm_endpoints_centralized_ssm_only_missing_all_online_pass():
    # ssmmessages present in-VPC, ssm missing but agents Online -> ssm reachable another way
    res = _ssmEp(ALL_ONLINE, [_iface('ssmmessages'), _iface('ec2messages')])
    assert res[0] == 1 and 'centralized' in res[1]


def test_ssm_endpoints_only_ssmmessages_missing_online_still_fails():
    # review repro: in-VPC ssm (private DNS) + ec2messages, no ssmmessages anywhere,
    # agents Online through the in-VPC ssm endpoint -> Session Manager broken -> FAIL
    res = _ssmEp(ALL_ONLINE, [_iface('ssm'), _iface('ec2messages')])
    assert res[0] == -1 and 'ssmmessages' in res[1] and 'centralized' not in res[1]
    res = _ssmEp({IID: 'Online', 'i-0second0000000000': 'ConnectionLost'}, [_iface('ssm')])
    assert res[0] == -1 and 'centralized' not in res[1]


def test_ssm_endpoints_centralized_partially_online_info():
    res = _ssmEp({IID: 'Online', 'i-0second0000000000': 'ConnectionLost'})
    assert res[0] == 0 and 'i-0second0000000000' in res[1]


def test_ssm_endpoints_missing_still_fails_without_online_agents():
    assert _ssmEp(None)[0] == -1                                   # SSM not readable: endpoint evidence stands
    assert _ssmEp({})[0] == -1                                     # not SSM-managed
    assert _ssmEp({IID: 'ConnectionLost'})[0] == -1


# --------------------------------------------------------------------------- #
# 4 / 5. selfManagedDataStoreOnEc2
# --------------------------------------------------------------------------- #
PG = {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}
SG = {'GroupId': 'sg-1', 'IpPermissions': [PG]}
RUNNING = {'InstanceId': IID, 'State': {'Name': 'running'}}


def test_datastore_security_groups_unreadable_not_silent():
    obj = Ec2SSM(IID, set(), RUNNING, None, {}, None, {}, None, 'UnauthorizedOperation')
    assert _run(obj, '_checkSelfManagedDataStoreOnEc2')['selfManagedDataStoreOnEc2'] == \
        [0, 'Unable to evaluate (UnauthorizedOperation)']
    obj = Ec2SSM(IID, set(), RUNNING, None, {}, None, {}, None)
    assert _run(obj, '_checkSelfManagedDataStoreOnEc2')['selfManagedDataStoreOnEc2'][0] == 0


def test_instance_security_groups_error_code_returned_not_shared():
    def denied():
        raise botocore.exceptions.ClientError({'Error': {'Code': 'UnauthorizedOperation'}}, 'DescribeSecurityGroups')
    ns = types.SimpleNamespace(_getAllSecurityGroupsCached=denied)
    assert Ec2.getInstanceAllSecurityGroups(ns, {'SecurityGroups': [{'GroupId': 'sg-1'}]}) == \
        (None, 'UnauthorizedOperation')
    assert not hasattr(ns, 'instanceSgError')          # no per-instance state on the shared object
    ns = types.SimpleNamespace(_getAllSecurityGroupsCached=lambda: {'sg-1': SG})
    assert Ec2.getInstanceAllSecurityGroups(ns, {'SecurityGroups': [{'GroupId': 'sg-1'}]}) == ([SG], None)


def test_datastore_ssm_lookup_failed_message():
    obj = Ec2SSM(IID, None, RUNNING, 'AccessDeniedException', {}, None, {}, [SG])
    res = _run(obj, '_checkSelfManagedDataStoreOnEc2')['selfManagedDataStoreOnEc2']
    assert res[0] == -1 and 'AccessDeniedException' in res[1] and 'not SSM-managed' not in res[1]
    obj = Ec2SSM(IID, set(), RUNNING, None, {}, None, {}, [SG])     # genuinely not managed
    assert 'instance not SSM-managed' in _run(obj, '_checkSelfManagedDataStoreOnEc2')['selfManagedDataStoreOnEc2'][1]


def test_datastore_inventory_paged_in_full():
    """Locked: no server-side filter, so a server package on a later page is still found."""
    ssm = _client('ssm')
    base = {'InstanceId': IID, 'TypeName': 'AWS:Application', 'MaxResults': 50}
    with Stubber(ssm) as st:
        st.add_response('list_inventory_entries', {'TypeName': 'AWS:Application', 'InstanceId': IID,
                                                   'Entries': [{'Name': 'bash'}], 'NextToken': 't1'}, base)
        st.add_response('list_inventory_entries', {'TypeName': 'AWS:Application', 'InstanceId': IID,
                                                   'Entries': [{'Name': 'MySQL-server'}]}, dict(base, NextToken='t1'))
        obj = Ec2SSM(IID, {IID}, RUNNING, None, {IID: 'Online'}, ssm, {IID: 'Linux'}, [])
        res = _run(obj, '_checkSelfManagedDataStoreOnEc2')['selfManagedDataStoreOnEc2']
        st.assert_no_pending_responses()
    assert res[0] == -1 and 'MySQL-server' in res[1]
