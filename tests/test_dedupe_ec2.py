"""EC2 drivers read each piece of AWS data once.

Per driver instance (_memo):
  Ec2EbsSnapshot   describe_snapshot_tier_status (3 archive checks)
  Ec2Regional      compute-optimizer get_recommendation_preferences(Ec2Instance)
  Ec2ElbClassic    describe_load_balancer_attributes
  Ec2ElbCommon     describe_listeners (paginated), describe_load_balancer_attributes
  Ec2Instance      get_metric_statistics(CPUUtilization, 14d, Average) (low + high util),
                   describe_instance_types(own type) (EBS-optimized + instance store, concurrent)
Per scan (_sharedMemo, keyed by region):
  describe_snapshots(OwnerIds=['self'])    Ec2EbsSnapshot (4 checks) + Ec2Regional quotas
  get_enrollment_status                    Ec2Regional (3 checks) + Ec2CompOpt
  describe_snapshots(volume-id=...)        Ec2EbsVolume + Ec2Instance (root volume)
  elb describe_load_balancers()            every Ec2AutoScaling
  describe_launch_template_versions / describe_images(ImageIds=[ami])  ASGs sharing them
Service (Ec2.advise):
  getChartGenCost (Cost Explorer + describe_instance_types) runs once, not twice
  vpcPeeringFullRoute reuses the route tables getSubnetRouting already read

Each Stubber gets exactly one queued response per de-duplicated call, so a
repeated call fails (StubResponseError), while every check keeps its result.
Clients point at an unroutable loopback endpoint with dummy credentials.
"""
import datetime as _dt
import os
import sys
import threading
from unittest import mock

import botocore.exceptions
import botocore.session
import pytest
from botocore.stub import Stubber, ANY

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.Config import Config  # noqa: E402
from services.ec2.acctCache import acctKey  # noqa: E402
from services.Evaluator import Evaluator  # noqa: E402
from services.ec2.Ec2 import Ec2  # noqa: E402
from services.ec2.drivers.Ec2EbsSnapshot import Ec2EbsSnapshot  # noqa: E402
from services.ec2.drivers.Ec2Regional import Ec2Regional  # noqa: E402
from services.ec2.drivers.Ec2CompOpt import Ec2CompOpt  # noqa: E402
from services.ec2.drivers.Ec2AutoScaling import Ec2AutoScaling  # noqa: E402
from services.ec2.drivers.Ec2ElbClassic import Ec2ElbClassic  # noqa: E402
from services.ec2.drivers.Ec2ElbCommon import Ec2ElbCommon  # noqa: E402
from services.ec2.drivers.Ec2EbsVolume import Ec2EbsVolume  # noqa: E402
from services.ec2.drivers.Ec2Instance import Ec2Instance  # noqa: E402
from services.ec2.drivers.Ec2Vpc import getPeerRouteContext  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

NOW = _dt.datetime.now(_dt.timezone.utc)


@pytest.fixture(autouse=True)
def _freshConfig():
    Config.init()
    Config.set('stsInfo', {'Account': '111111111111'})
    yield
    Config.init()


def _client(service):
    return botocore.session.get_session().create_client(
        service, region_name='us-east-1', endpoint_url='https://127.0.0.1:1',
        aws_access_key_id='testing', aws_secret_access_key='testing')


# --------------------------------------------------------------------------- #
# Ec2EbsSnapshot + Ec2Regional: describe_snapshots(self) / tier status
# --------------------------------------------------------------------------- #
SNAPS = {'Snapshots': [
    {'SnapshotId': 'snap-1', 'VolumeId': 'vol-gone', 'StartTime': NOW - _dt.timedelta(days=400), 'State': 'completed'},
    {'SnapshotId': 'snap-2', 'VolumeId': 'vol-gone', 'StartTime': NOW - _dt.timedelta(days=1), 'State': 'completed'},
    {'SnapshotId': 'snap-3', 'VolumeId': 'vol-live', 'StartTime': NOW - _dt.timedelta(days=2), 'State': 'completed'},
]}
TIERS = {'SnapshotTierStatuses': [
    {'SnapshotId': 'snap-1', 'StorageTier': 'archive'},
    {'SnapshotId': 'snap-2', 'StorageTier': 'archive'},
    {'SnapshotId': 'snap-3', 'StorageTier': 'standard'},
]}
SNAP_CHECKS = ['_checkDeletedVolumeSnapshotList', '_checkEBSSnapshotFirstArchived',
               '_checkEBSSnapshotLatestArchived', '_checkEBSSnapshotComplianceArchive']


def test_snapshot_listing_and_tier_status_read_once_and_shared_with_regional():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_snapshots', SNAPS, {'OwnerIds': ['self']})
        st.add_response('describe_snapshot_tier_status', TIERS,
                        {'Filters': [{'Name': 'snapshot-id', 'Values': ['snap-1', 'snap-2', 'snap-3']}]})
        d = Ec2EbsSnapshot(['vol-live'], ec2)
        for m in SNAP_CHECKS:
            getattr(d, m)()
        # Ec2Regional quota check: same describe_snapshots(OwnerIds=['self']) - not called again
        st.add_response('describe_account_attributes', {'AccountAttributes': []}, {})
        st.add_response('describe_instances', {'Reservations': []}, {})
        st.add_response('describe_volumes', {'Volumes': []}, {})
        Ec2Regional(ec2)._checkEC2ServiceQuotas()
        st.assert_no_pending_responses()
    assert d.results['EBSSnapshotDeletedVolume'] == [-1, 'snap-1, snap-2']
    assert d.results['EBSSnapshotFirstArchived'] == [-1, 'snap-1']
    assert d.results['EBSSnapshotLatestArchived'][0] == -1 and 'snap-2' in d.results['EBSSnapshotLatestArchived'][1]


def test_snapshot_listing_error_cached_and_handled_by_each_check():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_client_error('describe_snapshots', service_error_code='UnauthorizedOperation', http_status_code=403)
        d = Ec2EbsSnapshot([], ec2)
        with pytest.raises(botocore.exceptions.ClientError):   # unhandled here, as before
            d._checkDeletedVolumeSnapshotList()
        for m in SNAP_CHECKS[1:]:                              # these swallow errors, as before
            getattr(d, m)()
        st.assert_no_pending_responses()
    assert d.results == {}


# --------------------------------------------------------------------------- #
# Ec2Regional + Ec2CompOpt: Compute Optimizer
# --------------------------------------------------------------------------- #
def test_compute_optimizer_enrollment_and_preferences_read_once():
    co = _client('compute-optimizer')
    with Stubber(co) as st:
        st.add_response('get_enrollment_status', {'status': 'Active'}, {})
        st.add_response('get_recommendation_preferences', {'recommendationPreferencesDetails': []},
                        {'resourceType': 'Ec2Instance'})
        st.add_response('describe_recommendation_export_jobs', {'recommendationExportJobs': []}, {})
        r = Ec2Regional(_client('ec2'), co)
        r._checkComputeOptimizerEnhancedMetrics()
        r._checkComputeOptimizerRightsizingPrefs()
        r._checkComputeOptimizerExportRecommendations()
        c = Ec2CompOpt(co)
        c._checkComputeOptimizerEnabled()
        st.assert_no_pending_responses()
    assert r.results['ComputeOptimizerRightsizingPrefs'] == [-1, 'Default preferences']
    assert r.results['ComputeOptimizerExportRecommendations'] == [-1, 'No export jobs']
    assert 'ComputeOptimizerEnhancedMetrics' in r.results
    assert 'ComputeOptimizerEnabled' not in c.results


def test_compute_optimizer_inactive_shared_with_comp_opt_driver():
    co = _client('compute-optimizer')
    with Stubber(co) as st:
        st.add_response('get_enrollment_status', {'status': 'Inactive'}, {})
        r = Ec2Regional(_client('ec2'), co)
        r._checkComputeOptimizerEnhancedMetrics()
        r._checkComputeOptimizerRightsizingPrefs()
        r._checkComputeOptimizerExportRecommendations()
        c = Ec2CompOpt(co)
        c._checkComputeOptimizerEnabled()
        st.assert_no_pending_responses()
    assert r.results == {}
    assert c.results['ComputeOptimizerEnabled'] == [-1, 'Inactive']


# --------------------------------------------------------------------------- #
# Ec2AutoScaling: region-level reads shared across ASGs
# --------------------------------------------------------------------------- #
def _asg(name, lbs=(), template=None):
    a = {'AutoScalingGroupName': name, 'LoadBalancerNames': list(lbs), 'TargetGroupARNs': [],
         'AvailabilityZones': ['us-east-1a']}
    if template:
        a['MixedInstancesPolicy'] = {'LaunchTemplate': {'LaunchTemplateSpecification': {
            'LaunchTemplateId': template, 'Version': '$Latest'}}}
    return a


def test_asg_classic_lbs_template_and_image_read_once_per_scan():
    clb, ec2 = _client('elb'), _client('ec2')
    asgc, elbv2 = _client('autoscaling'), _client('elbv2')
    with Stubber(clb) as sc, Stubber(ec2) as se:
        sc.add_response('describe_load_balancers', {'LoadBalancerDescriptions': [{'LoadBalancerName': 'clb-a'}]}, {})
        se.add_response('describe_launch_template_versions', {'LaunchTemplateVersions': [
            {'LaunchTemplateData': {'ImageId': 'ami-0123456789abcdef0',
                                    'MetadataOptions': {'HttpTokens': 'optional'}}}]},
            {'LaunchTemplateId': 'lt-1', 'Versions': ['$Latest']})
        se.add_client_error('describe_images', service_error_code='InvalidAMIID.NotFound', http_status_code=400,
                            expected_params={'ImageIds': ['ami-0123456789abcdef0']})
        out = []
        for name, lbs in (('asg-1', ['clb-a']), ('asg-2', ['clb-missing'])):
            d = Ec2AutoScaling(_asg(name, lbs, 'lt-1'), asgc, elbv2, clb, ec2)
            d._checkClassicLBAssociation()
            d._checkAMIExist()
            out.append(d.results)
        sc.assert_no_pending_responses()
        se.assert_no_pending_responses()
    assert 'ASGClassicLBExist' not in out[0]
    assert out[1]['ASGClassicLBExist'] == [-1, ['clb-missing']]
    for res in out:     # cached NotFound error still reaches the except block of each ASG
        assert res['ASGAMIExist'] == [-1, 'ami-0123456789abcdef0']
        assert res['ASGIMDSv2'] == [-1, 'Optional']


# --------------------------------------------------------------------------- #
# ELB attributes / listeners per load balancer
# --------------------------------------------------------------------------- #
def test_clb_attributes_read_once_for_both_checks():
    elb = _client('elb')
    lb = {'LoadBalancerName': 'clb1', 'ListenerDescriptions': [], 'SecurityGroups': []}
    with Stubber(elb) as st:
        st.add_response('describe_load_balancer_attributes', {'LoadBalancerAttributes': {
            'CrossZoneLoadBalancing': {'Enabled': False}, 'AccessLog': {'Enabled': False},
            'ConnectionDraining': {'Enabled': True}}}, {'LoadBalancerName': 'clb1'})
        d = Ec2ElbClassic(lb, elb)
        d._checkAttributes()
        d._checkElbAccessLogsDisabled()
        st.assert_no_pending_responses()
    assert d.results['ELBCrossZone'] == ['-1', False]
    assert d.results['elbAccessLogsDisabled'] == [-1, 'Disabled']


def test_clb_attributes_error_cached_and_reraised():
    elb = _client('elb')
    lb = {'LoadBalancerName': 'clb1', 'ListenerDescriptions': [], 'SecurityGroups': []}
    with Stubber(elb) as st:
        st.add_client_error('describe_load_balancer_attributes', service_error_code='AccessDenied',
                            http_status_code=403)
        d = Ec2ElbClassic(lb, elb)
        d._checkElbAccessLogsDisabled()
        with pytest.raises(botocore.exceptions.ClientError):
            d._checkAttributes()
        st.assert_no_pending_responses()
    assert d.results['elbAccessLogsDisabled'] == [0, 'Unable to evaluate (AccessDenied)']


def test_elbv2_listeners_and_attributes_read_once_concurrently():
    elbv2 = _client('elbv2')
    arn = 'arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/a1/abc'
    lb = {'LoadBalancerArn': arn, 'LoadBalancerName': 'a1', 'Type': 'application', 'SecurityGroups': []}
    with Stubber(elbv2) as st:
        st.add_response('describe_listeners', {'Listeners': [
            {'ListenerArn': arn.replace('loadbalancer', 'listener') + '/l1', 'Port': 80, 'Protocol': 'HTTP'}]},
            {'LoadBalancerArn': arn})
        st.add_response('describe_load_balancer_attributes', {'Attributes': [
            {'Key': 'access_logs.s3.enabled', 'Value': 'false'},
            {'Key': 'load_balancing.cross_zone.enabled', 'Value': 'false'}]}, {'LoadBalancerArn': arn})
        d = Ec2ElbCommon(lb, [], elbv2, None)
        # listeners first (one thread each), then attributes - Stubber needs this response order
        for group in (('_checkListenerPortEncrypt', '_checkElbTlsPolicyOutdated', '_checkAlbMtlsOff',
                       '_checkElbUsesIamOrImportedCert'),
                      ('_checkCrossZoneLB', '_checkElbAccessLogsDisabled')):
            ts = [threading.Thread(target=getattr(d, m)) for m in group]
            [t.start() for t in ts]
            [t.join() for t in ts]
        st.assert_no_pending_responses()
    assert d.results['ELBListenerInsecure'] == [-1, 80]
    assert d.results['ELBCrossZone'] == [-1, 'Disabled']
    assert d.results['elbAccessLogsDisabled'] == [-1, 'Disabled']


# --------------------------------------------------------------------------- #
# Ec2Instance / Ec2EbsVolume
# --------------------------------------------------------------------------- #
def _instance(**extra):
    d = {'InstanceId': 'i-0123456789abcdef0', 'ImageId': 'ami-1', 'InstanceType': 'm5d.large',
         'State': {'Name': 'running'}, 'LaunchTime': NOW - _dt.timedelta(days=30)}
    d.update(extra)
    return d


def _newInstance(ec2, cw, **extra):
    Config.set(acctKey('ec2::image::ami-1'), None)           # image lookup cached: no describe_images
    Config.set(acctKey('ec2::imagestatus::ami-1'), 'missing')
    return Ec2Instance(_instance(**extra), ec2, cw)


def _points(value, n=14):
    return {'Datapoints': [{'Average': value, 'Timestamp': NOW - _dt.timedelta(days=i)} for i in range(n)]}


def _metricParams(name, stats=('Average',)):
    return {'Dimensions': [{'Name': 'InstanceId', 'Value': 'i-0123456789abcdef0'}], 'Namespace': 'AWS/EC2',
            'MetricName': name, 'StartTime': ANY, 'EndTime': ANY, 'Period': 86400, 'Statistics': list(stats)}


@pytest.mark.parametrize('cpu,low,high', [(5, True, False), (95, False, True)])
def test_cpu_metric_read_once_for_low_and_high_utilization(cpu, low, high):
    cw = _client('cloudwatch')
    with Stubber(cw) as st:
        st.add_response('get_metric_statistics', _points(cpu), _metricParams('CPUUtilization'))
        if low:
            st.add_response('get_metric_statistics', _points(1), _metricParams('NetworkOut'))
            st.add_response('get_metric_statistics', _points(1), _metricParams('NetworkIn'))
        d = _newInstance(_client('ec2'), cw)
        d._checkEC2LowUtilization()
        d._checkEC2HighUtilization()
        # spiky uses Average+Maximum: a different request, still made
        st.add_response('get_metric_statistics', {'Datapoints': []},
                        _metricParams('CPUUtilization', ('Average', 'Maximum')))
        d._checkEC2SpikyUtilization()
        st.assert_no_pending_responses()
    assert ('EC2LowUtilization' in d.results) is low
    assert ('EC2HighUtilization' in d.results) is high


def test_instance_type_read_once_by_concurrent_checks():
    ec2 = _client('ec2')
    with Stubber(ec2) as st:
        st.add_response('describe_instance_types', {'InstanceTypes': [{
            'InstanceType': 'm5d.large', 'EbsInfo': {'EbsOptimizedSupport': 'default'},
            'InstanceStorageInfo': {'TotalSizeInGB': 75}}]}, {'InstanceTypes': ['m5d.large']})
        d = _newInstance(ec2, None, EbsOptimized=False,
                         BlockDeviceMappings=[{'DeviceName': '/dev/xvda', 'Ebs': {'VolumeId': 'vol-1'}}])
        gate = threading.Barrier(2)
        ts = [threading.Thread(target=lambda m=m: (gate.wait(), getattr(d, m)()))
              for m in ('_checkEC2EbsOptimized', '_checkInstanceStoreUsage')]
        with mock.patch.object(d, '_fetchInstanceTypeInfo', side_effect=d._fetchInstanceTypeInfo) as f:
            [t.start() for t in ts]
            [t.join() for t in ts]
        st.assert_no_pending_responses()
    assert f.call_count == 1
    # an extra call would hit the empty Stubber and the checks would swallow the error
    assert d.results['EC2EbsOptimized'] == [-1, 'm5d.large']
    assert d.results['EC2InstanceStoreUsage'] == [-1, '75GB available']


def test_volume_snapshots_shared_by_ebs_volume_and_instance_root_volume():
    ec2 = _client('ec2')
    snaps = {'Snapshots': [{'SnapshotId': 'snap-9', 'VolumeId': 'vol-1', 'State': 'completed',
                            'StartTime': NOW - _dt.timedelta(days=20)}]}
    with Stubber(ec2) as st:
        st.add_response('describe_snapshots', snaps, {'Filters': [{'Name': 'volume-id', 'Values': ['vol-1']}]})
        st.add_response('describe_fast_snapshot_restores', {'FastSnapshotRestores': []},
                        {'Filters': [{'Name': 'snapshot-id', 'Values': ['snap-9']}]})
        v = Ec2EbsVolume({'VolumeId': 'vol-1', 'CreateTime': NOW - _dt.timedelta(days=60), 'Attachments': [],
                          'VolumeType': 'gp3', 'Encrypted': True, 'State': 'in-use'}, ec2, None)
        v._checkSnapshot()
        i = _newInstance(ec2, None, RootDeviceName='/dev/xvda', BlockDeviceMappings=[
            {'DeviceName': '/dev/xvda', 'Ebs': {'VolumeId': 'vol-1', 'DeleteOnTermination': True}}])
        i._checkEC2RootVolumeImplications()
        st.assert_no_pending_responses()
    assert v.results['EBSUpToDateSnapshot'] == [-1, '']
    assert i.results['EC2RootVolumeImplications'] == [-1, 'vol-1']


# --------------------------------------------------------------------------- #
# Ec2.advise(): cost chart once, route tables reused for vpcPeeringFullRoute
# --------------------------------------------------------------------------- #
def _mockService(rules=()):
    svc = mock.MagicMock()
    svc._ruleSelected.side_effect = lambda r: r in rules
    for m in ('getResources', 'getEBSResources', 'getELB', 'getELBClassic', 'getASG', 'getEIPResources',
              'getVpcs', 'getNetworkACLs', 'getKeyPairs', 'getSelfImages', 'getLaunchTemplates',
              'getNetworkInterfaces'):
        getattr(svc, m).return_value = []
    svc.ec2Client.meta.region_name = 'us-east-1'
    return svc


def test_advise_generates_cost_chart_once():
    svc = _mockService()
    svc.getChartGenCost.return_value = {'t3': 1.0}
    with mock.patch.object(Evaluator, 'run', lambda *a, **k: None):
        Ec2.advise(svc)
    assert svc.getChartGenCost.call_count == 1
    svc.setChartData.assert_called_once_with({'EC2 Instance Family Pricing': {'t3': 1.0}})


@pytest.mark.parametrize('cached', [True, False])
def test_advise_peer_routing_reuses_subnet_routing_route_tables(cached):
    rts = [{'RouteTableId': 'rtb-1', 'VpcId': 'vpc-1', 'Routes': []}]
    if cached:   # getSubnetRouting already ran in this scan (e.g. for the instance checks)
        Config.set(acctKey('ec2::subnetRouting::us-east-1'), {'subnets': {}, 'subnetVpc': {}, 'error': None,
                                                       '_routeTables': rts})
    svc = _mockService(rules=('vpcPeeringFullRoute',))
    svc.getVpcs.return_value = [{'VpcId': 'vpc-1', 'CidrBlock': '10.0.0.0/16'}]
    with mock.patch.object(Evaluator, 'run', lambda *a, **k: None), \
            mock.patch('services.ec2.Ec2.getPeerRouteContext', return_value={}) as g:
        Ec2.advise(svc)
    assert g.call_count == 1
    assert g.call_args[0][2] == (rts if cached else None)


def test_peer_route_context_with_given_route_tables_skips_describe_route_tables():
    ec2 = _client('ec2')
    rts = [{'RouteTableId': 'rtb-1', 'VpcId': 'vpc-1',
            'Routes': [{'DestinationCidrBlock': '10.1.0.0/16', 'VpcPeeringConnectionId': 'pcx-1', 'State': 'active'}]}]
    pcx = {'VpcPeeringConnections': [{'VpcPeeringConnectionId': 'pcx-1', 'Status': {'Code': 'active'}}]}
    with Stubber(ec2) as st:
        st.add_response('describe_vpc_peering_connections', pcx, {})
        given = getPeerRouteContext(ec2, [], rts)
        st.assert_no_pending_responses()
    with Stubber(ec2) as st:
        st.add_response('describe_route_tables', {'RouteTables': rts}, {})
        st.add_response('describe_vpc_peering_connections', pcx, {})
        read = getPeerRouteContext(ec2, [], None)
        st.assert_no_pending_responses()
    assert given == read and given['routeTables'] == {'vpc-1': rts}

