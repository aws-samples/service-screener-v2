"""Flag -> fix -> re-run tests for services/arc (ARC Region switch / routing control)."""
import json
import time

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck

TRUST = json.dumps({'Version': '2012-10-17', 'Statement': [{
    'Effect': 'Allow', 'Principal': {'Service': 'arc-region-switch.amazonaws.com'},
    'Action': 'sts:AssumeRole'}]})


def _role(emu, uid):
    iam = emu.client('iam')
    name = f'ss-arc-{uid}'
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=TRUST)['Role']['Arn']
    return name, arn


def _createPlan(rs, name, roleArn):
    step = lambda n: [{'name': n, 'executionBlockType': 'ManualApproval',
                       'executionBlockConfiguration': {'executionApprovalConfig': {
                           'approvalRole': roleArn, 'timeoutMinutes': 60}}}]
    return rs.create_plan(
        name=name, executionRole=roleArn, regions=['us-east-1', 'us-west-2'],
        recoveryApproach='activePassive', primaryRegion='us-east-1',
        workflows=[
            {'workflowTargetAction': 'activate', 'workflowTargetRegion': 'us-west-2', 'steps': step('approve-activate')},
            {'workflowTargetAction': 'deactivate', 'workflowTargetRegion': 'us-east-1', 'steps': step('approve-deactivate')},
        ])['plan']['arn']


def _latencyZone(emu, uid):
    """Multi-Region evidence: Route 53 latency records for one name in two
    Regions. Returns a cleanup function."""
    r53 = emu.client('route53')
    zid = r53.create_hosted_zone(Name=f'ss-arc-{uid}.example.com', CallerReference=f'ss-arc-{uid}')['HostedZone']['Id']
    r53.change_resource_record_sets(HostedZoneId=zid, ChangeBatch={'Changes': [
        {'Action': 'CREATE', 'ResourceRecordSet': {
            'Name': f'api.ss-arc-{uid}.example.com', 'Type': 'CNAME', 'SetIdentifier': r, 'Region': r,
            'TTL': 60, 'ResourceRecords': [{'Value': f'app.{r}.example.net'}]}}
        for r in ('us-east-1', 'us-west-2')]})

    def cleanup():
        try:
            for rec in r53.list_resource_record_sets(HostedZoneId=zid)['ResourceRecordSets']:
                if rec['Type'] not in ('NS', 'SOA'):
                    r53.change_resource_record_sets(HostedZoneId=zid, ChangeBatch={'Changes': [
                        {'Action': 'DELETE', 'ResourceRecordSet': rec}]})
            r53.delete_hosted_zone(Id=zid)
        except Exception:
            pass
    return cleanup


def _deletePlans(rs, arns):
    for arn in arns:
        try:
            rs.delete_plan(arn=arn)
        except Exception:
            pass


def test_arc_region_switch_plan_missing(emu, uid):
    rs = emu.client('arc-region-switch')
    rc = emu.client('route53-recovery-control-config')
    if rs.list_plans().get('plans') or rc.list_clusters().get('Clusters'):
        pytest.skip('emulator already has ARC plans/clusters; account-level absence cannot be staged')
    roleName, roleArn = _role(emu, uid)
    created = {'plans': [], 'clusters': [], 'zone': None}
    try:
        def misconfigure():
            ## No plan and no cluster, plus a multi-Region workload (latency
            ## records in two Regions): only then is missing ARC a finding.
            created['zone'] = _latencyZone(emu, uid)

        def fixWithPlan():
            created['plans'].append(_createPlan(rs, f'ss-arc-{uid}', roleArn))

        assertFlagFixCycle(emu, 'arc', 'regionSwitchPlanMissing', 'Account', misconfigure, fixWithPlan)

        def removePlan():
            _deletePlans(rs, created['plans'])
            created['plans'].clear()

        def fixWithCluster():
            created['clusters'].append(rc.create_cluster(ClusterName=f'ss-arc-{uid}')['Cluster']['ClusterArn'])

        assertFlagFixCycle(emu, 'arc', 'regionSwitchPlanMissing', 'Account', removePlan, fixWithCluster)
    finally:
        if created['zone']:
            created['zone']()
        _deletePlans(rs, created['plans'])
        for arn in created['clusters']:
            try:
                rc.delete_cluster(ClusterArn=arn)
            except Exception:
                pass
        emu.client('iam').delete_role(RoleName=roleName)


def test_arc_region_switch_plan_missing_single_region_is_info(emu, uid):
    """Without multi-Region evidence the absence of ARC is informational, not
    a finding (informational by design: ARC Region switch only applies to
    multi-Region workloads)."""
    rs = emu.client('arc-region-switch')
    rc = emu.client('route53-recovery-control-config')
    if rs.list_plans().get('plans') or rc.list_clusters().get('Clusters'):
        pytest.skip('emulator already has ARC plans/clusters; account-level absence cannot be staged')
    res = runCheck(emu, 'arc', 'regionSwitchPlanMissing', 'Account')
    msgs = [m for r in res.results.values() for k, m in r.items() if k == 'regionSwitchPlanMissing']
    if msgs and 'multi-Region infrastructure' in msgs[0][1]:
        pytest.skip(f'emulator already holds multi-Region evidence: {msgs[0]}')
    assert res.statuses() and all(v == 0 for v in res.statuses().values()), (res.statuses(), msgs)
    assert 'no multi-Region workload evidence' in msgs[0][1], msgs
    cleanup = _latencyZone(emu, uid)
    try:
        assert all(v == -1 for v in runCheck(emu, 'arc', 'regionSwitchPlanMissing', 'Account').statuses().values())
    finally:
        cleanup()


def test_arc_region_switch_plan_never_executed(emu, uid):
    rs = emu.client('arc-region-switch')
    roleName, roleArn = _role(emu, uid)
    planName = f'ss-arc-{uid}'
    arns = []
    try:
        def misconfigure():
            arns.append(_createPlan(rs, planName, roleArn))

        def fix():
            ex = rs.start_plan_execution(planArn=arns[0], targetRegion='us-west-2',
                                         action='activate', mode='graceful')
            for _ in range(20):
                items = rs.list_plan_executions(planArn=arns[0]).get('items', [])
                states = {i['executionState'] for i in items}
                if 'completed' in states:
                    return
                if 'pendingManualApproval' in states:
                    rs.approve_plan_execution_step(planArn=arns[0], executionId=ex['executionId'],
                                                   stepName='approve-activate', approval='approve')
                time.sleep(0.5)
            raise AssertionError(f'execution did not complete: {states}')

        assertFlagFixCycle(emu, 'arc', 'regionSwitchPlanNeverExecuted', planName, misconfigure, fix)
    finally:
        _deletePlans(rs, arns)
        emu.client('iam').delete_role(RoleName=roleName)
