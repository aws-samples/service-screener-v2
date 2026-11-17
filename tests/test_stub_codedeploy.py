"""
Stubber tests for codedeploy.codedeployNoAutoRollback.

Why Stubber: the local AWS Emulator scaffolds but does not implement
batch_get_deployment_groups (NotImplemented), which is the scanner's primary
hydration call. The emulator tests cover the get_deployment_group fallback;
these tests drive the batch path, the fallback-on-error path and the
'Unable to evaluate' path with real boto3 clients wrapped in botocore Stubber
(real API shapes). No network calls are made.
"""
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.codedeploy.Codedeploy import Codedeploy  # noqa: E402
from services.codedeploy.drivers.CodedeployDeploymentGroup import CodedeployDeploymentGroup  # noqa: E402

KEY = 'codedeployNoAutoRollback'


def _client():
    return boto3.session.Session(
        aws_access_key_id='x', aws_secret_access_key='x', region_name='us-east-1'
    ).client('codedeploy')


class _Svc(Codedeploy):
    """Codedeploy without Service.__init__/__del__ (which bootstrap a scan and
    write run artefacts); only the hydration helpers are exercised."""
    def __del__(self):
        pass


def _svc(client):
    s = _Svc.__new__(_Svc)
    s.cdClient = client
    s.region = 'us-east-1'
    s.tags = []
    return s


def _info(name, rollback=None):
    i = {'applicationName': 'app', 'deploymentGroupName': name,
         'computePlatform': 'Server'}
    if rollback is not None:
        i['autoRollbackConfiguration'] = rollback
    return i


def _status(info):
    obj = CodedeployDeploymentGroup(info, None)
    obj._checkCodedeployNoAutoRollback()
    return obj.results[KEY]


def _hydrateBatch(rollback):
    cd = _client()
    st = Stubber(cd)
    st.add_response('batch_get_deployment_groups',
                    {'deploymentGroupsInfo': [_info('g1', rollback)]},
                    {'applicationName': 'app', 'deploymentGroupNames': ['g1']})
    with st:
        out = _svc(cd)._getDeploymentGroups('app', ['g1'])
        st.assert_no_pending_responses()
    return out[0]


def test_batch_path_flag_fix():
    assert _status(_hydrateBatch(None))[0] == -1
    assert _status(_hydrateBatch({'enabled': False, 'events': ['DEPLOYMENT_FAILURE']}))[0] == -1
    assert _status(_hydrateBatch({'enabled': True, 'events': ['DEPLOYMENT_STOP_ON_REQUEST']}))[0] == -1
    assert _status(_hydrateBatch({'enabled': True, 'events': ['DEPLOYMENT_FAILURE']}))[0] == 1


def test_enabled_without_events_is_flagged():
    assert _status(_info('g', {'enabled': True, 'events': []}))[0] == -1


def test_batch_error_falls_back_to_get():
    cd = _client()
    st = Stubber(cd)
    st.add_client_error('batch_get_deployment_groups', 'NotImplemented')
    st.add_response('get_deployment_group',
                    {'deploymentGroupInfo': _info('g1', {'enabled': True,
                                                         'events': ['DEPLOYMENT_FAILURE']})},
                    {'applicationName': 'app', 'deploymentGroupName': 'g1'})
    with st:
        out = _svc(cd)._getDeploymentGroups('app', ['g1'])
        st.assert_no_pending_responses()
    assert _status(out[0])[0] == 1


def test_unreadable_group_is_unable_to_evaluate():
    cd = _client()
    st = Stubber(cd)
    st.add_client_error('batch_get_deployment_groups', 'AccessDeniedException')
    st.add_client_error('get_deployment_group', 'AccessDeniedException')
    with st:
        out = _svc(cd)._getDeploymentGroups('app', ['g1'])
        st.assert_no_pending_responses()
    assert _status(out[0]) == [0, 'Unable to evaluate (AccessDeniedException)']


def test_batching_splits_at_batch_size():
    cd = _client()
    st = Stubber(cd)
    names = [f'g{i}' for i in range(Codedeploy.BATCH_SIZE + 1)]
    st.add_response('batch_get_deployment_groups',
                    {'deploymentGroupsInfo': [_info(n) for n in names[:Codedeploy.BATCH_SIZE]]},
                    {'applicationName': 'app', 'deploymentGroupNames': names[:Codedeploy.BATCH_SIZE]})
    st.add_response('batch_get_deployment_groups',
                    {'deploymentGroupsInfo': [_info(names[-1])]},
                    {'applicationName': 'app', 'deploymentGroupNames': names[-1:]})
    with st:
        out = _svc(cd)._getDeploymentGroups('app', names)
        st.assert_no_pending_responses()
    assert [o['deploymentGroupName'] for o in out] == names
    assert all(_status(o)[0] == -1 for o in out)
