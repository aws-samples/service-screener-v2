"""Stubber flag -> fix tests for fisNoRecentExperiment.

FIS experiment history is append-only (it cannot be deleted), and the emulator
cannot back-date an experiment, so the "experiment older than 90 days",
"only failed/cancelled runs" and "AccessDenied" cases cannot be built on the
emulator. These tests drive the real Fis service discovery through a real
boto3 FIS client wrapped by botocore Stubber (real API shapes), then the
FisCommon driver.
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.fis.Fis import Fis  # noqa: E402
from services.fis.drivers.FisCommon import FisCommon  # noqa: E402

KEY = 'fisNoRecentExperiment'


class _Fis(Fis):
    """Fis without Service bootstrap/teardown (no session, no chart data)."""

    def __init__(self, client):
        self.region = 'us-east-1'
        self.fisClient = client

    def __del__(self):
        pass

NOW = datetime.datetime.now(datetime.timezone.utc)


def _client():
    return boto3.client('fis', region_name='us-east-1', aws_access_key_id='x',
                        aws_secret_access_key='x')


def _exp(eid, daysAgo, status):
    return {'id': eid, 'arn': f'arn:aws:fis:us-east-1:111122223333:experiment/{eid}',
            'experimentTemplateId': 'EXT1', 'state': {'status': status, 'reason': 'r'},
            'creationTime': NOW - datetime.timedelta(days=daysAgo), 'tags': {}}


def _evaluate(experimentsPages, templates=0, listError=None):
    client = _client()
    stub = Stubber(client)
    if listError:
        stub.add_client_error('list_experiments', service_error_code=listError, http_status_code=403)
    else:
        for i, page in enumerate(experimentsPages):
            resp = {'experiments': page}
            if i < len(experimentsPages) - 1:
                resp['nextToken'] = f't{i}'
            stub.add_response('list_experiments', resp)
    stub.add_response('list_experiment_templates', {'experimentTemplates': [
        {'id': f'EXT{i}', 'arn': f'arn:aws:fis:us-east-1:111122223333:experiment-template/EXT{i}'}
        for i in range(templates)]})
    svc = _Fis(client)
    with stub:
        detail = svc.getResources()
        stub.assert_no_pending_responses()
    drv = FisCommon(detail)
    drv._checkFisNoRecentExperiment()
    return drv.results[KEY]


def test_flag_no_experiments_then_fix_recent_completed():
    assert _evaluate([[]], templates=1)[0] == -1
    assert _evaluate([[_exp('EXP1', 3, 'completed')]], templates=1)[0] == 1


def test_flag_only_old_experiments_then_fix():
    assert _evaluate([[_exp('EXP1', 120, 'completed')]])[0] == -1
    assert _evaluate([[_exp('EXP1', 120, 'completed')], [_exp('EXP2', 10, 'stopped')]])[0] == 1


def test_flag_recent_but_never_ran_then_fix():
    res = _evaluate([[_exp('EXP1', 2, 'failed'), _exp('EXP2', 1, 'cancelled')]])
    assert res[0] == -1 and 'cancelled' in res[1] and 'failed' in res[1]
    assert _evaluate([[_exp('EXP1', 2, 'failed'), _exp('EXP3', 1, 'running')]])[0] == 1


def test_access_denied_is_not_evaluable():
    res = _evaluate(None, listError='AccessDeniedException')
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']
