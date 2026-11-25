"""SageMaker getResources: newest-first listing, history cap, in-use configs/models
always evaluated, and no unbounded listing of job history."""
import datetime
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.sagemaker.Sagemaker import Sagemaker  # noqa: E402
from utils.Config import Config  # noqa: E402


class FakePaginator:
    def __init__(self, items, key, calls):
        self.items, self.key, self.calls = items, key, calls

    def paginate(self, **kw):
        self.calls.append(kw)
        size = kw['PaginationConfig']['PageSize']
        ordered = sorted(self.items, key=lambda x: x['CreationTime'], reverse=True)
        for i in range(0, len(ordered), size):
            page = {self.key: ordered[i:i + size]}
            if i + size < len(ordered):
                page['NextToken'] = 't'
            yield page


def _items(prefix, nameKey, n):
    base = datetime.datetime(2026, 1, 1)
    return [{nameKey: f'{prefix}{i:04d}', 'CreationTime': base + datetime.timedelta(minutes=i)} for i in range(n)]


@pytest.fixture
def svc(monkeypatch):
    Config.set('_SS_PARAMS', {})
    s = Sagemaker.__new__(Sagemaker)
    s.tags = []
    s.region = 'us-east-1'
    s.registerItems = lambda objType, items, idFn=None: items
    client = MagicMock()
    data = {
        'list_endpoints': ('Endpoints', [{'EndpointName': 'ep1', 'CreationTime': datetime.datetime(2025, 1, 1)}]),
        'list_notebook_instances': ('NotebookInstances', _items('nb', 'NotebookInstanceName', 3)),
        'list_endpoint_configs': ('EndpointConfigs', _items('cfg', 'EndpointConfigName', 250)),
        'list_models': ('Models', _items('model', 'ModelName', 400)),
        'list_training_jobs': ('TrainingJobSummaries', _items('job', 'TrainingJobName', 5000)),
        'list_hyper_parameter_tuning_jobs': ('HyperParameterTuningJobSummaries',
                                             _items('tune', 'HyperParameterTuningJobName', 120)),
    }
    s._paginateCalls = {}

    def get_paginator(op):
        key, items = data[op]
        calls = s._paginateCalls.setdefault(op, [])
        return FakePaginator(items, key, calls)
    client.get_paginator.side_effect = get_paginator
    # ep1 uses an OLD config (cfg0000) whose model is an OLD model (model0003)
    client.describe_endpoint.side_effect = lambda EndpointName: {
        'EndpointName': EndpointName, 'EndpointArn': 'arn:ep', 'EndpointConfigName': 'cfg0000'}
    client.describe_endpoint_config.side_effect = lambda EndpointConfigName: {
        'EndpointConfigName': EndpointConfigName, 'EndpointConfigArn': 'arn:cfg',
        'ProductionVariants': [{'ModelName': 'model0003' if EndpointConfigName == 'cfg0000' else 'modelX'}]}
    client.describe_model.side_effect = lambda ModelName: {'ModelName': ModelName, 'ModelArn': 'arn:m'}
    client.describe_notebook_instance.side_effect = lambda NotebookInstanceName: {
        'NotebookInstanceName': NotebookInstanceName, 'NotebookInstanceArn': 'arn:nb'}
    client.describe_training_job.side_effect = lambda TrainingJobName: {
        'TrainingJobName': TrainingJobName, 'TrainingJobArn': 'arn:tj'}
    client.describe_hyper_parameter_tuning_job.side_effect = lambda HyperParameterTuningJobName: {
        'HyperParameterTuningJobName': HyperParameterTuningJobName, 'HyperParameterTuningJobArn': 'arn:tu'}
    s.sagemakerClient = client
    return s


def test_lists_newest_first_with_max_page_size(svc):
    svc.getResources()
    for op, calls in svc._paginateCalls.items():
        assert calls[0]['SortBy'] == 'CreationTime' and calls[0]['SortOrder'] == 'Descending', op
        assert calls[0]['PaginationConfig']['PageSize'] == 100, op


def test_history_capped_to_most_recent(svc):
    r = svc.getResources()
    names = [j['TrainingJobName'] for j in r['trainingJobs']]
    assert len(names) == 100
    assert names[0] == 'job4999' and 'job0000' not in names
    assert svc.sagemakerClient.describe_training_job.call_count == 100
    assert len(r['tuningJobs']) == 100


def test_live_resources_not_capped(svc):
    r = svc.getResources()
    assert [e['EndpointName'] for e in r['endpoints']] == ['ep1']
    assert len(r['notebooks']) == 3


def test_in_use_config_and_model_always_included(svc):
    r = svc.getResources()
    cfgs = {c['EndpointConfigName'] for c in r['endpointConfigs']}
    models = {m['ModelName'] for m in r['models']}
    assert 'cfg0000' in cfgs and len(cfgs) == 101          # 100 newest + the old in-use one
    assert 'model0003' in models and len(models) == 101


def test_history_limit_override(svc):
    Config.set('_SS_PARAMS', {'others': '{"sagemakerHistoryLimit": 10}'})
    try:
        r = svc.getResources()
        assert len(r['trainingJobs']) == 10
    finally:
        Config.set('_SS_PARAMS', {})


def test_small_account_not_truncated(svc):
    svc.HISTORY_LIMIT = 10000
    r = svc.getResources()
    assert len(r['trainingJobs']) == 5000
