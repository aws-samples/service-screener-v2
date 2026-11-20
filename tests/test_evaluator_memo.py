"""Evaluator._memo / _sharedMemo: fetch once, thread-safe, errors cached, copies returned."""
import os
import sys
import threading
import time

import botocore.exceptions
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.Evaluator import Evaluator  # noqa: E402
from utils.Config import Config  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")


class D(Evaluator):
    def __init__(self):
        super().__init__()
        self._resourceName = 'x'


def test_memo_fetches_once_across_threads():
    d, calls = D(), []
    def fn():
        calls.append(1); time.sleep(0.05); return {'a': [1]}
    out = []
    ts = [threading.Thread(target=lambda: out.append(d._memo('k', fn))) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len(calls) == 1 and all(o == {'a': [1]} for o in out)


def test_memo_returns_independent_copies():
    d = D()
    a = d._memo('k', lambda: {'a': [1]}); a['a'].append(2)
    assert d._memo('k', lambda: None) == {'a': [1]}


def test_memo_caches_and_reraises_errors():
    d, calls = D(), []
    def fn():
        calls.append(1)
        raise botocore.exceptions.ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'x'}}, 'Op')
    for _ in range(3):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            d._memo('k', fn)
        assert e.value.response['Error']['Code'] == 'AccessDenied'
    assert len(calls) == 1


def test_memo_is_per_instance():
    a, b = D(), D()
    assert a._memo('k', lambda: 1) == 1 and b._memo('k', lambda: 2) == 2


def test_shared_memo_across_instances_and_reset_by_config_init():
    Config.init()
    calls = []
    def fn():
        calls.append(1); return ['detector']
    assert D()._sharedMemo(('gd', 'us-east-1'), fn) == ['detector']
    assert D()._sharedMemo(('gd', 'us-east-1'), fn) == ['detector']
    assert len(calls) == 1
    D()._sharedMemo(('gd', 'eu-west-1'), fn)
    assert len(calls) == 2
    Config.init()
    D()._sharedMemo(('gd', 'us-east-1'), fn)
    assert len(calls) == 3


@pytest.mark.parametrize('code,status', [('ThrottlingException', 400), ('TooManyRequestsException', 429),
                                         ('InternalFailure', 500), ('ServiceUnavailable', 503)])
def test_transient_errors_not_cached(code, status):
    d, calls = D(), []
    def fn():
        calls.append(1)
        if len(calls) == 1:
            raise botocore.exceptions.ClientError(
                {'Error': {'Code': code, 'Message': 'x'}, 'ResponseMetadata': {'HTTPStatusCode': status}}, 'Op')
        return 'ok'
    with pytest.raises(botocore.exceptions.ClientError):
        d._memo('k', fn)
    assert d._memo('k', fn) == 'ok' and len(calls) == 2


def test_transient_errors_not_cached_shared():
    Config.init()
    calls = []
    def fn():
        calls.append(1)
        if len(calls) == 1:
            raise botocore.exceptions.ClientError({'Error': {'Code': 'Throttling', 'Message': 'x'}}, 'Op')
        return ['org']
    with pytest.raises(botocore.exceptions.ClientError):
        D()._sharedMemo('org', fn)
    assert D()._sharedMemo('org', fn) == ['org'] and len(calls) == 2


def _tbLen(e):
    n, tb = 0, e.__traceback__
    while tb is not None:
        n, tb = n + 1, tb.tb_next
    return n


@pytest.mark.parametrize('shared', [False, True])
def test_cached_error_traceback_does_not_grow(shared):
    """Re-raising the one cached exception appended every caller's frames to
    it (152 frames after 50 calls). Each caller must get a fresh copy."""
    Config.init()
    d = D()
    def fn():
        raise botocore.exceptions.ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'x'}}, 'Op')
    call = (lambda: D()._sharedMemo('org-denied', fn)) if shared else (lambda: d._memo('k', fn))
    seen, lens = [], []
    for _ in range(50):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            call()
        assert e.value.response['Error']['Code'] == 'AccessDenied'
        assert e.value.operation_name == 'Op'
        seen.append(e.value)
        lens.append(_tbLen(e.value))
    assert max(lens[1:]) == min(lens[1:]) <= 5, lens[:5]
    assert len({id(x) for x in seen[1:]}) == 49
    if not shared:
        assert _tbLen(d._memoStore['k'][1]) <= 5   # the cached object stays bounded too


def test_uncopyable_cached_error_still_reraised():
    class Odd(Exception):
        def __init__(self, a, b):
            super().__init__(a)
            self.b = b
    d = D()
    def fn():
        raise Odd('a', 'b')
    for _ in range(20):
        with pytest.raises(Odd) as e:
            d._memo('k', fn)
        assert _tbLen(e.value) <= 5
