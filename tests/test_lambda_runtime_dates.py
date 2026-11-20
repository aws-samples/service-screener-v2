"""lambdaDeprecatedRuntime: lock DEPRECATED_RUNTIMES to the dates AWS publishes.

Snapshot of https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
("Supported runtimes") and .../runtime-support-policy.html (deprecated runtimes
table), read 2026-11-20. Amazon Linux 2 based runtimes do NOT share one date:
provided.al2 was deprecated 2026-07-31 and python3.10 2026-10-31, while
java8.al2, java11, java17 and python3.11 are scheduled for 2027-06-30;
nodejs22.x is 2027-05-30 (not 2027-04-30)."""
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from services.lambda_.drivers.LambdaCommon import LambdaCommon  # noqa: E402

PUBLISHED_AL2 = {
    'provided.al2': '2026-07-31',
    'python3.10': '2026-10-31',
    'python3.11': '2027-06-30',
    'java8.al2': '2027-06-30',
    'java11': '2027-06-30',
    'java17': '2027-06-30',
}
PUBLISHED_OTHER = {
    'nodejs20.x': '2026-04-30', 'nodejs22.x': '2027-05-30', 'nodejs24.x': '2028-04-30',
    'python3.9': '2025-12-15', 'python3.12': '2028-10-31', 'python3.13': '2029-06-30', 'python3.14': '2029-06-30',
    'ruby3.2': '2026-03-31', 'ruby3.3': '2027-03-31', 'ruby3.4': '2028-03-31', 'ruby4.0': '2029-03-31',
    'java8.al2023': '2029-06-30', 'java11.al2023': '2029-06-30', 'java17.al2023': '2029-06-30',
    'java21': '2029-06-30', 'java25': '2029-06-30',
    'provided.al2023': '2029-06-30', 'dotnet8': '2026-11-10', 'dotnet10': '2028-11-14',
    'dotnet6': '2024-12-20', 'nodejs18.x': '2025-09-01',
}


@pytest.mark.parametrize('runtime,published', sorted(PUBLISHED_AL2.items()))
def test_al2_runtimes_match_published_dates(runtime, published):
    assert LambdaCommon.DEPRECATED_RUNTIMES[runtime] == published


@pytest.mark.parametrize('runtime,published', sorted(PUBLISHED_OTHER.items()))
def test_other_runtimes_match_published_dates(runtime, published):
    assert LambdaCommon.DEPRECATED_RUNTIMES.get(runtime) == published


def test_all_dates_are_iso():
    for rt, d in LambdaCommon.DEPRECATED_RUNTIMES.items():
        date.fromisoformat(d)
