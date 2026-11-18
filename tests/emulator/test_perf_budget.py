"""
API-call budget per resource (performance guard).

For each service, seed 1 resource and run the service's full scan, then seed
5 more and run it again. The extra API calls divided by 5 is the cost per
additional resource. Run time in a real account is dominated by this number,
so a check that starts re-fetching data per resource (or worse, per resource
per check) fails here before it reaches users.

Budgets are set from measured values with headroom. If a new check needs
more calls per resource, raise the budget deliberately in this file.
"""
import json
import threading
from contextlib import contextmanager

import botocore.client
import pytest

from tests.emulator.conftest import REGION
from utils.CheckRunner import CheckRunner

EXTRA = 5


@contextmanager
def countCalls():
    counts = {'n': 0}
    lock = threading.Lock()
    orig = botocore.client.BaseClient._make_api_call

    def wrapped(self, op, params):
        with lock:
            counts['n'] += 1
        return orig(self, op, params)
    botocore.client.BaseClient._make_api_call = wrapped
    try:
        yield counts
    finally:
        botocore.client.BaseClient._make_api_call = orig


def _scanCalls(sess, service):
    with countCalls() as c:
        CheckRunner.run(service, None, region=REGION, session=sess, emulator=True)
    return c['n']


# ---- seeders: create one resource named with the given suffix ------------- #
def seed_s3(sess, sfx):
    sess.client('s3').create_bucket(Bucket=f'ss-perf-{sfx}')


def seed_kms(sess, sfx):
    sess.client('kms').create_key(Description=f'ss-perf-{sfx}')


def seed_sqs(sess, sfx):
    sess.client('sqs').create_queue(QueueName=f'ss-perf-{sfx}')


def seed_sns(sess, sfx):
    sess.client('sns').create_topic(Name=f'ss-perf-{sfx}')


def seed_dynamodb(sess, sfx):
    sess.client('dynamodb').create_table(
        TableName=f'ss-perf-{sfx}', BillingMode='PAY_PER_REQUEST',
        AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
        KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}])


def seed_secretsmanager(sess, sfx):
    sess.client('secretsmanager').create_secret(Name=f'ss-perf-{sfx}', SecretString='x')


def seed_ecr(sess, sfx):
    sess.client('ecr').create_repository(repositoryName=f'ss-perf-{sfx}')


def seed_ec2(sess, sfx):
    ec2 = sess.client('ec2')
    vol = ec2.create_volume(AvailabilityZone=f'{REGION}a', Size=1, VolumeType='gp3')
    ec2.create_snapshot(VolumeId=vol['VolumeId'], Description=f'ss-perf-{sfx}')


def seed_iam(sess, sfx):
    sess.client('iam').create_role(RoleName=f'ss-perf-{sfx}', AssumeRolePolicyDocument=json.dumps({
        'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'},
                                                'Action': 'sts:AssumeRole'}]}))


# service: (seeder, max API calls per additional resource). Measured 2026-11-18 on the
# emulator after the de-duplication work: s3 15, dynamodb 12, sqs 9, ec2 5, kms 5,
# ecr 4, sns 4, secretsmanager 2, iam 0 (bulk-fetched). Budgets add ~50% headroom.
BUDGETS = {
    's3': (seed_s3, 22),
    'kms': (seed_kms, 8),
    'sqs': (seed_sqs, 14),
    'sns': (seed_sns, 6),
    'dynamodb': (seed_dynamodb, 18),
    'secretsmanager': (seed_secretsmanager, 4),
    'ecr': (seed_ecr, 6),
    'ec2': (seed_ec2, 8),
    'iam': (seed_iam, 3),
}


@pytest.mark.parametrize('service', sorted(BUDGETS))
def test_api_calls_per_resource(emu_fresh, service, uid):
    seed, budget = BUDGETS[service]
    seed(emu_fresh, f'{uid}-0')
    base = _scanCalls(emu_fresh, service)
    for i in range(1, EXTRA + 1):
        seed(emu_fresh, f'{uid}-{i}')
    more = _scanCalls(emu_fresh, service)
    perResource = (more - base) / EXTRA
    print(f'{service}: {base} calls with 1 resource, {more} with {1 + EXTRA}; {perResource:.1f} per extra resource')
    assert perResource <= budget, f'{service}: {perResource:.1f} API calls per extra resource exceeds budget {budget}'
