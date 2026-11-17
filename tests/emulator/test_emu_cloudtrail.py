"""Flag -> fix -> re-run tests for the CloudTrail WAFS2027 checks against the local AWS Emulator."""
import json

from tests.emulator.conftest import assertFlagFixCycle

ALL_MGMT = [{'ReadWriteType': 'All', 'IncludeManagementEvents': True}]
NO_KMS = [{'ReadWriteType': 'All', 'IncludeManagementEvents': True,
           'ExcludeManagementEventSources': ['kms.amazonaws.com']}]


def _trailBucket(emu, bucket, objectLock=False):
    s3 = emu.client('s3')
    acct = emu.client('sts').get_caller_identity()['Account']
    if objectLock:
        s3.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    else:
        s3.create_bucket(Bucket=bucket)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        'Version': '2012-10-17',
        'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
             'Action': 's3:GetBucketAcl', 'Resource': f'arn:aws:s3:::{bucket}'},
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'},
             'Action': 's3:PutObject', 'Resource': f'arn:aws:s3:::{bucket}/AWSLogs/{acct}/*',
             'Condition': {'StringEquals': {'s3:x-amz-acl': 'bucket-owner-full-control'}}}]}))


def _dropBucket(emu, bucket):
    s3 = emu.client('s3')
    try:
        for page in s3.get_paginator('list_object_versions').paginate(Bucket=bucket):
            objs = [{'Key': v['Key'], 'VersionId': v['VersionId']}
                    for v in (page.get('Versions', []) + page.get('DeleteMarkers', []))]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={'Objects': objs}, BypassGovernanceRetention=True)
    except Exception:
        pass
    try:
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket):
            objs = [{'Key': o['Key']} for o in page.get('Contents', [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={'Objects': objs})
    except Exception:
        pass
    for fn in (lambda: s3.delete_bucket_policy(Bucket=bucket), lambda: s3.delete_bucket(Bucket=bucket)):
        try:
            fn()
        except Exception:
            pass


def _dropTrail(emu, name):
    try:
        emu.client('cloudtrail').delete_trail(Name=name)
    except Exception:
        pass


def _newTrail(emu, name, bucket):
    ct = emu.client('cloudtrail')
    ct.create_trail(Name=name, S3BucketName=bucket, IsMultiRegionTrail=True)
    ct.start_logging(Name=name)
    return ct


def test_cloudtrail_excludes_kms_events_basic(emu, uid):
    bucket, trail = f'ss-ct-{uid}', f'ss-ct-{uid}'
    _trailBucket(emu, bucket)
    try:
        ct = _newTrail(emu, trail, bucket)
        assertFlagFixCycle(
            emu, 'cloudtrail', 'cloudtrailExcludesKmsEvents', 'General',
            lambda: ct.put_event_selectors(TrailName=trail, EventSelectors=NO_KMS),
            lambda: ct.put_event_selectors(TrailName=trail, EventSelectors=ALL_MGMT))
    finally:
        _dropTrail(emu, trail)
        _dropBucket(emu, bucket)


def test_cloudtrail_excludes_kms_events_advanced(emu, uid):
    bucket, trail = f'ss-ct-{uid}', f'ss-ct-{uid}'
    _trailBucket(emu, bucket)
    try:
        ct = _newTrail(emu, trail, bucket)

        def misconfigure():
            ct.put_event_selectors(TrailName=trail, AdvancedEventSelectors=[{
                'Name': 'mgmt-no-kms', 'FieldSelectors': [
                    {'Field': 'eventCategory', 'Equals': ['Management']},
                    {'Field': 'eventSource', 'NotEquals': ['kms.amazonaws.com']}]}])

        def fix():
            ct.put_event_selectors(TrailName=trail, AdvancedEventSelectors=[{
                'Name': 'mgmt', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]}])

        assertFlagFixCycle(emu, 'cloudtrail', 'cloudtrailExcludesKmsEvents', 'General', misconfigure, fix)
    finally:
        _dropTrail(emu, trail)
        _dropBucket(emu, bucket)


def test_has_management_events_captured_selector_list(emu, uid):
    """Regression: EventSelectors is a list; the check used to treat it as a dict and
    flagged every account. Also accepts advanced management selectors."""
    bucket, trail = f'ss-ct-{uid}', f'ss-ct-{uid}'
    _trailBucket(emu, bucket)
    try:
        ct = _newTrail(emu, trail, bucket)
        assertFlagFixCycle(
            emu, 'cloudtrail', 'HasManagementEventsCaptured', 'General',
            lambda: ct.put_event_selectors(TrailName=trail, EventSelectors=[{
                'ReadWriteType': 'All', 'IncludeManagementEvents': False,
                'DataResources': [{'Type': 'AWS::S3::Object', 'Values': [f'arn:aws:s3:::{bucket}/']}]}]),
            lambda: ct.put_event_selectors(TrailName=trail, AdvancedEventSelectors=[{
                'Name': 'mgmt', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]}]))
    finally:
        _dropTrail(emu, trail)
        _dropBucket(emu, bucket)


def test_trail_bucket_same_account(emu, uid):
    """The emulator account is an AWS Organizations management account, so the
    org gating passes. A trail delivering to a bucket in this account is flagged;
    removing it (logs then come only from a log archive account) clears the finding."""
    bucket, trail = f'ss-ct-{uid}', f'ss-ct-{uid}'
    _trailBucket(emu, bucket)
    try:
        assertFlagFixCycle(
            emu, 'cloudtrail', 'trailBucketSameAccount', 'General',
            lambda: _newTrail(emu, trail, bucket),
            lambda: _dropTrail(emu, trail))
    finally:
        _dropTrail(emu, trail)
        _dropBucket(emu, bucket)


def test_trail_bucket_no_object_lock(emu, uid):
    bucket, locked, trail = f'ss-ct-{uid}', f'ss-ct-lock-{uid}', f'ss-ct-{uid}'
    _trailBucket(emu, bucket)
    _trailBucket(emu, locked, objectLock=True)
    try:
        ct = emu.client('cloudtrail')
        assertFlagFixCycle(
            emu, 'cloudtrail', 'trailBucketNoObjectLock', trail,
            lambda: _newTrail(emu, trail, bucket),
            lambda: ct.update_trail(Name=trail, S3BucketName=locked))
    finally:
        _dropTrail(emu, trail)
        _dropBucket(emu, bucket)
        _dropBucket(emu, locked)
