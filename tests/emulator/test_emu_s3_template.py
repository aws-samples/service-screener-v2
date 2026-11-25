"""Reference flag -> fix -> re-run test. Copy this shape for every new check."""
import json

from tests.emulator.conftest import assertFlagFixCycle

ALL_FALSE = {k: False for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')}
ALL_TRUE = {k: True for k in ALL_FALSE}


def test_s3_public_read_list_form_wildcard(emu, uid):
    s3 = emu.client('s3')
    bucket = f'ss-test-{uid}'
    s3.create_bucket(Bucket=bucket)
    try:
        def misconfigure():
            s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=ALL_FALSE)
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': ['*']},
                               'Action': 's3:GetObject', 'Resource': f'arn:aws:s3:::{bucket}/*'}]}))

        def fix():
            s3.delete_bucket_policy(Bucket=bucket)
            s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=ALL_TRUE)

        assertFlagFixCycle(emu, 's3', 'PublicReadAccessBlock', bucket, misconfigure, fix)
    finally:
        try:
            s3.delete_bucket_policy(Bucket=bucket)
        except Exception:
            pass
        s3.delete_bucket(Bucket=bucket)
