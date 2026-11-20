"""Offline tests for cloudfrontDist._checkViewerMinTlsOld (default-certificate handling).

The check reads only the get_distribution_config response, so the driver is built
without its constructor. Emulator flag/fix cycles live in tests/emulator/test_emu_cloudfront.py.
"""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.cloudfront.drivers.cloudfrontDist import cloudfrontDist  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")

KEY = 'cloudfrontViewerMinTlsOld'
S3_ORIGIN = {'Id': 's3', 'DomainName': 'b.s3.amazonaws.com', 'S3OriginConfig': {'OriginAccessIdentity': ''}}


def _custom(protos):
    return {'Id': 'web', 'DomainName': 'example.com', 'CustomOriginConfig': {
        'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'https-only',
        'OriginSslProtocols': {'Quantity': len(protos), 'Items': protos}}}


def _run(viewerCert, origins):
    obj = cloudfrontDist.__new__(cloudfrontDist)
    obj.results = {}
    obj.distConfig = {'DistributionConfig': {'ViewerCertificate': viewerCert,
                                             'Origins': {'Quantity': len(origins), 'Items': origins}}}
    obj._checkViewerMinTlsOld()
    return obj.results[KEY]


DEFAULT = {'CloudFrontDefaultCertificate': True, 'MinimumProtocolVersion': 'TLSv1',
           'CertificateSource': 'cloudfront'}
CUSTOM_OK = {'CloudFrontDefaultCertificate': False, 'ACMCertificateArn': 'arn:aws:acm:us-east-1:1:certificate/x',
             'SSLSupportMethod': 'sni-only', 'MinimumProtocolVersion': 'TLSv1.2_2021'}


@pytest.mark.parametrize('origins', [[S3_ORIGIN], [_custom(['TLSv1.2'])]])
def test_default_certificate_is_info_not_pass(origins):
    """Regression: the default cert accepts TLS 1.0/1.1 viewers; it used to PASS with
    'Viewer and origin TLS policies require TLS 1.2+'."""
    r = _run(DEFAULT, origins)
    assert r[0] == 0, r
    assert 'fixed at TLSv1' in r[1] and 'TLS 1.0/1.1 accepted' in r[1]


def test_default_certificate_with_old_origin_fails_and_mentions_viewer():
    r = _run(DEFAULT, [_custom(['TLSv1', 'TLSv1.2'])])
    assert r[0] == -1
    assert 'origin web allows TLSv1' in r[1] and 'fixed at TLSv1' in r[1]


def test_custom_certificate_modern_policy_passes():
    assert _run(CUSTOM_OK, [S3_ORIGIN, _custom(['TLSv1.2'])]) == [1, 'Viewer and origin TLS policies require TLS 1.2+']


def test_custom_certificate_old_policy_fails():
    r = _run(dict(CUSTOM_OK, MinimumProtocolVersion='TLSv1.2_2019'), [S3_ORIGIN])
    assert r == [-1, 'viewer MinimumProtocolVersion TLSv1.2_2019 (TLS 1.2 minimum, but legacy cipher suites allowed)']


def test_custom_certificate_missing_policy_is_unable_to_evaluate():
    r = _run({k: v for k, v in CUSTOM_OK.items() if k != 'MinimumProtocolVersion'}, [S3_ORIGIN])
    assert r == [0, 'Unable to evaluate (MinimumProtocolVersionMissing)']
