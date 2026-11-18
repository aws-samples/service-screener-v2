"""Stubber tests for the AWS Private CA checks in services/acm (no AWS, no emulator).

These cover branches the emulator cannot reach with a flag -> fix cycle:
- a ROOT CA inside the 365-day window (a self-signed root cannot be re-issued past its own
  validity, so the emulator test uses a subordinate CA),
- FAILED / EXPIRED CA statuses (cannot be forced in the emulator),
- SHORT_LIVED_CERTIFICATE usage mode,
- AccessDenied on list_certificate_authorities (must be 'Unable to evaluate', never PASS).
Responses come from real boto3 clients wrapped by botocore.stub.Stubber, so API shapes are real.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from services.acm.drivers.AcmPcaCa import AcmPcaCa  # noqa: E402
from services.acm.drivers.AcmPcaAccount import AcmPcaAccount  # noqa: E402

ARN = 'arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/11111111-2222-3333-4444-555555555555'


def _client():
    return boto3.client('acm-pca', region_name='us-east-1',
                        aws_access_key_id='stub', aws_secret_access_key='stub')


def _ca(**over):
    now = datetime.now(timezone.utc)
    ca = {
        'Arn': ARN, 'OwnerAccount': '111122223333', 'Type': 'ROOT', 'Status': 'ACTIVE',
        'Serial': '01', 'CreatedAt': now, 'NotBefore': now, 'NotAfter': now + timedelta(days=3650),
        'CertificateAuthorityConfiguration': {'KeyAlgorithm': 'RSA_2048', 'SigningAlgorithm': 'SHA256WITHRSA',
                                              'Subject': {'CommonName': 'x'}},
        'RevocationConfiguration': {'CrlConfiguration': {'Enabled': False}, 'OcspConfiguration': {'Enabled': False}},
        'UsageMode': 'GENERAL_PURPOSE',
    }
    ca.update(over)
    return ca


def _described(ca):
    """Round-trip the CA through a stubbed describe_certificate_authority (validates the shape)."""
    c = _client()
    with Stubber(c) as st:
        st.add_response('describe_certificate_authority', {'CertificateAuthority': ca},
                        {'CertificateAuthorityArn': ARN})
        out = c.describe_certificate_authority(CertificateAuthorityArn=ARN)['CertificateAuthority']
    return out, c


def _run(ca, method, key):
    detail, c = _described(ca)
    d = AcmPcaCa(detail, c)
    getattr(d, method)()
    return d.results[key][0]


def test_root_expiry_window_flag_fix():
    now = datetime.now(timezone.utc)
    m, k = '_checkPcaCaCertExpiringOrFailed', 'pcaCaCertExpiringOrFailed'
    assert _run(_ca(NotAfter=now + timedelta(days=200)), m, k) == -1   # root < 365 days
    assert _run(_ca(NotAfter=now + timedelta(days=3650)), m, k) == 1   # rotated root
    ## 200 days is fine for a subordinate (90-day threshold)
    assert _run(_ca(Type='SUBORDINATE', NotAfter=now + timedelta(days=200)), m, k) == 1
    assert _run(_ca(Type='SUBORDINATE', NotAfter=now + timedelta(days=60)), m, k) == -1


def test_subordinate_in_place_renewal_flag_then_pass():
    """In-place renewal of the SAME subordinate CA (the AWS remediation the emulator rejects with
    InvalidStateException): 30 days left -> FAIL; after ImportCertificateAuthorityCertificate with
    a 5-year certificate, DescribeCertificateAuthority reports the new NotAfter -> PASS."""
    now = datetime.now(timezone.utc)
    m, k = '_checkPcaCaCertExpiringOrFailed', 'pcaCaCertExpiringOrFailed'
    sub = dict(Type='SUBORDINATE')
    flagged = _run(_ca(NotAfter=now + timedelta(days=30), **sub), m, k)
    assert flagged == -1

    c = _client()
    pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
    with Stubber(c) as st:
        st.add_response('import_certificate_authority_certificate', {},
                        {'CertificateAuthorityArn': ARN, 'Certificate': pem.encode(),
                         'CertificateChain': pem.encode()})
        st.add_response('describe_certificate_authority',
                        {'CertificateAuthority': _ca(NotAfter=now + timedelta(days=5 * 365), **sub)},
                        {'CertificateAuthorityArn': ARN})
        c.import_certificate_authority_certificate(CertificateAuthorityArn=ARN, Certificate=pem.encode(),
                                                   CertificateChain=pem.encode())
        renewed = c.describe_certificate_authority(CertificateAuthorityArn=ARN)['CertificateAuthority']
        st.assert_no_pending_responses()
    assert renewed['Arn'] == ARN
    d = AcmPcaCa(renewed, c)
    d._checkPcaCaCertExpiringOrFailed()
    assert d.results[k][0] == 1, d.results[k]
    assert 'SUBORDINATE CA certificate valid for' in d.results[k][1]


def test_retired_ca_is_not_applicable_not_pass():
    """A CA retired by replacement (DELETED / DISABLED) is neither flagged nor reported as PASS."""
    m, k = '_checkPcaCaCertExpiringOrFailed', 'pcaCaCertExpiringOrFailed'
    now = datetime.now(timezone.utc)
    for st in ('DELETED', 'DISABLED'):
        detail, c = _described(_ca(Type='SUBORDINATE', Status=st, NotAfter=now + timedelta(days=30)))
        d = AcmPcaCa(detail, c)
        d._checkPcaCaCertExpiringOrFailed()
        assert d.results[k] == [0, f'Not applicable (CA status {st})']


def test_failed_and_expired_status():
    m, k = '_checkPcaCaCertExpiringOrFailed', 'pcaCaCertExpiringOrFailed'
    assert _run(_ca(Status='FAILED', FailureReason='OTHER'), m, k) == -1
    assert _run(_ca(Status='EXPIRED'), m, k) == -1
    assert _run(_ca(Status='DELETED'), m, k) == 0
    assert _run(_ca(Status='ACTIVE'), m, k) == 1


def test_revocation_flag_fix_and_short_lived():
    m, k = '_checkPcaRevocationNotConfigured', 'pcaRevocationNotConfigured'
    assert _run(_ca(), m, k) == -1
    assert _run(_ca(RevocationConfiguration={'CrlConfiguration': {'Enabled': True, 'S3BucketName': 'crl-bucket'},
                                             'OcspConfiguration': {'Enabled': False}}), m, k) == 1
    assert _run(_ca(UsageMode='SHORT_LIVED_CERTIFICATE'), m, k) == 1
    assert _run(_ca(Status='DISABLED'), m, k) == 0


def test_root_in_workload_account_and_access_denied():
    c = _client()
    with Stubber(c) as st:
        st.add_client_error('list_certificate_authorities', 'AccessDeniedException', 'denied')
        try:
            c.list_certificate_authorities()
            code = None
        except c.exceptions.ClientError as e:
            code = e.response['Error']['Code']
    d = AcmPcaAccount(None, code, 3, None, 'us-east-1')
    d._checkPcaRootCaInWorkloadAccount()
    assert d.results['pcaRootCaInWorkloadAccount'] == [0, 'Unable to evaluate (AccessDeniedException)']

    flagged = AcmPcaAccount([_ca()], None, 2, None, 'us-east-1')
    flagged._checkPcaRootCaInWorkloadAccount()
    assert flagged.results['pcaRootCaInWorkloadAccount'][0] == -1

    for cas, inUse in (([_ca()], 0), ([_ca(Type='SUBORDINATE')], 5), ([_ca(Status='DELETED')], 5)):
        ok = AcmPcaAccount(cas, None, inUse, None, 'us-east-1')
        ok._checkPcaRootCaInWorkloadAccount()
        assert ok.results['pcaRootCaInWorkloadAccount'][0] == 1

    unk = AcmPcaAccount([_ca()], None, None, 'AccessDeniedException', 'us-east-1')
    unk._checkPcaRootCaInWorkloadAccount()
    assert unk.results['pcaRootCaInWorkloadAccount'][0] == 0
