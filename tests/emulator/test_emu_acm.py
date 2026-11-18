"""Flag -> fix -> re-run tests for the AWS Private CA (acm-pca) checks in services/acm."""
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck

ROOT_TEMPLATE = 'arn:aws:acm-pca:::template/RootCACertificate/V1'
SUB_TEMPLATE = 'arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1'


def _retry(fn, tries=40, delay=0.5):
    """acm-pca operations are asynchronous (RequestInProgressException)."""
    last = None
    for _ in range(tries):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            if 'RequestInProgress' not in type(e).__name__ and 'RequestInProgress' not in str(e):
                raise
            last = e
            time.sleep(delay)
    raise last


def _createRootCa(pca, name):
    arn = pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            'KeyAlgorithm': 'RSA_2048', 'SigningAlgorithm': 'SHA256WITHRSA',
            'Subject': {'CommonName': name}},
        CertificateAuthorityType='ROOT',
        Tags=[{'Key': 'Name', 'Value': name}])['CertificateAuthorityArn']
    return arn


def _installRootCert(pca, arn, validity):
    csr = _retry(lambda: pca.get_certificate_authority_csr(CertificateAuthorityArn=arn)['Csr'])
    certArn = pca.issue_certificate(
        CertificateAuthorityArn=arn, Csr=csr, SigningAlgorithm='SHA256WITHRSA',
        TemplateArn=ROOT_TEMPLATE, Validity=validity)['CertificateArn']
    cert = _retry(lambda: pca.get_certificate(CertificateAuthorityArn=arn, CertificateArn=certArn)['Certificate'])
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=arn, Certificate=cert)
    for _ in range(40):
        if pca.describe_certificate_authority(CertificateAuthorityArn=arn)['CertificateAuthority']['Status'] == 'ACTIVE':
            return
        time.sleep(0.5)


def _deleteCa(pca, arn):
    try:
        st = pca.describe_certificate_authority(CertificateAuthorityArn=arn)['CertificateAuthority']['Status']
        if st == 'DELETED':
            return
        if st == 'ACTIVE':
            pca.update_certificate_authority(CertificateAuthorityArn=arn, Status='DISABLED')
        pca.delete_certificate_authority(CertificateAuthorityArn=arn, PermanentDeletionTimeInDays=7)
    except Exception:
        pass


def _installSubCert(pca, subArn, rootArn, validity):
    csr = _retry(lambda: pca.get_certificate_authority_csr(CertificateAuthorityArn=subArn)['Csr'])
    certArn = pca.issue_certificate(
        CertificateAuthorityArn=rootArn, Csr=csr, SigningAlgorithm='SHA256WITHRSA',
        TemplateArn=SUB_TEMPLATE, Validity=validity)['CertificateArn']
    cert = _retry(lambda: pca.get_certificate(CertificateAuthorityArn=rootArn, CertificateArn=certArn)['Certificate'])
    chain = pca.get_certificate_authority_certificate(CertificateAuthorityArn=rootArn)['Certificate']
    pca.import_certificate_authority_certificate(CertificateAuthorityArn=subArn, Certificate=cert, CertificateChain=chain)
    for _ in range(40):
        if pca.describe_certificate_authority(CertificateAuthorityArn=subArn)['CertificateAuthority']['Status'] == 'ACTIVE':
            return
        time.sleep(0.5)


def _createSubCa(pca, name):
    return pca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            'KeyAlgorithm': 'RSA_2048', 'SigningAlgorithm': 'SHA256WITHRSA',
            'Subject': {'CommonName': name}},
        CertificateAuthorityType='SUBORDINATE')['CertificateAuthorityArn']


def test_pca_ca_cert_expiring(emu, uid):
    """Subordinate CA whose certificate expires in 30 days (< 90-day subordinate threshold).

    In AWS the fix is an in-place renewal (ImportCertificateAuthorityCertificate on the ACTIVE
    CA). The emulator rejects that (InvalidStateException for ACTIVE and DISABLED CAs), so the
    in-place FAIL -> PASS on the SAME CA is proven by
    tests/test_stub_acm.py::test_subordinate_in_place_renewal_flag_then_pass.

    Here the fix is the other real-world remediation: replace the CA with a new subordinate
    holding a 5-year certificate and retire the old one. Assertions:
      - old CA: FAIL before the fix,
      - replacement CA: PASS (a genuinely passing state produced by the emulator),
      - retired (DELETED) old CA: INFO 'Not applicable', never FAIL and never PASS.
    assertFlagFixCycle cannot express this (it re-checks the same resource), so the cycle is
    written out explicitly."""
    pca = emu.client('acm-pca')
    key = 'pcaCaCertExpiringOrFailed'
    rootArn = _createRootCa(pca, f'ss-root-{uid}')
    subArn = newArn = None
    try:
        _installRootCert(pca, rootArn, {'Value': 10, 'Type': 'YEARS'})
        subArn = _createSubCa(pca, f'ss-sub-{uid}')
        _installSubCert(pca, subArn, rootArn, {'Value': 30, 'Type': 'DAYS'})

        before = runCheck(emu, 'acm', key, subArn.split('/')[-1]).statuses()
        assert before and all(v == -1 for v in before.values()), before

        newArn = _createSubCa(pca, f'ss-sub2-{uid}')
        _installSubCert(pca, newArn, rootArn, {'Value': 5, 'Type': 'YEARS'})
        _deleteCa(pca, subArn)

        res = runCheck(emu, 'acm', key, newArn.split('/')[-1])
        after = res.statuses()
        assert after and all(v == 1 for v in after.values()), \
            (after, [m for r in res.results.values() for k, m in r.items() if k.lower() == key.lower()])

        retired = runCheck(emu, 'acm', key, subArn.split('/')[-1])
        msgs = [m for r in retired.results.values() for k, m in r.items() if k.lower() == key.lower()]
        assert msgs and all(m == [0, 'Not applicable (CA status DELETED)'] for m in msgs), msgs
    finally:
        for a in (newArn, subArn):
            if a:
                _deleteCa(pca, a)
        _deleteCa(pca, rootArn)


def test_pca_revocation_not_configured(emu, uid):
    pca = emu.client('acm-pca')
    arn = _createRootCa(pca, f'ss-rev-{uid}')
    try:
        _installRootCert(pca, arn, {'Value': 10, 'Type': 'YEARS'})

        def misconfigure():
            pca.update_certificate_authority(CertificateAuthorityArn=arn, RevocationConfiguration={
                'CrlConfiguration': {'Enabled': False}, 'OcspConfiguration': {'Enabled': False}})

        def fix():
            pca.update_certificate_authority(CertificateAuthorityArn=arn, RevocationConfiguration={
                'OcspConfiguration': {'Enabled': True}})

        assertFlagFixCycle(emu, 'acm', 'pcaRevocationNotConfigured', arn.split('/')[-1], misconfigure, fix)
    finally:
        _deleteCa(pca, arn)


def test_pca_root_ca_in_workload_account(emu, uid):
    """Account-level heuristic: active root CA + an ACM certificate in use (HTTPS ALB listener).
    Fix = move the root out of the account (here: disable + schedule deletion of the root CA).
    Note: the emulator keeps InUse=True on the ACM cert after the listener is deleted, so the
    fix is applied to the CA side rather than the workload side."""
    pca, acm, ec2, elb = (emu.client(s) for s in ('acm-pca', 'acm', 'ec2', 'elbv2'))
    arn = _createRootCa(pca, f'ss-wl-{uid}')
    created = {}
    try:
        _installRootCert(pca, arn, {'Value': 10, 'Type': 'YEARS'})

        def misconfigure():
            cert = acm.request_certificate(DomainName=f'{uid}.example.internal',
                                           CertificateAuthorityArn=arn)['CertificateArn']
            created['cert'] = cert
            for _ in range(40):
                if acm.describe_certificate(CertificateArn=cert)['Certificate']['Status'] == 'ISSUED':
                    break
                time.sleep(0.5)
            vpc = ec2.create_vpc(CidrBlock='10.77.0.0/16')['Vpc']['VpcId']
            created['vpc'] = vpc
            igw = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
            created['igw'] = igw
            ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
            created['subnets'] = [ec2.create_subnet(VpcId=vpc, CidrBlock=f'10.77.{i}.0/24', AvailabilityZone=z)['Subnet']['SubnetId']
                                  for i, z in enumerate(['us-east-1a', 'us-east-1b'])]
            created['lb'] = elb.create_load_balancer(Name=f'ss-lb-{uid}', Subnets=created['subnets'])['LoadBalancers'][0]['LoadBalancerArn']
            created['tg'] = elb.create_target_group(Name=f'ss-tg-{uid}', Protocol='HTTP', Port=80, VpcId=vpc)['TargetGroups'][0]['TargetGroupArn']
            created['listener'] = elb.create_listener(
                LoadBalancerArn=created['lb'], Protocol='HTTPS', Port=443,
                Certificates=[{'CertificateArn': cert}],
                DefaultActions=[{'Type': 'forward', 'TargetGroupArn': created['tg']}])['Listeners'][0]['ListenerArn']

        def fix():
            _deleteCa(pca, arn)

        assertFlagFixCycle(emu, 'acm', 'pcaRootCaInWorkloadAccount', 'PrivateCA::Account', misconfigure, fix)
    finally:
        for fn in (lambda: elb.delete_listener(ListenerArn=created['listener']),
                   lambda: elb.delete_load_balancer(LoadBalancerArn=created['lb']),
                   lambda: elb.delete_target_group(TargetGroupArn=created['tg']),
                   lambda: [ec2.delete_subnet(SubnetId=s) for s in created['subnets']],
                   lambda: ec2.detach_internet_gateway(InternetGatewayId=created['igw'], VpcId=created['vpc']),
                   lambda: ec2.delete_internet_gateway(InternetGatewayId=created['igw']),
                   lambda: ec2.delete_vpc(VpcId=created['vpc']),
                   lambda: acm.delete_certificate(CertificateArn=created['cert'])):
            try:
                fn()
            except Exception:
                pass
        _deleteCa(pca, arn)
