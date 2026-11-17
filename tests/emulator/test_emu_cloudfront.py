"""Flag -> fix -> re-run tests for CloudFront checks against the local AWS Emulator."""
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck

CACHING_OPTIMIZED = '658327ea-f89d-4fab-a63d-7e88639e58f6'
CHECK = 'cloudfrontViewerMinTlsOld'


def _distConfig(ref, sslProtocols):
    return {
        'CallerReference': ref, 'Comment': ref, 'Enabled': False,
        'Origins': {'Quantity': 1, 'Items': [{
            'Id': 'origin-' + ref, 'DomainName': 'example.com',
            'CustomOriginConfig': {
                'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'https-only',
                'OriginSslProtocols': {'Quantity': len(sslProtocols), 'Items': sslProtocols}}}]},
        'DefaultCacheBehavior': {'TargetOriginId': 'origin-' + ref, 'ViewerProtocolPolicy': 'redirect-to-https',
                                 'CachePolicyId': CACHING_OPTIMIZED},
    }


def _update(cf, distId, mutate):
    g = cf.get_distribution_config(Id=distId)
    cfg = g['DistributionConfig']
    mutate(cfg)
    cf.update_distribution(Id=distId, IfMatch=g['ETag'], DistributionConfig=cfg)


def _delete(cf, distId):
    for _ in range(30):
        try:
            if cf.get_distribution(Id=distId)['Distribution']['Status'] == 'Deployed':
                g = cf.get_distribution_config(Id=distId)
                cf.delete_distribution(Id=distId, IfMatch=g['ETag'])
                return
        except cf.exceptions.NoSuchDistribution:
            return
        except Exception:
            pass
        time.sleep(1)


def test_cloudfront_origin_allows_tls10(emu, uid):
    cf = emu.client('cloudfront')
    ref = f'ss-test-{uid}'
    distId = cf.create_distribution(DistributionConfig=_distConfig(ref, ['TLSv1.2']))['Distribution']['Id']
    try:
        def setProtocols(protos):
            def m(cfg):
                cfg['Origins']['Items'][0]['CustomOriginConfig']['OriginSslProtocols'] = {
                    'Quantity': len(protos), 'Items': protos}
            return m

        assertFlagFixCycle(emu, 'cloudfront', CHECK, distId,
                           lambda: _update(cf, distId, setProtocols(['TLSv1', 'TLSv1.2'])),
                           lambda: _update(cf, distId, setProtocols(['TLSv1.2'])))
    finally:
        _delete(cf, distId)


def test_cloudfront_viewer_min_tls_old(emu, uid):
    cf = emu.client('cloudfront')
    acm = emu.client('acm')
    ref = f'ss-test-{uid}'
    certArn = acm.request_certificate(DomainName=f'{uid}.example.com', ValidationMethod='DNS')['CertificateArn']
    distId = cf.create_distribution(DistributionConfig=_distConfig(ref, ['TLSv1.2']))['Distribution']['Id']
    try:
        # Default *.cloudfront.net certificate: policy not configurable -> not flagged by this check.
        st = runCheck(emu, 'cloudfront', CHECK, distId).statuses()
        assert st and all(s != -1 for s in st.values()), st

        def setViewer(minProto):
            def m(cfg):
                cfg['ViewerCertificate'] = {'ACMCertificateArn': certArn, 'SSLSupportMethod': 'sni-only',
                                            'MinimumProtocolVersion': minProto}
            return m

        assertFlagFixCycle(emu, 'cloudfront', CHECK, distId,
                           lambda: _update(cf, distId, setViewer('TLSv1.2_2019')),
                           lambda: _update(cf, distId, setViewer('TLSv1.2_2021')))
    finally:
        _delete(cf, distId)
        try:
            acm.delete_certificate(CertificateArn=certArn)
        except Exception:
            pass


def test_cloudfront_sslv3_origin_not_duplicated(emu, uid):
    """SSLv3-only origins belong to DeprecatedSSLProtocol; this key must not double-report them."""
    cf = emu.client('cloudfront')
    ref = f'ss-test-{uid}'
    distId = cf.create_distribution(DistributionConfig=_distConfig(ref, ['SSLv3', 'TLSv1.2']))['Distribution']['Id']
    try:
        st = runCheck(emu, 'cloudfront', CHECK, distId).statuses()
        assert st and all(s != -1 for s in st.values()), st
        old = runCheck(emu, 'cloudfront', 'DeprecatedSSLProtocol', distId).statuses()
        assert old and all(s == -1 for s in old.values()), old
    finally:
        _delete(cf, distId)
