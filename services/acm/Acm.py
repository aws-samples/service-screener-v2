import botocore

from utils.Config import Config
from utils.Tools import _pr, _pi
from services.Service import Service

from services.acm.drivers.AcmCommon import AcmCommon
from services.acm.drivers.AcmPcaCa import AcmPcaCa
from services.acm.drivers.AcmPcaAccount import AcmPcaAccount


class Acm(Service):
    """
    AWS Certificate Manager (ACM) service scanner.

    Discovers every certificate in the region via list_certificates. NOTE: the
    default list_certificates response only returns RSA_2048 certificates; we
    must pass an explicit Includes.keyTypes list covering every supported
    algorithm to get a complete inventory. Each certificate is then hydrated
    via describe_certificate and list_tags_for_certificate.
    """

    # Every keyType ACM supports for listing. Without this list, list_certificates
    # silently drops non-RSA_2048 certs (imported RSA_1024/4096, all ECDSA).
    ALL_KEY_TYPES = [
        'RSA_1024', 'RSA_2048', 'RSA_3072', 'RSA_4096',
        'EC_prime256v1', 'EC_secp384r1', 'EC_secp521r1'
    ]

    # Include every certificate lifecycle state; the default omits several.
    ALL_CERT_STATUSES = [
        'PENDING_VALIDATION', 'ISSUED', 'INACTIVE',
        'EXPIRED', 'VALIDATION_TIMED_OUT', 'REVOKED', 'FAILED'
    ]

    def __init__(self, region):
        super().__init__(region)

        ssBoto = self.ssBoto
        self.acmClient = ssBoto.client('acm', config=self.bConfig)
        self.acmCertificates = []

        self.pcaClient = ssBoto.client('acm-pca', config=self.bConfig)
        self.pcaCAs = None          # list of CertificateAuthority dicts (None = could not list)
        self.pcaError = None
        self.acmInUseCount = 0      # ACM certs with InUse=True (None = could not list)
        self.acmError = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        try:
            paginator = self.acmClient.get_paginator('list_certificates')
            page_iterator = paginator.paginate(
                Includes={'keyTypes': self.ALL_KEY_TYPES},
                CertificateStatuses=self.ALL_CERT_STATUSES
            )

            for page in page_iterator:
                summaries = [s for s in page.get('CertificateSummaryList', []) if s.get('CertificateArn')]
                self.acmInUseCount += sum(1 for s in summaries if s.get('InUse') is True)
                pendingArns = {s['CertificateArn'] for s in self.registerItems(
                    'AcmCommon', summaries, idFn=lambda s: s['CertificateArn']
                )}

                for summary in summaries:
                    arn = summary['CertificateArn']

                    if arn not in pendingArns:
                        ## Already checkpointed - keep the lightweight summary so advise()
                        ## still builds the driver and Evaluator.run() serves the cached result.
                        self.acmCertificates.append(summary)
                        continue

                    detail = self._describeCertificate(arn)
                    if detail is None:
                        continue

                    # Optional tag filtering (must be evaluated after we
                    # have the tag list).
                    if self.tags:
                        nTags = self.convertKeyPairTagToTagFormat(
                            {t['Key']: t.get('Value', '') for t in detail.get('_Tags', [])}
                        )
                        if self.resourceHasTags(nTags) is False:
                            continue

                    self.acmCertificates.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_certificates', e)
            self.acmInUseCount = None
            self.acmError = e.response.get('Error', {}).get('Code', 'Unknown')
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ACM not available in region {self.region}: {e}")
            self.acmInUseCount = None
            self.acmError = 'EndpointConnectionError'

    def getPrivateCAs(self):
        """List AWS Private CAs owned by this account (read-only) and hydrate
        each via describe_certificate_authority. Sets self.pcaCAs to None and
        self.pcaError on failure so checks report 'Unable to evaluate'."""
        cas = []
        try:
            paginator = self.pcaClient.get_paginator('list_certificate_authorities')
            for page in paginator.paginate(ResourceOwner='SELF'):
                cas.extend(c for c in page.get('CertificateAuthorities', []) if c.get('Arn'))
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_certificate_authorities', e)
            self.pcaError = e.response.get('Error', {}).get('Code', 'Unknown')
            return
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ACM PCA not available in region {self.region}: {e}")
            self.pcaError = 'EndpointConnectionError'
            return

        self.pcaCAs = cas

    def _describeCA(self, summary):
        """Fresh describe_certificate_authority; falls back to the list entry
        (same shape) when describe fails."""
        arn = summary['Arn']
        try:
            return self.pcaClient.describe_certificate_authority(
                CertificateAuthorityArn=arn).get('CertificateAuthority') or summary
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_certificate_authority({arn})', e)
            return summary

    def _caHasTags(self, arn):
        tags = {}
        try:
            for page in self.pcaClient.get_paginator('list_tags').paginate(CertificateAuthorityArn=arn):
                for t in page.get('Tags', []) or []:
                    tags[t['Key']] = t.get('Value', '')
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags({arn})', e)
            return False
        return self.resourceHasTags(self.convertKeyPairTagToTagFormat(tags)) is not False

    def _describeCertificate(self, arn):
        """Fetch full certificate metadata + tags. Returns dict or None on error."""
        try:
            resp = self.acmClient.describe_certificate(CertificateArn=arn)
            detail = resp.get('Certificate') or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_certificate({arn})', e)
            return None

        try:
            tagsResp = self.acmClient.list_tags_for_certificate(CertificateArn=arn)
            detail['_Tags'] = tagsResp.get('Tags', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_certificate({arn})', e)
            detail['_Tags'] = []

        return detail

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        self.getResources()

        for cert in self.acmCertificates:
            arn = cert.get('CertificateArn', 'unknown')
            identifier = cert.get('DomainName') or arn
            _pi('ACM', f"{identifier} ({arn})")

            try:
                obj = AcmCommon(cert, self.acmClient)
                obj.run(self.__class__)
                objs[f"ACM::{arn}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing ACM certificate {arn}: {e}")

        self.getPrivateCAs()

        ## Account/region-level Private CA posture: computed over all owned CAs
        ## (not tag-filtered, the finding is about the account).
        try:
            obj = AcmPcaAccount(self.pcaCAs, self.pcaError, self.acmInUseCount, self.acmError, self.region)
            obj.run(self.__class__)
            objs["ACM::PrivateCA::Account"] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing ACM PCA account checks: {e}")

        if self.pcaCAs:
            pending = {c['Arn'] for c in self.registerItems('AcmPcaCa', self.pcaCAs, idFn=lambda c: c['Arn'])}
            for summary in self.pcaCAs:
                arn = summary['Arn']
                if arn in pending:
                    if self.tags and not self._caHasTags(arn):
                        continue
                    ca = self._describeCA(summary)
                else:
                    ca = summary
                _pi('ACM PCA', arn)
                try:
                    obj = AcmPcaCa(ca, self.pcaClient)
                    obj.run(self.__class__)
                    objs[f"ACMPCA::{arn}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing ACM PCA {arn}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Acm {where}: {code} - {msg}")


if __name__ == "__main__":
    Config.init()
    o = Acm('ap-southeast-1')
    out = o.advise()
