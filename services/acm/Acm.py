import botocore

from utils.Config import Config
from utils.Tools import _pr, _pi
from services.Service import Service

from services.acm.drivers.AcmCommon import AcmCommon


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
                for summary in page.get('CertificateSummaryList', []):
                    arn = summary.get('CertificateArn')
                    if not arn:
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
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ACM not available in region {self.region}: {e}")

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
