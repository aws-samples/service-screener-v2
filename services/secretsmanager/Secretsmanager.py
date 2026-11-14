import botocore

from utils.Tools import _pi
from services.Service import Service

from services.secretsmanager.drivers.SecretsmanagerCommon import SecretsmanagerCommon


class Secretsmanager(Service):
    """
    AWS Secrets Manager service scanner.

    Discovers every secret in the region via list_secrets (paginated, including
    secrets scheduled for deletion) then hydrates each with:
      - describe_secret        (rotation, KMS key, dates, versions, replication, tags)
      - get_resource_policy    (resource-based policy for the public/cross-account checks)

    list_secrets already returns most of describe_secret's fields, but not
    VersionIdsToStages, so describe_secret is still required per secret.
    """

    # Error codes that mean "you are not allowed to see this" — swallowed quietly
    # so a least-privilege scan does not spam the console.
    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.smClient = ssBoto.client('secretsmanager', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        secrets = []
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            # IncludePlannedDeletion surfaces secrets with DeletedDate set, which
            # smPendingDeletion needs; without it they are invisible to the scan.
            for page in paginator.paginate(IncludePlannedDeletion=True):
                summaries = page.get('SecretList', []) or []
                pendingNames = {s.get('Name') for s in self.registerItems(
                    'SecretsmanagerCommon', summaries, idFn=lambda s: s.get('Name')
                )}

                for summary in summaries:
                    arn = summary.get('ARN')
                    name = summary.get('Name')
                    if not arn or not name:
                        continue

                    if name not in pendingNames:
                        ## Already checkpointed - a light stand-in carrying just the
                        ## synthetic keys advise()/the driver need, so we skip
                        ## describe_secret/get_resource_policy for this secret.
                        secrets.append({'_name': name, '_arn': arn})
                        continue

                    detail = self._describeSecret(arn, name, summary)
                    if detail is None:
                        continue
                    _pi('Secretsmanager', f"Secret: {detail.get('_name', name)}")
                    secrets.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_secrets', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Secrets Manager not available in region {self.region}: {e}")
        except botocore.exceptions.ParamValidationError:
            # Older botocore without IncludePlannedDeletion — retry unfiltered.
            secrets = self._getResourcesLegacy()
        return secrets

    def _getResourcesLegacy(self):
        """Fallback discovery for botocore versions predating IncludePlannedDeletion."""
        secrets = []
        try:
            paginator = self.smClient.get_paginator('list_secrets')
            for page in paginator.paginate():
                for summary in page.get('SecretList', []) or []:
                    arn = summary.get('ARN')
                    name = summary.get('Name')
                    if not arn or not name:
                        continue
                    detail = self._describeSecret(arn, name, summary)
                    if detail is None:
                        continue
                    secrets.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_secrets', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return secrets

    def _describeSecret(self, arn, name, summary):
        """Build a single secret descriptor dict with everything the driver needs."""
        detail = {}
        try:
            resp = self.smClient.describe_secret(SecretId=arn)
            detail = {k: v for k, v in resp.items() if k != 'ResponseMetadata'}
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('ResourceNotFoundException',):
                return None
            self._logClientError(f'describe_secret({name})', e)
            # Fall back to the list_secrets summary — it carries most fields.
            detail = {k: v for k, v in (summary or {}).items()}

        # Optional --filters tag filtering
        tags = detail.get('Tags') or []
        if self.tags and not self.resourceHasTags(tags):
            return None

        detail['_arn'] = arn
        detail['_name'] = name
        detail['_tags'] = tags
        detail['_resourcePolicy'] = self._getResourcePolicy(arn, name)
        detail['_currentAccount'] = self._currentAccount()
        detail['_region'] = self.region
        return detail

    def _getResourcePolicy(self, arn, name):
        """Return the resource policy JSON string, or None when none is attached."""
        try:
            resp = self.smClient.get_resource_policy(SecretId=arn)
            return resp.get('ResourcePolicy')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # A secret scheduled for deletion rejects this call; no policy is
            # also reported as an empty body rather than an error, but guard both.
            if code in ('ResourceNotFoundException', 'InvalidRequestException',
                        'InvalidParameterException'):
                return None
            self._logClientError(f'get_resource_policy({name})', e)
            return None

    def _currentAccount(self):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        secrets = self.getResources()

        for secret in secrets:
            try:
                name = secret.get('_name', 'unknown')
                _pi('Secretsmanager', f"Analyzing: {name}")
                obj = SecretsmanagerCommon(secret, self.smClient)
                obj.run(self.__class__)
                objs[f"Secretsmanager::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing secret {secret.get('_arn')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Secretsmanager {where}: {code} - {msg}")
