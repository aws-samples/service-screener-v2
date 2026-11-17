import re

import botocore

from services.Evaluator import Evaluator


class LambdaCodeSigningConfig(Evaluator):
    """Per code-signing-config checks.

      - signerProfileInvalid (S/L) The config's AllowedPublishers trust a signing
        profile version that is Revoked, Canceled or no longer exists (same account).
        Older (non-current) trusted versions and cross-account not-found are not
        evaluable (0) because their status cannot be read.

    Input:
      csc          -- item from lambda.list_code_signing_configs
      signerClient -- boto3 signer client for the same region
    """

    PROFILE_VERSION_ARN_RE = re.compile(
        r'^arn:(?P<partition>aws[a-z-]*):signer:(?P<region>[^:]*):(?P<account>\d{12}):'
        r'/signing-profiles/(?P<name>[^/]+)/(?P<version>[^/]+)$'
    )

    def __init__(self, csc, signerClient):
        super().__init__()
        self.csc = csc
        self.signerClient = signerClient
        self._resourceName = csc.get('CodeSigningConfigId') or csc.get('CodeSigningConfigArn', 'unknown')
        self.addII('codeSigningConfigArn', csc.get('CodeSigningConfigArn'))

    def _cscAccount(self):
        arn = self.csc.get('CodeSigningConfigArn') or ''
        parts = arn.split(':')
        return parts[4] if len(parts) > 4 else None

    def _checkSignerProfileInvalid(self):
        key = 'signerProfileInvalid'
        arns = ((self.csc.get('AllowedPublishers') or {}).get('SigningProfileVersionArns')) or []
        if not arns:
            self.results[key] = [0, 'No allowed publishers listed']
            return

        clientRegion = self.signerClient.meta.region_name
        ownAccount = self._cscAccount()
        invalid, unknown = [], []
        for arn in arns:
            m = self.PROFILE_VERSION_ARN_RE.match(arn)
            if not m:
                unknown.append('unparseable ARN')
                continue
            name, version = m.group('name'), m.group('version')
            if m.group('region') != clientRegion:
                unknown.append(f'{name} (other region)')
                continue
            crossAccount = bool(ownAccount and m.group('account') != ownAccount)
            kwargs = {'profileName': name}
            if crossAccount:
                kwargs['profileOwner'] = m.group('account')
            try:
                prof = self.signerClient.get_signing_profile(**kwargs)
            except botocore.exceptions.ClientError as e:
                code = e.response['Error']['Code']
                if code == 'ResourceNotFoundException' and not crossAccount:
                    invalid.append(f'{name}/{version} (not found)')
                else:
                    # Cross-account: a profile not shared with this account also
                    # returns not-found, so it cannot be judged from here.
                    unknown.append(f'{name} ({code})')
                continue

            status = prof.get('status')
            currentVersion = prof.get('profileVersion')
            if status == 'Canceled':
                # Cancellation applies to the whole profile (every version).
                invalid.append(f'{name}/{version} (Canceled)')
            elif currentVersion and currentVersion != version:
                # get_signing_profile only describes the current version; the
                # status of an older trusted version cannot be determined.
                unknown.append(f'{name}/{version} (older version; current is {currentVersion})')
            elif status and status != 'Active':
                invalid.append(f'{name}/{version} ({status})')

        if invalid:
            self.results[key] = [-1, 'Trusts invalid signing profile version(s): ' + ', '.join(invalid[:5])]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate (' + ', '.join(unknown[:5]) + ')']
        else:
            self.results[key] = [1, 'All allowed signing profiles are Active']
