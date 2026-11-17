"""
Flag -> fix -> re-run tests for accessanalyzer checks, using botocore Stubber
around real boto3 clients (real API request/response shapes are validated).

Why Stubber and not the AWS Emulator:
- aaUnusedAccessFindingsOpen: accessanalyzer.list_findings_v2 is NotImplemented
  in the emulator, and the emulator never generates unused-access findings.
- ramOrgSharingDisabled: organizations.list_aws_service_access_for_organization
  is NotImplemented, and a member / delegated-admin caller cannot be modelled.
- ramSharesNotPromoted: the emulator only creates STANDARD shares (a
  CREATED_FROM_POLICY share cannot be produced) and
  promote_resource_share_created_from_policy is NotImplemented.
- ramShareExternalPrincipals: the emulator always reports the 'external' flag
  and does not implement organizations.list_accounts, so the fallback path
  (org account list / 12-digit account != self) is covered here. The main
  path is in tests/emulator/test_emu_accessanalyzer.py.

No network is used: clients carry fake credentials and every call is served
by a Stubber (an unexpected call fails the test).
"""
import datetime
import os
import sys

import boto3
from botocore.stub import Stubber

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from utils.Config import Config  # noqa: E402
from services.accessanalyzer.drivers.AccessanalyzerCommon import AccessanalyzerCommon  # noqa: E402
from services.accessanalyzer.drivers.AccessanalyzerRamShare import AccessanalyzerRamShare  # noqa: E402

SELF = '111111111111'
MEMBER = '222222222222'
OUTSIDER = '999999999999'
ORG_ID = 'o-abcdefghij'
UNUSED_ARN = f'arn:aws:access-analyzer:us-east-1:{SELF}:analyzer/unused'
SHARE_ARN = f'arn:aws:ram:us-east-1:{SELF}:resource-share/11111111-2222-3333-4444-555555555555'
NOW = datetime.datetime.now(datetime.timezone.utc)


def _client(name):
    return boto3.session.Session(aws_access_key_id='AKIDSTUBONLY', aws_secret_access_key='stub',
                                 region_name='us-east-1').client(name)


def _setConfig(account=SELF, regions=('us-east-1',)):
    Config.set('stsInfo', {'Account': account})
    Config.set('REGIONS_SELECTED', list(regions))


def _detail(analyzers):
    return {'_region': 'us-east-1', '_analyzers': analyzers, '_activeExternalFindings': None,
            '_findingsCapped': False, '_archiveRuleCount': 0}


UNUSED_ANALYZER = {'arn': UNUSED_ARN, 'name': 'unused', 'type': 'ACCOUNT_UNUSED_ACCESS',
                   'createdAt': NOW, 'status': 'ACTIVE'}


def _finding(fid, ftype, ageDays, status='ACTIVE'):
    created = NOW - datetime.timedelta(days=ageDays)
    return {'id': fid, 'findingType': ftype, 'status': status, 'createdAt': created,
            'analyzedAt': created, 'updatedAt': created, 'resourceType': 'AWS::IAM::Role',
            'resource': f'arn:aws:iam::{SELF}:role/{fid}', 'resourceOwnerAccount': SELF}


def _runUnused(findingsPages, analyzers=(UNUSED_ANALYZER,), error=None):
    _setConfig()
    aa = _client('accessanalyzer')
    with Stubber(aa) as st:
        params = {'analyzerArn': UNUSED_ARN, 'filter': {'status': {'eq': ['ACTIVE']}}, 'maxResults': 100}
        if error:
            st.add_client_error('list_findings_v2', service_error_code=error, expected_params=params)
        for i, page in enumerate(findingsPages):
            resp = {'findings': page}
            p = dict(params)
            if i > 0:
                p['nextToken'] = f't{i}'
            if i < len(findingsPages) - 1:
                resp['nextToken'] = f't{i + 1}'
            st.add_response('list_findings_v2', resp, p)
        obj = AccessanalyzerCommon(_detail(list(analyzers)), aa)
        obj._checkAaUnusedAccessFindingsOpen()
        st.assert_no_pending_responses()
    return obj.results['aaUnusedAccessFindingsOpen']


# ---------------------------------------------------------------- #
# aaUnusedAccessFindingsOpen
# ---------------------------------------------------------------- #
def test_unused_findings_flag_fix():
    flagged = _runUnused([[_finding('old-role', 'UnusedIAMRole', 45)],
                          [_finding('new-perm', 'UnusedPermission', 3)]])
    assert flagged[0] == -1, flagged
    assert 'old-role' in flagged[1]

    fixed = _runUnused([[_finding('new-perm', 'UnusedPermission', 3)]])
    assert fixed[0] == 1, fixed

    empty = _runUnused([[]])
    assert empty[0] == 1, empty


def test_unused_findings_ignores_non_unused_types():
    res = _runUnused([[_finding('ext', 'ExternalAccess', 90)]])
    assert res[0] != -1, res


def test_unused_findings_access_denied_is_not_pass():
    res = _runUnused([], error='AccessDeniedException')
    assert res == [0, 'Unable to evaluate (AccessDeniedException)']


def test_unused_findings_no_unused_analyzer_is_info():
    _setConfig()
    obj = AccessanalyzerCommon(_detail([{'arn': 'x', 'name': 'ext', 'type': 'ACCOUNT', 'status': 'ACTIVE'}]),
                               _client('accessanalyzer'))
    obj._checkAaUnusedAccessFindingsOpen()
    assert obj.results['aaUnusedAccessFindingsOpen'][0] == 0


# ---------------------------------------------------------------- #
# ramOrgSharingDisabled
# ---------------------------------------------------------------- #
def _org(mgmt=SELF):
    return {'Organization': {
        'Id': ORG_ID, 'Arn': f'arn:aws:organizations::{mgmt}:organization/{ORG_ID}', 'FeatureSet': 'ALL',
        'MasterAccountArn': f'arn:aws:organizations::{mgmt}:account/{ORG_ID}/{mgmt}',
        'MasterAccountId': mgmt, 'MasterAccountEmail': 'mgmt@example.com'}}


def _runOrg(principals=None, account=SELF, error=None, describeError=None, regions=('us-east-1',)):
    _setConfig(account=account, regions=regions)
    org = _client('organizations')
    with Stubber(org) as st:
        if describeError:
            st.add_client_error('describe_organization', service_error_code=describeError)
        else:
            st.add_response('describe_organization', _org())
            if error:
                st.add_client_error('list_aws_service_access_for_organization', service_error_code=error)
            else:
                st.add_response('list_aws_service_access_for_organization', {'EnabledServicePrincipals': [
                    {'ServicePrincipal': p, 'DateEnabled': NOW} for p in principals]})
        obj = AccessanalyzerCommon(_detail([]), _client('accessanalyzer'), org)
        obj._checkRamOrgSharingDisabled()
        st.assert_no_pending_responses()
    return obj.results.get('ramOrgSharingDisabled')


def test_ram_org_sharing_flag_fix():
    flagged = _runOrg(['access-analyzer.amazonaws.com'])
    assert flagged[0] == -1, flagged
    fixed = _runOrg(['access-analyzer.amazonaws.com', 'ram.amazonaws.com'])
    assert fixed[0] == 1, fixed


def test_ram_org_sharing_member_account_not_evaluable():
    assert _runOrg(account=MEMBER, error='AccessDeniedException') == [0, 'Not evaluable from member account']


def test_ram_org_sharing_not_in_org():
    res = _runOrg(describeError='AWSOrganizationsNotInUseException')
    assert res[0] == 0, res


def test_ram_org_sharing_mgmt_error_unable_to_evaluate():
    assert _runOrg(error='TooManyRequestsException') == [0, 'Unable to evaluate (TooManyRequestsException)']


def test_ram_org_sharing_reported_once_not_per_region():
    _setConfig(regions=('ap-southeast-1', 'us-east-1'))
    obj = AccessanalyzerCommon(_detail([]), _client('accessanalyzer'), _client('organizations'))
    obj._checkRamOrgSharingDisabled()   # us-east-1 is not the first region: no API call, no result
    assert 'ramOrgSharingDisabled' not in obj.results


# ---------------------------------------------------------------- #
# RAM share checks
# ---------------------------------------------------------------- #
def _share(allowExternal=True, featureSet='STANDARD'):
    return {'resourceShareArn': SHARE_ARN, 'name': 'share', 'owningAccountId': SELF,
            'allowExternalPrincipals': allowExternal, 'status': 'ACTIVE', 'featureSet': featureSet}


def _assoc(entity, status='ASSOCIATED', external=None):
    a = {'resourceShareArn': SHARE_ARN, 'resourceShareName': 'share', 'associatedEntity': entity,
         'associationType': 'PRINCIPAL', 'status': status}
    if external is not None:
        a['external'] = external
    return a


def _runShare(share, assocs=None, orgAccounts=None, error=None):
    ram = _client('ram')
    with Stubber(ram) as st:
        if share.get('allowExternalPrincipals'):
            params = {'associationType': 'PRINCIPAL', 'resourceShareArns': [SHARE_ARN]}
            if error:
                st.add_client_error('get_resource_share_associations', service_error_code=error,
                                    expected_params=params)
            else:
                st.add_response('get_resource_share_associations',
                                {'resourceShareAssociations': assocs or []}, params)
        obj = AccessanalyzerRamShare(share, ram, SELF, (lambda: orgAccounts))
        obj._checkRamShareExternalPrincipals()
        st.assert_no_pending_responses()
    return obj.results['ramShareExternalPrincipals']


def test_ram_external_flag_fix_with_external_flag():
    assert _runShare(_share(), [_assoc(OUTSIDER, external=True)])[0] == -1
    # fix: external principal removed (only an org member remains)
    assert _runShare(_share(), [_assoc(OUTSIDER, 'DISASSOCIATED', True), _assoc(MEMBER, external=False)])[0] == 1
    # fix: allowExternalPrincipals turned off (no association call needed)
    assert _runShare(_share(allowExternal=False))[0] == 1


def test_ram_external_fallback_org_account_list():
    org = {SELF, MEMBER}
    assert _runShare(_share(), [_assoc(OUTSIDER)], orgAccounts=org)[0] == -1
    assert _runShare(_share(), [_assoc(f'arn:aws:iam::{OUTSIDER}:role/x')], orgAccounts=org)[0] == -1
    assert _runShare(_share(), [_assoc(MEMBER)], orgAccounts=org)[0] == 1


def test_ram_external_fallback_without_org_list():
    assert _runShare(_share(), [_assoc(MEMBER)])[0] == -1          # cannot prove in-org: any other account
    assert _runShare(_share(), [_assoc(SELF)])[0] == 1
    assert _runShare(_share(), [_assoc(f'arn:aws:organizations::{SELF}:ou/{ORG_ID}/ou-ab12-1')])[0] == 1


def test_ram_external_unable_to_evaluate():
    assert _runShare(_share(), error='AccessDeniedException') == [0, 'Unable to evaluate (AccessDeniedException)']


def test_ram_shares_not_promoted_flag_fix():
    def run(fs):
        obj = AccessanalyzerRamShare(_share(featureSet=fs), _client('ram'), SELF)
        obj._checkRamSharesNotPromoted()
        return obj.results['ramSharesNotPromoted'][0]
    assert run('CREATED_FROM_POLICY') == -1
    assert run('PROMOTING_TO_STANDARD') == 0
    assert run('STANDARD') == 1
