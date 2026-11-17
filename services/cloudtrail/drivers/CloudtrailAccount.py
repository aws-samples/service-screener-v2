import botocore
import datetime
import json
import threading

from utils.Config import Config
from services.Evaluator import Evaluator
from services.cloudtrail.drivers.CloudtrailHelper import selectorCoverage, ownedBucketNames, errCode, accountIdFromArn

class CloudtrailAccount(Evaluator):
    def __init__(self, ctClient, sizeofTrail, s3Client=None, cfgClient=None, orgClient=None):
        super().__init__()
        self.ctClient = ctClient
        self.sizeofTrail = sizeofTrail
        self.s3Client = s3Client
        self.cfgClient = cfgClient
        self.orgClient = orgClient
        self._trailCacheLock = threading.Lock()
        self._trailCache = None
        
        self._resourceName = 'General'

        self.init()
    
    ## For General Trail purpose
    def _checkHasOneTrailConfiguredCorrectly(self):
        if self.sizeofTrail == 0:
            self.results['NeedToEnableCloudTrail'] = [-1, '']
        
        if Config.get('CloudTrail_hasOneMultiRegion') == False:
            self.results['HasOneMultiRegionTrail'] = [-1, '']
            
        if Config.get('CloudTrail_hasGlobalServEnabled') == False:
            self.results['HasCoverGlobalServices'] = [-1, '']
            
        if Config.get('CloudTrail_hasManagementEventsCaptured') == False:
            self.results['HasManagementEventsCaptured'] = [-1, '']
        else:
            self.results['HasManagementEventsCaptured'] = [1, '']
        
        if Config.get('CloudTrail_hasDataEventsCaptured') == False:
            self.results['HasDataEventsCaptured'] = [-1, '']
        else:
            self.results['HasDataEventsCaptured'] = [1, '']
            
        lists = Config.get('CloudTrail_listGlobalServEnabled')
        if len(lists) > 1:
            self.results['DuplicateGlobalTrail'] = [-1, '<br>'.join(lists)]

    def _checkGuardDutyIntegration(self):
        """
        Validates that Amazon GuardDuty is enabled for threat detection
        leveraging CloudTrail logs
        """
        try:
            import boto3
            gdClient = boto3.client('guardduty')
            
            # List all detectors in the region
            response = gdClient.list_detectors()
            detectorIds = response.get('DetectorIds', [])
            
            if len(detectorIds) == 0:
                self.results['GuardDutyIntegration'] = [-1, 'No GuardDuty detectors enabled']
                return
            
            # Check if at least one detector is active
            hasActiveDetector = False
            disabledDetectors = []
            
            for detectorId in detectorIds:
                detectorResponse = gdClient.get_detector(DetectorId=detectorId)
                status = detectorResponse.get('Status')
                
                if status == 'ENABLED':
                    hasActiveDetector = True
                    break
                elif status == 'DISABLED':
                    disabledDetectors.append(detectorId)
            
            # Only report if no active detectors found
            if not hasActiveDetector:
                if len(disabledDetectors) > 0:
                    self.results['GuardDutyIntegration'] = [0, f'GuardDuty detector {disabledDetectors[0]} is disabled']
                else:
                    self.results['GuardDutyIntegration'] = [-1, 'All GuardDuty detectors are disabled']
                
        except Exception as e:
            print(f'-- Unable to check GuardDuty integration: {str(e)}')
    
    def _checkSecurityHubIntegration(self):
        """
        Validates that AWS Security Hub is enabled for centralized
        security posture management and CloudTrail monitoring
        """
        try:
            import boto3
            import botocore
            shClient = boto3.client('securityhub')
            
            # Check if Security Hub is enabled
            try:
                response = shClient.describe_hub()
                hubArn = response.get('HubArn')
                
                if not hubArn:
                    self.results['SecurityHubIntegration'] = [-1, 'Security Hub not enabled']
                    return
                
                # Check if any standards are enabled
                standardsResponse = shClient.get_enabled_standards()
                enabledStandards = standardsResponse.get('StandardsSubscriptions', [])
                
                if len(enabledStandards) == 0:
                    self.results['SecurityHubIntegration'] = [0, 'Security Hub enabled but no standards subscribed']
                
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['InvalidAccessException', 'ResourceNotFoundException']:
                    self.results['SecurityHubIntegration'] = [-1, 'Security Hub not enabled']
                else:
                    raise
                
        except Exception as e:
            print(f'-- Unable to check Security Hub integration: {str(e)}')
    
    def _checkIAMFullAccessRestriction(self):
        """
        Identifies IAM users and roles with AWSCloudTrail_FullAccess
        managed policy attached, recommending least privilege access
        """
        try:
            import boto3
            iamClient = boto3.client('iam')
            
            principalsWithFullAccess = []
            fullAccessPolicyArn = 'arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess'
            
            # Check IAM users
            usersPaginator = iamClient.get_paginator('list_users')
            for usersPage in usersPaginator.paginate():
                for user in usersPage.get('Users', []):
                    userName = user['UserName']
                    
                    # Get attached policies for user
                    policiesResponse = iamClient.list_attached_user_policies(UserName=userName)
                    for policy in policiesResponse.get('AttachedPolicies', []):
                        if policy['PolicyArn'] == fullAccessPolicyArn:
                            principalsWithFullAccess.append(f'User: {userName}')
                            break
            
            # Check IAM roles (exclude service-linked roles)
            rolesPaginator = iamClient.get_paginator('list_roles')
            for rolesPage in rolesPaginator.paginate():
                for role in rolesPage.get('Roles', []):
                    roleName = role['RoleName']
                    rolePath = role.get('Path', '/')
                    
                    # Skip service-linked roles
                    if rolePath.startswith('/aws-service-role/'):
                        continue
                    
                    # Get attached policies for role
                    policiesResponse = iamClient.list_attached_role_policies(RoleName=roleName)
                    for policy in policiesResponse.get('AttachedPolicies', []):
                        if policy['PolicyArn'] == fullAccessPolicyArn:
                            principalsWithFullAccess.append(f'Role: {roleName}')
                            break
            
            # Evaluate results
            count = len(principalsWithFullAccess)
            if count >= 5:
                self.results['IAMFullAccessRestriction'] = [-1, f'{count} principals with full access: {", ".join(principalsWithFullAccess[:5])}...']
            elif count > 0:
                self.results['IAMFullAccessRestriction'] = [0, f'{count} principals with full access: {", ".join(principalsWithFullAccess)}']
            
        except Exception as e:
            print(f'-- Unable to check IAM full access restriction: {str(e)}')
    
    def _checkOrganizationTrailEnabled(self):
        """
        Validates that organization trails are configured for centralized
        multi-account logging in AWS Organizations
        """
        try:
            import boto3
            
            # Check if account is in an organization
            try:
                orgClient = boto3.client('organizations')
                orgResponse = orgClient.describe_organization()
                organization = orgResponse.get('Organization')
                
                if not organization:
                    # Not in an organization, skip check
                    return
                
                # Check if this is the management account
                stsClient = boto3.client('sts')
                identity = stsClient.get_caller_identity()
                currentAccountId = identity['Account']
                managementAccountId = organization.get('MasterAccountId')
                
                if currentAccountId != managementAccountId:
                    # Member account, skip check (organization trails are managed by management account)
                    return
                
            except orgClient.exceptions.AWSOrganizationsNotInUseException:
                # Not in an organization, skip check
                return
            except Exception as e:
                if 'AccessDenied' in str(e):
                    # Cannot determine organization status, skip check
                    return
                raise
            
            # Check if any trail is an organization trail
            response = self.ctClient.describe_trails()
            trails = response.get('trailList', [])
            
            hasOrgTrail = False
            for trail in trails:
                if trail.get('IsOrganizationTrail', False):
                    hasOrgTrail = True
                    break
            
            if not hasOrgTrail:
                self.results['OrganizationTrailEnabled'] = [-1, 'No organization trail configured for AWS Organizations']
            
        except Exception as e:
            print(f'-- Unable to check organization trail: {str(e)}')

    ## ---- WAFS2027 checks -------------------------------------------------

    def _accountId(self):
        return (Config.get('stsInfo', {}) or {}).get('Account')

    def _regionTrails(self):
        """All trails that apply to this Region (incl. multi-Region and organization
        shadow trails), each with its logging status and event selector coverage.
        Returns (list, None) or (None, errorCode)."""
        with self._trailCacheLock:
            if self._trailCache is not None:
                return self._trailCache
            try:
                trails = self.ctClient.describe_trails(includeShadowTrails=True).get('trailList', []) or []
            except Exception as e:
                self._trailCache = (None, errCode(e))
                return self._trailCache

            out = []
            for t in trails:
                arn = t.get('TrailARN')
                info = {'trail': t, 'logging': None, 'coverage': None, 'error': None}
                try:
                    st = self.ctClient.get_trail_status(Name=arn)
                    info['logging'] = st.get('IsLogging') is True
                except Exception as e:
                    info['error'] = errCode(e)
                try:
                    sel = self.ctClient.get_event_selectors(TrailName=arn)
                    info['coverage'] = selectorCoverage(sel)
                except Exception as e:
                    info['error'] = info['error'] or errCode(e)
                out.append(info)
            self._trailCache = (out, None)
            return self._trailCache

    def _checkCloudtrailExcludesKmsEvents(self):
        """
        KMS key usage (Decrypt, GenerateDataKey, ScheduleKeyDeletion, ...) must be
        auditable. Flags the Region when every logging trail that captures management
        events excludes kms.amazonaws.com (basic ExcludeManagementEventSources or an
        advanced selector on eventSource).
        """
        key = 'cloudtrailExcludesKmsEvents'
        trails, code = self._regionTrails()
        if trails is None:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(code)]
            return

        mgmt, excluding, unknown = [], [], []
        for t in trails:
            name = t['trail'].get('Name') or t['trail'].get('TrailARN')
            if t['logging'] is False:
                continue
            if t['logging'] is None or t['coverage'] is None:
                unknown.append('{} ({})'.format(name, t['error']))
                continue
            if not t['coverage']['management']:
                continue
            mgmt.append(name)
            if t['coverage']['kms']:
                self.results[key] = [1, 'Trail {} logs KMS management events'.format(name)]
                return
            if t['coverage'].get('kmsAmbiguous'):
                unknown.append('{} (selector with several positive operators on eventSource)'.format(name))
                continue
            excluding.append(name)

        if unknown:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(', '.join(unknown))]
            return
        if not mgmt:
            self.results[key] = [0, 'No logging trail captures management events in this Region']
            return
        self.results[key] = [-1, 'KMS events excluded by: {}'.format(', '.join(excluding))]

    _ownTrailMemoLock = threading.Lock()

    def _countOwnTrailHere(self, t, region, accountId):
        """Evaluate each of this account's trails once per scan. Normally that is its
        home Region. A multi-Region trail whose home Region is not part of the scan
        (e.g. --regions subset) is counted in the first scanned Region where it is
        visible, so it is not hidden (false PASS). Memoised per account."""
        home = t.get('HomeRegion') or region
        if home == region:
            return True
        if not t.get('IsMultiRegionTrail'):
            return False
        selected = Config.get('REGIONS_SELECTED', None)
        if isinstance(selected, (list, tuple, set)) and home in selected:
            return False  # counted when its home Region is scanned
        memoKey = 'CloudTrail_ownTrailCounted::' + accountId
        arn = t.get('TrailARN') or t.get('Name')
        with CloudtrailAccount._ownTrailMemoLock:
            seen = Config.get(memoKey, None) or set()
            if arn in seen:
                return False
            seen = set(seen)
            seen.add(arn)
            Config.set(memoKey, seen)
        return True

    def _checkTrailBucketSameAccount(self):
        """
        In a multi-account (AWS Organizations) environment, CloudTrail and AWS Config
        logs should be delivered to a dedicated log archive account so that a
        compromised workload account cannot tamper with its own audit trail.
        """
        key = 'trailBucketSameAccount'
        if self.orgClient is None or self.s3Client is None:
            self.results[key] = [0, 'Unable to evaluate (no client)']
            return

        try:
            self.orgClient.describe_organization()
        except Exception as e:
            c = errCode(e)
            if c == 'AWSOrganizationsNotInUseException':
                self.results[key] = [0, 'Standalone account (not in AWS Organizations); log archive separation not evaluated']
            else:
                self.results[key] = [0, 'Unable to evaluate ({})'.format(c)]
            return

        accountId = self._accountId()
        if not accountId:
            self.results[key] = [0, 'Unable to evaluate (unknown account id)']
            return

        owned, code = ownedBucketNames(self.s3Client)
        if owned is None:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(code)]
            return

        try:
            trails = self.ctClient.describe_trails(includeShadowTrails=True).get('trailList', []) or []
        except Exception as e:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(errCode(e))]
            return

        own, foreign = [], []
        region = self.ctClient.meta.region_name
        for t in trails:
            if accountIdFromArn(t.get('TrailARN')) == accountId:
                if self._countOwnTrailHere(t, region, accountId):
                    own.append(t)
            else:
                foreign.append(t)

        # Organization trails owned by another account that deliver into a bucket of
        # this account: this account is the log archive, so local delivery is expected.
        # The result is memoised per account for the scan, because a single-Region
        # organization trail is only visible in its home Region.
        memoKey = 'CloudTrail_logArchive::' + accountId
        for t in foreign:
            if t.get('S3BucketName') in owned:
                Config.set(memoKey, t.get('Name'))
                break
        archiveOf = Config.get(memoKey, None)
        if archiveOf:
            self.results[key] = [1, 'This account appears to be the log archive account (receives trail {})'.format(archiveOf)]
            return

        flagged = []
        for t in own:
            b = t.get('S3BucketName')
            if b and b in owned:
                flagged.append('trail {} -> {}'.format(t.get('Name'), b))

        cfgError = None
        cfgChannels = 0
        if self.cfgClient is not None:
            try:
                for ch in self.cfgClient.describe_delivery_channels().get('DeliveryChannels', []) or []:
                    cfgChannels += 1
                    b = ch.get('s3BucketName')
                    if b and b in owned:
                        flagged.append('Config channel {} -> {}'.format(ch.get('name'), b))
            except Exception as e:
                cfgError = errCode(e)

        if flagged:
            self.results[key] = [-1, '; '.join(flagged)]
        elif cfgError:
            self.results[key] = [0, 'Unable to evaluate AWS Config delivery channel ({})'.format(cfgError)]
        elif own or cfgChannels:
            self.results[key] = [1, 'Logs are delivered to buckets outside this account']
        elif foreign:
            self.results[key] = [1, 'Account is covered by an organization trail owned by another account']
        else:
            self.results[key] = [0, 'No trail or AWS Config delivery channel in this Region']

    CONSOLE_LOOKBACK_DAYS = 30
    CONSOLE_MAX_EVENTS = 250

    def _checkManualConsoleWritesDetected(self):
        """
        Heuristic (tier 3): write API calls made from an AWS Management Console session
        in the last 30 days in this Region indicate changes made outside a deployment
        pipeline. Samples at most CONSOLE_MAX_EVENTS recent write events, because
        LookupEvents is limited to 2 requests per second per Region.
        """
        key = 'manualConsoleWritesDetected'
        now = datetime.datetime.now(datetime.timezone.utc)
        start = now - datetime.timedelta(days=self.CONSOLE_LOOKBACK_DAYS)
        seen = 0
        hits = {}
        capped = False
        try:
            pages = self.ctClient.get_paginator('lookup_events').paginate(
                LookupAttributes=[{'AttributeKey': 'ReadOnly', 'AttributeValue': 'false'}],
                StartTime=start, EndTime=now,
                PaginationConfig={'MaxItems': self.CONSOLE_MAX_EVENTS, 'PageSize': 50})
            for page in pages:
                for ev in page.get('Events', []) or []:
                    seen += 1
                    try:
                        rec = json.loads(ev.get('CloudTrailEvent') or '{}')
                    except ValueError:
                        continue
                    if rec.get('eventType') != 'AwsApiCall':
                        continue
                    if str(rec.get('readOnly')).lower() == 'true':
                        continue
                    if str(rec.get('sessionCredentialFromConsole')).lower() != 'true':
                        continue
                    # Calls made by an AWS service on the user's behalf are not manual changes.
                    if (rec.get('userIdentity') or {}).get('invokedBy'):
                        continue
                    who = (rec.get('userIdentity') or {}).get('arn') or ev.get('Username') or 'unknown'
                    hits.setdefault(who, set()).add(rec.get('eventSource', '') + ':' + (rec.get('eventName') or ev.get('EventName') or ''))
            capped = seen >= self.CONSOLE_MAX_EVENTS
        except Exception as e:
            self.results[key] = [0, 'Unable to evaluate ({})'.format(errCode(e))]
            return

        if hits:
            parts = []
            for who in sorted(hits)[:5]:
                parts.append('{}: {}'.format(who, ', '.join(sorted(hits[who])[:5])))
            self.results[key] = [-1, '{} principal(s) made console write calls: {}'.format(len(hits), '; '.join(parts))]
        elif capped:
            self.results[key] = [0, 'No console write calls in the {} most recent write events (sample only)'.format(seen)]
        else:
            self.results[key] = [1, 'No console write calls in the last {} days ({} write events)'.format(self.CONSOLE_LOOKBACK_DAYS, seen)]
