import json
import re

import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.cognito.drivers.CognitoCommon import CognitoCommon
from services.cognito.drivers.CognitoIdentityPool import CognitoIdentityPool
from services.cognito.drivers.CognitoAccount import CognitoAccount


class Cognito(Service):
    """
    Amazon Cognito (User Pools) service scanner.

    Discovers every user pool in the region via list_user_pools (paginated),
    hydrates each with:
      - describe_user_pool     (MFA / password policy / advanced security /
                                deletion protection / recovery settings /
                                lambda triggers / auto-verified attributes /
                                device configuration / user pool tags)
      - list_user_pool_clients (paginated) + describe_user_pool_client for each
                                (token validity, needed by the token-validity
                                check that operates on the pool level).

    Identity pools (Cognito Federated Identities, cognito-identity) are
    discovered via list_identity_pools and evaluated by CognitoIdentityPool
    (guest-role breadth, role mapping). CognitoAccount runs once per region
    (identity-store sprawl across user pools).
    """

    IDENTITY_POOL_METHODS = ('cognitoidentitypoolguestrolebroad', 'cognitoidentitypoolnorolemapping')
    ALARM_METHODS = ('cognitonoauthmetricalarm',)
    ACCOUNT_METHODS = ('cognitoperappidentitysilos',)
    ERROR_CODES_DENIED = ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                          'NotAuthorizedException')

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cognitoClient = ssBoto.client('cognito-idp', config=self.bConfig)
        # WAFv2 for user-pool WebACL association lookup (Cognito user pools
        # are REGIONAL resources so this client runs in the target region).
        self.wafClient = ssBoto.client('wafv2', config=self.bConfig)
        # IAM for evaluating group-role policies (check #36).
        self.iamClient = ssBoto.client('iam', config=self.bConfig)
        self.identityClient = ssBoto.client('cognito-identity', config=self.bConfig)
        self.cwClient = ssBoto.client('cloudwatch', config=self.bConfig)
        # poolId -> first error code seen while listing app clients / IdPs
        self._enumErrors = {}
        # user-pool summaries whose describe_user_pool failed
        self._skippedPools = []
        self._listPoolsError = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        pools = []
        try:
            paginator = self.cognitoClient.get_paginator('list_user_pools')
            # MaxResults must be 1..60 for list_user_pools
            for page in paginator.paginate(MaxResults=60):
                summaries = page.get('UserPools', [])
                pendingIds = {s.get('Id') for s in self.registerItems(
                    ## idFn must match CognitoCommon._resourceName exactly (Name, falling back to Id)
                    'CognitoCommon', summaries, idFn=lambda s: s.get('Name') or s.get('Id') or 'unknown'
                )}

                for summary in summaries:
                    poolId = summary.get('Id')
                    if not poolId:
                        continue

                    if poolId not in pendingIds:
                        ## Already checkpointed - keep the lightweight summary, skip
                        ## describe_user_pool plus every per-pool enrichment call below
                        ## (app clients, risk config, WAF association, log config,
                        ## identity providers, groups). CognitoCommon.__init__ is lazy
                        ## (.get()-only), and Evaluator.run() never executes checks for
                        ## an already-checkpointed pool, so none of that data is read.
                        pools.append(summary)
                        continue

                    detail = self._describeUserPool(poolId)
                    if detail is None:
                        self._skippedPools.append(summary)
                        continue

                    # Tag filtering (respects --tags flag). Cognito returns
                    # tags as a dict inside UserPoolTags.
                    tagList = self._userPoolTagsAsList(detail.get('UserPoolTags') or {})
                    if self.tags and not self.resourceHasTags(tagList):
                        continue
                    detail['_tagList'] = tagList

                    detail['_appClients'] = self._listAppClients(poolId)
                    detail['_riskConfiguration'] = self._describeRiskConfiguration(poolId)
                    detail['_wafWebAclArn'] = self._getAssociatedWebAcl(detail.get('Arn'))
                    detail['_logConfig'] = self._getLogDeliveryConfig(poolId)
                    detail['_identityProviders'] = self._listIdentityProviders(poolId)
                    detail['_groups'] = self._listGroups(poolId)

                    _pi('Cognito', f"User pool: {detail.get('Name', poolId)}")
                    pools.append(detail)
        except botocore.exceptions.ClientError as e:
            self._listPoolsError = self._errCode(e)
            self._logClientError('list_user_pools', e)
        except botocore.exceptions.EndpointConnectionError as e:
            self._listPoolsError = 'EndpointConnectionError'
            print(f"Cognito not available in region {self.region}: {e}")
        return pools

    def _describeUserPool(self, poolId):
        try:
            resp = self.cognitoClient.describe_user_pool(UserPoolId=poolId)
            return resp.get('UserPool')
        except botocore.exceptions.ClientError as e:
            self._noteEnumError(poolId, e)
            self._logClientError(f'describe_user_pool({poolId})', e)
            return None

    def _listAppClients(self, poolId):
        """Return a list of describe_user_pool_client responses for each app client."""
        clients = []
        try:
            paginator = self.cognitoClient.get_paginator('list_user_pool_clients')
            for page in paginator.paginate(UserPoolId=poolId, MaxResults=60):
                for summary in page.get('UserPoolClients', []):
                    clientId = summary.get('ClientId')
                    if not clientId:
                        continue
                    detail = self._describeAppClient(poolId, clientId)
                    if detail is not None:
                        clients.append(detail)
        except botocore.exceptions.ClientError as e:
            self._noteEnumError(poolId, e)
            self._logClientError(f'list_user_pool_clients({poolId})', e)
        return clients

    def _describeAppClient(self, poolId, clientId):
        try:
            resp = self.cognitoClient.describe_user_pool_client(
                UserPoolId=poolId, ClientId=clientId
            )
            return resp.get('UserPoolClient')
        except botocore.exceptions.ClientError as e:
            self._noteEnumError(poolId, e)
            self._logClientError(f'describe_user_pool_client({clientId})', e)
            return None

    @staticmethod
    def _userPoolTagsAsList(tagsDict):
        return [{'Key': k, 'Value': v} for k, v in (tagsDict or {}).items()]

    def _describeRiskConfiguration(self, poolId):
        """Return the pool-level RiskConfiguration dict, or None if not set / not permitted.

        DescribeRiskConfiguration is only meaningful when Advanced Security is
        enabled; when it isn't, AWS returns a mostly-empty response — which
        the driver treats as INFO for the compromised-credentials check.
        """
        try:
            resp = self.cognitoClient.describe_risk_configuration(UserPoolId=poolId)
            return resp.get('RiskConfiguration')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # UserPoolAddOnNotEnabled means Advanced Security is off — return None,
            # driver skips gracefully.
            if code in ('UserPoolAddOnNotEnabledException',
                        'ResourceNotFoundException', 'InvalidParameterException'):
                return None
            self._logClientError(f'describe_risk_configuration({poolId})', e)
            return None

    def _getAssociatedWebAcl(self, poolArn):
        """Return the ARN of a WAFv2 WebACL associated with this user pool, or None."""
        if not poolArn:
            return None
        try:
            resp = self.wafClient.get_web_acl_for_resource(ResourceArn=poolArn)
            wac = resp.get('WebACL') or {}
            return wac.get('ARN')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # WAFNonexistentItemException = no WebACL associated (normal case)
            # WAFInvalidParameterException = resource type not supported in this region
            if code in ('WAFNonexistentItemException',
                        'WAFInvalidParameterException'):
                return None
            self._logClientError(f'wafv2.get_web_acl_for_resource({poolArn})', e)
            return None

    def _getLogDeliveryConfig(self, poolId):
        """Return the pool-level log delivery configuration, or {} if none / not permitted."""
        try:
            resp = self.cognitoClient.get_log_delivery_configuration(
                UserPoolId=poolId
            )
            return resp.get('LogDeliveryConfiguration') or {}
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('ResourceNotFoundException', 'InvalidParameterException'):
                # Older pools or unsupported tiers → treated as "not configured"
                return {}
            self._logClientError(f'get_log_delivery_configuration({poolId})', e)
            return {}

    def _listIdentityProviders(self, poolId):
        """Return the list of DescribeIdentityProvider dicts for this pool."""
        providers = []
        try:
            paginator = self.cognitoClient.get_paginator('list_identity_providers')
            for page in paginator.paginate(UserPoolId=poolId, MaxResults=60):
                for summary in page.get('Providers', []) or []:
                    name = summary.get('ProviderName')
                    if not name:
                        continue
                    try:
                        resp = self.cognitoClient.describe_identity_provider(
                            UserPoolId=poolId, ProviderName=name
                        )
                        p = resp.get('IdentityProvider')
                        if p:
                            providers.append(p)
                    except botocore.exceptions.ClientError as e:
                        self._noteEnumError(poolId, e)
                        self._logClientError(
                            f'describe_identity_provider({poolId}/{name})', e
                        )
        except botocore.exceptions.ClientError as e:
            self._noteEnumError(poolId, e)
            self._logClientError(f'list_identity_providers({poolId})', e)
        return providers

    def _listGroups(self, poolId):
        """Return a list of user-pool group descriptors, each augmented with
        _rolePolicies (list of policy documents) when a RoleArn is set.

        The role policies are fetched inline + attached (attached policies use
        the default policy version). Only same-account roles are inspected;
        cross-account role ARNs are recorded with empty _rolePolicies + a
        _crossAccount flag so the driver can degrade to INFO.
        """
        from utils.Config import Config
        groups = []
        try:
            paginator = self.cognitoClient.get_paginator('list_groups')
            for page in paginator.paginate(UserPoolId=poolId, Limit=60):
                for g in page.get('Groups', []) or []:
                    entry = dict(g)
                    role_arn = g.get('RoleArn')
                    if role_arn:
                        me = (Config.get('stsInfo', {}) or {}).get('Account')
                        parts = role_arn.split(':')
                        acct = parts[4] if len(parts) >= 5 else ''
                        entry['_rolePolicies'] = []
                        entry['_crossAccount'] = bool(me and acct and acct != me)
                        if not entry['_crossAccount']:
                            entry['_rolePolicies'] = self._fetchRolePolicies(role_arn)
                    groups.append(entry)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_groups({poolId})', e)
        return groups

    def _fetchRolePolicies(self, roleArn):
        """Return a list of policy document dicts (parsed JSON) for the role's
        inline + attached policies. Returns [] on any lookup error."""
        import json as _json
        if not roleArn or ':role/' not in roleArn:
            return []
        roleName = roleArn.split(':role/', 1)[1].split('/')[-1]
        docs = []
        try:
            inline_resp = self.iamClient.list_role_policies(RoleName=roleName)
            for policyName in inline_resp.get('PolicyNames', []) or []:
                try:
                    p = self.iamClient.get_role_policy(
                        RoleName=roleName, PolicyName=policyName
                    )
                    doc = p.get('PolicyDocument')
                    if isinstance(doc, str):
                        try: doc = _json.loads(doc)
                        except (ValueError, TypeError): doc = None
                    if isinstance(doc, dict):
                        docs.append(doc)
                except botocore.exceptions.ClientError:
                    continue
            attached_resp = self.iamClient.list_attached_role_policies(RoleName=roleName)
            for p in attached_resp.get('AttachedPolicies', []) or []:
                policyArn = p.get('PolicyArn')
                if not policyArn:
                    continue
                try:
                    pol = self.iamClient.get_policy(PolicyArn=policyArn)
                    versionId = (pol.get('Policy') or {}).get('DefaultVersionId')
                    if not versionId:
                        continue
                    ver = self.iamClient.get_policy_version(
                        PolicyArn=policyArn, VersionId=versionId
                    )
                    doc = (ver.get('PolicyVersion') or {}).get('Document')
                    if isinstance(doc, str):
                        try: doc = _json.loads(doc)
                        except (ValueError, TypeError): doc = None
                    if isinstance(doc, dict):
                        docs.append(doc)
                except botocore.exceptions.ClientError:
                    continue
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code not in ('AccessDenied', 'AccessDeniedException',
                            'NoSuchEntity', 'NoSuchEntityException'):
                self._logClientError(f'iam policy fetch for role {roleName}', e)
        return docs

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        pools = self.getResources()

        if pools and self._wants(self.ALARM_METHODS):
            alarmIndex = self._buildAlarmIndex()
            for pool in pools:
                pool['_alarmIndex'] = alarmIndex

        for pool in pools:
            try:
                name = pool.get('Name') or pool.get('Id') or 'unknown'
                _pi('Cognito', f"Analyzing: {name}")
                obj = CognitoCommon(pool, self.cognitoClient)
                obj.run(self.__class__)
                objs[f"Cognito::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Cognito user pool {pool.get('Id')}: {e}")

        if self._wants(self.IDENTITY_POOL_METHODS):
            for ipool in self.getIdentityPools():
                try:
                    _pi('Cognito', f"Analyzing identity pool: {ipool['_resourceName']}")
                    obj = CognitoIdentityPool(ipool)
                    obj.run(self.__class__)
                    objs[f"CognitoIdentityPool::{ipool['_resourceName']}"] = obj.getInfo()
                    del obj
                except Exception as e:
                    print(f"Error processing Cognito identity pool {ipool.get('IdentityPoolId')}: {e}")

        ## Only emit the region-level silo result when there is something to say
        ## (user pools exist, or their listing failed) - avoids INFO noise in
        ## every empty region.
        if self._wants(self.ACCOUNT_METHODS) and (pools or self._skippedPools or self._listPoolsError):
            try:
                from utils.Checkpoint import Checkpoint
                acct = (Config.get('stsInfo', {}) or {}).get('Account', 'default')
                account = {'_region': self.region, '_pools': [], '_listError': None}
                ## Checkpointed: run() restores the cached result, skip the enumeration.
                if not Checkpoint.isDone(acct, self.__class__.__name__, self.region,
                                         'CognitoAccount', f"Account::{self.region}"):
                    account['_pools'] = self._siloSummary(pools)
                    account['_listError'] = self._listPoolsError
                obj = CognitoAccount(account)
                obj.run(self.__class__)
                objs[f"Cognito::Account::{self.region}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Cognito account checks: {e}")

        return objs

    def _wants(self, methods):
        rules = Config.get(self.RULESPREFIX, []) or []
        return not rules or any(m in rules for m in methods)

    # ------------------------------------------------------------------ #
    # Identity pools (cognito-identity)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _identityPoolResourceName(summary):
        ## Identity pool names are not unique - include the id.
        ## Must match CognitoIdentityPool._resourceName.
        name = summary.get('IdentityPoolName') or 'unknown'
        return f"{name} ({summary.get('IdentityPoolId', '?')})"

    def getIdentityPools(self):
        out = []
        try:
            paginator = self.identityClient.get_paginator('list_identity_pools')
            for page in paginator.paginate(MaxResults=60):
                summaries = page.get('IdentityPools', []) or []
                pendingIds = {s.get('IdentityPoolId') for s in self.registerItems(
                    'CognitoIdentityPool', summaries, idFn=self._identityPoolResourceName
                )}
                for summary in summaries:
                    ipid = summary.get('IdentityPoolId')
                    if not ipid:
                        continue
                    resName = self._identityPoolResourceName(summary)
                    if ipid not in pendingIds:
                        ## Already checkpointed - run() restores cached results.
                        out.append(dict(summary, _resourceName=resName))
                        continue
                    try:
                        detail = self.identityClient.describe_identity_pool(IdentityPoolId=ipid)
                        detail.pop('ResponseMetadata', None)
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'describe_identity_pool({ipid})', e)
                        out.append(dict(summary, _resourceName=resName,
                                        _describeError=self._errCode(e)))
                        continue
                    tagList = self._userPoolTagsAsList(detail.get('IdentityPoolTags') or {})
                    if self.tags and not self.resourceHasTags(tagList):
                        continue
                    detail['_resourceName'] = resName
                    self._hydrateIdentityPool(detail)
                    out.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_identity_pools', e)
            ## Do not let a failed listing look like "no identity pools": record a
            ## region-level placeholder so both identity-pool checks report
            ## 'Unable to evaluate (<code>)'.
            out.append({'IdentityPoolId': f'ListIdentityPools::{self.region}',
                        'IdentityPoolName': 'ListIdentityPools',
                        '_resourceName': f'ListIdentityPools::{self.region}',
                        '_describeError': self._errCode(e)})
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Cognito identity pools not available in region {self.region}: {e}")
        return out

    def _hydrateIdentityPool(self, detail):
        ipid = detail['IdentityPoolId']
        detail['_roles'] = None
        detail['_rolesError'] = None
        detail['_principalTagMaps'] = {}
        detail['_unauthRole'] = None
        try:
            resp = self.identityClient.get_identity_pool_roles(IdentityPoolId=ipid)
            detail['_roles'] = {'Roles': resp.get('Roles') or {},
                                'RoleMappings': resp.get('RoleMappings') or {}}
        except botocore.exceptions.ClientError as e:
            detail['_rolesError'] = self._errCode(e)
            self._logClientError(f'get_identity_pool_roles({ipid})', e)
            return

        roles = detail['_roles']['Roles']
        providers = CognitoIdentityPool.loginProviders(detail)
        ## Principal-tag (ABAC) maps only matter when no role mapping exists and
        ## several sign-in sources share the default authenticated role.
        if (not detail['_roles']['RoleMappings'] and roles.get('authenticated')
                and len(providers) >= 2):
            for prov in sorted(set(providers)):
                detail['_principalTagMaps'][prov] = self._getPrincipalTagMap(ipid, prov)

        unauthArn = roles.get('unauthenticated')
        if detail.get('AllowUnauthenticatedIdentities') and unauthArn:
            detail['_unauthRole'] = self._fetchRoleEvaluation(unauthArn)

    def _getPrincipalTagMap(self, ipid, provider):
        try:
            resp = self.identityClient.get_principal_tag_attribute_map(
                IdentityPoolId=ipid, IdentityProviderName=provider)
            return {'UseDefaults': bool(resp.get('UseDefaults')),
                    'PrincipalTags': resp.get('PrincipalTags') or {}}
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'ResourceNotFoundException':
                return None  # no principal tags configured for this provider
            self._logClientError(f'get_principal_tag_attribute_map({ipid}/{provider})', e)
            return {'_error': code}

    def _policyDocument(self, policyArn):
        pol = self.iamClient.get_policy(PolicyArn=policyArn).get('Policy') or {}
        versionId = pol.get('DefaultVersionId')
        if not versionId:
            return None
        ver = self.iamClient.get_policy_version(PolicyArn=policyArn, VersionId=versionId)
        return self._asDoc((ver.get('PolicyVersion') or {}).get('Document'))

    @staticmethod
    def _asDoc(doc):
        if isinstance(doc, str):
            try:
                from urllib.parse import unquote
                doc = json.loads(unquote(doc))
            except (ValueError, TypeError):
                return None
        return doc if isinstance(doc, dict) else None

    @staticmethod
    def _isAwsManaged(policyArn):
        return ':iam::aws:policy/' in (policyArn or '')

    def _fetchRoleEvaluation(self, roleArn):
        """Collect what is needed to judge a role's breadth (read-only IAM calls).

        Returns {'roleArn', 'roleName', 'crossAccount', 'error', 'policyErrors',
                 'policies': [{'name', 'arn', 'managedByAws', 'document'}],
                 'boundary': None | {'name', 'arn', 'managedByAws', 'document', 'error'}}"""
        res = {'roleArn': roleArn, 'roleName': None, 'crossAccount': False, 'error': None,
               'policyErrors': [], 'policies': [], 'boundary': None}
        if ':role/' not in (roleArn or ''):
            res['error'] = 'InvalidRoleArn'
            return res
        res['roleName'] = roleName = roleArn.split(':role/', 1)[1].split('/')[-1]
        me = (Config.get('stsInfo', {}) or {}).get('Account')
        parts = roleArn.split(':')
        acct = parts[4] if len(parts) >= 5 else ''
        if not me:
            ## Cannot tell whether the role is local; get_role by bare name could
            ## evaluate an unrelated same-named role in the scanning account.
            res['error'] = 'CallerAccountUnknown'
            return res
        if acct and acct != me:
            res['crossAccount'] = True
            return res
        try:
            role = self.iamClient.get_role(RoleName=roleName).get('Role') or {}
            pag = self.iamClient.get_paginator('list_role_policies')
            for page in pag.paginate(RoleName=roleName):
                for pname in page.get('PolicyNames', []) or []:
                    try:
                        doc = self._asDoc(self.iamClient.get_role_policy(
                            RoleName=roleName, PolicyName=pname).get('PolicyDocument'))
                        res['policies'].append({'name': pname, 'arn': None,
                                                'managedByAws': False, 'document': doc})
                    except botocore.exceptions.ClientError as e:
                        res['policyErrors'].append(self._errCode(e))
            pag = self.iamClient.get_paginator('list_attached_role_policies')
            for page in pag.paginate(RoleName=roleName):
                for ap in page.get('AttachedPolicies', []) or []:
                    arn = ap.get('PolicyArn')
                    entry = {'name': ap.get('PolicyName') or (arn or '').split('/')[-1],
                             'arn': arn, 'managedByAws': self._isAwsManaged(arn), 'document': None}
                    try:
                        entry['document'] = self._policyDocument(arn)
                    except botocore.exceptions.ClientError as e:
                        res['policyErrors'].append(self._errCode(e))
                    res['policies'].append(entry)
            pbArn = (role.get('PermissionsBoundary') or {}).get('PermissionsBoundaryArn')
            if pbArn:
                b = {'name': pbArn.split('/')[-1], 'arn': pbArn,
                     'managedByAws': self._isAwsManaged(pbArn), 'document': None, 'error': None}
                try:
                    b['document'] = self._policyDocument(pbArn)
                except botocore.exceptions.ClientError as e:
                    b['error'] = self._errCode(e)
                res['boundary'] = b
        except botocore.exceptions.ClientError as e:
            res['error'] = self._errCode(e)
            self._logClientError(f'iam role evaluation for {roleName}', e)
        return res

    # ------------------------------------------------------------------ #
    # CloudWatch alarms on AWS/Cognito metrics
    # ------------------------------------------------------------------ #
    _ALARM_REF_RE = re.compile(r"\b(?:ALARM|OK|INSUFFICIENT_DATA)\s*\(\s*[\"']?([^\"')]+?)[\"']?\s*\)")

    @staticmethod
    def _alarmHasActions(alarm):
        return bool(alarm.get('ActionsEnabled', True) and alarm.get('AlarmActions'))

    @staticmethod
    def _cognitoDimensionValues(alarm):
        """Dimension values of every AWS/Cognito metric an alarm evaluates."""
        dims = []
        if alarm.get('Namespace') == 'AWS/Cognito':
            dims.extend(alarm.get('Dimensions') or [])
        for q in alarm.get('Metrics') or []:
            m = (q.get('MetricStat') or {}).get('Metric') or {}
            if m.get('Namespace') == 'AWS/Cognito':
                dims.extend(m.get('Dimensions') or [])
        return {d.get('Value') for d in dims if d.get('Value')}

    def _buildAlarmIndex(self):
        """{'error': code|None, 'actioned': {poolId}, 'unactioned': {poolId}}"""
        idx = {'error': None, 'actioned': set(), 'unactioned': set()}
        metricAlarms, composites = [], []
        try:
            pag = self.cwClient.get_paginator('describe_alarms')
            for page in pag.paginate(AlarmTypes=['MetricAlarm', 'CompositeAlarm']):
                metricAlarms.extend(page.get('MetricAlarms', []) or [])
                composites.extend(page.get('CompositeAlarms', []) or [])
        except botocore.exceptions.ClientError as e:
            idx['error'] = self._errCode(e)
            self._logClientError('cloudwatch.describe_alarms', e)
            return idx
        except botocore.exceptions.EndpointConnectionError:
            idx['error'] = 'EndpointConnectionError'
            return idx

        ## Alarms that notify through a composite alarm with actions (transitively).
        byName = {c.get('AlarmName'): c for c in composites}
        covered = set()
        stack = [c for c in composites if self._alarmHasActions(c)]
        seen = set()
        while stack:
            c = stack.pop()
            if c.get('AlarmName') in seen:
                continue
            seen.add(c.get('AlarmName'))
            for ref in self._ALARM_REF_RE.findall(c.get('AlarmRule') or ''):
                ref = ref.strip().split(':alarm:')[-1]
                covered.add(ref)
                if ref in byName:
                    stack.append(byName[ref])

        for a in metricAlarms:
            values = self._cognitoDimensionValues(a)
            if not values:
                continue
            if self._alarmHasActions(a) or a.get('AlarmName') in covered:
                idx['actioned'] |= values
            else:
                idx['unactioned'] |= values
        return idx

    # ------------------------------------------------------------------ #
    # Account-level summary
    # ------------------------------------------------------------------ #
    def _siloSummary(self, pools):
        out = []
        for pool in pools:
            pid = pool.get('Id')
            entry = {'id': pid, 'name': pool.get('Name'), 'clientCount': 0,
                     'idpCount': 0, 'error': None}
            if '_appClients' in pool:
                entry['clientCount'] = len(pool.get('_appClients') or [])
                entry['idpCount'] = len(pool.get('_identityProviders') or [])
                entry['error'] = self._enumErrors.get(pid)
            else:
                ## Checkpointed pool (summary only): count with list calls.
                try:
                    pag = self.cognitoClient.get_paginator('list_user_pool_clients')
                    for page in pag.paginate(UserPoolId=pid, MaxResults=60):
                        entry['clientCount'] += len(page.get('UserPoolClients', []) or [])
                    pag = self.cognitoClient.get_paginator('list_identity_providers')
                    for page in pag.paginate(UserPoolId=pid, MaxResults=60):
                        entry['idpCount'] += len(page.get('Providers', []) or [])
                except botocore.exceptions.ClientError as e:
                    entry['error'] = self._errCode(e)
            out.append(entry)
        for s in self._skippedPools:
            out.append({'id': s.get('Id'), 'name': s.get('Name'), 'clientCount': 0, 'idpCount': 0,
                        'error': self._enumErrors.get(s.get('Id')) or 'DescribeUserPoolFailed'})
        return out

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(error):
        return error.response.get('Error', {}).get('Code', 'Unknown')

    def _noteEnumError(self, poolId, error):
        self._enumErrors.setdefault(poolId, self._errCode(error))

    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                    'NotAuthorizedException'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Cognito {where}: {code} - {msg}")
