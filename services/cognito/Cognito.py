import botocore

from utils.Tools import _pi
from services.Service import Service

from services.cognito.drivers.CognitoCommon import CognitoCommon


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

    Identity-pools (Cognito Federated Identities) are a separate service
    (cognito-identity); this scanner covers only user pools.
    """

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cognitoClient = ssBoto.client('cognito-idp', config=self.bConfig)
        # WAFv2 for user-pool WebACL association lookup (Cognito user pools
        # are REGIONAL resources so this client runs in the target region).
        self.wafClient = ssBoto.client('wafv2', config=self.bConfig)
        # IAM for evaluating group-role policies (check #36).
        self.iamClient = ssBoto.client('iam', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        pools = []
        try:
            paginator = self.cognitoClient.get_paginator('list_user_pools')
            # MaxResults must be 1..60 for list_user_pools
            for page in paginator.paginate(MaxResults=60):
                for summary in page.get('UserPools', []):
                    poolId = summary.get('Id')
                    if not poolId:
                        continue
                    detail = self._describeUserPool(poolId)
                    if detail is None:
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
            self._logClientError('list_user_pools', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Cognito not available in region {self.region}: {e}")
        return pools

    def _describeUserPool(self, poolId):
        try:
            resp = self.cognitoClient.describe_user_pool(UserPoolId=poolId)
            return resp.get('UserPool')
        except botocore.exceptions.ClientError as e:
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
            self._logClientError(f'list_user_pool_clients({poolId})', e)
        return clients

    def _describeAppClient(self, poolId, clientId):
        try:
            resp = self.cognitoClient.describe_user_pool_client(
                UserPoolId=poolId, ClientId=clientId
            )
            return resp.get('UserPoolClient')
        except botocore.exceptions.ClientError as e:
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
                        self._logClientError(
                            f'describe_identity_provider({poolId}/{name})', e
                        )
        except botocore.exceptions.ClientError as e:
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

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                    'NotAuthorizedException'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Cognito {where}: {code} - {msg}")
