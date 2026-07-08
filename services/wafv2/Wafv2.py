import botocore

from utils.Tools import _pi
from services.Service import Service

from services.wafv2.drivers.Wafv2Common import Wafv2Common


class Wafv2(Service):
    """
    AWS WAFv2 service scanner.

    Discovers WebACLs in two scopes:
      - REGIONAL   → protects ALB / API Gateway / AppSync / Cognito UP / App Runner
                      etc. Available in every region.
      - CLOUDFRONT → protects CloudFront distributions. WAFv2 stores these in
                      us-east-1 only, so we only query them when scanning
                      us-east-1 to avoid duplicates.

    For each WebACL the scanner hydrates:
      - get_web_acl                    (rules, DefaultAction, VisibilityConfig, ...)
      - get_logging_configuration      (WAFNonexistentItemException == not configured)
      - list_resources_for_web_acl     (REGIONAL only; per resource-type)
      - cloudfront.list_distributions_by_web_acl_id  (CLOUDFRONT only)
      - list_tags_for_resource         (tag-based governance)
    """

    # REGIONAL protects these resource types. list_resources_for_web_acl is
    # per-type and we OR the results.
    REGIONAL_RESOURCE_TYPES = [
        'APPLICATION_LOAD_BALANCER',
        'API_GATEWAY',
        'APPSYNC',
        'COGNITO_USER_POOL',
        'APP_RUNNER_SERVICE',
        'VERIFIED_ACCESS_INSTANCE',
    ]

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.wafClient = ssBoto.client('wafv2', config=self.bConfig)
        # CloudFront is global; used only for CLOUDFRONT-scoped resource lookups.
        self.cfClient = ssBoto.client('cloudfront', config=self.bConfig)
        # Cross-service clients for coverage-gap checks (37-41). Constructed
        # lazily-tolerant: any client whose service isn't available in this
        # region will still work via boto3's shared endpoint config, and we
        # wrap every call in try/except.
        self.elbClient = ssBoto.client('elbv2', config=self.bConfig)
        self.apigwClient = ssBoto.client('apigateway', config=self.bConfig)
        self.appsyncClient = ssBoto.client('appsync', config=self.bConfig)
        self.cognitoClient = ssBoto.client('cognito-idp', config=self.bConfig)
        # Cached per-region: {'ipSets','regexPatternSets','ruleGroups','crossService'}
        self._regionAssets = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        webAcls = []

        webAcls.extend(self._discoverScope('REGIONAL'))

        # CLOUDFRONT WebACLs live only in us-east-1. Skip elsewhere so we don't
        # report the same ACL once per region.
        if self.region == 'us-east-1':
            webAcls.extend(self._discoverScope('CLOUDFRONT'))

        # Region-level assets (IP sets, regex sets, rule groups) + cross-service
        # coverage. Fetched once per scan; injected into every ACL detail.
        assets = self._collectRegionAssets(webAcls)
        primary_marked = False
        for acl in webAcls:
            acl['_regionAssets'] = assets
            if not primary_marked:
                acl['_isPrimaryAcl'] = True
                primary_marked = True
            else:
                acl['_isPrimaryAcl'] = False

        return webAcls

    def _discoverScope(self, scope):
        acls = []
        try:
            marker = None
            while True:
                kwargs = {'Scope': scope, 'Limit': 100}
                if marker:
                    kwargs['NextMarker'] = marker
                resp = self.wafClient.list_web_acls(**kwargs)
                for summary in resp.get('WebACLs', []) or []:
                    detail = self._describeWebAcl(summary, scope)
                    if detail is None:
                        continue

                    # Tag filtering (respects --tags flag)
                    tags = self._listTags(detail.get('_arn'))
                    if self.tags and not self.resourceHasTags(tags):
                        continue
                    detail['_tags'] = tags

                    _pi('Wafv2', f"WebACL [{scope}]: {detail.get('_name', detail.get('_arn'))}")
                    acls.append(detail)

                marker = resp.get('NextMarker')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_web_acls({scope})', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"WAFv2 not available in region {self.region}: {e}")
        return acls

    def _describeWebAcl(self, summary, scope):
        name = summary.get('Name')
        wid = summary.get('Id')
        arn = summary.get('ARN')
        if not (name and wid and arn):
            return None

        try:
            resp = self.wafClient.get_web_acl(Name=name, Id=wid, Scope=scope)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_web_acl({arn})', e)
            return None

        webAcl = resp.get('WebACL') or {}

        detail = {
            '_arn': arn,
            '_name': name,
            '_id': wid,
            '_scope': scope,
            '_webAcl': webAcl,
            '_loggingConfiguration': self._getLoggingConfig(arn),
        }
        associated, lookupFailed = self._listAssociatedResources(arn, wid, scope)
        detail['_associatedResources'] = associated
        detail['_associationLookupFailed'] = lookupFailed
        # Phase-1 extension data: fetch per-managed-group details + per-IP-set
        # contents, only for entities actually referenced by this WebACL.
        detail['_managedRuleGroupDetails'] = self._describeManagedGroupsFor(webAcl, scope)
        detail['_ipSets'] = self._fetchReferencedIpSets(webAcl, scope)
        return detail

    def _describeManagedGroupsFor(self, webAcl, scope):
        """
        Return a dict keyed by (VendorName, Name) -> {
            'total_rules': int,            (from describe_managed_rule_group)
            'versions': list of {Name, LastUpdateTimestamp, ExpiryTimestamp}
                                            (from list_available_managed_rule_group_versions)
        }
        Only calls each API once per group referenced by this WebACL.
        """
        info = {}
        rules = webAcl.get('Rules') or []
        seen = set()
        for r in rules:
            stmt = r.get('Statement') or {}
            mrg = stmt.get('ManagedRuleGroupStatement')
            if not isinstance(mrg, dict):
                continue
            vendor = mrg.get('VendorName')
            name = mrg.get('Name')
            if not vendor or not name:
                continue
            key = (vendor, name)
            if key in seen:
                continue
            seen.add(key)
            entry = {'total_rules': None, 'versions': []}
            try:
                d = self.wafClient.describe_managed_rule_group(
                    VendorName=vendor, Name=name, Scope=scope
                )
                entry['total_rules'] = len(d.get('Rules') or [])
            except botocore.exceptions.ClientError as e:
                self._logClientError(
                    f'describe_managed_rule_group({vendor}/{name})', e
                )
            try:
                v = self.wafClient.list_available_managed_rule_group_versions(
                    VendorName=vendor, Name=name, Scope=scope
                )
                entry['versions'] = v.get('Versions') or []
            except botocore.exceptions.ClientError as e:
                self._logClientError(
                    f'list_available_managed_rule_group_versions({vendor}/{name})', e
                )
            info[key] = entry
        return info

    def _fetchReferencedIpSets(self, webAcl, scope):
        """Fetch every IPSet referenced by this WebACL. Keys are IPSet ARNs."""
        out = {}
        for arn in self._ipSetArnsInWebAcl(webAcl):
            # ARN: arn:aws:wafv2:region:account:scope/ipset/<name>/<id>
            parts = arn.split('/')
            if len(parts) < 4 or 'ipset' not in parts:
                continue
            try:
                name = parts[-2]
                wid = parts[-1]
            except IndexError:
                continue
            try:
                resp = self.wafClient.get_ip_set(Name=name, Id=wid, Scope=scope)
                ipset = resp.get('IPSet') or {}
                out[arn] = {
                    'Name': name,
                    'IPAddressVersion': ipset.get('IPAddressVersion'),
                    'Addresses': ipset.get('Addresses') or [],
                }
            except botocore.exceptions.ClientError as e:
                self._logClientError(f'get_ip_set({name})', e)
        return out

    @staticmethod
    def _ipSetArnsInWebAcl(webAcl):
        """Walk every rule statement and collect ARNs from IPSetReferenceStatement."""
        arns = set()
        def walk(stmt):
            if not isinstance(stmt, dict):
                return
            ipset = stmt.get('IPSetReferenceStatement')
            if isinstance(ipset, dict):
                a = ipset.get('ARN')
                if a:
                    arns.add(a)
            for k in ('AndStatement', 'OrStatement'):
                sub = stmt.get(k)
                if isinstance(sub, dict):
                    for s in (sub.get('Statements') or []):
                        walk(s)
            nsub = stmt.get('NotStatement')
            if isinstance(nsub, dict):
                walk(nsub.get('Statement'))
            rb = stmt.get('RateBasedStatement')
            if isinstance(rb, dict):
                walk(rb.get('ScopeDownStatement'))
        for r in (webAcl.get('Rules') or []):
            walk(r.get('Statement'))
        return arns

    def _getLoggingConfig(self, arn):
        """Return the LoggingConfiguration dict, or None if not configured."""
        try:
            resp = self.wafClient.get_logging_configuration(ResourceArn=arn)
            return resp.get('LoggingConfiguration')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'WAFNonexistentItemException':
                # Documented AWS response for "no logging configured".
                return None
            self._logClientError(f'get_logging_configuration({arn})', e)
            return None

    def _listAssociatedResources(self, arn, wid, scope):
        """
        Return (associated_arns, lookup_failed).

        REGIONAL   -> wafv2.list_resources_for_web_acl (per resource type)
        CLOUDFRONT -> cloudfront.list_distributions_by_web_acl_id

        `lookup_failed` is True if any AccessDenied / authorization error
        prevented us from enumerating associations — the driver uses this to
        downgrade wafv2NotAssociated from FAIL to INFO so we don't
        false-positive on a missing IAM permission.
        """
        associated = []
        lookup_failed = False

        if scope == 'REGIONAL':
            for rtype in self.REGIONAL_RESOURCE_TYPES:
                try:
                    resp = self.wafClient.list_resources_for_web_acl(
                        WebACLArn=arn, ResourceType=rtype
                    )
                    for r in resp.get('ResourceArns', []) or []:
                        associated.append(r)
                except botocore.exceptions.ClientError as e:
                    code = e.response.get('Error', {}).get('Code', '')
                    # WAFInvalidParameterException for unsupported types in a region — ignore
                    if code == 'WAFInvalidParameterException':
                        continue
                    if code in ('AccessDenied', 'AccessDeniedException',
                                'AuthorizationError', 'UnauthorizedOperation'):
                        lookup_failed = True
                        continue
                    self._logClientError(
                        f'list_resources_for_web_acl({arn}, {rtype})', e
                    )
        else:  # CLOUDFRONT
            try:
                # list_distributions_by_web_acl_id is paginated but has no boto
                # paginator; iterate manually.
                marker = None
                while True:
                    kwargs = {'WebACLId': wid}
                    if marker:
                        kwargs['Marker'] = marker
                    resp = self.cfClient.list_distributions_by_web_acl_id(**kwargs)
                    dl = resp.get('DistributionList') or {}
                    for item in dl.get('Items', []) or []:
                        arn_ = item.get('ARN')
                        if arn_:
                            associated.append(arn_)
                    if dl.get('IsTruncated'):
                        marker = dl.get('NextMarker')
                        if not marker:
                            break
                    else:
                        break
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', '')
                if code in ('AccessDenied', 'AccessDeniedException',
                            'AuthorizationError', 'UnauthorizedOperation'):
                    lookup_failed = True
                else:
                    self._logClientError(
                        f'cloudfront.list_distributions_by_web_acl_id({wid})', e
                    )
        return associated, lookup_failed

    def _listTags(self, arn):
        if not arn:
            return []
        tags = []
        try:
            marker = None
            while True:
                kwargs = {'ResourceARN': arn, 'Limit': 100}
                if marker:
                    kwargs['NextMarker'] = marker
                resp = self.wafClient.list_tags_for_resource(**kwargs)
                info = resp.get('TagInfoForResource') or {}
                for t in info.get('TagList', []) or []:
                    tags.append(t)
                marker = resp.get('NextMarker')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({arn})', e)
        return tags

    # ------------------------------------------------------------------ #
    # Region-wide asset + cross-service coverage caching (checks 32-41)
    # ------------------------------------------------------------------ #
    def _collectRegionAssets(self, webAcls):
        """
        Build a shared dict injected into every WebACL detail:
          {
            'ipSets':           {arn: {'name','scope','addresses'}},
            'regexPatternSets': {arn: {'name','scope','patterns'}},
            'ruleGroups':       {arn: {'name','scope','ruleCount','description'}},
            'crossService': {
                'alb':        [{'arn','name','scheme','protected'}],
                'apiGateway': [{'arn','name','protected'}],
                'cloudfront': [{'id','arn','protected'}],
                'appsync':    [{'arn','name','authType','protected'}],
                'cognito':    [{'arn','id','name','protected'}],
            }
          }
        Failures are absorbed silently — the corresponding checks degrade to
        INFO when data is missing.
        """
        if self._regionAssets is not None:
            return self._regionAssets

        assets = {
            'ipSets': {},
            'regexPatternSets': {},
            'ruleGroups': {},
            'crossService': {
                'alb': [], 'apiGateway': [], 'cloudfront': [],
                'appsync': [], 'cognito': [],
            },
        }

        scopes = ['REGIONAL']
        if self.region == 'us-east-1':
            scopes.append('CLOUDFRONT')

        for scope in scopes:
            self._collectIpSets(scope, assets)
            self._collectRegexPatternSets(scope, assets)
            self._collectRuleGroups(scope, assets)

        # Cross-service coverage only makes sense when we have some WebACLs to
        # attribute the finding to. But even if the account has zero WebACLs
        # (a legitimate misconfiguration!) the coverage-gap check can't fire
        # against a driver instance — the driver runs per-ACL. In that case
        # the whole check surface simply isn't invoked.
        self._collectAlbCoverage(assets)
        self._collectApiGatewayCoverage(assets)
        # CloudFront distributions are global — only probe when scanning us-east-1
        # so a multi-region scan doesn't attribute the same distribution to
        # every region.
        if self.region == 'us-east-1':
            self._collectCloudFrontCoverage(assets)
        self._collectAppSyncCoverage(assets)
        self._collectCognitoCoverage(assets)

        self._regionAssets = assets
        return assets

    def _collectIpSets(self, scope, assets):
        try:
            marker = None
            while True:
                kw = {'Scope': scope, 'Limit': 100}
                if marker:
                    kw['NextMarker'] = marker
                resp = self.wafClient.list_ip_sets(**kw)
                for s in resp.get('IPSets', []) or []:
                    name, wid, arn = s.get('Name'), s.get('Id'), s.get('ARN')
                    if not (name and wid and arn):
                        continue
                    try:
                        d = self.wafClient.get_ip_set(Name=name, Id=wid, Scope=scope)
                        ipset = d.get('IPSet') or {}
                        assets['ipSets'][arn] = {
                            'name': name,
                            'scope': scope,
                            'addresses': ipset.get('Addresses') or [],
                        }
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'get_ip_set({name})', e)
                marker = resp.get('NextMarker')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_ip_sets({scope})', e)

    def _collectRegexPatternSets(self, scope, assets):
        try:
            marker = None
            while True:
                kw = {'Scope': scope, 'Limit': 100}
                if marker:
                    kw['NextMarker'] = marker
                resp = self.wafClient.list_regex_pattern_sets(**kw)
                for s in resp.get('RegexPatternSets', []) or []:
                    name, wid, arn = s.get('Name'), s.get('Id'), s.get('ARN')
                    if not (name and wid and arn):
                        continue
                    try:
                        d = self.wafClient.get_regex_pattern_set(
                            Name=name, Id=wid, Scope=scope
                        )
                        rps = d.get('RegexPatternSet') or {}
                        assets['regexPatternSets'][arn] = {
                            'name': name,
                            'scope': scope,
                            'patterns': rps.get('RegularExpressionList') or [],
                        }
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'get_regex_pattern_set({name})', e)
                marker = resp.get('NextMarker')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_regex_pattern_sets({scope})', e)

    def _collectRuleGroups(self, scope, assets):
        try:
            marker = None
            while True:
                kw = {'Scope': scope, 'Limit': 100}
                if marker:
                    kw['NextMarker'] = marker
                resp = self.wafClient.list_rule_groups(**kw)
                for s in resp.get('RuleGroups', []) or []:
                    name, wid, arn = s.get('Name'), s.get('Id'), s.get('ARN')
                    if not (name and wid and arn):
                        continue
                    try:
                        d = self.wafClient.get_rule_group(
                            Name=name, Id=wid, Scope=scope
                        )
                        rg = d.get('RuleGroup') or {}
                        assets['ruleGroups'][arn] = {
                            'name': name,
                            'scope': scope,
                            'ruleCount': len(rg.get('Rules') or []),
                            'description': rg.get('Description', ''),
                        }
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'get_rule_group({name})', e)
                marker = resp.get('NextMarker')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_rule_groups({scope})', e)

    def _collectAlbCoverage(self, assets):
        """Enumerate ALBs + probe each for WebACL association."""
        try:
            paginator = self.elbClient.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []) or []:
                    if lb.get('Type') != 'application':
                        continue
                    arn = lb.get('LoadBalancerArn')
                    if not arn:
                        continue
                    protected = self._probeAssociation(arn)
                    assets['crossService']['alb'].append({
                        'arn': arn,
                        'name': lb.get('LoadBalancerName', arn),
                        'scheme': lb.get('Scheme', 'unknown'),
                        'protected': protected,
                    })
        except botocore.exceptions.ClientError as e:
            self._logClientError('elbv2.describe_load_balancers', e)
        except botocore.exceptions.EndpointConnectionError:
            pass

    def _collectApiGatewayCoverage(self, assets):
        """REST APIs only — HTTP APIs (v2) use a different WAF mechanism."""
        try:
            marker = None
            while True:
                kw = {'limit': 500}
                if marker:
                    kw['position'] = marker
                resp = self.apigwClient.get_rest_apis(**kw)
                for api in resp.get('items', []) or []:
                    api_id = api.get('id')
                    if not api_id:
                        continue
                    try:
                        stages_resp = self.apigwClient.get_stages(restApiId=api_id)
                        stages = stages_resp.get('item', []) or []
                    except botocore.exceptions.ClientError:
                        stages = []
                    for stage in stages:
                        stage_name = stage.get('stageName')
                        if not stage_name:
                            continue
                        # Construct the WAF resource ARN for the stage
                        arn = (f"arn:aws:apigateway:{self.region}::/restapis/"
                               f"{api_id}/stages/{stage_name}")
                        protected = self._probeAssociation(arn)
                        assets['crossService']['apiGateway'].append({
                            'arn': arn,
                            'name': f"{api.get('name', api_id)}/{stage_name}",
                            'protected': protected,
                        })
                marker = resp.get('position')
                if not marker:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError('apigateway.get_rest_apis', e)
        except botocore.exceptions.EndpointConnectionError:
            pass

    def _collectCloudFrontCoverage(self, assets):
        """Every CloudFront distribution — check DistributionConfig.WebACLId."""
        try:
            marker = None
            while True:
                kw = {}
                if marker:
                    kw['Marker'] = marker
                resp = self.cfClient.list_distributions(**kw)
                dl = resp.get('DistributionList') or {}
                for item in dl.get('Items', []) or []:
                    dist_id = item.get('Id')
                    arn = item.get('ARN')
                    if not (dist_id and arn):
                        continue
                    web_acl_id = item.get('WebACLId') or ''
                    assets['crossService']['cloudfront'].append({
                        'id': dist_id,
                        'arn': arn,
                        'protected': bool(web_acl_id),
                    })
                if dl.get('IsTruncated'):
                    marker = dl.get('NextMarker')
                    if not marker:
                        break
                else:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError('cloudfront.list_distributions', e)

    def _collectAppSyncCoverage(self, assets):
        """AppSync GraphQL APIs — WafWebAclArn is the association attribute."""
        try:
            token = None
            while True:
                kw = {}
                if token:
                    kw['nextToken'] = token
                resp = self.appsyncClient.list_graphql_apis(**kw)
                for api in resp.get('graphqlApis', []) or []:
                    arn = api.get('arn')
                    if not arn:
                        continue
                    protected = bool(api.get('wafWebAclArn'))
                    assets['crossService']['appsync'].append({
                        'arn': arn,
                        'name': api.get('name', arn),
                        'authType': api.get('authenticationType', 'UNKNOWN'),
                        'protected': protected,
                    })
                token = resp.get('nextToken')
                if not token:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError('appsync.list_graphql_apis', e)
        except botocore.exceptions.EndpointConnectionError:
            pass

    def _collectCognitoCoverage(self, assets):
        """Cognito user pools — probe each pool ARN for WebACL association."""
        try:
            paginator = self.cognitoClient.get_paginator('list_user_pools')
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get('UserPools', []) or []:
                    pool_id = pool.get('Id')
                    if not pool_id:
                        continue
                    arn = (f"arn:aws:cognito-idp:{self.region}:"
                           f"{self._currentAccount()}:userpool/{pool_id}")
                    protected = self._probeAssociation(arn)
                    assets['crossService']['cognito'].append({
                        'arn': arn,
                        'id': pool_id,
                        'name': pool.get('Name', pool_id),
                        'protected': protected,
                    })
        except botocore.exceptions.ClientError as e:
            self._logClientError('cognito-idp.list_user_pools', e)

    def _probeAssociation(self, resource_arn):
        """Return True if a WebACL is associated with the given resource, False otherwise."""
        try:
            resp = self.wafClient.get_web_acl_for_resource(ResourceArn=resource_arn)
            wac = resp.get('WebACL') or {}
            return bool(wac.get('ARN'))
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'WAFNonexistentItemException':
                return False
            # Any other error — treat as "unknown" (assume protected to avoid
            # false-positive floods; the association is really just "we don't know").
            return True

    def _currentAccount(self):
        from utils.Config import Config
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account', '')
        return ''

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        webAcls = self.getResources()

        for acl in webAcls:
            try:
                name = acl.get('_name', 'unknown')
                _pi('Wafv2', f"Analyzing: {name}")
                obj = Wafv2Common(acl, self.wafClient)
                obj.run(self.__class__)
                objs[f"Wafv2::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Wafv2 WebACL {acl.get('_arn')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException',
                    'WAFOptimisticLockException', 'AuthorizationError'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Wafv2 {where}: {code} - {msg}")
