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
        return detail

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
