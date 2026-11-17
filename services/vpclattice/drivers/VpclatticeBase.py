import botocore

from services.Evaluator import Evaluator
from utils import PolicyPrincipal as pp


class VpclatticeBase(Evaluator):
    """
    Shared logic for VPC Lattice service networks and services.

    Both resource types carry an authType (NONE | AWS_IAM), an optional auth
    policy (get_auth_policy) and optional access log subscriptions
    (list_access_log_subscriptions). Subclasses set:
      self.resource      -- get_service_network / get_service output
      self.kindLabel     -- 'service network' / 'service'
    All calls here are read-only.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    INVOKE_ACTIONS = ['vpc-lattice-svcs:Invoke']

    def __init__(self, resource, client, accountId=None):
        super().__init__()
        self.resource = resource or {}
        self.client = client
        self.accountId = accountId
        self.identifier = self.resource.get('arn') or self.resource.get('id')
        self._resourceName = self.resource.get('name') or self.resource.get('id') or 'unknown'
        self.addII('id', self.resource.get('id'))
        self.addII('authType', self.resource.get('authType'))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _ownerAccount(self):
        arn = self.resource.get('arn') or ''
        parts = arn.split(':')
        return parts[4] if len(parts) > 5 else None

    def _sharedFromOtherAccount(self):
        owner = self._ownerAccount()
        return bool(owner and self.accountId and owner != self.accountId)

    def _listAccessLogSubscriptions(self, identifier):
        """Return the list of subscriptions, or raise ClientError."""
        items = []
        paginator = self.client.get_paginator('list_access_log_subscriptions')
        for page in paginator.paginate(resourceIdentifier=identifier):
            items += page.get('items', []) or []
        return items

    @staticmethod
    def _coversServiceTraffic(subscriptions):
        """serviceNetworkLogType RESOURCE captures resource-configuration
        traffic only. Subscriptions without the field (services, and service
        networks created before resource logging existed) log service traffic."""
        return [s for s in subscriptions
                if (s.get('serviceNetworkLogType') or 'SERVICE') == 'SERVICE']

    @staticmethod
    def anonymousAllowStatements(policyDoc):
        """Allow statements that let ANY caller, including anonymous
        (unsigned) callers, invoke: wildcard principal, an action covering
        vpc-lattice-svcs:Invoke and no Condition at all. With AWS_IAM such a
        policy is functionally equivalent to authType NONE."""
        out = []
        for stmt in pp.iterStatements(policyDoc):
            if str(stmt.get('Effect', '')).lower() != 'allow':
                continue
            if not (pp.principalIsWildcard(stmt.get('Principal')) or 'NotPrincipal' in stmt):
                continue
            if stmt.get('Condition'):
                continue
            if pp.statementAllowsAction(stmt, VpclatticeBase.INVOKE_ACTIONS):
                out.append(stmt)
        return out

    # ------------------------------------------------------------------ #
    # Auth type
    # ------------------------------------------------------------------ #
    def _evaluateAuthType(self):
        key = 'latticeAuthTypeNone'
        label = self.kindLabel
        authType = self.resource.get('authType')

        if self._sharedFromOtherAccount():
            self.results[key] = [0, f"Shared from account {self._ownerAccount()}; evaluate in the owner account"]
            return
        if not authType:
            self.results[key] = [0, 'Unable to evaluate (authType not returned)']
            return
        if authType == 'NONE':
            self.results[key] = [
                -1,
                f"The {label} has authType NONE: any caller in a VPC connected to the "
                "service network can send unauthenticated, unauthorised requests at this layer"
            ]
            return
        if authType != 'AWS_IAM':
            self.results[key] = [0, f'Unable to evaluate (unknown authType {authType})']
            return

        try:
            resp = self.client.get_auth_policy(resourceIdentifier=self.identifier)
        except botocore.exceptions.ClientError as e:
            code = self._errCode(e)
            if code == 'ResourceNotFoundException':
                self.results[key] = [
                    1,
                    f"AWS_IAM is enforced and no auth policy is attached, so every request to "
                    f"the {label} is denied by default"
                ]
            else:
                self.results[key] = [0, f'Unable to evaluate ({code})']
            return

        policy = resp.get('policy')
        if not policy:
            self.results[key] = [
                1,
                f"AWS_IAM is enforced and the auth policy is empty, so every request to the "
                f"{label} is denied by default"
            ]
            return
        if pp.parsePolicy(policy) is None:
            self.results[key] = [0, 'Unable to evaluate (auth policy could not be parsed)']
            return

        anon = self.anonymousAllowStatements(policy)
        if anon:
            sids = ', '.join(str(s.get('Sid', '(no Sid)')) for s in anon[:3])
            self.results[key] = [
                -1,
                f"authType is AWS_IAM but the auth policy allows Principal \"*\" to invoke with no "
                f"Condition (statement {sids}), which admits anonymous callers - equivalent to NONE"
            ]
            return
        self.results[key] = [1, 'AWS_IAM is enforced with an auth policy that does not allow anonymous callers']

    # ------------------------------------------------------------------ #
    # Access logs
    # ------------------------------------------------------------------ #
    def _ownAccessLogs(self):
        """Return (subscriptions, None) or (None, errorCode)."""
        try:
            return self._listAccessLogSubscriptions(self.identifier), None
        except botocore.exceptions.ClientError as e:
            return None, self._errCode(e)
