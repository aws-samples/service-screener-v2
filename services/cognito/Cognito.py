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
