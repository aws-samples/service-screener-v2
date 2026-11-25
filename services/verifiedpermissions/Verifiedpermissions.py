import botocore

from utils.Tools import _pi
from services.Service import Service

from services.verifiedpermissions.drivers.VerifiedpermissionsPolicyStore import VerifiedpermissionsPolicyStore


class Verifiedpermissions(Service):
    """
    Amazon Verified Permissions service scanner.

    One driver instance per policy store (VerifiedpermissionsPolicyStore).

    Hydration calls (all read-only):
      - list_policy_stores  (paginated)
      - get_policy_store    (per store; tags=True only when a tag filter is set,
                             because returning tags needs the extra
                             ListTagsForResource permission)
      - get_schema          (per store; informational context only)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.avpClient = ssBoto.client('verifiedpermissions', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        stores = []
        try:
            paginator = self.avpClient.get_paginator('list_policy_stores')
            for page in paginator.paginate():
                for s in page.get('policyStores', []) or []:
                    if s.get('policyStoreId'):
                        stores.append(s)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_policy_stores', e)
            return []
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Verified Permissions not available in region {self.region}: {e}")
            return []

        out = []
        for s in stores:
            detail = dict(s)
            detail['_region'] = self.region
            detail['_store'] = None
            detail['_storeError'] = None
            detail['_schema'] = None
            detail['_schemaError'] = None

            psid = s['policyStoreId']
            try:
                kwargs = {'policyStoreId': psid}
                if self.tags:
                    kwargs['tags'] = True
                store = self.avpClient.get_policy_store(**kwargs)
                store.pop('ResponseMetadata', None)
                detail['_store'] = store
            except botocore.exceptions.ClientError as e:
                detail['_storeError'] = e.response.get('Error', {}).get('Code', 'Unknown')
                self._logClientError(f'get_policy_store({psid})', e)

            if self.tags:
                tags = self._normaliseTags((detail['_store'] or {}).get('tags') or {})
                if not self.resourceHasTags(tags):
                    continue

            try:
                schema = self.avpClient.get_schema(policyStoreId=psid)
                schema.pop('ResponseMetadata', None)
                detail['_schema'] = schema
            except botocore.exceptions.ClientError as e:
                code = e.response.get('Error', {}).get('Code', 'Unknown')
                ## ResourceNotFoundException == the store has no schema.
                detail['_schemaError'] = code
                if code != 'ResourceNotFoundException':
                    self._logClientError(f'get_schema({psid})', e)

            _pi('Verifiedpermissions', f"Policy store: {psid}")
            out.append(detail)
        return out

    def _normaliseTags(self, tags):
        """get_policy_store returns tags as a {key: value} map."""
        if isinstance(tags, dict):
            return [{'Key': k, 'Value': v} for k, v in tags.items()]
        return []

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for store in self.getResources():
            psid = store.get('policyStoreId', 'unknown')
            try:
                obj = VerifiedpermissionsPolicyStore(store, self.avpClient)
                obj.run(self.__class__)
                objs[f"PolicyStore::{psid}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Verified Permissions policy store {psid}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Verifiedpermissions {where}: {code} - {msg}")
