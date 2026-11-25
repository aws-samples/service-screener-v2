import json

import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.ssm.drivers.SsmParameter import SsmParameter
from services.ssm.drivers.SsmManagedInstance import SsmManagedInstance
from services.ssm.drivers.SsmSessionManager import SsmSessionManager
from services.ssm.drivers.SsmDocument import SsmDocument


class Ssm(Service):
    """
    AWS Systems Manager service scanner.

    SSM has four unrelated check subjects, so discovery fans out into four
    drivers:

      SsmParameter       -- per Parameter Store parameter (encryption, hygiene)
      SsmManagedInstance -- per managed instance (patch compliance, agent, ping)
      SsmDocument        -- per self-owned SSM document (public sharing)
      SsmSessionManager  -- region-scoped ("SSM::Account"): Session Manager
                            preferences, Default Host Management, the public
                            document sharing setting and patch automation

    Hydration calls (all read-only):
      - describe_parameters          (paginated)
      - list_tags_for_resource       (per parameter)
      - describe_instance_information(paginated)
      - describe_instance_patch_states (batched, 50 instance ids per call)
      - list_inventory_entries       (per instance, AWS:InstanceInformation)
      - get_document                 (SSM-SessionManagerRunShell preferences)
      - get_service_setting          (Default Host Management Configuration)
      - list_documents               (Owner=Self, paginated)
    Region-scoped checks additionally call (inside the check, read-only):
      describe_document_permission, get_service_setting, list_associations,
      describe_association, describe_maintenance_windows,
      describe_maintenance_window_tasks, get_maintenance_window_task,
      ssm-quicksetup list_configuration_managers.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## The Session Manager preferences document. AWS stores the region's Session
    ## Manager settings as the content of this well-known SSM document.
    SESSION_PREFERENCES_DOCUMENT = 'SSM-SessionManagerRunShell'

    ## Setting ID for Default Host Management Configuration.
    ##
    ## NOTE: this is deliberately NOT the ID given in the original spec
    ## ('/ssm/managed-instance/default-instance-management-configuration/
    ## ec2-instance-management'), which does not exist — GetServiceSetting
    ## rejects it with ServiceSettingNotFound. The real setting ID is below, and
    ## its SettingValue is the NAME OF AN IAM ROLE (not 'true'/'false'), with
    ## Status 'Customized' once DHMC has been configured and 'Default' when it
    ## has not.
    DHMC_SETTING_ID = '/ssm/managed-instance/default-ec2-instance-management-role'

    ## describe_instance_patch_states caps InstanceIds at 50 per call.
    PATCH_STATE_BATCH_SIZE = 50

    ## Inventory is queried per instance and each call is a round trip. Cap the
    ## number of instances probed so a fleet of thousands does not turn one
    ## check into a multi-minute scan; the check reports how many it sampled.
    INVENTORY_SAMPLE_LIMIT = 25

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ssmClient = ssBoto.client('ssm', config=self.bConfig)
        ## Quick Setup is not offered in every Region; the check tolerates
        ## endpoint errors, so a client that cannot be built is just skipped.
        try:
            self.quickSetupClient = ssBoto.client('ssm-quicksetup',
                                                  config=self.bConfig)
        except Exception:
            self.quickSetupClient = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        """Kept for interface parity with the other services; see advise()."""
        return self._describeParameters()

    def _describeParameters(self):
        parameters = []
        try:
            paginator = self.ssmClient.get_paginator('describe_parameters')
            for page in paginator.paginate():
                for param in page.get('Parameters', []) or []:
                    name = param.get('Name')
                    if not name:
                        continue
                    tags = self._listParameterTags(name)

                    ## Optional --filters tag filtering.
                    if self.tags and not self.resourceHasTags(tags):
                        continue

                    param['_name'] = name
                    param['_tags'] = tags
                    param['_region'] = self.region
                    _pi('Ssm', f"Parameter: {name}")
                    parameters.append(param)
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_parameters', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Systems Manager not available in region {self.region}: {e}")
        return parameters

    def _listParameterTags(self, name):
        try:
            resp = self.ssmClient.list_tags_for_resource(
                ResourceType='Parameter', ResourceId=name)
            return resp.get('TagList', []) or []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            ## A parameter under a path the caller cannot read, or one deleted
            ## between the list and this call.
            if code in ('InvalidResourceId', 'ParameterNotFound',
                        'ValidationException'):
                return []
            self._logClientError(f'list_tags_for_resource({name})', e)
            return []

    def _listSelfOwnedDocuments(self):
        documents = []
        try:
            paginator = self.ssmClient.get_paginator('list_documents')
            for page in paginator.paginate(
                    Filters=[{'Key': 'Owner', 'Values': ['Self']}]):
                for doc in page.get('DocumentIdentifiers', []) or []:
                    if not doc.get('Name'):
                        continue
                    if self.tags and not self.resourceHasTags(
                            doc.get('Tags') or []):
                        continue
                    doc['_region'] = self.region
                    documents.append(doc)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_documents', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return documents

    def _describeInstances(self):
        """Managed instances, each hydrated with patch state and inventory."""
        instances = []
        try:
            paginator = self.ssmClient.get_paginator(
                'describe_instance_information')
            for page in paginator.paginate():
                for inst in page.get('InstanceInformationList', []) or []:
                    if inst.get('InstanceId'):
                        instances.append(inst)
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_instance_information', e)
            return []
        except botocore.exceptions.EndpointConnectionError:
            return []

        if not instances:
            return []

        patchStates = self._describeInstancePatchStates(
            [i['InstanceId'] for i in instances])

        for index, inst in enumerate(instances):
            instanceId = inst['InstanceId']
            inst['_patchState'] = patchStates.get(instanceId)
            inst['_region'] = self.region
            ## Inventory is sampled rather than exhaustive — see
            ## INVENTORY_SAMPLE_LIMIT.
            if index < self.INVENTORY_SAMPLE_LIMIT:
                inst['_inventoryEntryCount'] = self._countInventoryEntries(
                    instanceId)
            else:
                inst['_inventoryEntryCount'] = None
            _pi('Ssm', f"Managed instance: {instanceId}")

        return instances

    def _describeInstancePatchStates(self, instanceIds):
        """Return {instanceId: patchState} for every instance that reports one."""
        states = {}
        for i in range(0, len(instanceIds), self.PATCH_STATE_BATCH_SIZE):
            batch = instanceIds[i:i + self.PATCH_STATE_BATCH_SIZE]
            try:
                resp = self.ssmClient.describe_instance_patch_states(
                    InstanceIds=batch)
                for state in resp.get('InstancePatchStates', []) or []:
                    if state.get('InstanceId'):
                        states[state['InstanceId']] = state
            except botocore.exceptions.ClientError as e:
                self._logClientError('describe_instance_patch_states', e)
        return states

    def _countInventoryEntries(self, instanceId):
        """
        Number of AWS:InstanceInformation inventory entries for the instance.
        Returns None when the lookup fails, so the check can distinguish "no
        inventory" from "could not tell".
        """
        try:
            resp = self.ssmClient.list_inventory_entries(
                InstanceId=instanceId, TypeName='AWS:InstanceInformation')
            return len(resp.get('Entries', []) or [])
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code in ('InvalidInstanceId',):
                return 0
            self._logClientError(f'list_inventory_entries({instanceId})', e)
            return None

    def _getSessionManagerDetail(self):
        """Region-scoped Session Manager preferences and the DHMC setting."""
        return {
            '_region': self.region,
            '_accountId': self._currentAccount(),
            '_sessionPreferences': self._getSessionPreferences(),
            '_sessionPreferencesFound': self._sessionPreferencesFound,
            '_sessionPreferencesError': self._sessionPreferencesError,
            '_dhmcSetting': self._getDhmcSetting(),
        }

    def _getSessionPreferences(self):
        """
        Parse the inputs block of SSM-SessionManagerRunShell. When the document
        does not exist the region has never had Session Manager preferences
        customised, which is itself the finding — recorded via
        _sessionPreferencesFound so the checks do not read an empty dict as
        "configured with empty values".
        """
        self._sessionPreferencesFound = False
        self._sessionPreferencesError = None
        try:
            ## JSON is GetDocument's documented default; requested explicitly so
            ## a document authored in YAML is always returned as parseable JSON.
            resp = self.ssmClient.get_document(
                Name=self.SESSION_PREFERENCES_DOCUMENT, DocumentFormat='JSON')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code not in ('InvalidDocument', 'InvalidDocumentVersion'):
                ## Not "missing" — the document could not be read.
                self._sessionPreferencesError = code or 'Unknown'
                self._logClientError('get_document(SSM-SessionManagerRunShell)', e)
            return {}
        except botocore.exceptions.EndpointConnectionError:
            self._sessionPreferencesError = 'EndpointConnectionError'
            return {}

        ## The document EXISTS from here on. Content that cannot be read as a
        ## JSON object with an 'inputs' object is "could not evaluate", never
        ## "no preferences configured" (that would be a false FAIL).
        try:
            content = json.loads(resp.get('Content') or '')
        except (ValueError, TypeError):
            self._sessionPreferencesError = 'InvalidDocumentContent'
            return {}

        inputs = content.get('inputs') if isinstance(content, dict) else None
        if not isinstance(inputs, dict):
            self._sessionPreferencesError = 'InvalidDocumentContent'
            return {}

        self._sessionPreferencesFound = True
        return inputs

    def _getDhmcSetting(self):
        """
        Return the Default Host Management Configuration service setting, or None
        when it cannot be read. The caller distinguishes 'Default' (not
        configured) from 'Customized' (configured) via the Status field.
        """
        try:
            resp = self.ssmClient.get_service_setting(
                SettingId=self.DHMC_SETTING_ID)
            return resp.get('ServiceSetting') or None
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            ## ServiceSettingNotFound means this region does not expose the
            ## setting at all; treated as unknown rather than as a failure.
            if code in ('ServiceSettingNotFound',):
                return None
            self._logClientError('get_service_setting(DHMC)', e)
            return None
        except botocore.exceptions.EndpointConnectionError:
            return None

    def _currentAccount(self):
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}

        for param in self._describeParameters():
            name = param.get('_name', 'unknown')
            try:
                _pi('Ssm', f"Analyzing parameter: {name}")
                obj = SsmParameter(param, self.ssmClient)
                obj.run(self.__class__)
                objs[f"SSM Parameter::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing SSM parameter {name}: {e}")

        for inst in self._describeInstances():
            instanceId = inst.get('InstanceId', 'unknown')
            try:
                _pi('Ssm', f"Analyzing instance: {instanceId}")
                obj = SsmManagedInstance(inst, self.ssmClient)
                obj.run(self.__class__)
                objs[f"SSM Instance::{instanceId}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing SSM managed instance {instanceId}: {e}")

        for doc in self._listSelfOwnedDocuments():
            name = doc.get('Name', 'unknown')
            try:
                _pi('Ssm', f"Analyzing document: {name}")
                obj = SsmDocument(doc, self.ssmClient)
                obj.run(self.__class__)
                objs[f"SSM Document::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing SSM document {name}: {e}")

        ## Session Manager preferences are region-scoped and always evaluated:
        ## they govern every session opened in the region whether or not any
        ## instance is currently registered.
        try:
            detail = self._getSessionManagerDetail()
            obj = SsmSessionManager(detail, self.ssmClient,
                                    self.quickSetupClient)
            obj.run(self.__class__)
            objs['SSM::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing SSM Session Manager posture: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Ssm {where}: {code} - {msg}")
