import botocore

from services.Evaluator import Evaluator


class SsmSessionManager(Evaluator):
    """
    Region-scoped ("SSM::Account") checks: Session Manager preferences,
    Default Host Management, public document sharing and patch automation.

      ssmSessionManagerNoEncryption
      ssmSessionManagerNoCloudWatchLogs
      ssmSessionManagerNoS3Logs
      ssmSessionManagerRunAsDisabled
      ssmDefaultHostManagementDisabled
      ssmSessionPrefsWeak       -- idle timeout > 20 min / no max duration
      ssmDocumentPublic         -- region allows public document sharing
                                   (per-document half lives in SsmDocument)
      ssmNoAutomatedPatching    -- managed instances exist but nothing
                                   installs patches automatically

    Session Manager preferences are a single per-region document, not a
    per-instance setting, so they are evaluated once for the region — following
    the precedent of services/ec2/drivers/Ec2Regional.py.

    Input:
      detail -- dict from services/ssm/Ssm.py._getSessionManagerDetail. Keys:
        '_region', '_accountId', '_sessionPreferences' (the inputs block of
        SSM-SessionManagerRunShell), '_sessionPreferencesFound',
        '_dhmcSetting' (a GetServiceSetting ServiceSetting dict, or None),
        '_sessionPreferencesError' (error code when get_document failed for a
        reason other than the document not existing, else None).
      ssmClient        -- boto3 ssm client (read-only calls in the checks).
      quickSetupClient -- optional boto3 ssm-quicksetup client.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.
    """

    ## GetServiceSetting Status values. 'Default' means the setting has never
    ## been changed from the AWS default, 'Customized' means the account set it.
    STATUS_DEFAULT = 'Default'
    STATUS_CUSTOMIZED = 'Customized'

    ## Service setting that controls whether documents may be shared publicly.
    ## Value 'Enable' (the AWS default) allows it, 'Disable' blocks it.
    PUBLIC_SHARING_SETTING_ID = '/ssm/documents/console/public-sharing-permission'

    ## Session Manager thresholds (minutes). 20 is the AWS default idle
    ## timeout; anything longer leaves abandoned shells open for longer.
    IDLE_TIMEOUT_MAX_MINUTES = 20

    ## Documents that run Patch Manager. Their 'Operation' parameter defaults
    ## to 'Scan', which only reports missing patches; only 'Install' patches.
    PATCH_OPERATION_DOCUMENTS = (
        'AWS-RunPatchBaseline',
        'AWS-RunPatchBaselineAssociation',
        'AWS-RunPatchBaselineWithHooks',
    )
    ## Automation runbooks that always install patches.
    PATCH_INSTALL_DOCUMENTS = (
        'AWS-PatchInstanceWithRollback',
        'AWS-PatchAsgInstance',
    )
    QUICKSETUP_PATCH_POLICY_TYPE = 'AWSQuickSetupType-PatchPolicy'

    UNAVAILABLE_CODES = ('NotImplemented', 'UnknownOperationException',
                         'InvalidAction')

    def __init__(self, detail, ssmClient, quickSetupClient=None):
        super().__init__()
        self.detail = detail
        self.ssmClient = ssmClient
        self.quickSetupClient = quickSetupClient
        self.prefsError = detail.get('_sessionPreferencesError')

        ## Region-scoped subject; there is no per-resource name.
        self._resourceName = 'Account'

        self.prefs = detail.get('_sessionPreferences') or {}
        self.prefsFound = bool(detail.get('_sessionPreferencesFound'))
        self.dhmc = detail.get('_dhmcSetting')

        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('sessionPreferencesDocumentFound', str(self.prefsFound))
        self.addII('kmsKeyId', self.prefs.get('kmsKeyId') or 'None')
        self.addII('cloudWatchLogGroupName',
                   self.prefs.get('cloudWatchLogGroupName') or 'None')
        self.addII('s3BucketName', self.prefs.get('s3BucketName') or 'None')
        self.addII('runAsEnabled', str(self.prefs.get('runAsEnabled', 'N/A')))
        self.addII('idleSessionTimeout',
                   str(self.prefs.get('idleSessionTimeout') or 'N/A'))
        self.addII('dhmcStatus',
                   (self.dhmc or {}).get('Status', 'N/A'))

    # ------------------------------------------------------------------ #
    # 1. Session data not encrypted with a KMS key
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoEncryption(self):
        if not self.prefsFound:
            self.results['ssmSessionManagerNoEncryption'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "Session Manager preferences have never been configured, so "
                "session data is not encrypted with a customer managed KMS key"
            ]
            return

        kmsKeyId = self.prefs.get('kmsKeyId')
        if kmsKeyId:
            self.results['ssmSessionManagerNoEncryption'] = [
                1, f"Session data is KMS encrypted with {kmsKeyId}"
            ]
        else:
            self.results['ssmSessionManagerNoEncryption'] = [
                -1,
                "Session Manager has no kmsKeyId configured — session data is "
                "protected only by TLS in transit, with no additional KMS "
                "encryption of the session content itself"
            ]

    # ------------------------------------------------------------------ #
    # 2. Session activity not logged to CloudWatch Logs
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoCloudWatchLogs(self):
        """
        cloudWatchStreamingEnabled alone is not sufficient: without a log group
        name there is nowhere to stream to. Both are required for the session
        transcript to actually land in CloudWatch.
        """
        if not self.prefsFound:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "no session activity is logged to CloudWatch Logs"
            ]
            return

        logGroup = self.prefs.get('cloudWatchLogGroupName')
        streaming = self.prefs.get('cloudWatchStreamingEnabled')

        if logGroup and streaming is not False:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                1, f"Session activity streams to CloudWatch log group {logGroup}"
            ]
            return

        if logGroup and streaming is False:
            self.results['ssmSessionManagerNoCloudWatchLogs'] = [
                -1,
                f"CloudWatch log group '{logGroup}' is configured but "
                "cloudWatchStreamingEnabled is false — no session transcript is "
                "written"
            ]
            return

        self.results['ssmSessionManagerNoCloudWatchLogs'] = [
            -1,
            "Session Manager has no cloudWatchLogGroupName — shell sessions on "
            "managed instances leave no transcript in CloudWatch Logs, so there "
            "is no record of what commands an operator ran"
        ]

    # ------------------------------------------------------------------ #
    # 3. Session output not archived to S3
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerNoS3Logs(self):
        if not self.prefsFound:
            self.results['ssmSessionManagerNoS3Logs'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "no session output is archived to S3"
            ]
            return

        bucket = self.prefs.get('s3BucketName')
        if bucket:
            self.results['ssmSessionManagerNoS3Logs'] = [
                1, f"Session output is archived to s3://{bucket}"
            ]
        else:
            self.results['ssmSessionManagerNoS3Logs'] = [
                -1,
                "Session Manager has no s3BucketName — session output is not "
                "archived to S3, so there is no durable long-term copy of the "
                "transcript independent of the CloudWatch log retention period"
            ]

    # ------------------------------------------------------------------ #
    # 4. Run As not enabled
    # ------------------------------------------------------------------ #
    def _checkSsmSessionManagerRunAsDisabled(self):
        """
        With Run As disabled every session runs as ssm-user, so all operators
        share one OS identity and on-host logs cannot attribute an action to a
        person. Enabling it makes the session assume a per-user OS account.
        """
        if not self.prefsFound:
            self.results['ssmSessionManagerRunAsDisabled'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "Run As is not enabled, so every session runs as the shared "
                "ssm-user account"
            ]
            return

        runAs = self.prefs.get('runAsEnabled')
        if runAs is True:
            defaultUser = self.prefs.get('runAsDefaultUser')
            suffix = f", default user '{defaultUser}'" if defaultUser else ""
            self.results['ssmSessionManagerRunAsDisabled'] = [
                1, f"Run As is enabled{suffix}"
            ]
        else:
            self.results['ssmSessionManagerRunAsDisabled'] = [
                -1,
                "Session Manager has runAsEnabled=false — every session runs as "
                "the shared ssm-user account, so on-host audit logs cannot "
                "attribute a command to the individual who ran it"
            ]

    # ------------------------------------------------------------------ #
    # 5. Default Host Management Configuration not enabled
    # ------------------------------------------------------------------ #
    def _checkSsmDefaultHostManagementDisabled(self):
        """
        DHMC lets Systems Manager manage every EC2 instance in the region through
        an IAM role, without attaching an instance profile to each one.

        The setting is read from
        '/ssm/managed-instance/default-ec2-instance-management-role'. Its
        SettingValue is the NAME OF THE IAM ROLE, not a boolean — so the
        authoritative signal is Status: 'Customized' means DHMC was configured,
        'Default' means it never was.
        """
        if self.dhmc is None:
            self.results['ssmDefaultHostManagementDisabled'] = [
                0,
                "The Default Host Management Configuration service setting could "
                "not be read in this region (not exposed, or "
                "ssm:GetServiceSetting denied)"
            ]
            return

        status = self.dhmc.get('Status')
        value = self.dhmc.get('SettingValue')

        if status == self.STATUS_CUSTOMIZED and value:
            self.results['ssmDefaultHostManagementDisabled'] = [
                1,
                "Default Host Management Configuration is enabled with IAM role "
                f"'{value}'"
            ]
            return

        if status == self.STATUS_DEFAULT:
            self.results['ssmDefaultHostManagementDisabled'] = [
                -1,
                "Default Host Management Configuration is not enabled — every EC2 "
                "instance needs its own instance profile to become managed, so "
                "any instance launched without one silently misses patching, "
                "inventory and Session Manager access"
            ]
            return

        ## Customized but with no role name, or an unrecognised status.
        self.results['ssmDefaultHostManagementDisabled'] = [
            -1,
            "Default Host Management Configuration reports status "
            f"'{status or 'unknown'}' with setting value "
            f"'{value or 'empty'}' — it is not usably configured"
        ]

    # ------------------------------------------------------------------ #
    # 6. Session Manager idle timeout / maximum session duration
    # ------------------------------------------------------------------ #
    def _checkSsmSessionPrefsWeak(self):
        """
        idleSessionTimeout (minutes, AWS default 20) ends a session left idle;
        maxSessionDuration (minutes, no default) ends any session after a fixed
        time. FAIL when the idle timeout is longer than 20 minutes or no
        maximum session duration is set.
        """
        if self.prefsError:
            self.results['ssmSessionPrefsWeak'] = [
                0, f"Unable to evaluate ({self.prefsError})"
            ]
            return

        if not self.prefsFound:
            self.results['ssmSessionPrefsWeak'] = [
                -1,
                "No SSM-SessionManagerRunShell document exists in this region — "
                "Session Manager runs with the defaults: a 20 minute idle "
                "timeout and no maximum session duration"
            ]
            return

        rawIdle = self.prefs.get('idleSessionTimeout')
        rawMax = self.prefs.get('maxSessionDuration')

        if rawIdle in (None, ''):
            idle = self.IDLE_TIMEOUT_MAX_MINUTES  # AWS default
        else:
            try:
                idle = int(str(rawIdle).strip())
            except (TypeError, ValueError):
                self.results['ssmSessionPrefsWeak'] = [
                    0,
                    "Unable to evaluate (idleSessionTimeout value "
                    f"'{rawIdle}' is not a number of minutes)"
                ]
                return

        problems = []
        if idle > self.IDLE_TIMEOUT_MAX_MINUTES:
            problems.append(
                f"idleSessionTimeout is {idle} minutes (more than "
                f"{self.IDLE_TIMEOUT_MAX_MINUTES})")
        if rawMax in (None, '') or not str(rawMax).strip():
            problems.append("maxSessionDuration is not set, so a session can "
                            "stay open indefinitely while it is active")

        if problems:
            self.results['ssmSessionPrefsWeak'] = [
                -1, "Session Manager preferences are weak: " + "; ".join(problems)
            ]
        else:
            self.results['ssmSessionPrefsWeak'] = [
                1,
                f"Session Manager idle timeout is {idle} minutes and maximum "
                f"session duration is {str(rawMax).strip()} minutes"
            ]

    # ------------------------------------------------------------------ #
    # 7. Region allows SSM documents to be shared publicly
    # ------------------------------------------------------------------ #
    def _checkSsmDocumentPublic(self):
        """
        Region half of ssmDocumentPublic (FSBP SSM.7). The per-document half
        (a self-owned document already shared with 'all', FSBP SSM.4) is
        evaluated by services/ssm/drivers/SsmDocument.py.
        """
        try:
            resp = self.ssmClient.get_service_setting(
                SettingId=self.PUBLIC_SHARING_SETTING_ID)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results['ssmDocumentPublic'] = [
                0, f"Unable to evaluate ({code})"
            ]
            return

        value = ((resp.get('ServiceSetting') or {}).get('SettingValue') or '')
        if value.lower() == 'disable':
            self.results['ssmDocumentPublic'] = [
                1, "Block public sharing is turned on for SSM documents in this "
                   "region"
            ]
        elif value.lower() == 'enable':
            self.results['ssmDocumentPublic'] = [
                -1,
                "Block public sharing is turned off for SSM documents in this "
                "region (public-sharing-permission = Enable) — any self-owned "
                "document can be shared with every AWS account"
            ]
        else:
            self.results['ssmDocumentPublic'] = [
                0,
                "Unable to evaluate (unexpected public-sharing-permission value "
                f"'{value or 'empty'}')"
            ]

    # ------------------------------------------------------------------ #
    # 8. Managed instances exist but nothing installs patches automatically
    # ------------------------------------------------------------------ #
    def _checkSsmNoAutomatedPatching(self):
        """
        Mechanism check, complementing the outcome check
        ssmManagedInstanceNotPatched. PASS when at least one of these installs
        patches on a schedule:
          - a State Manager association running a Patch Manager document with
            Operation=Install (AWS-RunPatchBaseline* default to Scan), or an
            association created by a Quick Setup patch policy that installs;
          - a task in an enabled maintenance window doing the same;
          - a Quick Setup patch policy whose PatchOperation is ScanAndInstall
            and whose TargetRegions/TargetAccounts include this Region/account.
        Third-party patching tools are invisible to this check.
        """
        key = 'ssmNoAutomatedPatching'
        instanceCount = 0
        try:
            paginator = self.ssmClient.get_paginator(
                'describe_instance_information')
            for page in paginator.paginate():
                instanceCount += len(page.get('InstanceInformationList', []) or [])
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results[key] = [0, f"Unable to evaluate ({code})"]
            return

        if instanceCount == 0:
            self.results[key] = [
                0, "No managed instances in this region — patch automation not "
                   "applicable"
            ]
            return

        installers = []   # human-readable mechanisms that install patches
        scanOnly = []     # patch mechanisms that only scan
        errors = []       # error codes that prevented a complete evaluation

        self._collectPatchAssociations(installers, scanOnly, errors)
        if not installers:
            self._collectPatchWindowTasks(installers, scanOnly, errors)
        if not installers:
            self._collectQuickSetupPatchPolicies(installers, scanOnly)

        if installers:
            self.results[key] = [
                1,
                f"{instanceCount} managed instance(s); patches are installed "
                "automatically by: " + ", ".join(installers[:5])
            ]
            return

        if errors:
            self.results[key] = [
                0, "Unable to evaluate (" + ", ".join(sorted(set(errors))) + ")"
            ]
            return

        detail = ""
        if scanOnly:
            detail = (" Patch mechanisms found only scan (Operation=Scan): "
                      + ", ".join(scanOnly[:5]) + ".")
        self.results[key] = [
            -1,
            f"{instanceCount} managed instance(s) but no State Manager "
            "association, maintenance window task or Quick Setup patch policy "
            "installs patches (AWS-RunPatchBaseline with Operation=Install)."
            + detail + " If a third-party tool patches these instances, this "
            "finding can be accepted."
        ]

    # ---- patch mechanism discovery helpers (read-only) ---------------- #
    @staticmethod
    def _docName(nameOrArn):
        ## Shared documents may be referenced by ARN: arn:...:document/Name
        return str(nameOrArn or '').split('/')[-1]

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    def _isPatchPolicy(self, *names):
        return any('patchpolicy' in str(n or '').lower() for n in names)

    def _operationInstalls(self, values):
        if isinstance(values, str):
            values = [values]
        return any(str(v).strip().lower() == 'install' for v in (values or []))

    def _collectPatchAssociations(self, installers, scanOnly, errors):
        try:
            paginator = self.ssmClient.get_paginator('list_associations')
            associations = []
            for page in paginator.paginate():
                associations.extend(page.get('Associations', []) or [])
        except botocore.exceptions.ClientError as e:
            errors.append(self._errCode(e))
            return

        for assoc in associations:
            doc = self._docName(assoc.get('Name'))
            assocName = assoc.get('AssociationName') or assoc.get('AssociationId')
            label = f"association '{assocName}' ({doc})"
            isPolicy = self._isPatchPolicy(assocName, doc)

            if doc in self.PATCH_INSTALL_DOCUMENTS:
                installers.append(label)
                return
            if doc not in self.PATCH_OPERATION_DOCUMENTS and not isPolicy:
                continue

            params = None
            if assoc.get('AssociationId'):
                try:
                    resp = self.ssmClient.describe_association(
                        AssociationId=assoc['AssociationId'])
                    params = (resp.get('AssociationDescription') or {}).get(
                        'Parameters') or {}
                except botocore.exceptions.ClientError as e:
                    errors.append(self._errCode(e))
                    continue

            operation = (params or {}).get('Operation')
            if operation is not None:
                installs = self._operationInstalls(operation)
            elif isPolicy and doc not in self.PATCH_OPERATION_DOCUMENTS:
                ## Quick Setup patch policies deploy several associations
                ## (scan, install, IAM attach, agent update...). Only count one
                ## as an installer on positive evidence: its name says
                ## 'install'. Anything else is unknown, never an installer.
                lowered = str(assocName or '').lower()
                if 'install' in lowered:
                    installers.append(label)
                    return
                if 'scan' in lowered:
                    scanOnly.append(label)
                continue
            else:
                installs = False  # Operation defaults to Scan

            if installs:
                installers.append(label)
                return
            scanOnly.append(label)

    def _collectPatchWindowTasks(self, installers, scanOnly, errors):
        try:
            paginator = self.ssmClient.get_paginator(
                'describe_maintenance_windows')
            windows = []
            for page in paginator.paginate():
                windows.extend(page.get('WindowIdentities', []) or [])
        except botocore.exceptions.ClientError as e:
            errors.append(self._errCode(e))
            return

        for window in windows:
            if window.get('Enabled') is False or not window.get('WindowId'):
                continue
            windowId = window['WindowId']
            try:
                paginator = self.ssmClient.get_paginator(
                    'describe_maintenance_window_tasks')
                tasks = []
                for page in paginator.paginate(WindowId=windowId):
                    tasks.extend(page.get('Tasks', []) or [])
            except botocore.exceptions.ClientError as e:
                errors.append(self._errCode(e))
                continue

            for task in tasks:
                doc = self._docName(task.get('TaskArn'))
                label = (f"maintenance window '{window.get('Name') or windowId}' "
                         f"task ({doc})")
                if doc in self.PATCH_INSTALL_DOCUMENTS:
                    installers.append(label)
                    return
                if doc not in self.PATCH_OPERATION_DOCUMENTS:
                    continue

                operation = ((task.get('TaskParameters') or {})
                             .get('Operation') or {}).get('Values')
                if operation is None and task.get('WindowTaskId'):
                    ## Tasks registered with TaskInvocationParameters do not
                    ## echo parameters in describe_maintenance_window_tasks.
                    try:
                        full = self.ssmClient.get_maintenance_window_task(
                            WindowId=windowId, WindowTaskId=task['WindowTaskId'])
                    except botocore.exceptions.ClientError as e:
                        errors.append(self._errCode(e))
                        continue
                    invocation = full.get('TaskInvocationParameters') or {}
                    for sub in ('RunCommand', 'Automation'):
                        p = (invocation.get(sub) or {}).get('Parameters') or {}
                        if 'Operation' in p:
                            operation = p['Operation']
                            break

                if self._operationInstalls(operation):
                    installers.append(label)
                    return
                scanOnly.append(label)

    def _collectQuickSetupPatchPolicies(self, installers, scanOnly):
        """
        Enrichment only: Quick Setup patch policies also deploy State Manager
        associations into each target account/Region, which
        _collectPatchAssociations already sees. Failures here are therefore
        not treated as 'unable to evaluate'.
        """
        if self.quickSetupClient is None:
            return
        try:
            paginator = self.quickSetupClient.get_paginator(
                'list_configuration_managers')
            for page in paginator.paginate():
                for manager in page.get('ConfigurationManagersList', []) or []:
                    for summary in manager.get(
                            'ConfigurationDefinitionSummaries', []) or []:
                        if summary.get('Type') != self.QUICKSETUP_PATCH_POLICY_TYPE:
                            continue
                        label = ("Quick Setup patch policy "
                                 f"'{manager.get('Name') or manager.get('ManagerArn')}'")
                        ## Patch policy option: 'Scan' or 'ScanAndInstall'.
                        params = summary.get('FirstClassParameters') or {}
                        if not self._policyCoversHere(params):
                            continue
                        op = (params.get('ConfigurationOptionsPatchOperation')
                              or params.get('PatchOperation') or '')
                        if 'install' in str(op).lower():
                            installers.append(label)
                            return
                        scanOnly.append(label)
        except (botocore.exceptions.ClientError,
                botocore.exceptions.BotoCoreError):
            ## BotoCoreError covers EndpointConnectionError,
            ## ConnectTimeoutError, etc. Enrichment only: never drop the result.
            return

    @staticmethod
    def _splitList(value):
        if isinstance(value, (list, tuple)):
            items = value
        else:
            items = str(value or '').split(',')
        return [str(i).strip() for i in items if str(i).strip()]

    def _policyCoversHere(self, params):
        """
        list_configuration_managers returns managers whose home Region is this
        Region, but a patch policy may target other Regions/accounts only.
        Exclude a policy when its TargetRegions / TargetAccounts explicitly
        omit this Region / account. Organization/OU targets cannot be resolved
        from here and are accepted.
        """
        region = self.detail.get('_region')
        regions = self._splitList(params.get('TargetRegions'))
        if region and regions and region not in regions:
            return False
        account = self.detail.get('_accountId')
        accounts = self._splitList(params.get('TargetAccounts'))
        ous = self._splitList(params.get('TargetOrganizationalUnits'))
        if account and accounts and not ous and account not in accounts:
            return False
        return True
