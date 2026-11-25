import botocore

from utils.Tools import _pi
from services.Service import Service

from services.backup.drivers.BackupVault import BackupVault
from services.backup.drivers.BackupPlan import BackupPlan
from services.backup.drivers.BackupAccount import BackupAccount


class Backup(Service):
    """
    AWS Backup service scanner.

    Discovers resources in three layers and dispatches to three drivers:

      - BackupVault   -- one instance per backup vault. Runs vault-level checks
                         (vault lock, encryption, access policy, empty state,
                         lock-finalisation) plus recovery-point-level checks
                         (encrypted, never-restored, expired-lifecycle, no-CMK).

      - BackupPlan    -- one instance per backup plan. Runs plan-level checks
                         (rules, lifecycle, cross-region copy, selections,
                         schedule frequency, completion window, continuous
                         backup).

      - BackupAccount -- exactly one instance per region. Runs account/region
                         level checks (no plan exists, cross-account backup
                         off, service opt-in disabled, service management
                         disabled, critical resources unprotected, no
                         logically air-gapped vault).

    Cross-service correlation for backupCriticalResourcesUnprotected uses
    lightweight describe_* calls to RDS/DynamoDB/EFS/EC2. Failures in any of
    those (permission-denied, region-not-supported) degrade the check to INFO
    rather than raising.
    """

    # Services tracked by the region-opt-in check.
    CRITICAL_SERVICES_OPT_IN = [
        'DynamoDB', 'EBS', 'EC2', 'EFS', 'RDS', 'Aurora', 'S3', 'FSx',
    ]

    # Services tracked by the management-preference check (only these two
    # currently accept ResourceTypeManagementPreference).
    MANAGED_SERVICES = ['DynamoDB', 'EFS']

    # Recovery-point sampling cap per vault. list_recovery_points_by_backup_vault
    # can return thousands of entries in production; we sample the first N to
    # keep scan time bounded.
    RECOVERY_POINT_SAMPLE_LIMIT = 100

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.backupClient = ssBoto.client('backup', config=self.bConfig)
        # Cross-service clients for backupCriticalResourcesUnprotected.
        # Any of these may fail (permission, region) — every call is wrapped
        # in try/except and the check degrades to INFO on failure.
        self.rdsClient = ssBoto.client('rds', config=self.bConfig)
        self.dynamodbClient = ssBoto.client('dynamodb', config=self.bConfig)
        self.efsClient = ssBoto.client('efs', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        # kms:DescribeKey (read-only) tells a customer-managed key apart from
        # the AWS-managed aws/backup key, which EncryptionKeyType does not.
        self.kmsClient = ssBoto.client('kms', config=self.bConfig)
        # Alerting evidence for backupNoFailureAlerting (read-only calls).
        self.eventsClient = ssBoto.client('events', config=self.bConfig)
        self.cloudwatchClient = ssBoto.client('cloudwatch', config=self.bConfig)
        # Vault summaries from list_backup_vaults keyed by name (all vaults,
        # including checkpointed ones) - used by plan-level checks that need
        # to know whether a rule's target vault is locked / air-gapped.
        self._vaultIndex = {}
        # Cache for describe_backup_vault lookups of copy destinations in
        # other Regions of this account: {vaultArn: summary|None}.
        self._remoteVaultCache = {}
        self._remoteBackupClients = {}
        # Error codes of failed list calls. A failed listing must read as
        # 'Unable to evaluate', never as 'nothing exists'.
        self._vaultsError = None
        self._plansError = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        """Return a dict with 'vaults', 'plans', 'account' so advise() can
        dispatch to the three drivers. Each entry is fully hydrated."""
        vaults = self._discoverVaults()
        plans = self._discoverPlans()
        account = self._discoverAccount(vaults, plans)
        return {'vaults': vaults, 'plans': plans, 'account': account}

    # ------------------------------------------------------------------ #
    # Vault discovery
    # ------------------------------------------------------------------ #
    def _discoverVaults(self):
        vaults = []
        try:
            paginator = self.backupClient.get_paginator('list_backup_vaults')
            for page in paginator.paginate():
                summaries = [s for s in (page.get('BackupVaultList', []) or []) if s.get('BackupVaultName')]
                for vs in summaries:
                    self._vaultIndex[vs['BackupVaultName']] = vs
                pendingNames = {s['BackupVaultName'] for s in self.registerItems(
                    'BackupVault', summaries, idFn=lambda s: s.get('BackupVaultName', 'unknown')
                )}

                for summary in summaries:
                    name = summary['BackupVaultName']

                    if name not in pendingNames:
                        ## Already checkpointed - BackupAccount is a singleton, never
                        ## gated itself, and reads _vaultType off every vault in _vaults
                        ## for the air-gapped-vault check regardless of checkpoint state.
                        ## Keep that field; everything else is safe to skip since
                        ## BackupVault's own checks are fully served from cache.
                        vaults.append({
                            '_name': name,
                            '_vaultType': summary.get('VaultType') or 'BACKUP_VAULT',
                        })
                        continue

                    detail = self._describeVault(name, summary)
                    if detail is None:
                        continue
                    _pi('Backup', f"Vault: {name}")
                    vaults.append(detail)
        except botocore.exceptions.ClientError as e:
            self._vaultsError = self._errCode(e)
            self._logClientError('list_backup_vaults', e)
        except botocore.exceptions.EndpointConnectionError as e:
            self._vaultsError = 'EndpointConnectionError'
            print(f"AWS Backup not available in region {self.region}: {e}")
        return vaults

    def _describeVault(self, name, summary):
        try:
            resp = self.backupClient.describe_backup_vault(BackupVaultName=name)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_backup_vault({name})', e)
            return None

        # get_backup_vault_access_policy raises ResourceNotFoundException when
        # no policy is attached — treat that as an explicit None.
        access_policy = None
        access_policy_missing = False
        access_policy_error = None
        try:
            pol_resp = self.backupClient.get_backup_vault_access_policy(
                BackupVaultName=name
            )
            access_policy = pol_resp.get('Policy')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'ResourceNotFoundException':
                access_policy_missing = True
            else:
                # Unreadable (AccessDenied, throttling, ...) - recorded so the
                # policy check reports "Unable to evaluate" instead of
                # treating the vault as having no policy.
                access_policy_error = code or 'ClientError'
                self._logClientError(
                    f'get_backup_vault_access_policy({name})', e
                )

        recovery_points = self._listRecoveryPoints(name)

        detail = {
            '_name': name,
            '_arn': resp.get('BackupVaultArn') or summary.get('BackupVaultArn'),
            '_creationDate': resp.get('CreationDate') or summary.get('CreationDate'),
            '_encryptionKeyArn': resp.get('EncryptionKeyArn') or summary.get('EncryptionKeyArn'),
            # EncryptionKeyType is not always present in the API response.
            # Derive from the ARN if missing (alias/aws/backup == AWS_OWNED_KMS_KEY).
            '_encryptionKeyType': resp.get('EncryptionKeyType'),
            '_numberOfRecoveryPoints': resp.get('NumberOfRecoveryPoints', 0),
            '_locked': resp.get('Locked', False),
            '_lockDate': resp.get('LockDate'),
            '_minRetentionDays': resp.get('MinRetentionDays'),
            '_maxRetentionDays': resp.get('MaxRetentionDays'),
            '_vaultType': resp.get('VaultType') or summary.get('VaultType') or 'BACKUP_VAULT',
            '_accessPolicy': access_policy,
            '_accessPolicyMissing': access_policy_missing,
            '_accessPolicyError': access_policy_error,
            # Multi-party approval (logically air-gapped vaults only).
            '_mpaApprovalTeamArn': resp.get('MpaApprovalTeamArn'),
            '_vaultState': resp.get('VaultState'),
            '_recoveryPoints': recovery_points,
        }
        return detail

    def _listRecoveryPoints(self, vaultName):
        """Sample up to RECOVERY_POINT_SAMPLE_LIMIT recovery points from the
        vault. list_recovery_points_by_backup_vault has MaxResults up to 1000
        but even 100 is enough to determine encryption/never-restored posture."""
        points = []
        try:
            resp = self.backupClient.list_recovery_points_by_backup_vault(
                BackupVaultName=vaultName,
                MaxResults=self.RECOVERY_POINT_SAMPLE_LIMIT,
            )
            for rp in resp.get('RecoveryPoints', []) or []:
                points.append(rp)
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # Empty / newly-created vaults may not return anything — that's
            # not an error condition. Log only unexpected codes.
            if code not in ('ResourceNotFoundException',):
                self._logClientError(
                    f'list_recovery_points_by_backup_vault({vaultName})', e
                )
        return points

    # ------------------------------------------------------------------ #
    # Plan discovery
    # ------------------------------------------------------------------ #
    def _discoverPlans(self):
        plans = []
        try:
            paginator = self.backupClient.get_paginator('list_backup_plans')
            for page in paginator.paginate():
                summaries = [s for s in (page.get('BackupPlansList', []) or []) if s.get('BackupPlanId')]
                pendingIds = {s['BackupPlanId'] for s in self.registerItems(
                    'BackupPlan', summaries,
                    idFn=lambda s: s.get('BackupPlanName') or s.get('BackupPlanId', 'unknown')
                )}

                for summary in summaries:
                    plan_id = summary['BackupPlanId']

                    if plan_id not in pendingIds:
                        ## Already checkpointed - BackupAccount only needs len(_plans),
                        ## no per-plan field access. Selections are internal-only to
                        ## BackupPlan's own checks (no separate selection-level driver
                        ## exists), which are fully served from cache for this plan -
                        ## safe to skip get_backup_plan + _listSelections() entirely.
                        plans.append({
                            '_id': plan_id,
                            '_name': summary.get('BackupPlanName') or plan_id,
                        })
                        continue

                    detail = self._describePlan(plan_id, summary)
                    if detail is None:
                        ## get_backup_plan failed: keep a stub so account-level
                        ## checks know the plan exists (and re-fetch / report it
                        ## as unreadable) instead of judging only the readable
                        ## plans. '_unreadable' keeps it out of BackupPlan.
                        plans.append({
                            '_id': plan_id,
                            '_name': summary.get('BackupPlanName') or plan_id,
                            '_unreadable': True,
                        })
                        continue
                    _pi('Backup', f"Plan: {detail.get('_name', plan_id)}")
                    plans.append(detail)
        except botocore.exceptions.ClientError as e:
            # Recorded so backupNoPlanExists reports 'Unable to evaluate'
            # instead of 'No backup plans exist' (the list may be partial).
            self._plansError = self._errCode(e)
            self._logClientError('list_backup_plans', e)
        except botocore.exceptions.EndpointConnectionError:
            self._plansError = 'EndpointConnectionError'
        return plans

    def _describePlan(self, planId, summary):
        try:
            resp = self.backupClient.get_backup_plan(BackupPlanId=planId)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_backup_plan({planId})', e)
            return None

        plan_body = resp.get('BackupPlan') or {}
        selections, selectionsError = self._listSelections(planId)

        detail = {
            '_id': planId,
            '_name': summary.get('BackupPlanName') or plan_body.get('BackupPlanName') or planId,
            '_arn': resp.get('BackupPlanArn') or summary.get('BackupPlanArn'),
            '_rules': plan_body.get('Rules') or [],
            '_selections': selections,
            # Error code when list_backup_selections failed (the list may be
            # empty or partial) - backupPlanNotAssigned must not FAIL on it.
            '_selectionsError': selectionsError,
            '_scanSettings': plan_body.get('ScanSettings') or [],
            '_creationDate': resp.get('CreationDate') or summary.get('CreationDate'),
        }
        return detail

    def _listSelections(self, planId):
        """Return every BackupSelection attached to a plan, hydrated with the
        Resources / ListOfTags / Conditions fields (which list_backup_selections
        does not include — those require get_backup_selection).

        Returns (selections, errorCode); errorCode is None when the whole
        listing was read."""
        selections = []
        try:
            paginator = self.backupClient.get_paginator('list_backup_selections')
            for page in paginator.paginate(BackupPlanId=planId):
                for summary in page.get('BackupSelectionsList', []) or []:
                    selection_id = summary.get('SelectionId')
                    if not selection_id:
                        selections.append(summary)
                        continue
                    detail = self._getSelectionDetail(planId, selection_id, summary)
                    selections.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_backup_selections({planId})', e)
            return selections, self._errCode(e)
        return selections, None

    def _getSelectionDetail(self, planId, selectionId, summary):
        """Merge get_backup_selection's BackupSelection body (Resources,
        ListOfTags, Conditions, NotResources, IamRoleArn) into the summary
        entry so drivers see one flat dict."""
        merged = dict(summary)
        try:
            resp = self.backupClient.get_backup_selection(
                BackupPlanId=planId, SelectionId=selectionId
            )
            body = resp.get('BackupSelection') or {}
            for k in ('Resources', 'ListOfTags', 'Conditions',
                      'NotResources', 'IamRoleArn', 'SelectionName'):
                if k in body:
                    merged[k] = body[k]
        except botocore.exceptions.ClientError as e:
            self._logClientError(
                f'get_backup_selection({planId}/{selectionId})', e
            )
        return merged

    # ------------------------------------------------------------------ #
    # Account-level discovery
    # ------------------------------------------------------------------ #
    def _discoverAccount(self, vaults, plans):
        global_settings = self._describeGlobalSettings()
        region_settings = self._describeRegionSettings()
        protected_arns, protected_error = self._listProtectedResources()
        candidate_resources, candidate_errors = self._enumerateBackupCandidates()

        return {
            '_name': self.region,
            '_region': self.region,
            '_accountId': self._callerAccountId(),
            '_vaults': vaults,
            '_vaultsError': self._vaultsError,
            '_plans': plans,
            '_plansError': self._plansError,
            '_globalSettings': global_settings,
            '_regionSettings': region_settings,
            '_protectedArns': protected_arns,
            '_protectedArnsError': protected_error,
            '_candidateResources': candidate_resources,
            '_candidateErrors': candidate_errors,
            '_criticalServicesOptIn': self.CRITICAL_SERVICES_OPT_IN,
            '_managedServices': self.MANAGED_SERVICES,
        }

    def _describeGlobalSettings(self):
        """describe_global_settings only works if the account is a member of
        AWS Organizations (management or delegated admin). Otherwise the API
        raises InvalidRequestException. Handle gracefully — the check
        downgrades to INFO in that case."""
        try:
            resp = self.backupClient.describe_global_settings()
            return {
                '_available': True,
                'GlobalSettings': resp.get('GlobalSettings') or {},
                'LastUpdateTime': resp.get('LastUpdateTime'),
            }
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # InvalidRequestException / AccessDeniedException == not in an
            # organization (or the caller lacks permission). Either way the
            # check is not applicable to this account.
            if code in ('InvalidRequestException', 'AccessDenied',
                        'AccessDeniedException', 'AuthorizationError'):
                return {'_available': False, '_reason': code, 'GlobalSettings': {}}
            self._logClientError('describe_global_settings', e)
            return {'_available': False, '_reason': code, 'GlobalSettings': {}}

    def _describeRegionSettings(self):
        try:
            resp = self.backupClient.describe_region_settings()
            return {
                '_available': True,
                'ResourceTypeOptInPreference': resp.get('ResourceTypeOptInPreference') or {},
                'ResourceTypeManagementPreference': resp.get('ResourceTypeManagementPreference') or {},
            }
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            self._logClientError('describe_region_settings', e)
            return {
                '_available': False,
                '_reason': code,
                'ResourceTypeOptInPreference': {},
                'ResourceTypeManagementPreference': {},
            }

    def _listProtectedResources(self):
        """Return (arns, errorCode): the ARNs of every resource that AWS Backup
        has taken at least one recovery point of, used by
        backupCriticalResourcesUnprotected as the 'protected' set. errorCode is
        set when the listing failed - the set is then empty or partial and the
        check must not treat its absence as 'unprotected'."""
        arns = set()
        try:
            paginator = self.backupClient.get_paginator('list_protected_resources')
            for page in paginator.paginate():
                for entry in page.get('Results', []) or []:
                    arn = entry.get('ResourceArn')
                    if arn:
                        arns.add(arn)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_protected_resources', e)
            return arns, self._errCode(e)
        except botocore.exceptions.EndpointConnectionError:
            return arns, 'EndpointConnectionError'
        return arns, None

    def _enumerateBackupCandidates(self):
        """Enumerate resources across RDS/DynamoDB/EFS/EC2 that ought to be
        backed up. Returns ({service: [candidate, ...]}, [error, ...]).

        A candidate is a dict {'arn': <ARN shown in the report>, 'protectedBy':
        [ARNs any one of which, when in list_protected_resources, protects it]}.
        AWS Backup protects some resources at a different level than the one
        they are listed at: Aurora / DocumentDB / Neptune per cluster, and EBS
        volumes also through a backup of the EC2 instance they are attached to.

        Every service is enumerated independently so one failing does not
        block the others; errors are returned (as 'service.operation:code')
        so the check reports 'Unable to evaluate' instead of a PASS that
        silently skipped a service."""
        errors = []
        out = {}
        for svc, fn in (('RDS', self._enumRdsInstances), ('DynamoDB', self._enumDynamoTables),
                        ('EFS', self._enumEfsFilesystems), ('EBS', self._enumEbsVolumes)):
            items, errs = fn()
            out[svc] = items
            errors.extend(errs)
        return out, errors

    @staticmethod
    def _candidate(arn, protectedBy=None):
        return {'arn': arn, 'protectedBy': list(protectedBy or [arn])}

    def _enumRdsInstances(self):
        """RDS DB instances and DB clusters. Instances that belong to a cluster
        (Aurora, DocumentDB, Neptune, Multi-AZ DB clusters) are backed up by
        AWS Backup per cluster, so list_protected_resources reports the
        cluster ARN (arn:<p>:rds:<r>:<acct>:cluster:<id>), never the member
        instance ARN. Those instances are folded into one cluster candidate;
        clusters with no instances are added from describe_db_clusters."""
        items, errors = [], []
        clusterArns = {}
        try:
            paginator = self.rdsClient.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []) or []:
                    arn = db.get('DBInstanceArn')
                    if not arn:
                        continue
                    clusterId = db.get('DBClusterIdentifier')
                    if clusterId and ':db:' in arn:
                        clusterArns.setdefault(
                            f"{arn.rsplit(':db:', 1)[0]}:cluster:{clusterId}", True)
                        continue
                    items.append(self._candidate(arn))
        except botocore.exceptions.ClientError as e:
            self._logClientError('rds.describe_db_instances', e)
            errors.append(f"rds.describe_db_instances:{self._errCode(e)}")
        except botocore.exceptions.EndpointConnectionError:
            errors.append('rds.describe_db_instances:EndpointConnectionError')
        try:
            paginator = self.rdsClient.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                for cl in page.get('DBClusters', []) or []:
                    arn = cl.get('DBClusterArn')
                    if arn:
                        clusterArns.setdefault(arn, True)
        except botocore.exceptions.ClientError as e:
            self._logClientError('rds.describe_db_clusters', e)
            errors.append(f"rds.describe_db_clusters:{self._errCode(e)}")
        except botocore.exceptions.EndpointConnectionError:
            errors.append('rds.describe_db_clusters:EndpointConnectionError')
        items.extend(self._candidate(a) for a in clusterArns)
        return items, errors

    def _enumDynamoTables(self):
        items, errors = [], []
        try:
            paginator = self.dynamodbClient.get_paginator('list_tables')
            for page in paginator.paginate():
                for name in page.get('TableNames', []) or []:
                    # describe_table returns the TableArn in the exact format
                    # list_protected_resources uses (partition included).
                    try:
                        d = self.dynamodbClient.describe_table(TableName=name)
                        arn = (d.get('Table') or {}).get('TableArn')
                        if arn:
                            items.append(self._candidate(arn))
                    except botocore.exceptions.ClientError as e:
                        errors.append(f"dynamodb.describe_table({name}):{self._errCode(e)}")
        except botocore.exceptions.ClientError as e:
            self._logClientError('dynamodb.list_tables', e)
            errors.append(f"dynamodb.list_tables:{self._errCode(e)}")
        except botocore.exceptions.EndpointConnectionError:
            errors.append('dynamodb.list_tables:EndpointConnectionError')
        return items, errors

    def _enumEfsFilesystems(self):
        items, errors = [], []
        try:
            paginator = self.efsClient.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []) or []:
                    arn = fs.get('FileSystemArn')
                    if arn:
                        items.append(self._candidate(arn))
        except botocore.exceptions.ClientError as e:
            self._logClientError('efs.describe_file_systems', e)
            errors.append(f"efs.describe_file_systems:{self._errCode(e)}")
        except botocore.exceptions.EndpointConnectionError:
            errors.append('efs.describe_file_systems:EndpointConnectionError')
        return items, errors

    def _enumEbsVolumes(self):
        """In-use EBS volumes. Unattached ('available') volumes are not
        enumerated, to avoid flagging leftovers of terminated instances.

        describe_volumes returns no ARN, so it is built as
        arn:<partition>:ec2:<region>:<account>:volume/<id> - the format
        list_protected_resources uses. The partition comes from the caller
        ARN (aws, aws-cn, aws-us-gov, ...). A volume counts as protected when
        either the volume itself or an instance it is attached to is in the
        protected set (EC2 backups are listed per instance). Without a known
        account id no ARN can be built: reported as an error, never as a bare
        volume id that could never match."""
        items, errors = [], []
        acct = self._callerAccountId()
        partition = self._partition()
        if not acct or not partition:
            return items, ['ec2.describe_volumes:caller account/partition unknown']
        prefix = f"arn:{partition}:ec2:{self.region}:{acct}"
        try:
            paginator = self.ec2Client.get_paginator('describe_volumes')
            for page in paginator.paginate(
                Filters=[{'Name': 'status', 'Values': ['in-use']}]
            ):
                for vol in page.get('Volumes', []) or []:
                    vol_id = vol.get('VolumeId')
                    if not vol_id:
                        continue
                    arn = f"{prefix}:volume/{vol_id}"
                    via = [arn]
                    for att in vol.get('Attachments') or []:
                        if att.get('InstanceId'):
                            via.append(f"{prefix}:instance/{att['InstanceId']}")
                    items.append(self._candidate(arn, via))
        except botocore.exceptions.ClientError as e:
            self._logClientError('ec2.describe_volumes', e)
            errors.append(f"ec2.describe_volumes:{self._errCode(e)}")
        except botocore.exceptions.EndpointConnectionError:
            errors.append('ec2.describe_volumes:EndpointConnectionError')
        return items, errors

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        try:
            resources = self.getResources()
        except botocore.exceptions.ClientError as e:
            self._logClientError('getResources', e)
            return objs

        # --- Per-vault --------------------------------------------------
        for vault in resources.get('vaults', []):
            try:
                name = vault.get('_name', 'unknown')
                _pi('Backup', f"Analyzing vault: {name}")
                obj = BackupVault(vault, self.backupClient, kmsClient=self.kmsClient)
                obj.run(self.__class__)
                objs[f"Backup::Vault::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing backup vault {vault.get('_name')}: {e}")

        # --- Per-plan ---------------------------------------------------
        for plan in resources.get('plans', []):
            if plan.get('_unreadable'):
                continue
            try:
                name = plan.get('_name') or plan.get('_id') or 'unknown'
                _pi('Backup', f"Analyzing plan: {name}")
                obj = BackupPlan(plan, self.backupClient,
                                 vaultLookup=self._lookupVault,
                                 accountId=self._callerAccountId(),
                                 region=self.region)
                obj.run(self.__class__)
                objs[f"Backup::Plan::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing backup plan {plan.get('_id')}: {e}")

        # --- Account/region-level --------------------------------------
        try:
            account = resources.get('account') or {}
            _pi('Backup', f"Analyzing account/region: {self.region}")
            obj = BackupAccount(account, self.backupClient,
                                eventsClient=self.eventsClient,
                                cloudwatchClient=self.cloudwatchClient,
                                vaultLookup=self._lookupVault)
            obj.run(self.__class__)
            objs[f"Backup::Account::{self.region}"] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing backup account/region {self.region}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _callerAccountId(self):
        from utils.Config import Config
        return (Config.get('stsInfo', {}) or {}).get('Account')

    def _partition(self):
        """ARN partition of the scanned account: from the caller ARN, else
        from the region (botocore endpoint data). None when unknown."""
        from utils.Config import Config
        arn = (Config.get('stsInfo', {}) or {}).get('Arn') or ''
        parts = arn.split(':')
        if len(parts) > 2 and parts[0] == 'arn' and parts[1]:
            return parts[1]
        try:
            return self.ssBoto.get_partition_for_region(self.region)
        except Exception:
            return None

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code') or 'ClientError'

    def _lookupVault(self, vaultArn):
        """Resolve a backup vault ARN (in this account) to a vault summary
        dict with at least Locked / VaultType / MinRetentionDays.

        Returns (summary, None) on success, (None, reason) when the vault
        cannot be read. Vaults in this Region come from the list_backup_vaults
        index; vaults in another Region of this account are read with a
        read-only describe_backup_vault call against that Region. A bare
        vault name is resolved against this Region's index."""
        if vaultArn and not vaultArn.startswith('arn:'):
            if vaultArn in self._vaultIndex:
                return self._vaultIndex[vaultArn], None
            return None, 'vault not found'
        parts = (vaultArn or '').split(':')
        if len(parts) < 7 or parts[2] != 'backup' or parts[5] != 'backup-vault':
            return None, 'unparseable ARN'
        region, name = parts[3], ':'.join(parts[6:])
        if region == self.region:
            if name in self._vaultIndex:
                return self._vaultIndex[name], None
            return None, 'vault not found'
        if vaultArn in self._remoteVaultCache:
            return self._remoteVaultCache[vaultArn]
        result = (None, 'unknown')
        try:
            client = self._remoteBackupClients.get(region)
            if client is None:
                from botocore.config import Config as _BConfig
                client = self.ssBoto.client('backup', region_name=region,
                                            config=self.bConfig.merge(_BConfig(region_name=region)))
                self._remoteBackupClients[region] = client
            resp = client.describe_backup_vault(BackupVaultName=name)
            result = (resp, None)
        except botocore.exceptions.ClientError as e:
            result = (None, e.response.get('Error', {}).get('Code', 'ClientError'))
        except botocore.exceptions.BotoCoreError as e:
            result = (None, type(e).__name__)
        self._remoteVaultCache[vaultArn] = result
        return result

    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError',
                    'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Backup {where}: {code} - {msg}")
