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
                for summary in page.get('BackupVaultList', []) or []:
                    name = summary.get('BackupVaultName')
                    if not name:
                        continue
                    detail = self._describeVault(name, summary)
                    if detail is None:
                        continue
                    _pi('Backup', f"Vault: {name}")
                    vaults.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_backup_vaults', e)
        except botocore.exceptions.EndpointConnectionError as e:
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
                for summary in page.get('BackupPlansList', []) or []:
                    plan_id = summary.get('BackupPlanId')
                    if not plan_id:
                        continue
                    detail = self._describePlan(plan_id, summary)
                    if detail is None:
                        continue
                    _pi('Backup', f"Plan: {detail.get('_name', plan_id)}")
                    plans.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_backup_plans', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return plans

    def _describePlan(self, planId, summary):
        try:
            resp = self.backupClient.get_backup_plan(BackupPlanId=planId)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_backup_plan({planId})', e)
            return None

        plan_body = resp.get('BackupPlan') or {}
        selections = self._listSelections(planId)

        detail = {
            '_id': planId,
            '_name': summary.get('BackupPlanName') or plan_body.get('BackupPlanName') or planId,
            '_arn': resp.get('BackupPlanArn') or summary.get('BackupPlanArn'),
            '_rules': plan_body.get('Rules') or [],
            '_selections': selections,
            '_creationDate': resp.get('CreationDate') or summary.get('CreationDate'),
        }
        return detail

    def _listSelections(self, planId):
        """Return every BackupSelection attached to a plan, hydrated with the
        Resources / ListOfTags / Conditions fields (which list_backup_selections
        does not include — those require get_backup_selection)."""
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
        return selections

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
        protected_arns = self._listProtectedResources()
        candidate_resources = self._enumerateBackupCandidates()

        return {
            '_name': self.region,
            '_region': self.region,
            '_vaults': vaults,
            '_plans': plans,
            '_globalSettings': global_settings,
            '_regionSettings': region_settings,
            '_protectedArns': protected_arns,
            '_candidateResources': candidate_resources,
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
        """Return a set of ARNs for every resource that AWS Backup has taken
        at least one recovery point of. Used by
        backupCriticalResourcesUnprotected as the 'protected' set."""
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
        return arns

    def _enumerateBackupCandidates(self):
        """Enumerate resources across RDS/DynamoDB/EFS/EC2 that ought to be
        backed up. Returns a dict of {service: [arn, ...]}. Every call is
        wrapped in its own try/except so a single service failing does not
        block the others; the check reports what it could enumerate."""
        return {
            'RDS': self._enumRdsInstances(),
            'DynamoDB': self._enumDynamoTables(),
            'EFS': self._enumEfsFilesystems(),
            'EBS': self._enumEbsVolumes(),
        }

    def _enumRdsInstances(self):
        arns = []
        try:
            paginator = self.rdsClient.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []) or []:
                    arn = db.get('DBInstanceArn')
                    if arn:
                        arns.append(arn)
        except botocore.exceptions.ClientError as e:
            self._logClientError('rds.describe_db_instances', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return arns

    def _enumDynamoTables(self):
        arns = []
        try:
            paginator = self.dynamodbClient.get_paginator('list_tables')
            for page in paginator.paginate():
                for name in page.get('TableNames', []) or []:
                    # Cheaper than describe_table: build the ARN from account
                    # + region + name. Match backup's list_protected_resources
                    # response format.
                    try:
                        d = self.dynamodbClient.describe_table(TableName=name)
                        arn = (d.get('Table') or {}).get('TableArn')
                        if arn:
                            arns.append(arn)
                    except botocore.exceptions.ClientError:
                        continue
        except botocore.exceptions.ClientError as e:
            self._logClientError('dynamodb.list_tables', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return arns

    def _enumEfsFilesystems(self):
        arns = []
        try:
            paginator = self.efsClient.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []) or []:
                    arn = fs.get('FileSystemArn')
                    if arn:
                        arns.append(arn)
        except botocore.exceptions.ClientError as e:
            self._logClientError('efs.describe_file_systems', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return arns

    def _enumEbsVolumes(self):
        """EBS volumes are backed up per-volume. Only enumerate 'in-use'
        volumes to avoid flagging root-of-terminated-instance snapshots or
        transient volumes. AWS Backup ARNs for EBS use the format
        arn:aws:ec2:region:account:volume/vol-xxxxx."""
        arns = []
        from utils.Config import Config
        acct = (Config.get('stsInfo', {}) or {}).get('Account')
        try:
            paginator = self.ec2Client.get_paginator('describe_volumes')
            for page in paginator.paginate(
                Filters=[{'Name': 'status', 'Values': ['in-use', 'available']}]
            ):
                for vol in page.get('Volumes', []) or []:
                    vol_id = vol.get('VolumeId')
                    if not vol_id:
                        continue
                    if acct:
                        arns.append(f"arn:aws:ec2:{self.region}:{acct}:volume/{vol_id}")
                    else:
                        arns.append(vol_id)
        except botocore.exceptions.ClientError as e:
            self._logClientError('ec2.describe_volumes', e)
        except botocore.exceptions.EndpointConnectionError:
            pass
        return arns

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
                obj = BackupVault(vault, self.backupClient)
                obj.run(self.__class__)
                objs[f"Backup::Vault::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing backup vault {vault.get('_name')}: {e}")

        # --- Per-plan ---------------------------------------------------
        for plan in resources.get('plans', []):
            try:
                name = plan.get('_name') or plan.get('_id') or 'unknown'
                _pi('Backup', f"Analyzing plan: {name}")
                obj = BackupPlan(plan, self.backupClient)
                obj.run(self.__class__)
                objs[f"Backup::Plan::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing backup plan {plan.get('_id')}: {e}")

        # --- Account/region-level --------------------------------------
        try:
            account = resources.get('account') or {}
            _pi('Backup', f"Analyzing account/region: {self.region}")
            obj = BackupAccount(account, self.backupClient)
            obj.run(self.__class__)
            objs[f"Backup::Account::{self.region}"] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing backup account/region {self.region}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'AuthorizationError',
                    'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Backup {where}: {code} - {msg}")
