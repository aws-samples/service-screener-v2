import datetime

from services.Evaluator import Evaluator
from services.bedrock.drivers.BedrockAgent import _inspectRoleForBroadPolicies


class BedrockKnowledgeBase(Evaluator):
    """
    Per-knowledge-base checks (reporter keys 21-25):
      bedrockKBNoEncryption, bedrockKBStatusFailed, bedrockKBNoDataSources,
      bedrockKBDataSourceSyncStale, bedrockKBRoleOverprivileged.

    Input is the dict returned by Bedrock.py._describeKnowledgeBase(...) — i.e.,
    the 'knowledgeBase' field of get_knowledge_base, plus the internal
    '_dataSources' and '_ingestionJobs' attachments.
    """

    SYNC_STALE_DAYS = 7

    BROAD_ACTIONS = {'*', 'bedrock:*', 's3:*', 'kms:*', 'aoss:*', 'opensearch:*'}

    NON_OPERATIONAL_KB_STATUSES = {'FAILED', 'DELETING', 'DELETE_UNSUCCESSFUL'}

    def __init__(self, kb, agentClient, iamClient):
        super().__init__()
        self.kb = kb
        self.agentClient = agentClient
        self.iamClient = iamClient

        name = kb.get('name') or kb.get('knowledgeBaseId', 'unknown')
        self._resourceName = name

        self.addII('knowledgeBaseId', kb.get('knowledgeBaseId', 'N/A'))
        self.addII('name', name)
        self.addII('status', kb.get('status', 'N/A'))
        self.addII('roleArn', kb.get('roleArn', 'N/A'))
        self.addII('dataSourceCount', len(kb.get('_dataSources') or []))

    # ------------------------------------------------------------------ #
    # 21. No customer-managed encryption key
    # ------------------------------------------------------------------ #
    def _checkBedrockKBNoEncryption(self):
        # Modern boto3 surfaces this at the top-level knowledgeBase too;
        # check both common spellings for robustness.
        kms = None
        kbCfg = self.kb.get('knowledgeBaseConfiguration') or {}
        # Some configurations carry encryption under managed KB config:
        managed = kbCfg.get('managedKnowledgeBaseConfiguration') or {}
        sse = managed.get('serverSideEncryptionConfiguration') or {}
        kms = sse.get('kmsKeyArn')

        # Vector KBs use a storage configuration; we also accept the top-level
        # 'serverSideEncryptionConfiguration' if present.
        topSSE = self.kb.get('serverSideEncryptionConfiguration') or {}
        kms = kms or topSSE.get('kmsKeyArn')

        if kms:
            self.results['bedrockKBNoEncryption'] = [1, f"CMK: {kms}"]
        else:
            self.results['bedrockKBNoEncryption'] = [-1, "Default encryption (no CMK)"]

    # ------------------------------------------------------------------ #
    # 22. Status FAILED
    # ------------------------------------------------------------------ #
    def _checkBedrockKBStatusFailed(self):
        status = self.kb.get('status', 'UNKNOWN')
        if status in self.NON_OPERATIONAL_KB_STATUSES:
            self.results['bedrockKBStatusFailed'] = [-1, f"KB status: {status}"]
        else:
            self.results['bedrockKBStatusFailed'] = [1, f"KB status: {status}"]

    # ------------------------------------------------------------------ #
    # 23. No data sources
    # ------------------------------------------------------------------ #
    def _checkBedrockKBNoDataSources(self):
        dataSources = self.kb.get('_dataSources') or []
        if not dataSources:
            self.results['bedrockKBNoDataSources'] = [-1, "Knowledge base has 0 data sources"]
        else:
            self.results['bedrockKBNoDataSources'] = [1, f"{len(dataSources)} data source(s)"]

    # ------------------------------------------------------------------ #
    # 24. Data source sync stale
    # ------------------------------------------------------------------ #
    def _checkBedrockKBDataSourceSyncStale(self):
        dataSources = self.kb.get('_dataSources') or []
        if not dataSources:
            # Nothing to sync; check #23 covers the empty-KB case.
            self.results['bedrockKBDataSourceSyncStale'] = [0, "No data sources to evaluate"]
            return

        ingestionByDs = self.kb.get('_ingestionJobs') or {}
        threshold = datetime.timedelta(days=self.SYNC_STALE_DAYS)
        # Use a tz-aware "now" so timestamps from boto3 (UTC tz-aware) compare cleanly.
        now = datetime.datetime.now(datetime.timezone.utc)

        stale = []
        for ds in dataSources:
            dsId = ds.get('dataSourceId')
            dsName = ds.get('name', dsId or 'unknown')
            jobs = ingestionByDs.get(dsId, [])

            if not jobs:
                stale.append(f"{dsName}(never synced)")
                continue

            # Pick the most-recent COMPLETE job (fall back to most-recent of any status)
            completedTimes = []
            allTimes = []
            for j in jobs:
                t = j.get('updatedAt') or j.get('startedAt')
                if not t:
                    continue
                t = self._asAware(t)
                allTimes.append(t)
                if j.get('status') == 'COMPLETE':
                    completedTimes.append(t)

            mostRecent = max(completedTimes) if completedTimes else (max(allTimes) if allTimes else None)
            if mostRecent is None:
                stale.append(f"{dsName}(no timestamp)")
                continue

            if (now - mostRecent) > threshold:
                stale.append(f"{dsName}(synced {mostRecent.date().isoformat()})")

        if stale:
            self.results['bedrockKBDataSourceSyncStale'] = [
                -1,
                f"Stale data source(s): {', '.join(stale)}"
            ]
        else:
            self.results['bedrockKBDataSourceSyncStale'] = [
                1,
                f"All {len(dataSources)} data source(s) synced within {self.SYNC_STALE_DAYS} days"
            ]

    # ------------------------------------------------------------------ #
    # 25. KB role overprivileged
    # ------------------------------------------------------------------ #
    def _checkBedrockKBRoleOverprivileged(self):
        roleArn = self.kb.get('roleArn')
        if not roleArn:
            self.results['bedrockKBRoleOverprivileged'] = [0, "No service role to inspect"]
            return

        roleName = self._roleNameFromArn(roleArn)
        if not roleName:
            self.results['bedrockKBRoleOverprivileged'] = [0, f"Could not parse role ARN: {roleArn}"]
            return

        findings = _inspectRoleForBroadPolicies(self.iamClient, roleName, self.BROAD_ACTIONS)
        if findings:
            self.results['bedrockKBRoleOverprivileged'] = [
                -1,
                "Overly permissive: " + "; ".join(findings)
            ]
        else:
            self.results['bedrockKBRoleOverprivileged'] = [1, "Role appears scoped"]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _roleNameFromArn(arn):
        if not arn or ':role/' not in arn:
            return None
        return arn.split(':role/', 1)[1].split('/')[-1]

    @staticmethod
    def _asAware(dt):
        """Return a timezone-aware datetime (assume UTC if naive)."""
        if not isinstance(dt, datetime.datetime):
            # boto3 returns datetime objects; defensive fallback if a string slipped through.
            try:
                return datetime.datetime.fromisoformat(str(dt)).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                return datetime.datetime.now(datetime.timezone.utc)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt
