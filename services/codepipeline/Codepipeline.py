import json
import threading

import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.codepipeline.drivers.CodepipelinePipeline import CodepipelinePipeline


class Codepipeline(Service):
    """
    AWS CodePipeline service scanner. One driver per pipeline.

    Hydration calls (all read-only):
      - codepipeline.list_pipelines            (paginated)
      - codepipeline.get_pipeline              (per pipeline)
      - codepipeline.list_tags_for_resource    (only when --tags filtering is used)
      - codestar-notifications.list_notification_rules / describe_notification_rule
                                                (lazy, once per region, shared)
      - events.list_rules / list_targets_by_rule (lazy, once per region, shared)
      - iam.list_attached_role_policies / get_policy / get_policy_version /
        list_role_policies / get_role_policy  (lazy, once per role, shared)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cpClient = ssBoto.client('codepipeline', config=self.bConfig)
        self.iamClient = ssBoto.client('iam', config=self.bConfig)
        self.csnClient = ssBoto.client('codestar-notifications', config=self.bConfig)
        self.evClient = ssBoto.client('events', config=self.bConfig)
        ## Shared, lazily-populated lookups. Drivers run checks in threads, so
        ## every shared cache is guarded by a lock.
        self.shared = CodepipelineShared(self.iamClient, self.csnClient, self.evClient)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        names = self._listPipelineNames()
        if not names:
            return []

        pending = set(self.registerItems('CodepipelinePipeline', names))
        pipelines = []
        for name in names:
            if name not in pending:
                ## Already checkpointed: the driver restores cached results.
                pipelines.append({'pipeline': {'name': name}, 'metadata': {}})
                continue
            try:
                resp = self.cpClient.get_pipeline(name=name)
            except botocore.exceptions.ClientError as e:
                self._logClientError('get_pipeline', e)
                continue

            pipeline = resp.get('pipeline') or {}
            metadata = resp.get('metadata') or {}
            if not pipeline.get('name'):
                continue

            if self.tags:
                tags = self._getTags(metadata.get('pipelineArn'))
                if not self.resourceHasTags(tags):
                    continue

            _pi('Codepipeline', f"Pipeline: {name}")
            pipelines.append({'pipeline': pipeline, 'metadata': metadata})
        return pipelines

    def _listPipelineNames(self):
        names = []
        try:
            paginator = self.cpClient.get_paginator('list_pipelines')
            for page in paginator.paginate():
                for p in page.get('pipelines', []) or []:
                    if p.get('name'):
                        names.append(p['name'])
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_pipelines', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CodePipeline not available in region {self.region}: {e}")
        return names

    def _getTags(self, arn):
        if not arn:
            return []
        tags = []
        try:
            paginator = self.cpClient.get_paginator('list_tags_for_resource')
            for page in paginator.paginate(resourceArn=arn):
                for t in page.get('tags', []) or []:
                    tags.append({'Key': t.get('key'), 'Value': t.get('value')})
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_tags_for_resource', e)
        return tags

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        for item in self.getResources():
            name = item['pipeline'].get('name')
            try:
                obj = CodepipelinePipeline(item['pipeline'], item['metadata'], self.shared)
                obj.run(self.__class__)
                objs[f"Pipeline::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodePipeline pipeline {name}: {e}")
        return objs

    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Codepipeline {where}: {code} - {msg}")


class CodepipelineShared:
    """
    Region-wide lookups shared by every pipeline driver, computed at most once.

    Each getter returns either the data or raises CodepipelineLookupError
    carrying the AWS error code, so a check can record [0, 'Unable to
    evaluate (<code>)'] instead of silently passing.
    """

    def __init__(self, iamClient, csnClient, evClient):
        self.iamClient = iamClient
        self.csnClient = csnClient
        self.evClient = evClient
        self._lock = threading.Lock()
        self._roleCache = {}
        self._notificationRules = None
        self._eventRules = None

    # ---------------- IAM role admin inspection ---------------- #
    def roleAdminFindings(self, roleArn):
        """
        Return a list of strings naming the admin-equivalent grants on the role
        (empty list = none), None if the role does not exist, or raise
        CodepipelineLookupError if the role cannot be read.
        """
        with self._lock:
            if roleArn in self._roleCache:
                cached = self._roleCache[roleArn]
                if isinstance(cached, CodepipelineLookupError):
                    raise cached
                return cached
            try:
                result = self._inspectRole(roleArn)
            except CodepipelineLookupError as e:
                self._roleCache[roleArn] = e
                raise
            self._roleCache[roleArn] = result
            return result

    def _inspectRole(self, roleArn):
        roleName = roleArn.split('/')[-1]
        findings = []
        try:
            pager = self.iamClient.get_paginator('list_attached_role_policies')
            for page in pager.paginate(RoleName=roleName):
                for p in page.get('AttachedPolicies', []) or []:
                    arn = p.get('PolicyArn', '') or ''
                    pname = p.get('PolicyName') or arn.split('/')[-1]
                    if arn.endswith(':policy/AdministratorAccess'):
                        findings.append('managed:AdministratorAccess')
                        continue
                    ## AWS-managed policies other than AdministratorAccess are
                    ## not "*:*"; only read customer-managed documents.
                    if ':aws:policy/' in arn:
                        continue
                    pol = self.iamClient.get_policy(PolicyArn=arn).get('Policy', {}) or {}
                    vid = pol.get('DefaultVersionId')
                    if not vid:
                        continue
                    doc = self.iamClient.get_policy_version(
                        PolicyArn=arn, VersionId=vid).get('PolicyVersion', {}).get('Document')
                    if documentGrantsAdmin(doc):
                        findings.append(f'managed:{pname}')

            pager = self.iamClient.get_paginator('list_role_policies')
            for page in pager.paginate(RoleName=roleName):
                for pname in page.get('PolicyNames', []) or []:
                    doc = self.iamClient.get_role_policy(
                        RoleName=roleName, PolicyName=pname).get('PolicyDocument')
                    if documentGrantsAdmin(doc):
                        findings.append(f'inline:{pname}')
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            if code in ('NoSuchEntity', 'NoSuchEntityException'):
                return None
            raise CodepipelineLookupError(code)
        return findings

    # ---------------- Notifications ---------------- #
    def notificationRules(self):
        """List of describe_notification_rule responses (whole region)."""
        with self._lock:
            if isinstance(self._notificationRules, CodepipelineLookupError):
                raise self._notificationRules
            if self._notificationRules is not None:
                return self._notificationRules
            rules = []
            try:
                pager = self.csnClient.get_paginator('list_notification_rules')
                for page in pager.paginate():
                    for r in page.get('NotificationRules', []) or []:
                        if not r.get('Arn'):
                            continue
                        rules.append(self.csnClient.describe_notification_rule(Arn=r['Arn']))
            except botocore.exceptions.ClientError as e:
                self._notificationRules = CodepipelineLookupError(
                    e.response.get('Error', {}).get('Code', 'Unknown'))
                raise self._notificationRules
            except botocore.exceptions.EndpointConnectionError:
                self._notificationRules = CodepipelineLookupError('EndpointUnavailable')
                raise self._notificationRules
            self._notificationRules = rules
            return rules

    def eventRules(self):
        """ENABLED default-bus rules matching aws.codepipeline that have targets:
        list of (ruleName, parsedEventPattern)."""
        with self._lock:
            if isinstance(self._eventRules, CodepipelineLookupError):
                raise self._eventRules
            if self._eventRules is not None:
                return self._eventRules
            rules = []
            try:
                pager = self.evClient.get_paginator('list_rules')
                for page in pager.paginate():
                    for r in page.get('Rules', []) or []:
                        if r.get('State') != 'ENABLED' or not r.get('EventPattern'):
                            continue
                        try:
                            pattern = json.loads(r['EventPattern'])
                        except (ValueError, TypeError):
                            continue
                        if not isinstance(pattern, dict) or \
                                'aws.codepipeline' not in _asList(pattern.get('source')):
                            continue
                        targets = []
                        tpager = self.evClient.get_paginator('list_targets_by_rule')
                        for tpage in tpager.paginate(Rule=r['Name']):
                            targets += tpage.get('Targets', []) or []
                        if targets:
                            rules.append((r['Name'], pattern))
            except botocore.exceptions.ClientError as e:
                self._eventRules = CodepipelineLookupError(
                    e.response.get('Error', {}).get('Code', 'Unknown'))
                raise self._eventRules
            self._eventRules = rules
            return rules


class CodepipelineLookupError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _asList(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def documentGrantsAdmin(doc):
    """True if an Allow statement grants Action '*' (or '*:*') on Resource '*'."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (ValueError, TypeError):
            return False
    if not isinstance(doc, dict):
        return False
    stmts = doc.get('Statement', [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts if isinstance(stmts, list) else []:
        if not isinstance(s, dict) or s.get('Effect') != 'Allow':
            continue
        actions = _asList(s.get('Action'))
        resources = _asList(s.get('Resource'))
        if any(a in ('*', '*:*') for a in actions) and '*' in resources:
            return True
    return False
