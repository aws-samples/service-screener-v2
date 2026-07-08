import botocore

from utils.Config import Config
from utils.Tools import _pi
from services.Service import Service

from services.bedrock.drivers.BedrockAgent import BedrockAgent
from services.bedrock.drivers.BedrockGuardrail import BedrockGuardrail
from services.bedrock.drivers.BedrockKnowledgeBase import BedrockKnowledgeBase
from services.bedrock.drivers.BedrockAccount import BedrockAccount
from services.bedrock.drivers.BedrockServiceLimits import BedrockServiceLimits
from services.bedrock.drivers.BedrockAgentCore import BedrockAgentCore


class Bedrock(Service):
    """
    Amazon Bedrock service scanner.

    Covers:
      - Agents (bedrock-agent client): get_agent, list_agent_action_groups, list_agent_versions
      - Guardrails (bedrock client): list_guardrails / get_guardrail
      - Knowledge Bases (bedrock-agent client): list_knowledge_bases / get_knowledge_base
        + list_data_sources + list_ingestion_jobs
      - Account-level model invocation logging (bedrock client)
      - Service quotas (service-quotas client, ServiceCode='bedrock')
    """

    # Cap to avoid pathological costs on accounts with very large agent fleets.
    AGENT_VERSION_LIST_LIMIT = 20

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto

        # bedrock-agent: agents, action groups, knowledge bases, data sources, ingestion jobs
        self.agentClient = ssBoto.client('bedrock-agent', config=self.bConfig)
        # bedrock: guardrails, model invocation logging
        self.bedrockClient = ssBoto.client('bedrock', config=self.bConfig)
        # service-quotas: service-limit checks
        self.serviceQuotaClient = ssBoto.client('service-quotas', config=self.bConfig)
        # iam: role policy analysis (regional caller, IAM is global)
        self.iamClient = ssBoto.client('iam', config=self.bConfig)

        # bedrock-agentcore-control: AgentCore runtimes, gateways, memory, policy, identity, evaluators
        # Constructed best-effort; the region may not support AgentCore yet.
        try:
            self.agentcoreControlClient = ssBoto.client(
                'bedrock-agentcore-control', config=self.bConfig
            )
        except Exception as e:
            print(f"bedrock-agentcore-control client unavailable in region {self.region}: {e}")
            self.agentcoreControlClient = None

    # ------------------------------------------------------------------ #
    # Resource discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        resources = {
            'agents': [],
            'guardrails': [],
            'knowledgeBases': [],
            'loggingConfig': None,
            'agentcore': None,
        }

        self._collectAgents(resources)
        self._collectGuardrails(resources)
        self._collectKnowledgeBases(resources)
        self._collectLoggingConfig(resources)
        self._collectAgentCore(resources)

        return resources

    def _collectAgents(self, resources):
        try:
            paginator = self.agentClient.get_paginator('list_agents')
            for page in paginator.paginate():
                for summary in page.get('agentSummaries', []):
                    agentId = summary.get('agentId')
                    if not agentId:
                        continue
                    detail = self._describeAgent(agentId)
                    if detail is None:
                        continue
                    _pi('Bedrock', f"Agent: {detail.get('agentName', agentId)}")
                    resources['agents'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_agents', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Bedrock not available in region {self.region}: {e}")

    def _describeAgent(self, agentId):
        try:
            resp = self.agentClient.get_agent(agentId=agentId)
            agent = resp.get('agent', {})
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_agent({agentId})', e)
            return None

        # Action groups for the working DRAFT version
        actionGroups = []
        try:
            ag_paginator = self.agentClient.get_paginator('list_agent_action_groups')
            for page in ag_paginator.paginate(agentId=agentId, agentVersion='DRAFT'):
                for summary in page.get('actionGroupSummaries', []):
                    agId = summary.get('actionGroupId')
                    if not agId:
                        continue
                    try:
                        agResp = self.agentClient.get_agent_action_group(
                            agentId=agentId,
                            agentVersion='DRAFT',
                            actionGroupId=agId
                        )
                        actionGroups.append(agResp.get('agentActionGroup', {}))
                    except botocore.exceptions.ClientError as e:
                        self._logClientError(f'get_agent_action_group({agId})', e)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_agent_action_groups({agentId})', e)

        # Versions (capped)
        versions = []
        try:
            v_paginator = self.agentClient.get_paginator('list_agent_versions')
            for page in v_paginator.paginate(agentId=agentId):
                versions.extend(page.get('agentVersionSummaries', []))
                if len(versions) >= self.AGENT_VERSION_LIST_LIMIT:
                    break
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_agent_versions({agentId})', e)

        agent['_actionGroups'] = actionGroups
        agent['_versions'] = versions
        return agent

    def _collectGuardrails(self, resources):
        try:
            paginator = self.bedrockClient.get_paginator('list_guardrails')
            for page in paginator.paginate():
                for summary in page.get('guardrails', []):
                    guardrailId = summary.get('id') or summary.get('arn')
                    if not guardrailId:
                        continue
                    detail = self._describeGuardrail(guardrailId)
                    if detail is None:
                        continue
                    _pi('Bedrock', f"Guardrail: {detail.get('name', guardrailId)}")
                    resources['guardrails'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_guardrails', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Bedrock guardrails not available in region {self.region}: {e}")

    def _describeGuardrail(self, guardrailId):
        try:
            # No version param => DRAFT (latest)
            return self.bedrockClient.get_guardrail(guardrailIdentifier=guardrailId)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_guardrail({guardrailId})', e)
            return None

    def _collectKnowledgeBases(self, resources):
        try:
            paginator = self.agentClient.get_paginator('list_knowledge_bases')
            for page in paginator.paginate():
                for summary in page.get('knowledgeBaseSummaries', []):
                    kbId = summary.get('knowledgeBaseId')
                    if not kbId:
                        continue
                    detail = self._describeKnowledgeBase(kbId)
                    if detail is None:
                        continue
                    _pi('Bedrock', f"KnowledgeBase: {detail.get('name', kbId)}")
                    resources['knowledgeBases'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_knowledge_bases', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Bedrock knowledge bases not available in region {self.region}: {e}")

    def _describeKnowledgeBase(self, kbId):
        try:
            resp = self.agentClient.get_knowledge_base(knowledgeBaseId=kbId)
            kb = resp.get('knowledgeBase', {})
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'get_knowledge_base({kbId})', e)
            return None

        # Data sources
        dataSources = []
        try:
            ds_paginator = self.agentClient.get_paginator('list_data_sources')
            for page in ds_paginator.paginate(knowledgeBaseId=kbId):
                dataSources.extend(page.get('dataSourceSummaries', []))
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_data_sources({kbId})', e)

        # Most recent ingestion job per data source (used for sync-stale check)
        ingestionByDs = {}
        for ds in dataSources:
            dsId = ds.get('dataSourceId')
            if not dsId:
                continue
            try:
                ij = self.agentClient.list_ingestion_jobs(
                    knowledgeBaseId=kbId,
                    dataSourceId=dsId,
                    maxResults=10
                )
                jobs = ij.get('ingestionJobSummaries', [])
                ingestionByDs[dsId] = jobs
            except botocore.exceptions.ClientError as e:
                self._logClientError(f'list_ingestion_jobs({dsId})', e)
                ingestionByDs[dsId] = []

        kb['_dataSources'] = dataSources
        kb['_ingestionJobs'] = ingestionByDs
        return kb

    def _collectLoggingConfig(self, resources):
        try:
            resp = self.bedrockClient.get_model_invocation_logging_configuration()
            resources['loggingConfig'] = resp.get('loggingConfig')
        except botocore.exceptions.ClientError as e:
            code = e.response['Error']['Code']
            # ValidationException is the normal "not configured" signal
            if code in ('ValidationException', 'ResourceNotFoundException'):
                resources['loggingConfig'] = None
            else:
                self._logClientError('get_model_invocation_logging_configuration', e)
                resources['loggingConfig'] = None
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Bedrock invocation logging not available in region {self.region}: {e}")
            resources['loggingConfig'] = None

    # ------------------------------------------------------------------ #
    # AgentCore discovery (best-effort; many regions don't have the service yet)
    # ------------------------------------------------------------------ #
    def _collectAgentCore(self, resources):
        ac = {
            'available': False,
            'runtimes': [],
            'gateways': [],            # each gateway dict carries '_targets'
            'memories': [],
            'policyEngines': [],
            'oauthProviders': [],
            'apiKeyProviders': [],
            'workloadIdentities': [],
            'evaluators': [],
        }
        client = self.agentcoreControlClient
        if client is None:
            resources['agentcore'] = ac
            return

        # If any of these calls returns an EndpointConnectionError, the service
        # isn't available in this region — bail out cleanly.
        try:
            self._collectACRuntimes(client, ac)
            self._collectACGateways(client, ac)
            self._collectACMemories(client, ac)
            self._collectACPolicyEngines(client, ac)
            self._collectACIdentities(client, ac)
            self._collectACEvaluators(client, ac)
            ac['available'] = True
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"Bedrock AgentCore not available in region {self.region}: {e}")
            ac['available'] = False

        resources['agentcore'] = ac

    def _collectACRuntimes(self, client, ac):
        try:
            paginator = client.get_paginator('list_agent_runtimes')
            for page in paginator.paginate():
                for summary in page.get('agentRuntimes', []):
                    rtId = summary.get('agentRuntimeId')
                    if not rtId:
                        continue
                    detail = self._safeGet(
                        client.get_agent_runtime, agentRuntimeId=rtId
                    )
                    if detail is None:
                        # If get fails, fall back to summary so checks still see basic fields
                        detail = summary
                    _pi('Bedrock', f"AgentCore runtime: {detail.get('agentRuntimeName', rtId)}")
                    ac['runtimes'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_agent_runtimes', e)

    def _collectACGateways(self, client, ac):
        try:
            paginator = client.get_paginator('list_gateways')
            for page in paginator.paginate():
                for summary in page.get('items', []):
                    gwId = summary.get('gatewayId')
                    if not gwId:
                        continue
                    detail = self._safeGet(client.get_gateway, gatewayIdentifier=gwId)
                    if detail is None:
                        detail = dict(summary)
                    detail['_targets'] = self._collectACGatewayTargets(client, gwId)
                    _pi('Bedrock', f"AgentCore gateway: {detail.get('name', gwId)}")
                    ac['gateways'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_gateways', e)

    def _collectACGatewayTargets(self, client, gatewayId):
        targets = []
        try:
            paginator = client.get_paginator('list_gateway_targets')
            for page in paginator.paginate(gatewayIdentifier=gatewayId):
                for summary in page.get('items', []):
                    tId = summary.get('targetId')
                    if not tId:
                        continue
                    detail = self._safeGet(
                        client.get_gateway_target,
                        gatewayIdentifier=gatewayId,
                        targetId=tId,
                    )
                    if detail is None:
                        detail = dict(summary)
                    targets.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logACClientError(f'list_gateway_targets({gatewayId})', e)
        return targets

    def _collectACMemories(self, client, ac):
        try:
            paginator = client.get_paginator('list_memories')
            for page in paginator.paginate():
                for summary in page.get('memories', []):
                    mId = summary.get('id')
                    if not mId:
                        continue
                    detail = self._safeGet(client.get_memory, memoryId=mId)
                    if detail is None:
                        # Get failure — fall back to summary (wrapped to match GetMemory shape)
                        detail = {'memory': summary}
                    ac['memories'].append(detail)
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_memories', e)

    def _collectACPolicyEngines(self, client, ac):
        try:
            paginator = client.get_paginator('list_policy_engines')
            for page in paginator.paginate():
                for summary in page.get('items', []):
                    peId = summary.get('policyEngineId')
                    if not peId:
                        ac['policyEngines'].append(summary)
                        continue
                    detail = self._safeGet(
                        client.get_policy_engine, policyEngineIdentifier=peId
                    )
                    ac['policyEngines'].append(detail or summary)
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_policy_engines', e)

    def _collectACIdentities(self, client, ac):
        try:
            paginator = client.get_paginator('list_oauth2_credential_providers')
            for page in paginator.paginate():
                ac['oauthProviders'].extend(
                    page.get('credentialProviders')
                    or page.get('items')
                    or []
                )
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_oauth2_credential_providers', e)

        try:
            paginator = client.get_paginator('list_api_key_credential_providers')
            for page in paginator.paginate():
                ac['apiKeyProviders'].extend(
                    page.get('credentialProviders')
                    or page.get('items')
                    or []
                )
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_api_key_credential_providers', e)

        try:
            paginator = client.get_paginator('list_workload_identities')
            for page in paginator.paginate():
                ac['workloadIdentities'].extend(
                    page.get('workloadIdentities')
                    or page.get('items')
                    or []
                )
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_workload_identities', e)

    def _collectACEvaluators(self, client, ac):
        try:
            paginator = client.get_paginator('list_evaluators')
            for page in paginator.paginate():
                ac['evaluators'].extend(
                    page.get('items')
                    or page.get('evaluators')
                    or []
                )
        except botocore.exceptions.ClientError as e:
            self._logACClientError('list_evaluators', e)

    @staticmethod
    def _safeGet(fn, **kwargs):
        try:
            return fn(**kwargs)
        except botocore.exceptions.ClientError:
            return None

    def _logACClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        # Quietly swallow access-denied (operator scoped permissions) and
        # not-found (transient race conditions between list and get).
        if code in (
            'AccessDenied', 'AccessDeniedException',
            'ResourceNotFoundException', 'ValidationException',
        ):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"AgentCore {where}: {code} - {msg}")

    # ------------------------------------------------------------------ #
    # Advice / driver orchestration
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        resources = self.getResources()

        # Per-agent checks
        for agent in resources['agents']:
            try:
                name = agent.get('agentName') or agent.get('agentId', 'unknown')
                _pi('Bedrock', f"Analyzing Agent: {name}")
                obj = BedrockAgent(agent, self.agentClient, self.iamClient)
                obj.run(self.__class__)
                objs[f"Agent::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Bedrock agent {agent.get('agentId')}: {e}")

        # Per-guardrail checks
        for guardrail in resources['guardrails']:
            try:
                name = guardrail.get('name') or guardrail.get('guardrailId', 'unknown')
                _pi('Bedrock', f"Analyzing Guardrail: {name}")
                obj = BedrockGuardrail(guardrail, self.bedrockClient)
                obj.run(self.__class__)
                objs[f"Guardrail::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Bedrock guardrail {guardrail.get('guardrailId')}: {e}")

        # Per-KB checks
        for kb in resources['knowledgeBases']:
            try:
                name = kb.get('name') or kb.get('knowledgeBaseId', 'unknown')
                _pi('Bedrock', f"Analyzing KnowledgeBase: {name}")
                obj = BedrockKnowledgeBase(kb, self.agentClient, self.iamClient)
                obj.run(self.__class__)
                objs[f"KnowledgeBase::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Bedrock knowledge base {kb.get('knowledgeBaseId')}: {e}")

        # Account-level (runs once per region)
        try:
            _pi('Bedrock', 'Analyzing account-level configuration')
            obj = BedrockAccount(
                resources['agents'],
                resources['guardrails'],
                resources['loggingConfig'],
                self.bedrockClient
            )
            obj.run(self.__class__)
            objs['Bedrock::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Bedrock account-level checks: {e}")

        # Service-limit checks (runs once per region)
        try:
            _pi('Bedrock', 'Analyzing service quotas')
            obj = BedrockServiceLimits(
                resources['agents'],
                resources['guardrails'],
                resources['knowledgeBases'],
                self.serviceQuotaClient
            )
            obj.run(self.__class__)
            objs['Bedrock::ServiceLimits'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing Bedrock service-limit checks: {e}")

        # AgentCore checks (only if service is available in this region)
        ac = resources.get('agentcore') or {}
        if ac.get('available'):
            try:
                _pi('Bedrock', 'Analyzing AgentCore configuration')
                obj = BedrockAgentCore(ac, self.serviceQuotaClient, self.iamClient)
                obj.run(self.__class__)
                objs['Bedrock::AgentCore'] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing Bedrock AgentCore checks: {e}")
        else:
            print(f"Bedrock AgentCore checks skipped in region {self.region} "
                  "(service endpoint unavailable)")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        msg = error.response.get('Error', {}).get('Message', str(error))
        # Don't spam on plain access-denied — operator may have intentionally scoped permissions
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'):
            return
        print(f"Bedrock {where}: {code} - {msg}")
