import json

import botocore

from utils.Tools import _pi
from services.Service import Service

from services.emr.drivers.EmrCluster import EmrCluster
from services.emr.drivers.EmrRegional import EmrRegional


class Emr(Service):
    """
    Amazon EMR service scanner.

    Two check subjects, so two drivers:
      EmrCluster  -- per active cluster
      EmrRegional -- the account/region-level block-public-access configuration
                     (Security Hub resource type AWS::::Account, so it must be
                     evaluated ONCE per region, not once per cluster)

    Hydration calls (all read-only):
      - list_clusters(ClusterStates=[RUNNING, WAITING])
      - describe_cluster                    (per cluster)
      - describe_security_configuration     (per DISTINCT security config name;
                                             the response is a JSON STRING that
                                             must be parsed)
      - list_instances(InstanceGroupTypes=[MASTER])  (per cluster, for public IP)
      - get_block_public_access_configuration        (once per region)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## Security Hub's EMR.1 only evaluates clusters in these states, and a
    ## terminated cluster's configuration is not actionable.
    ACTIVE_STATES = ['RUNNING', 'WAITING']

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.emrClient = ssBoto.client('emr', config=self.bConfig)
        ## Security configurations are shared between clusters; cache the parsed
        ## form so N clusters sharing one config cost one API call.
        self._securityConfigCache = {}

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        clusters = []
        try:
            paginator = self.emrClient.get_paginator('list_clusters')
            for page in paginator.paginate(ClusterStates=self.ACTIVE_STATES):
                summaries = page.get('Clusters', []) or []
                pendingIds = {s.get('Id') for s in self.registerItems(
                    ## idFn must match EmrCluster._resourceName exactly (Name, falling back to Id)
                    'EmrCluster', summaries, idFn=lambda s: s.get('Name') or s.get('Id', 'unknown')
                )}

                for summary in summaries:
                    clusterId = summary.get('Id')
                    if not clusterId:
                        continue

                    if clusterId not in pendingIds:
                        ## Already checkpointed - Id/Name are shared between the
                        ## list summary and describe_cluster's response, so the
                        ## bare summary is enough for advise()/the driver.
                        clusters.append(summary)
                        continue

                    detail = self._describeCluster(clusterId)
                    if detail is None:
                        continue
                    _pi('Emr', f"Cluster: {detail.get('Name', clusterId)}")
                    clusters.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_clusters', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"EMR not available in region {self.region}: {e}")
        except botocore.exceptions.OperationNotPageableError:
            clusters = self._listClustersUnpaginated()
        return clusters

    def _listClustersUnpaginated(self):
        clusters = []
        try:
            resp = self.emrClient.list_clusters(ClusterStates=self.ACTIVE_STATES)
            for summary in resp.get('Clusters', []) or []:
                if summary.get('Id'):
                    detail = self._describeCluster(summary['Id'])
                    if detail is not None:
                        clusters.append(detail)
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_clusters', e)
        return clusters

    def _describeCluster(self, clusterId):
        try:
            resp = self.emrClient.describe_cluster(ClusterId=clusterId)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_cluster({clusterId})', e)
            return None

        detail = resp.get('Cluster') or {}
        if not detail:
            return None

        tags = detail.get('Tags') or []
        ## Optional --filters tag filtering.
        if self.tags and not self.resourceHasTags(tags):
            return None

        detail['_region'] = self.region
        detail['_tags'] = tags
        ## describe_cluster returns only the security configuration NAME; the
        ## content requires a second call whose payload is a JSON string.
        detail['_securityConfig'] = self._getSecurityConfig(
            detail.get('SecurityConfiguration'))
        detail['_masterPublicIps'] = self._masterPublicIps(clusterId)
        return detail

    def _getSecurityConfig(self, name):
        """
        Return the PARSED security configuration dict, or None when the cluster
        has none / it cannot be read. describe_security_configuration returns the
        configuration as a JSON string in the 'SecurityConfiguration' field, not
        as a structure.
        """
        if not name:
            return None
        if name in self._securityConfigCache:
            return self._securityConfigCache[name]

        parsed = None
        try:
            resp = self.emrClient.describe_security_configuration(Name=name)
            raw = resp.get('SecurityConfiguration')
            if raw:
                parsed = json.loads(raw)
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'describe_security_configuration({name})', e)
        except (ValueError, TypeError):
            ## Malformed JSON from the API — treat as unreadable rather than
            ## letting a parse error abort the cluster's whole check run.
            print(f"Emr: security configuration '{name}' is not valid JSON")

        self._securityConfigCache[name] = parsed
        return parsed

    def _masterPublicIps(self, clusterId):
        """
        Public IPs on the cluster's MASTER instance group. Returns None when the
        lookup fails, so the check can distinguish "no public IP" from "could not
        tell".
        """
        try:
            resp = self.emrClient.list_instances(
                ClusterId=clusterId, InstanceGroupTypes=['MASTER'])
            ips = []
            for instance in resp.get('Instances', []) or []:
                ip = instance.get('PublicIpAddress')
                if ip:
                    ips.append(ip)
            return ips
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_instances({clusterId})', e)
            return None

    def _getBlockPublicAccess(self):
        try:
            resp = self.emrClient.get_block_public_access_configuration()
            return resp.get('BlockPublicAccessConfiguration') or None
        except botocore.exceptions.ClientError as e:
            self._logClientError('get_block_public_access_configuration', e)
            return None
        except botocore.exceptions.EndpointConnectionError:
            return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}

        clusters = self.getResources()
        for cluster in clusters:
            name = cluster.get('Name') or cluster.get('Id', 'unknown')
            try:
                _pi('Emr', f"Analyzing cluster: {name}")
                obj = EmrCluster(cluster, self.emrClient)
                obj.run(self.__class__)
                objs[f"EMR Cluster::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing EMR cluster {name}: {e}")

        ## Block public access is account/region-level. Evaluate it once,
        ## unconditionally — an account with no clusters today can still have the
        ## protection switched off for the next one someone launches.
        try:
            detail = {
                '_region': self.region,
                '_blockPublicAccess': self._getBlockPublicAccess(),
                '_clusterCount': len(clusters),
            }
            obj = EmrRegional(detail, self.emrClient)
            obj.run(self.__class__)
            objs['EMR::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing EMR regional posture: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Emr {where}: {code} - {msg}")
