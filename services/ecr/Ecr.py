import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.ecr.drivers.EcrCommon import EcrCommon


class Ecr(Service):
    """
    Amazon ECR (private registry) service scanner.

    Discovers every repository in the region via describe_repositories
    (paginated), hydrates each with:
      - repository-level lifecycle policy (get_lifecycle_policy)
      - repository-level access policy   (get_repository_policy)
      - image list                       (describe_images, paginated)
      - repository tags                  (list_tags_for_resource)

    Registry-level configuration is fetched ONCE per region and shared with
    every repo descriptor:
      - registry scanning config     (get_registry_scanning_configuration)
      - replication configuration    (describe_registry)
      - pull-through cache rules     (describe_pull_through_cache_rules)

    Registry-level findings are emitted only on the first repository we
    discover in the region — subsequent repos report INFO deferring to it.
    This avoids duplicate FAILs across every repo for the same registry-wide
    condition. If the account has zero repos in the region, no registry-level
    findings are emitted (there is no anchor resource to hang them on, which
    matches the existing service-screener patterns).
    """

    # Cap for image-level scanning to keep API cost bounded. For repos with
    # more than IMAGE_SCAN_CAP images we still page through the whole
    # collection (there is no server-side "newest first" filter) but we stop
    # accumulating detail beyond IMAGE_SCAN_CAP entries per repo.
    IMAGE_SCAN_CAP = 200

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ecrClient = ssBoto.client('ecr', config=self.bConfig)

        # Registry-level data, populated lazily on first use.
        self._registryScanningConfig = None
        self._replicationRules = None
        self._pullThroughCacheRules = None
        self._registryDataLoaded = False

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        repos = []
        try:
            paginator = self.ecrClient.get_paginator('describe_repositories')
            for page in paginator.paginate():
                for repo in page.get('repositories', []) or []:
                    repoName = repo.get('repositoryName')
                    if not repoName:
                        continue
                    hydrated = self._hydrateRepo(repo)
                    if hydrated is None:
                        continue

                    # Tag filtering
                    if self.tags and not self.resourceHasTags(hydrated.get('_tagList') or []):
                        continue

                    _pi('Ecr', f"Repository: {repoName}")
                    repos.append(hydrated)
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_repositories', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ECR not available in region {self.region}: {e}")

        # Load registry-level config once, then flag the first repo as the
        # anchor for registry-level findings.
        if repos:
            self._loadRegistryLevelData()
            for i, r in enumerate(repos):
                r['_registryScanningConfig'] = self._registryScanningConfig
                r['_replicationRules'] = self._replicationRules
                r['_pullThroughCacheRules'] = self._pullThroughCacheRules
                r['_reportRegistryChecks'] = (i == 0)
                r['_ownAccount'] = self._ownAccount()

        return repos

    def _hydrateRepo(self, repo):
        """Attach lifecycle policy, repo policy, images, and tags to a repo dict."""
        repoName = repo['repositoryName']
        detail = dict(repo)

        detail['_lifecyclePolicy'] = self._getLifecyclePolicy(repoName)
        detail['_repositoryPolicy'] = self._getRepositoryPolicy(repoName)
        detail['_images'] = self._describeImages(repoName)
        detail['_tagList'] = self._listTags(repo.get('repositoryArn'))
        return detail

    def _getLifecyclePolicy(self, repoName):
        """Return the parsed lifecycle policy dict, or:
            - {'_missing': True} if no policy is set
            - None on other errors (access denied etc.)
        """
        import json as _json
        try:
            resp = self.ecrClient.get_lifecycle_policy(repositoryName=repoName)
            raw = resp.get('lifecyclePolicyText')
            if isinstance(raw, str):
                try:
                    return _json.loads(raw)
                except (ValueError, TypeError):
                    return None
            return raw
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'LifecyclePolicyNotFoundException':
                return {'_missing': True}
            self._logClientError(f'get_lifecycle_policy({repoName})', e)
            return None

    def _getRepositoryPolicy(self, repoName):
        """Return the parsed repository access policy dict, or None if not set."""
        import json as _json
        try:
            resp = self.ecrClient.get_repository_policy(repositoryName=repoName)
            raw = resp.get('policyText')
            if isinstance(raw, str):
                try:
                    return _json.loads(raw)
                except (ValueError, TypeError):
                    return None
            return raw
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            if code == 'RepositoryPolicyNotFoundException':
                return None
            self._logClientError(f'get_repository_policy({repoName})', e)
            return None

    def _describeImages(self, repoName):
        """Return a bounded list of image detail dicts for this repository.

        The pagination iterates fully — server-side ordering is not guaranteed
        so we stop accumulating detail once we hit the cap. For very large
        repos this bounds per-repo memory and downstream check cost.
        """
        images = []
        try:
            paginator = self.ecrClient.get_paginator('describe_images')
            for page in paginator.paginate(repositoryName=repoName):
                for img in page.get('imageDetails', []) or []:
                    images.append(img)
                    if len(images) >= self.IMAGE_SCAN_CAP:
                        return images
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', '')
            # Empty repos raise no error; permission denials do — log & skip.
            if code not in ('RepositoryNotFoundException',):
                self._logClientError(f'describe_images({repoName})', e)
        return images

    def _listTags(self, repoArn):
        if not repoArn:
            return []
        try:
            resp = self.ecrClient.list_tags_for_resource(resourceArn=repoArn)
            return resp.get('tags', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError(f'list_tags_for_resource({repoArn})', e)
            return []

    # ------------------------------------------------------------------ #
    # Registry-level (once per region)
    # ------------------------------------------------------------------ #
    def _loadRegistryLevelData(self):
        if self._registryDataLoaded:
            return
        self._registryDataLoaded = True

        try:
            resp = self.ecrClient.get_registry_scanning_configuration()
            self._registryScanningConfig = resp.get('scanningConfiguration') or {}
        except botocore.exceptions.ClientError as e:
            self._logClientError('get_registry_scanning_configuration', e)
            self._registryScanningConfig = {}

        try:
            resp = self.ecrClient.describe_registry()
            self._replicationRules = (
                (resp.get('replicationConfiguration') or {}).get('rules') or []
            )
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_registry', e)
            self._replicationRules = []

        try:
            resp = self.ecrClient.describe_pull_through_cache_rules()
            self._pullThroughCacheRules = resp.get('pullThroughCacheRules') or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('describe_pull_through_cache_rules', e)
            self._pullThroughCacheRules = []

    def _ownAccount(self):
        info = Config.get('stsInfo', {})
        if isinstance(info, dict):
            return info.get('Account')
        return None

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        repos = self.getResources()

        for repo in repos:
            try:
                name = repo.get('repositoryName') or 'unknown'
                _pi('Ecr', f"Analyzing: {name}")
                obj = EcrCommon(repo, self.ecrClient)
                obj.run(self.__class__)
                objs[f"Ecr::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing ECR repository {repo.get('repositoryName')}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in ('AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation'):
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"ECR {where}: {code} - {msg}")
