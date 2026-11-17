import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.codeartifact.drivers.CodeartifactAccount import CodeartifactAccount
from services.codeartifact.drivers.CodeartifactDomain import CodeartifactDomain
from services.codeartifact.drivers.CodeartifactRepository import CodeartifactRepository


class Codeartifact(Service):
    """
    AWS CodeArtifact service scanner.

    Drivers:
      CodeartifactAccount    -- region-scoped: is any CodeArtifact domain in use
      CodeartifactDomain     -- per domain owned by this account (domain policy)
      CodeartifactRepository -- per repository administered by this account
                                (repository policy, package origin controls)

    Discovery calls (all read-only):
      - list_domains                 (paginated; domains owned by the caller)
      - list_repositories_in_domain  (paginated; per owned domain)
      - list_repositories            (paginated; repositories the caller
                                      administers, including in domains owned
                                      by other accounts)
      - describe_repository          (per repository; upstreams and external
                                      connections)
      - list_tags_for_resource       (only when a --tags filter is given)

    Repositories are discovered from both list_repositories_in_domain (owned
    domains) and list_repositories, de-duplicated by ARN, so that a failure or
    gap in one listing does not hide repositories from the other.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.caClient = ssBoto.client('codeartifact', config=self.bConfig)
        self.accountId = (Config.get('stsInfo', {}) or {}).get('Account')

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def _paginate(self, op, key, **kwargs):
        items = []
        paginator = self.caClient.get_paginator(op)
        for page in paginator.paginate(**kwargs):
            items += page.get(key, []) or []
        return items

    def getResources(self):
        """
        Return dict:
          domains        -- list of DomainSummary (owned by this account)
          domainError    -- error code if list_domains failed, else None
          repositories   -- list of RepositorySummary, each enriched with
                            '_upstreams', '_externalConnections',
                            '_describeError'
        """
        out = {'domains': [], 'domainError': None, 'repositories': []}
        try:
            out['domains'] = self._paginate('list_domains', 'domains')
        except botocore.exceptions.ClientError as e:
            out['domainError'] = e.response.get('Error', {}).get('Code', 'Unknown')
            self._logClientError('list_domains', e)

        repos = {}
        for d in out['domains']:
            name = d.get('name')
            if not name:
                continue
            kwargs = {'domain': name}
            if d.get('owner'):
                kwargs['domainOwner'] = d['owner']
            try:
                for r in self._paginate('list_repositories_in_domain', 'repositories', **kwargs):
                    ## Repositories administered by another account in this
                    ## domain are that account's responsibility (and their
                    ## policies are not normally readable from here).
                    admin = r.get('administratorAccount')
                    if self.accountId and admin and admin != self.accountId:
                        continue
                    if r.get('arn'):
                        repos[r['arn']] = r
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_repositories_in_domain', e)

        try:
            for r in self._paginate('list_repositories', 'repositories'):
                if r.get('arn') and r['arn'] not in repos:
                    repos[r['arn']] = r
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_repositories', e)

        for r in repos.values():
            r['_upstreams'] = []
            r['_externalConnections'] = []
            r['_externalFormats'] = []
            r['_describeError'] = None
            try:
                kwargs = {'domain': r.get('domainName'), 'repository': r.get('name')}
                if r.get('domainOwner'):
                    kwargs['domainOwner'] = r['domainOwner']
                desc = self.caClient.describe_repository(**kwargs).get('repository', {}) or {}
                r['_upstreams'] = [u.get('repositoryName') for u in (desc.get('upstreams') or [])
                                   if u.get('repositoryName')]
                r['_externalConnections'] = [c.get('externalConnectionName')
                                             for c in (desc.get('externalConnections') or [])
                                             if c.get('externalConnectionName')]
                r['_externalFormats'] = [c.get('packageFormat')
                                         for c in (desc.get('externalConnections') or [])
                                         if c.get('packageFormat')]
            except botocore.exceptions.ClientError as e:
                r['_describeError'] = e.response.get('Error', {}).get('Code', 'Unknown')
                self._logClientError('describe_repository', e)
        out['repositories'] = list(repos.values())
        return out

    def _matchesTags(self, arn):
        if not self.tags:
            return True
        try:
            tags = self.caClient.list_tags_for_resource(resourceArn=arn).get('tags', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_tags_for_resource', e)
            return False
        return self.resourceHasTags([{'Key': t.get('key'), 'Value': t.get('value')} for t in tags])

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        try:
            res = self.getResources()
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CodeArtifact not available in region {self.region}: {e}")
            return objs

        try:
            obj = CodeartifactAccount({
                '_region': self.region,
                '_domains': res['domains'],
                '_domainError': res['domainError'],
                '_repositoryCount': len(res['repositories']),
            })
            obj.run(self.__class__)
            objs['CodeArtifact::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing CodeArtifact account posture in {self.region}: {e}")

        for d in res['domains']:
            name = d.get('name')
            if not name or not self._matchesTags(d.get('arn', '')):
                continue
            _pi('CodeArtifact', f"domain {name}")
            try:
                obj = CodeartifactDomain(d, self.caClient)
                obj.run(self.__class__)
                objs[f"CodeArtifact::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodeArtifact domain {name}: {e}")

        ## Lookup for upstream-chain resolution: (domainOwner, domain, repo)
        repoIndex = {
            (r.get('domainOwner'), r.get('domainName'), r.get('name')): r
            for r in res['repositories']
        }
        for r in res['repositories']:
            label = f"{r.get('domainName')}/{r.get('name')}"
            if not self._matchesTags(r.get('arn', '')):
                continue
            _pi('CodeArtifact', f"repository {label}")
            try:
                obj = CodeartifactRepository(r, self.caClient, repoIndex)
                obj.run(self.__class__)
                objs[f"CodeArtifact::{label}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodeArtifact repository {label}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Codeartifact {where}: {code} - {msg}")
