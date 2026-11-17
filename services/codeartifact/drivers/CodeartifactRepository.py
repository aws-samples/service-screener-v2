import botocore

from services.Evaluator import Evaluator
from services.codeartifact.drivers.CodeartifactPolicyUtil import evaluateBroadPolicy


class CodeartifactRepository(Evaluator):
    """
    Per-repository CodeArtifact checks.

    repo: a RepositorySummary enriched by Codeartifact.getResources with
          '_upstreams' (upstream repository names, same domain),
          '_externalConnections' (e.g. 'public:npmjs') and '_describeError'.
    repoIndex: {(domainOwner, domainName, repoName): repo} for every scanned
          repository, used to follow upstream chains to an external connection.
    """

    ## list_packages page cap (max 1000 packages per page). The check only
    ## needs to know whether any package matches, and samples names for the
    ## message.
    PACKAGE_PAGE_CAP = 10

    def __init__(self, repo, caClient, repoIndex=None):
        super().__init__()
        self.repo = repo
        self.caClient = caClient
        self.repoIndex = repoIndex or {}
        self._resourceName = repo.get('arn') or f"{repo.get('domainName')}/{repo.get('name')}"
        self.addII('domain', repo.get('domainName'))
        self.addII('repository', repo.get('name'))
        self.addII('upstreams', ', '.join(repo.get('_upstreams') or []) or 'none')
        self.addII('externalConnections', ', '.join(repo.get('_externalConnections') or []) or 'none')

    def _baseKwargs(self):
        kwargs = {'domain': self.repo.get('domainName'), 'repository': self.repo.get('name')}
        if self.repo.get('domainOwner'):
            kwargs['domainOwner'] = self.repo['domainOwner']
        return kwargs

    def _checkCodeartifactRepoPolicyBroad(self):
        kwargs = self._baseKwargs()
        self.results['codeartifactRepoPolicyBroad'] = evaluateBroadPolicy(
            lambda: self.caClient.get_repository_permissions_policy(**kwargs),
            f"repository {self.repo.get('domainName')}/{self.repo.get('name')}")

    def _externalReach(self):
        """
        Follow this repository and its upstream chain (same domain).

        Return (formats, path, unknown):
          formats -- set of package formats ('npm', 'pypi', ...) for which a
                     public external connection is reachable; '*' when an
                     external connection's format is not reported
          path    -- first route found to an external connection, for messages
          unknown -- True when some repository in the chain could not be
                     inspected (so reachability may be understated)
        """
        owner, domain = self.repo.get('domainOwner'), self.repo.get('domainName')
        formats, path, unknown = set(), None, False
        seen = {self.repo.get('name')}
        stack = [(self.repo, [self.repo.get('name')])]
        while stack:
            r, route = stack.pop()
            if r.get('_describeError'):
                unknown = True
                continue
            conns = r.get('_externalConnections') or []
            if conns:
                fm = r.get('_externalFormats') or []
                formats |= set(fm) if fm else {'*'}
                path = path or ' -> '.join(route + [conns[0]])
            for up in r.get('_upstreams') or []:
                if up in seen:
                    continue
                seen.add(up)
                nxt = self.repoIndex.get((owner, domain, up))
                if nxt is None:
                    unknown = True
                    continue
                stack.append((nxt, route + [up]))
        return formats, path, unknown

    def _checkCodeartifactPackageOriginUnrestricted(self):
        key = 'codeartifactPackageOriginUnrestricted'
        if self.repo.get('_describeError'):
            self.results[key] = [0, f"Unable to evaluate ({self.repo['_describeError']})"]
            return
        formats, path, unknown = self._externalReach()
        if not formats and not unknown:
            self.results[key] = [
                1, "Repository has no external connection, directly or through its upstreams, "
                   "so package origin controls cannot admit public package versions"]
            return

        names, pages, capped, token = [], 0, False, None
        try:
            while True:
                kwargs = dict(self._baseKwargs(), publish='ALLOW', upstream='ALLOW', maxResults=1000)
                if token:
                    kwargs['nextToken'] = token
                resp = self.caClient.list_packages(**kwargs)
                for p in resp.get('packages', []) or []:
                    ns = p.get('namespace')
                    label = f"{p.get('format')}:{ns + '/' if ns else ''}{p.get('package')}"
                    ## Defensive: confirm the returned restrictions even though
                    ## the request filtered server-side.
                    rest = (p.get('originConfiguration') or {}).get('restrictions') or {}
                    if rest.get('publish', 'ALLOW') != 'ALLOW' or rest.get('upstream', 'ALLOW') != 'ALLOW':
                        continue
                    ## A public external connection only serves its own
                    ## format (public:npmjs -> npm). When the chain could not
                    ## be fully inspected, keep every format (conservative).
                    if not unknown and '*' not in formats and p.get('format') not in formats:
                        continue
                    names.append(label)
                token = resp.get('nextToken')
                pages += 1
                if not token:
                    break
                if pages >= self.PACKAGE_PAGE_CAP:
                    capped = True
                    break
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results[key] = [0, f"Unable to evaluate ({code})"]
            return

        via = f" (via {path})" if path else " (an upstream repository could not be inspected)"
        if names:
            more = '+' if capped else ''
            self.results[key] = [
                -1,
                f"{len(names)}{more} package(s) in this repository allow BOTH direct publishing and "
                f"ingestion from upstream sources while the repository can reach a public registry{via}. "
                "An attacker can publish a same-named public version and have it mixed into an internal "
                "package (dependency substitution). Examples: " + ', '.join(names[:5])]
            return
        if unknown:
            self.results[key] = [
                1, "No package allows both publish and upstream; an upstream repository could not be "
                   "inspected"]
            return
        self.results[key] = [
            1, "No package of a format served by the reachable public registry allows both direct "
               f"publishing and upstream ingestion{via}"]
