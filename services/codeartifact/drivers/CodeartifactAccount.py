from services.Evaluator import Evaluator


class CodeartifactAccount(Evaluator):
    """
    Region-scoped CodeArtifact usage check.

    detail: '_region', '_domains' (list_domains output), '_domainError'
            (error code or None), '_repositoryError' (list_repositories error
            code or None), '_repositoryCount' (repositories this account
            administers, including in domains owned by other accounts).
    """

    def __init__(self, detail):
        super().__init__()
        self.detail = detail
        self._resourceName = 'Account'
        self.domains = detail.get('_domains') or []
        self.addII('region', detail.get('_region', 'N/A'))
        self.addII('domainCount', str(len(self.domains)))
        self.addII('repositoryCount', str(detail.get('_repositoryCount') or 0))

    def _checkCodeartifactNotUsed(self):
        err = self.detail.get('_domainError')
        repoCount = self.detail.get('_repositoryCount') or 0
        if self.domains or repoCount:
            self.results['codeartifactNotUsed'] = [
                1, f"CodeArtifact is in use in this region ({len(self.domains)} owned domain(s), "
                   f"{repoCount} repository(ies))"
            ]
            return
        ## Either listing failing means usage is unknown: an account with no
        ## owned domain may still administer repositories in a shared domain.
        err = err or self.detail.get('_repositoryError')
        if err:
            self.results['codeartifactNotUsed'] = [0, f"Unable to evaluate ({err})"]
            return
        self.results['codeartifactNotUsed'] = [
            -1,
            "No CodeArtifact domain or repository exists in this region. If workloads here pull "
            "third-party packages, they likely fetch them directly from public registries with no "
            "curated, private proxy. This is a weak signal: another private registry (Artifactory, "
            "Nexus, ECR pull-through cache) or a different Region may already serve this purpose"
        ]
