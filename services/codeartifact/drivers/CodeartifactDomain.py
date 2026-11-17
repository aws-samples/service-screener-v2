from services.Evaluator import Evaluator
from services.codeartifact.drivers.CodeartifactPolicyUtil import evaluateBroadPolicy


class CodeartifactDomain(Evaluator):
    """Per-domain CodeArtifact checks. domain: a list_domains DomainSummary."""

    def __init__(self, domain, caClient):
        super().__init__()
        self.domain = domain
        self.caClient = caClient
        self._resourceName = domain.get('arn') or domain.get('name')
        self.addII('domain', domain.get('name'))
        self.addII('owner', domain.get('owner'))
        self.addII('status', domain.get('status'))

    def _checkCodeartifactRepoPolicyBroad(self):
        kwargs = {'domain': self.domain.get('name')}
        if self.domain.get('owner'):
            kwargs['domainOwner'] = self.domain['owner']
        self.results['codeartifactRepoPolicyBroad'] = evaluateBroadPolicy(
            lambda: self.caClient.get_domain_permissions_policy(**kwargs),
            f"domain {self.domain.get('name')}")
