import json
import fnmatch

import botocore

from services.Evaluator import Evaluator


class CodecommitRepository(Evaluator):
    """
    Per-repository CodeCommit checks.

    codecommitNoApprovalRule (SEC11-BP05): a repository is flagged when no
    associated approval rule template enforces at least one approval on pull
    requests targeting the repository's default branch. Approval rule
    templates are the only repository-level mechanism; rules added ad hoc to a
    single pull request are not an enforced control and are not considered.

    Status: -1 FAIL, 1 PASS, 0 not evaluable (API error / unparseable content).
    """

    KEY = 'codecommitNoApprovalRule'

    def __init__(self, repo, ccClient, templateCache=None):
        super().__init__()
        self.repo = repo
        self.ccClient = ccClient
        self.templateCache = templateCache if templateCache is not None else {}
        self._resourceName = repo.get('repositoryName')

    def _listAssociatedTemplates(self):
        names, token = [], None
        while True:
            kwargs = {'repositoryName': self._resourceName}
            if token:
                kwargs['nextToken'] = token
            resp = self.ccClient.list_associated_approval_rule_templates_for_repository(**kwargs)
            names += resp.get('approvalRuleTemplateNames', []) or []
            token = resp.get('nextToken')
            if not token:
                return names

    def _getTemplateContent(self, name):
        """Return (contentDict|None, errorCode|None); cached across repositories."""
        if name not in self.templateCache:
            try:
                tpl = self.ccClient.get_approval_rule_template(
                    approvalRuleTemplateName=name).get('approvalRuleTemplate', {}) or {}
                self.templateCache[name] = (json.loads(tpl.get('approvalRuleTemplateContent') or ''), None)
            except botocore.exceptions.ClientError as e:
                self.templateCache[name] = (None, e.response.get('Error', {}).get('Code', 'Unknown'))
            except (ValueError, TypeError):
                self.templateCache[name] = (None, 'UnparseableContent')
        return self.templateCache[name]

    @staticmethod
    def _requiredApprovals(content):
        best = 0
        for st in content.get('Statements', []) or []:
            if not isinstance(st, dict) or st.get('Type') != 'Approvers':
                continue
            try:
                best = max(best, int(st.get('NumberOfApprovalsNeeded') or 0))
            except (TypeError, ValueError):
                continue
        return best

    @staticmethod
    def _coversBranch(content, ref):
        dests = content.get('DestinationReferences')
        if not dests:
            return True  # no destination filter = applies to every branch
        if ref is None:
            return True  # empty repo / unknown default branch: cannot narrow
        return any(d == ref or fnmatch.fnmatchcase(ref, d) for d in dests if isinstance(d, str))

    def _checkNoApprovalRule(self):
        try:
            names = self._listAssociatedTemplates()
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results[self.KEY] = [0, f'Unable to evaluate ({code})']
            return

        if not names:
            self.results[self.KEY] = [
                -1, 'No approval rule template is associated with this repository; '
                    'pull requests can be merged without any reviewer approval']
            return

        branch = self.repo.get('defaultBranch')
        ref = f'refs/heads/{branch}' if branch else None
        errors, effective, zeroOrOther = [], [], []
        for n in names:
            content, err = self._getTemplateContent(n)
            if err or not isinstance(content, dict):
                errors.append(f'{n}: {err or "UnparseableContent"}')
                continue
            if self._requiredApprovals(content) >= 1 and self._coversBranch(content, ref):
                effective.append(n)
            else:
                zeroOrOther.append(n)

        if effective:
            where = f'default branch {branch}' if branch else 'pull requests (default branch not yet set)'
            self.results[self.KEY] = [
                1, f"Approval rule template(s) {', '.join(effective[:5])} require at least one approval for {where}"]
        elif errors:
            self.results[self.KEY] = [0, f"Unable to evaluate ({'; '.join(errors[:3])})"]
        else:
            target = f'the default branch ({branch})' if branch else 'pull requests'
            self.results[self.KEY] = [
                -1, f"Associated approval rule template(s) {', '.join(zeroOrOther[:5])} do not require "
                    f"at least one approval for {target}"]
