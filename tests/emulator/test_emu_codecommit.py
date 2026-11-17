"""Flag -> fix -> re-run tests for codecommit.codecommitNoApprovalRule (emulator)."""
import json

from tests.emulator.conftest import assertFlagFixCycle, runCheck

KEY = 'codecommitNoApprovalRule'


def _content(n, refs=None):
    c = {'Version': '2018-11-08', 'Statements': [{'Type': 'Approvers', 'NumberOfApprovalsNeeded': n}]}
    if refs is not None:
        c['DestinationReferences'] = refs
    return json.dumps(c)


def _cleanup(cc, repo, templates):
    for t in templates:
        try:
            cc.disassociate_approval_rule_template_from_repository(approvalRuleTemplateName=t, repositoryName=repo)
        except Exception:
            pass
        try:
            cc.delete_approval_rule_template(approvalRuleTemplateName=t)
        except Exception:
            pass
    try:
        cc.delete_repository(repositoryName=repo)
    except Exception:
        pass


def test_codecommit_no_template_then_associate(emu, uid):
    cc = emu.client('codecommit')
    repo, tpl = f'ss-cc-{uid}', f'ss-cc-tpl-{uid}'
    cc.create_repository(repositoryName=repo)
    try:
        def misconfigure():
            pass  # a fresh repository has no approval rule template

        def fix():
            cc.create_approval_rule_template(approvalRuleTemplateName=tpl,
                                             approvalRuleTemplateContent=_content(1))
            cc.associate_approval_rule_template_with_repository(approvalRuleTemplateName=tpl, repositoryName=repo)

        before, after = assertFlagFixCycle(emu, 'codecommit', KEY, f'Repository::{repo}', misconfigure, fix)
        assert set(after.values()) == {1}
    finally:
        _cleanup(cc, repo, [tpl])


def test_codecommit_template_wrong_branch_then_fixed(emu, uid):
    """Template exists but targets another branch -> FAIL; retarget to default branch -> PASS."""
    cc = emu.client('codecommit')
    repo, tpl = f'ss-cc-{uid}', f'ss-cc-tpl-{uid}'
    cc.create_repository(repositoryName=repo)
    try:
        cc.put_file(repositoryName=repo, branchName='main', fileContent=b'x', filePath='README.md',
                    commitMessage='init')
        branch = cc.get_repository(repositoryName=repo)['repositoryMetadata'].get('defaultBranch')
        assert branch == 'main', branch

        def misconfigure():
            cc.create_approval_rule_template(approvalRuleTemplateName=tpl,
                                             approvalRuleTemplateContent=_content(2, ['refs/heads/release']))
            cc.associate_approval_rule_template_with_repository(approvalRuleTemplateName=tpl, repositoryName=repo)

        def fix():
            cur = cc.get_approval_rule_template(approvalRuleTemplateName=tpl)['approvalRuleTemplate']
            cc.update_approval_rule_template_content(
                approvalRuleTemplateName=tpl, newRuleContent=_content(2, ['refs/heads/main']),
                existingRuleContentSha256=cur['ruleContentSha256'])

        before, after = assertFlagFixCycle(emu, 'codecommit', KEY, f'Repository::{repo}', misconfigure, fix)
        assert set(after.values()) == {1}
    finally:
        _cleanup(cc, repo, [tpl])

