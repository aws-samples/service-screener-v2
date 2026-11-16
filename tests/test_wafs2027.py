"""
Tests for the WAFS2027 framework (Well-Architected Framework, Nov 2026 release).

- map.json integrity: structure, BP IDs, every check exists in a reporter.json.
- WATools2027: title/ID based matching (never positional), lens-status gating,
  preservation of existing selections, "None of these" handling, pagination.
- WAFS2027 hooks: results are attached to the matched question/choice.
"""
import glob
import json
import os
import re
import sys
from unittest.mock import MagicMock

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)

from frameworks.WAFS2027.WATools2027 import WATools2027, normalizeTitle  # noqa: E402
from frameworks.WAFS2027 import WAFS2027 as wafs2027_module  # noqa: E402

MAP_PATH = os.path.join(ROOT, 'frameworks', 'WAFS2027', 'map.json')
Q_RE = re.compile(r'^(SEC\d{2}|FND\d{2}|REL\d{2}) \S')
BP_RE = re.compile(r'^((SEC|FND|REL)\d{2})-BP\d{2} \S')


def _allChecks():
    checks = set()
    for f in glob.glob(os.path.join(ROOT, 'services', '*', '*.reporter.json')):
        svc = os.path.basename(f).split('.')[0]
        for k, v in json.load(open(f)).items():
            if isinstance(v, dict):
                checks.add(f'{svc}.{k}')
    return checks


# --------------------------------------------------------------------------- #
# map.json
# --------------------------------------------------------------------------- #
class TestMap:
    m = json.load(open(MAP_PATH))

    def test_metadata(self):
        meta = self.m['metadata']
        assert meta['shortname'] == 'WAFS2027'
        for k in ('originator', 'fullname', 'description', 'emptyCheckDefaultMsg'):
            assert meta.get(k)

    def test_keys_are_self_describing_and_consistent(self):
        for q, bps in self.m['mapping'].items():
            assert Q_RE.match(q), q
            qid = q.split()[0]
            assert bps, q
            for bp in bps:
                mm = BP_RE.match(bp)
                assert mm, bp
                assert mm.group(1) == qid, (q, bp)

    def test_security_pillar_complete(self):
        sec = {bp.split()[0] for q, bps in self.m['mapping'].items() if q.startswith('SEC') for bp in bps}
        assert len(sec) == 52
        assert {f'SEC{n:02}' for n in range(1, 12)} == {b[:5] for b in sec}

    def test_no_cost_question(self):
        assert not any(q.startswith('FND06') for q in self.m['mapping'])

    def test_every_check_exists(self):
        known = _allChecks()
        missing = []
        for bps in self.m['mapping'].values():
            for checks in bps.values():
                for c in checks:
                    if c.endswith('.$length'):
                        continue
                    if c not in known:
                        missing.append(c)
        assert not missing, missing

    def test_no_duplicate_checks_within_bp(self):
        for bps in self.m['mapping'].values():
            for bp, checks in bps.items():
                assert len(checks) == len(set(checks)), bp


# --------------------------------------------------------------------------- #
# WATools2027
# --------------------------------------------------------------------------- #
def _answers(pillar):
    """Fake list_answers payloads. Deliberately ordered so that position-based
    matching would pick the wrong choice."""
    if pillar == 'security':
        return [{
            'QuestionId': 'securely-operate',
            'QuestionTitle': 'How do you securely operate your workload?',
            'SelectedChoices': ['user-picked'],
            'Choices': [
                {'ChoiceId': 'sec-threats', 'Title': 'Stay up to date with security threats and recommendations'},
                {'ChoiceId': 'sec-accounts', 'Title': 'Separate workloads using accounts'},
                {'ChoiceId': 'user-picked', 'Title': 'Identify and validate control objectives'},
                {'ChoiceId': 'sec-none', 'Title': 'None of these'},
            ],
        }]
    if pillar == 'foundations':
        return [{
            'QuestionId': 'fnd-iam',
            'QuestionTitle': 'How do you manage identity and access across your organization?',
            'SelectedChoices': ['fnd-none'],
            'Choices': [
                {'ChoiceId': 'fnd-root', 'Title': 'FND02-BP01 Protect account root users, and establish alternate contacts'},
                {'ChoiceId': 'fnd-none', 'Title': 'None of these'},
            ],
        }]
    return []


def _tools(lens_status='CURRENT', paginate=False):
    t = WATools2027()
    t.waInfo = {'isExists': True, 'WorkloadId': 'wl-1', 'LensesAlias': 'wellarchitected'}
    t.waClient = MagicMock()
    t.waClient.get_lens_review.return_value = {'LensReview': {
        'LensVersion': '2026-11-16', 'LensStatus': lens_status,
        'PillarReviewSummaries': [{'PillarId': 'security'}, {'PillarId': 'foundations'}],
    }}

    def list_answers(**kw):
        items = _answers(kw['PillarId'])
        if paginate and kw['PillarId'] == 'security':
            if 'NextToken' not in kw:
                return {'AnswerSummaries': [], 'NextToken': 'p2'}
            return {'AnswerSummaries': items}
        return {'AnswerSummaries': items}
    t.waClient.list_answers.side_effect = list_answers
    t.waClient.update_answer.return_value = {}
    t.listAnswers()
    return t


class TestWATools2027:
    def test_normalize(self):
        assert normalizeTitle('SEC01-BP01 Separate workloads using accounts') == 'separate workloads using accounts'
        assert normalizeTitle('Separate workloads, using accounts.') == 'separate workloads using accounts'
        assert normalizeTitle(None) == ''

    def test_default_report_name_differs_from_wafs(self):
        params = {'region': 'us-east-1'}
        t = WATools2027()
        t.preCheck(params)
        assert params['reportName'] == 'SS_Report_2027'

    def test_matches_by_title_not_position(self):
        t = _tools()
        info = t.lookup('SEC01-BP01', 'Separate workloads using accounts')
        assert info['choiceId'] == 'sec-accounts'          # 2nd choice, not 1st
        assert info['questionId'] == 'securely-operate'

    def test_matches_across_pillars_and_by_id(self):
        t = _tools()
        info = t.lookup('FND02-BP01', 'Protect account root users, and establish alternate contacts')
        assert info['choiceId'] == 'fnd-root' and info['pillarId'] == 'foundations'
        assert t.lookup('FND02-BP01', 'title changed upstream')['choiceId'] == 'fnd-root'

    def test_unknown_bp_not_matched(self):
        assert _tools().lookup('SEC09-BP09', 'Does not exist') is None

    def test_none_of_these_not_indexed(self):
        assert _tools().lookup('X', 'None of these') is None

    def test_pagination_uses_next_token(self):
        t = _tools(paginate=True)
        assert t.lookup('SEC01-BP01', 'Separate workloads using accounts') is not None
        calls = [c.kwargs for c in t.waClient.list_answers.call_args_list if c.kwargs['PillarId'] == 'security']
        assert any(c.get('NextToken') == 'p2' for c in calls)

    def test_update_preserves_existing_selection(self):
        t = _tools()
        t.updateAnswers('securely-operate', ['sec-accounts'], 'notes')
        args = t.waClient.update_answer.call_args.kwargs
        assert args['SelectedChoices'] == ['user-picked', 'sec-accounts']

    def test_update_drops_none_of_these_when_adding(self):
        t = _tools()
        t.updateAnswers('fnd-iam', ['fnd-root'], 'notes')
        assert t.waClient.update_answer.call_args.kwargs['SelectedChoices'] == ['fnd-root']

    @pytest.mark.parametrize('status', ['NOT_CURRENT', 'DEPRECATED'])
    def test_no_write_when_lens_not_current(self, status):
        t = _tools(lens_status=status)
        assert t.canWrite is False
        assert t.updateAnswers('securely-operate', ['sec-accounts'], 'x') is None
        t.waClient.update_answer.assert_not_called()


# --------------------------------------------------------------------------- #
# WAFS2027 hooks
# --------------------------------------------------------------------------- #
def _framework(tools):
    fw = wafs2027_module.WAFS2027.__new__(wafs2027_module.WAFS2027)
    fw.WATools = tools
    fw.ResultCache = {}
    fw.unmatched = []
    return fw


class TestWAFS2027Hooks:
    def test_results_attached_to_matched_choice(self):
        t = _tools()
        fw = _framework(t)
        q = 'SEC01 Securely operate your workload'
        fw._hookPostItemActivity(q, 'SEC01-BP01 Separate workloads using accounts', '', 1)
        fw._hookPostItemActivity(q, 'SEC01-BP03 Stay up to date with security threats and recommendations', '', -1)
        fw._hookPostItemActivity(q, 'SEC01-BP06 Identify threats and prioritize mitigations using a threat model', '', 0)
        res = fw.ResultCache['securely-operate']
        assert res['selected'] == ['sec-accounts']
        assert res['failed'] == ['SEC01-BP03 Stay up to date with security threats and recommendations']
        assert fw.unmatched == ['SEC01-BP06']

        fw._hookPostItemsLoop()
        args = t.waClient.update_answer.call_args.kwargs
        assert args['QuestionId'] == 'securely-operate'
        assert args['SelectedChoices'] == ['user-picked', 'sec-accounts']
        assert 'SEC01-BP03' in args['Notes']

    def test_no_wa_tools_is_noop(self):
        fw = _framework(None)
        out = fw._hookPostItemActivity('t', 'SEC01-BP01 x', 'checks', 1)
        assert out == ('t', 'SEC01-BP01 x', 'checks', 1)
        fw._hookPostItemsLoop()


# --------------------------------------------------------------------------- #
# Render smoke test through the real Framework pipeline (no AWS, no WA Tool)
# --------------------------------------------------------------------------- #
def test_generate_mapping_information_smoke():
    from utils.Config import Config
    Config.set('_SS_PARAMS', {})
    Config.set('cli_services', {'iam': 1, 's3': 2})
    data = {
        'iam': {'summary': {'rootMfaActive': {
            'shortDesc': 'Enable MFA on root user', '__affectedResources': {'GLOBAL': ['User::root']},
            '__links': ["<a href='https://docs.aws.amazon.com'>AWS Docs</a>"]}}},
        's3': {'summary': {}},
    }
    fw = wafs2027_module.WAFS2027(data)
    assert fw.WATools is None                      # WA Tool integration is opt-in
    fw.readFile()
    rows = fw.generateMappingInformation()
    graph = fw.generateGraphInformation()

    total_bps = sum(len(v) for v in fw.map['mapping'].values())
    assert len(rows) == total_bps
    assert sum(graph['mcn']) == total_bps
    root_rows = [r for r in rows if r[1].startswith('FND02-BP01 ')]
    assert root_rows and root_rows[0][2] == -1      # failing root MFA check surfaces here
    manual = [r for r in rows if r[1].startswith('SEC01-BP06 ')]
    assert manual and manual[0][2] == 0             # threat model: manual review
