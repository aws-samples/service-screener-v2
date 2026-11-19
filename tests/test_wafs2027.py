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


def _initialAnswers():
    return {
        'securely-operate': {'SelectedChoices': ['user-picked'], 'Notes': ''},
        'fnd-iam': {'SelectedChoices': ['fnd-none'], 'Notes': ''},
    }


def _tools(lens_status='CURRENT', paginate=False, answers=None):
    """WATools2027 with a fake, stateful WA Tool client: update_answer
    changes what get_answer/list_answers return on the next run."""
    state = answers if answers is not None else _initialAnswers()
    t = WATools2027()
    t.waInfo = {'isExists': True, 'WorkloadId': 'wl-1', 'LensesAlias': 'wellarchitected'}
    t.waClient = MagicMock()
    t.waClient.get_lens_review.return_value = {'LensReview': {
        'LensVersion': '2026-11-16', 'LensStatus': lens_status,
        'PillarReviewSummaries': [{'PillarId': 'security'}, {'PillarId': 'foundations'}],
    }}

    def list_answers(**kw):
        items = [dict(a, SelectedChoices=list(state.get(a['QuestionId'], {}).get('SelectedChoices', [])))
                 for a in _answers(kw['PillarId'])]
        if paginate and kw['PillarId'] == 'security':
            if 'NextToken' not in kw:
                return {'AnswerSummaries': [], 'NextToken': 'p2'}
            return {'AnswerSummaries': items}
        return {'AnswerSummaries': items}

    def get_answer(**kw):
        a = state[kw['QuestionId']]
        return {'Answer': {'QuestionId': kw['QuestionId'], 'SelectedChoices': list(a['SelectedChoices']),
                           'Notes': a.get('Notes', '')}}

    def update_answer(**kw):
        state[kw['QuestionId']] = {'SelectedChoices': list(kw['SelectedChoices']), 'Notes': kw['Notes']}
        return {}
    t.waClient.list_answers.side_effect = list_answers
    t.waClient.get_answer.side_effect = get_answer
    t.waClient.update_answer.side_effect = update_answer
    t.state = state
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
    fw.choiceResults = {}
    fw._mapDupTitles = None
    fw.map = json.load(open(MAP_PATH))
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
        assert res['choices'] == ['sec-accounts', 'sec-threats']
        assert res['passed'] == ['SEC01-BP01 Separate workloads using accounts']
        assert res['failed'] == ['SEC01-BP03 Stay up to date with security threats and recommendations']
        assert fw.unmatched == ['SEC01-BP06']

        fw._hookPostItemsLoop()
        args = t.waClient.update_answer.call_args.kwargs
        assert args['QuestionId'] == 'securely-operate'
        # sec-threats failed, so it is not selected
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
def test_generate_mapping_information_smoke(tmp_path):
    from utils.Config import Config
    Config.set('_SS_PARAMS', {})
    # Full scan results: iam.rootMfaActive failed; iam.hasOrganization passed.
    _writeRaw(tmp_path, {'iam': {'GLOBAL': {'User::root': {'rootMfaActive': [-1, 'x']},
                                            'Org': {'hasOrganization': [1, 'ok']}}}})
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
    # Nothing ran for guardduty/cloudtrail: not evaluated, never compliant
    assert all(r[2] in (-1, 0) or _bpHasPass(fw, r[1]) for r in rows)


# --------------------------------------------------------------------------- #
# Helpers for the regression tests below
# --------------------------------------------------------------------------- #
_RAW_SENTINEL = object()


@pytest.fixture(autouse=True)
def _restoreConfig():
    from utils.Config import Config
    cache = Config.retrieveAllCache()
    keys = ('HTML_ACCOUNT_FOLDER_FULLPATH', 'cli_services', '_SS_PARAMS')
    saved = {k: cache.get(k, _RAW_SENTINEL) for k in keys}
    yield
    for k, v in saved.items():
        if v is _RAW_SENTINEL:
            cache.pop(k, None)
        else:
            cache[k] = v


@pytest.fixture(autouse=True)
def _emptyForkDir(tmp_path, monkeypatch):
    # Never read a real __fork/error.txt left by a local scan.
    d = tmp_path / '_emptyfork'
    d.mkdir()
    monkeypatch.setattr(wafs2027_module._C, 'FORK_DIR', str(d))


def _writeRaw(tmp_path, results):
    """Write api-raw.json the way Screener.generateScreenerOutput does:
    {service: {'results': {region: {identifier: {check: [status, msg]}}}}}"""
    from utils.Config import Config
    raw = {svc: {'results': regions, 'charts': {}} for svc, regions in results.items()}
    (tmp_path / 'api-raw.json').write_text(json.dumps(raw))
    Config.set('HTML_ACCOUNT_FOLDER_FULLPATH', str(tmp_path))


def _bpHasPass(fw, section):
    for bps in fw.map['mapping'].values():
        if section in bps:
            return 'iam.hasOrganization' in bps[section]
    return False


def _summary(check, resources=None):
    return {check: {'shortDesc': check, '__affectedResources': {'GLOBAL': resources or ['r1']},
                    '__links': []}}


def _runFramework(data, tools=None):
    """Run the real WAFS2027 mapping pipeline (no AWS), optionally with a
    fake WA Tool attached."""
    from utils.Config import Config
    Config.set('_SS_PARAMS', {})
    fw = wafs2027_module.WAFS2027(data)
    fw.readFile()
    fw.WATools = tools
    rows = fw.generateMappingInformation()
    return fw, {r[1].split(' ', 1)[0]: r[2] for r in rows}, rows


SEC01_BP01_CHECKS = ['accountMixesEnvironments', 'accountNotVended', 'enableCostBudget', 'hasOrganization',
                     'orgMgmtAccountHostsWorkloads', 'orgOuStructureFlat']


# --------------------------------------------------------------------------- #
# Finding (high): BPs whose checks never ran / could not be evaluated were
# compliant and written to the WA Tool as implemented.
# --------------------------------------------------------------------------- #
class TestComplianceRequiresEvaluatedPass:
    def test_not_scanned_service_is_not_compliant_and_not_selected(self, tmp_path):
        # Scan ran with --services s3 only: no iam results at all.
        _writeRaw(tmp_path, {'s3': {'us-east-1': {'b1': {'BucketVersioning': [1, 'ok']}}}})
        t = _tools()
        fw, comp, _ = _runFramework({'s3': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0          # old code: 1
        assert comp['FND02-BP01'] == 0          # old code: 1
        fw._hookPostItemsLoop()
        for c in t.waClient.update_answer.call_args_list:
            assert 'sec-accounts' not in c.kwargs['SelectedChoices']
            assert 'fnd-root' not in c.kwargs['SelectedChoices']
        assert t.state['securely-operate']['SelectedChoices'] == ['user-picked']

    def test_status_zero_only_is_not_evaluated(self, tmp_path):
        # Member account: org checks report 0 "Not evaluable from member account".
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {c: [0, 'Not evaluable from member account']
                                                            for c in SEC01_BP01_CHECKS}}}})
        t = _tools()
        fw, comp, rows = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert 'Unable to evaluate' in row[3] and 'fa-check' not in row[3]
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']

    def test_member_account_unreadable_checks_block_pass(self, tmp_path):
        # Member account: 5 of 6 SEC01-BP01 checks are "Not evaluable from
        # member account" and 1 passes. The unreadable checks may hide a
        # failure, so the BP is not met and the choice is not selected.
        # Old code: comp 1 and 'sec-accounts' selected.
        res = {c: [0, 'Not evaluable from member account'] for c in SEC01_BP01_CHECKS}
        res['hasOrganization'] = [1, 'ok']
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': res}}})
        t = _tools()
        fw, comp, rows = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert 'Unable to evaluate' in row[3]
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']

    def test_unreadable_check_blocks_pass_of_another_check_in_bp(self, tmp_path):
        # Old code: comp 1 (pass on hasOrganization hid the AccessDenied).
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {
            'hasOrganization': [1, 'ok'],
            'orgMgmtAccountHostsWorkloads': [0, 'Unable to evaluate (AccessDenied)']}}}})
        t = _tools()
        fw, comp, _ = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']

    def test_evaluated_pass_with_unrun_checks_is_compliant_and_selected(self, tmp_path):
        # Checks that did not run (no resources / not scanned) do not block a
        # pass from a check that did run.
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [1, 'ok']}}}})
        t = _tools()
        fw, comp, _ = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 1
        fw._hookPostItemsLoop()
        assert t.state['securely-operate']['SelectedChoices'] == ['user-picked', 'sec-accounts']

    def test_informational_only_check_does_not_block_pass(self, tmp_path):
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {
            'hasOrganization': [1, 'ok'],
            'enableCostBudget': [0, 'Not applicable: account is not part of AWS Organizations']}}}})
        _, comp, rows = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 1
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert 'Informational only' in row[3]

    @pytest.mark.parametrize('msg', ['Error: ThrottlingException', 'Error: An error occurred (AccessDenied)',
                                     'Unknown mode: SSE-FOO'])
    def test_error_results_on_one_region_block_glue_pass(self, tmp_path, msg):
        # glue.PublicAccessibility passes in us-east-1 and returns
        # [0, 'Error: ...'] in eu-west-1. Old code: SEC03-BP03 = SEC08-BP04 = 1.
        _writeRaw(tmp_path, {'glue': {
            'us-east-1': {'Catalog': {'PublicAccessibility': [1, 'ok']}},
            'eu-west-1': {'Catalog': {'PublicAccessibility': [0, msg]}}}})
        _, comp, _ = _runFramework({'glue': {'summary': {}}})
        assert comp['SEC03-BP03'] == 0
        assert comp['SEC08-BP04'] == 0

    def test_glue_pass_in_all_regions_is_compliant(self, tmp_path):
        _writeRaw(tmp_path, {'glue': {
            'us-east-1': {'Catalog': {'PublicAccessibility': [1, 'ok']}},
            'eu-west-1': {'Catalog': {'PublicAccessibility': [1, 'ok']}}}})
        _, comp, _ = _runFramework({'glue': {'summary': {}}})
        assert comp['SEC03-BP03'] == 1

    def test_check_that_raised_on_one_resource_blocks_pass(self, tmp_path, monkeypatch):
        # Evaluator records no result for a check that raised, only a
        # traceback in __fork/error.txt. Old code: comp 1.
        forkDir = tmp_path / 'fork'
        forkDir.mkdir()
        (forkDir / 'error.txt').write_text(
            'Traceback (most recent call last):\n'
            '  File "/repo/services/Evaluator.py", line 85, in runSingleCheck\n'
            '    getattr(obj, method_name)()\n'
            '  File "/repo/services/glue/drivers/GlueCatalog.py", line 40, in _checkPublicAccessibility\n'
            '    policy = json.loads(resp["PolicyInJson"])\n'
            'KeyError: \'PolicyInJson\'\n')
        monkeypatch.setattr(wafs2027_module._C, 'FORK_DIR', str(forkDir))
        _writeRaw(tmp_path, {'glue': {'us-east-1': {'Catalog': {'PublicAccessibility': [1, 'ok']}}}})
        _, comp, rows = _runFramework({'glue': {'summary': {}}})
        assert comp['SEC03-BP03'] == 0
        row = [r for r in rows if r[1].startswith('SEC03-BP03 ')][0]
        assert 'Unable to evaluate' in row[3]

    @staticmethod
    def _writeErrorTxt(tmp_path, monkeypatch, frames):
        forkDir = tmp_path / 'fork'
        forkDir.mkdir()
        text = ''
        for path, method in frames:
            text += ('Traceback (most recent call last):\n'
                     '  File "/repo/services/Evaluator.py", line 85, in runSingleCheck\n'
                     '    getattr(obj, method_name)()\n'
                     f'  File "/repo/{path}", line 900, in {method}\n'
                     '    x = resp["Missing"]\n'
                     "KeyError: 'Missing'\n\n")
        (forkDir / 'error.txt').write_text(text)
        monkeypatch.setattr(wafs2027_module._C, 'FORK_DIR', str(forkDir))

    def test_check_that_raised_everywhere_blocks_pass_of_other_check(self, tmp_path, monkeypatch):
        # Review round 2, cause 1: _checkOrgMgmtAccountHostsWorkloads raised on
        # every resource (no raw result), hasOrganization passed. Old code
        # returned 'Not run' before looking at errors: SEC01-BP01 comp 1.
        self._writeErrorTxt(tmp_path, monkeypatch, [
            ('services/iam/drivers/IamAccount.py', '_checkOrgMgmtAccountHostsWorkloads')])
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [1, 'ok']}}}})
        t = _tools()
        fw, comp, rows = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert '[orgMgmtAccountHostsWorkloads] - Unable to evaluate' in row[3]
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']

    def test_raised_check_matched_to_lower_camel_key(self, tmp_path, monkeypatch):
        # Review round 2, cause 2: the result key is lowerCamel
        # ('orgMgmtAccountHostsWorkloads'), not the method name. Old code
        # compared case-sensitively: SEC01-BP01 comp 1.
        self._writeErrorTxt(tmp_path, monkeypatch, [
            ('services/iam/drivers/IamAccount.py', '_checkOrgMgmtAccountHostsWorkloads')])
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {
            'Account': {'hasOrganization': [1, 'ok'], 'orgMgmtAccountHostsWorkloads': [1, 'ok']}}}})
        fw, comp, _ = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 0
        assert fw._checkOutcome('iam', 'orgMgmtAccountHostsWorkloads') == wafs2027_module.CHECK_UNREADABLE
        # Unrelated iam checks are not affected by an attributable error.
        assert fw._checkOutcome('iam', 'hasOrganization') == wafs2027_module.CHECK_PASS

    def test_raised_check_matched_by_key_suffix(self, tmp_path, monkeypatch):
        # AcmCommon._checkCertExpired writes 'acmCertExpired'.
        self._writeErrorTxt(tmp_path, monkeypatch, [
            ('services/acm/drivers/AcmCommon.py', '_checkCertExpired')])
        _writeRaw(tmp_path, {'acm': {'us-east-1': {'c1': {'acmCertExpired': [1, 'ok']}}}})
        fw, _, _ = _runFramework({'acm': {'summary': {}}})
        assert fw._checkOutcome('acm', 'acmCertExpired') == wafs2027_module.CHECK_UNREADABLE

    def test_unattributable_raised_check_blocks_whole_service(self, tmp_path, monkeypatch):
        # A raised method whose result key cannot be identified makes every
        # mapped check of that service unreadable (never a false PASS).
        self._writeErrorTxt(tmp_path, monkeypatch, [
            ('services/iam/drivers/IamAccount.py', '_checkZzNoSuchThing')])
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [1, 'ok']}}}})
        fw, comp, _ = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 0
        assert fw._checkOutcome('iam', 'hasOrganization') == wafs2027_module.CHECK_UNREADABLE

    def test_raised_check_in_other_service_does_not_block(self, tmp_path, monkeypatch):
        self._writeErrorTxt(tmp_path, monkeypatch, [
            ('services/acm/drivers/AcmCommon.py', '_checkCertExpired')])
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [1, 'ok']}}}})
        _, comp, _ = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 1

    @pytest.mark.parametrize('msg,unreadable', [
        ('Unable to evaluate (AccessDenied)', True),
        ('Not evaluable from member account', True),
        ('Error: ThrottlingException', True),
        ('Unknown mode: X', True),
        ('Unknown option: X', True),
        ('Source server s-1: Unable to evaluate (replication state X)', True),
        ('Aggregator index in us-east-1: unable to read state (AccessDenied)', True),
        ('Vault access policy present but not parseable', True),
        ('CloudTrail client not available', True),
        ('Not applicable: account is not part of AWS Organizations', False),
        ('No user pools in this region', False),
        ('Shared from account 111122223333; evaluate in the owner account', False),
        ('Exception recorded by tag ss-exception=true (x, active key(s) y)', False),
    ])
    def test_unreadable_message_classification(self, msg, unreadable):
        assert wafs2027_module.WAFS2027._isUnreadable([0, msg]) is unreadable

    def test_pass_on_one_resource_does_not_cover_unreadable_resource(self, tmp_path):
        # hasOrganization passed on one resource but could not be read on
        # another: the check is not evaluated, so the BP is not compliant.
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {
            'Account': {'hasOrganization': [1, 'ok']},
            'Account2': {'hasOrganization': [0, 'Unable to evaluate (AccessDenied)']}}}})
        t = _tools()
        fw, comp, rows = _runFramework({'iam': {'summary': {}}}, t)
        assert comp['SEC01-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert 'Unable to evaluate' in row[3]
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']

    def test_informational_zero_does_not_block_pass(self, tmp_path):
        # A status 0 that is informational (not an unreadable-data message)
        # next to a real pass keeps the check passing.
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {
            'Account': {'hasOrganization': [1, 'ok']},
            'Account2': {'hasOrganization': [0, 'Shared from account 111122223333']}}}})
        _, comp, _ = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 1

    def test_failure_in_summary_is_minus_one(self, tmp_path):
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [-1, 'no org']}}}})
        _, comp, _ = _runFramework({'iam': {'summary': _summary('hasOrganization')}})
        assert comp['SEC01-BP01'] == -1

    def test_suppressed_failure_is_not_a_pass(self, tmp_path):
        # -1 in the raw results but absent from the summary = suppressed.
        _writeRaw(tmp_path, {'iam': {'GLOBAL': {'Account': {'hasOrganization': [-1, 'no org'],
                                                            'enableCostBudget': [1, 'ok']}}}})
        _, comp, rows = _runFramework({'iam': {'summary': {}}})
        assert comp['SEC01-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC01-BP01 ')][0]
        assert 'Failed, suppressed' in row[3]

    def test_unreadable_scan_results_never_pass(self, tmp_path):
        from utils.Config import Config
        Config.set('HTML_ACCOUNT_FOLDER_FULLPATH', str(tmp_path / 'missing'))
        _, comp, _ = _runFramework({'iam': {'summary': {}}})
        assert set(comp.values()) <= {0}

    def test_resource_count_absence_is_not_a_failure(self, tmp_path):
        # SEC05-BP01 maps cloudfront.$length; having no CloudFront is not a
        # network-layer failure (old code: -1 "Need at least 1 cloudfront").
        from utils.Config import Config
        _writeRaw(tmp_path, {})
        Config.set('cli_services', {})
        _, comp, _ = _runFramework({})
        assert comp['SEC05-BP01'] == 0

    def test_resource_count_alone_is_not_a_pass(self, tmp_path):
        from utils.Config import Config
        _writeRaw(tmp_path, {})
        Config.set('cli_services', {'cloudfront': 3})
        _, comp, rows = _runFramework({})
        assert comp['SEC05-BP01'] == 0
        row = [r for r in rows if r[1].startswith('SEC05-BP01 ')][0]
        assert '3 cloudfront resource(s) scanned' in row[3]


# --------------------------------------------------------------------------- #
# Finding (medium): duplicate map title FND02-BP08 / SEC02-BP05 resolved to
# the same WA Tool choice.
# --------------------------------------------------------------------------- #
def _dupLensTools(withIds=False, foundationsPillar='foundations', answers=None):
    t = WATools2027()
    t.waInfo = {'isExists': True, 'WorkloadId': 'wl-1', 'LensesAlias': 'wellarchitected'}
    t.waClient = MagicMock()
    pfx = (lambda i: f'{i} ') if withIds else (lambda i: '')
    lens = {
        'security': [{'QuestionId': 'sec-creds', 'QuestionTitle': 'How do you manage identities?',
                      'Choices': [{'ChoiceId': 'sec-rotate', 'Title': pfx('SEC02-BP05') + 'Audit and rotate credentials periodically'}]}],
        foundationsPillar: [{'QuestionId': 'fnd-creds', 'QuestionTitle': 'How do you manage credentials?',
                             'Choices': [{'ChoiceId': 'fnd-rotate', 'Title': pfx('FND02-BP08') + 'Audit and rotate credentials periodically'}]}],
    }
    state = answers if answers is not None else {'sec-creds': {'SelectedChoices': [], 'Notes': ''},
                                                 'fnd-creds': {'SelectedChoices': [], 'Notes': ''}}
    t.waClient.get_lens_review.return_value = {'LensReview': {
        'LensVersion': '2026-11-16', 'LensStatus': 'CURRENT',
        'PillarReviewSummaries': [{'PillarId': p} for p in lens]}}
    t.waClient.list_answers.side_effect = lambda **kw: {'AnswerSummaries': [
        dict(a, SelectedChoices=state[a['QuestionId']]['SelectedChoices']) for a in lens.get(kw['PillarId'], [])]}
    t.waClient.get_answer.side_effect = lambda **kw: {'Answer': dict(state[kw['QuestionId']])}

    def upd(**kw):
        state[kw['QuestionId']] = {'SelectedChoices': kw['SelectedChoices'], 'Notes': kw['Notes']}
        return {}
    t.waClient.update_answer.side_effect = upd
    t.state = state
    t.listAnswers()
    return t


class TestDuplicateTitle:
    def _run(self, t):
        fw = _framework(t)
        fw._hookPostItemActivity('FND02 x', 'FND02-BP08 Audit and rotate credentials periodically', '', 1)
        fw._hookPostItemActivity('SEC02 x', 'SEC02-BP05 Audit and rotate credentials periodically', '', -1)
        fw._hookPostItemsLoop()
        return fw

    def test_fnd_pass_does_not_select_failed_sec_choice(self):
        t = _dupLensTools()
        self._run(t)
        # old code: FND02-BP08 pass resolved to sec-rotate and selected it
        assert 'sec-rotate' not in t.state['sec-creds']['SelectedChoices']
        assert t.state['fnd-creds']['SelectedChoices'] == ['fnd-rotate']
        assert 'SEC02-BP05' in t.state['sec-creds']['Notes']

    def test_id_prefixed_titles_resolve_by_id(self):
        t = _dupLensTools(withIds=True)
        assert t.lookup('FND02-BP08', 'Audit and rotate credentials periodically')['choiceId'] == 'fnd-rotate'
        assert t.lookup('SEC02-BP05', 'Audit and rotate credentials periodically')['choiceId'] == 'sec-rotate'
        self._run(t)
        assert t.state['sec-creds']['SelectedChoices'] == []
        assert t.state['fnd-creds']['SelectedChoices'] == ['fnd-rotate']

    def test_ambiguous_title_is_not_matched_without_scope(self):
        t = _dupLensTools()
        assert t.lookup('X', 'Audit and rotate credentials periodically') is None

    def test_fnd_never_matches_a_security_pillar_choice_by_shared_title(self):
        # Lens places the foundations question inside the security pillar:
        # only SEC02-BP05 may claim the security choices by title.
        t = _dupLensTools(foundationsPillar='security')
        fw = self._run(t)
        assert 'FND02-BP08' in fw.unmatched
        assert t.state['sec-creds']['SelectedChoices'] == []
        assert t.state['fnd-creds']['SelectedChoices'] == []

    def test_id_and_title_disagree_is_refused(self):
        t = _tools()
        # ID points at fnd-root, title at sec-accounts
        assert t.lookup('FND02-BP01', 'Separate workloads using accounts') is None

    def test_any_failed_bp_on_shared_choice_blocks_selection(self):
        t = _tools()
        fw = _framework(t)
        q = 'SEC01 Securely operate your workload'
        fw._hookPostItemActivity(q, 'SEC01-BP01 Separate workloads using accounts', '', 1)
        fw._hookPostItemActivity(q, 'SEC01-BP99 Separate workloads using accounts', '', -1)
        fw._hookPostItemsLoop()
        assert 'sec-accounts' not in t.state['securely-operate']['SelectedChoices']


# --------------------------------------------------------------------------- #
# Finding (medium): choices SS selected earlier stayed selected after the BP
# started failing.
# --------------------------------------------------------------------------- #
class TestStaleSelectionsWithdrawn:
    Q = 'SEC01 Securely operate your workload'
    BP = 'SEC01-BP01 Separate workloads using accounts'

    def _run(self, state, comp):
        t = _tools(answers=state)
        fw = _framework(t)
        fw._hookPostItemActivity(self.Q, self.BP, '', comp)
        fw._hookPostItemsLoop()
        return t

    def test_failing_bp_withdraws_choice_ss_selected_earlier(self):
        state = _initialAnswers()
        self._run(state, 1)
        assert state['securely-operate']['SelectedChoices'] == ['user-picked', 'sec-accounts']
        self._run(state, -1)
        # old code: sec-accounts kept
        assert state['securely-operate']['SelectedChoices'] == ['user-picked']
        assert 'withdrawn' in state['securely-operate']['Notes']
        assert 'SEC01-BP01' in state['securely-operate']['Notes']

    def test_not_evaluated_bp_withdraws_choice_ss_selected_earlier(self):
        state = _initialAnswers()
        self._run(state, 1)
        self._run(state, 0)
        assert state['securely-operate']['SelectedChoices'] == ['user-picked']

    def test_user_selected_choice_kept_when_not_evaluated(self):
        state = _initialAnswers()
        state['securely-operate']['SelectedChoices'] = ['user-picked', 'sec-accounts']
        self._run(state, 0)
        assert state['securely-operate']['SelectedChoices'] == ['user-picked', 'sec-accounts']

    def test_user_selected_choice_withdrawn_when_bp_fails(self):
        state = _initialAnswers()
        state['securely-operate']['SelectedChoices'] = ['user-picked', 'sec-accounts']
        self._run(state, -1)
        assert state['securely-operate']['SelectedChoices'] == ['user-picked']

    def test_repeated_pass_keeps_choice(self):
        state = _initialAnswers()
        self._run(state, 1)
        self._run(state, 1)
        assert state['securely-operate']['SelectedChoices'] == ['user-picked', 'sec-accounts']


# --------------------------------------------------------------------------- #
# Finding (medium): update_answer replaced the customer's notes.
# --------------------------------------------------------------------------- #
class TestNotesPreserved:
    Q = 'SEC01 Securely operate your workload'
    BP = 'SEC01-BP01 Separate workloads using accounts'

    def _run(self, state, comp=-1):
        t = _tools(answers=state)
        fw = _framework(t)
        fw._hookPostItemActivity(self.Q, self.BP, '', comp)
        fw._hookPostItemsLoop()
        return t

    def test_customer_notes_kept_and_ss_block_replaced(self):
        state = _initialAnswers()
        state['securely-operate']['Notes'] = 'Reviewer: accounts split per BU, see ticket 42.'
        self._run(state, -1)
        n1 = state['securely-operate']['Notes']
        # old code: notes == SS text only
        assert n1.startswith('Reviewer: accounts split per BU, see ticket 42.')
        assert 'SEC01-BP01' in n1
        self._run(state, 1)
        n2 = state['securely-operate']['Notes']
        assert n2.startswith('Reviewer: accounts split per BU, see ticket 42.')
        assert n2.count('***Generated by SS (WAFS2027)') == 1
        assert 'failed SS checks' not in n2

    def test_legacy_ss_notes_replaced_not_duplicated(self):
        state = _initialAnswers()
        state['securely-operate']['Notes'] = ('***Generated by SS (WAFS2027)\n\nBest practices with failed SS '
                                              'checks:\n- SEC01-BP01 Separate workloads using accounts')
        self._run(state, 1)
        n = state['securely-operate']['Notes']
        assert n.count('***Generated by SS (WAFS2027)') == 1
        assert 'failed SS checks' not in n

    def test_notes_within_limit_and_customer_text_intact(self):
        from frameworks.WAFS2027.WATools2027 import NOTES_MAX
        state = _initialAnswers()
        user = 'u' * 1900
        state['securely-operate']['Notes'] = user
        t = _tools(answers=state)
        t.updateAnswers('securely-operate', ['sec-accounts'],
                        ['Best practices with failed SS checks:'] + [f'- BP{i:02} long title ' * 3 for i in range(40)])
        n = state['securely-operate']['Notes']
        assert len(n) <= NOTES_MAX and n.startswith(user)
        assert '[ss-selected: sec-accounts]' in n

    def test_full_customer_notes_kept_and_no_untracked_choice_added(self):
        from frameworks.WAFS2027.WATools2027 import NOTES_MAX
        state = _initialAnswers()
        user = 'n' * NOTES_MAX
        state['securely-operate']['Notes'] = user
        t = _tools(answers=state)
        t.updateAnswers('securely-operate', ['sec-accounts'], ['x'])
        assert state['securely-operate']['Notes'] == user
        assert state['securely-operate']['SelectedChoices'] == ['user-picked']

    def test_no_write_when_current_answer_unreadable(self):
        from botocore.exceptions import ClientError
        t = _tools()
        t.waClient.get_answer.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, 'GetAnswer')
        assert t.updateAnswers('securely-operate', ['sec-accounts'], 'x') is None
        t.waClient.update_answer.assert_not_called()


def test_stubber_real_api_shapes():
    """get_answer / update_answer requests validated against the real
    wellarchitected service model with botocore Stubber."""
    import boto3
    from botocore.stub import Stubber
    from frameworks.WAFS2027.WATools2027 import SS_NOTES_START, SS_NOTES_END

    client = boto3.client('wellarchitected', region_name='us-east-1',
                          aws_access_key_id='x', aws_secret_access_key='x')
    t = WATools2027()
    t.waInfo = {'isExists': True, 'WorkloadId': 'a' * 32, 'LensesAlias': 'wellarchitected'}
    t.waClient = client
    t.canWrite = True
    t.questions = {'securely-operate': {'selected': [], 'noneChoices': {'sec-none'}}}
    t.choiceTitles = {'sec-accounts': 'Separate workloads using accounts'}
    old = f"Customer note\n\n{SS_NOTES_START}\n\nold\n\n[ss-selected: sec-accounts]\n{SS_NOTES_END}"
    with Stubber(client) as st:
        st.add_response('get_answer', {
            'WorkloadId': 'a' * 32, 'LensAlias': 'wellarchitected',
            'Answer': {'QuestionId': 'securely-operate', 'SelectedChoices': ['user-picked', 'sec-accounts'],
                       'Notes': old}},
            {'WorkloadId': 'a' * 32, 'LensAlias': 'wellarchitected', 'QuestionId': 'securely-operate'})
        st.add_response('update_answer', {}, {
            'WorkloadId': 'a' * 32, 'LensAlias': 'wellarchitected', 'QuestionId': 'securely-operate',
            'SelectedChoices': ['user-picked'],
            'Notes': ("Customer note\n\n" + SS_NOTES_START + "\n\nBest practices with failed SS checks:\n"
                      "- SEC01-BP01 Separate workloads using accounts\n\n"
                      "Choices withdrawn by SS (best practice did not pass in this run):\n"
                      "- Separate workloads using accounts\n\n[ss-selected: ]\n" + SS_NOTES_END)})
        t.updateAnswers('securely-operate', [],
                        ['Best practices with failed SS checks:', '- SEC01-BP01 Separate workloads using accounts'],
                        failedChoices=['sec-accounts'])
        st.assert_no_pending_responses()
