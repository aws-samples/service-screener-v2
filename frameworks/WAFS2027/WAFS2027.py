import ast, json, os, re, traceback

import constants as _C
from utils.Config import Config
from utils.Tools import _warn
from frameworks.Framework import Framework
from frameworks.WAFS2027.WATools2027 import WATools2027, normalizeTitle

# Per-check outcome, derived from the full scan results (api-raw.json).
CHECK_FAIL = 'fail'              # in the Reporter summary (status -1, not suppressed)
CHECK_PASS = 'pass'              # ran with status 1 on at least one resource, never -1
CHECK_NOT_EVALUATED = 'notEvaluated'  # ran, but only with informational status 0 results
CHECK_UNREADABLE = 'unreadable'  # data could not be read on at least one resource, or the check raised
CHECK_SUPPRESSED = 'suppressed'  # failed (-1) but every failure is suppressed
CHECK_NOT_RUN = 'notRun'         # service not scanned or no resources (a check that raised is unreadable)
CHECK_EVIDENCE = 'evidence'      # <service>.$length entries: resource-count context only

# Status 0 results whose message says the data could not be read (or the
# value could not be interpreted). Any such result on any resource makes the
# check CHECK_UNREADABLE, and any unreadable mapped check keeps its best
# practice at 0 (never selected in the WA Tool). Matching is on markers
# anywhere in the message, not just the prefix, so wrapped messages such as
# "Error: ThrottlingException", "Unknown mode: X" or "Source server s-1:
# Unable to evaluate (...)" are caught. Other status 0 results (not
# applicable, no resources, advisory notes) are informational.
# The pattern is deliberately broad: a misclassified informational message
# can only give a false 0 (manual review), never a false PASS. Keep new
# informational status 0 messages free of these markers.
UNREADABLE = 'unreadable'
UNREADABLE_PATTERN = re.compile(
    r"unable to|not evaluable|could not|cannot |can't|\berror\b|\bexception:|"
    r"unknown|unparseable|not parseable|unreadable|not readable|unavailable|"
    r"client not available|not returned|not reported|not collected|not retrieved|"
    r"\bfailed\b|access ?denied|throttl|timed out|timeout|still in progress|"
    r"still being established|not yet in",
    re.IGNORECASE)

# Traceback frame of a driver check method in error.txt
# (services/Evaluator.py writes every exception a check raised there).
_CHECK_FRAME = re.compile(
    r'File "([^"]*[/\\]services[/\\]([A-Za-z0-9_]+)[/\\]drivers[/\\][^"]+)", line \d+, in _check(\w+)')

# Standard WA Tool pillar IDs. A title shared by several BPs in the map is
# matched only inside the pillar its BP ID belongs to; FND (Cloud
# Foundations) practices only outside the standard pillars.
STANDARD_PILLARS = {'operationalExcellence', 'security', 'reliability', 'performance',
                    'costOptimization', 'sustainability'}
PREFIX_PILLAR = {'SEC': 'security', 'REL': 'reliability', 'OPS': 'operationalExcellence',
                 'PERF': 'performance', 'COST': 'costOptimization', 'SUS': 'sustainability'}


class WAFS2027(Framework):
    """AWS Well-Architected Framework (Nov 2026 release) - Security pillar,
    security-relevant Cloud Foundations capabilities, and REL09/REL13.

    Map keys are self-describing:
        mapping["SEC01 Securely operate your workload"]["SEC01-BP01 Separate workloads using accounts"] = [checks]

    WA Tool integration (optional, via --others '{"WA": {...}}') matches each
    best practice to its WA Tool choice by ID/title - never by position.

    Compliance per best practice (the base Framework treats every check that
    is absent from the failure summary as compliant; WAFS2027 does not):
        -1  at least one mapped check failed
         1  at least one mapped check ran and passed, and none failed,
            were suppressed, or were unreadable (checks that did not run or
            were informational only do not block)
         0  no mapped check passed, or any mapped check could not read its
            data on any resource, or raised (traceback in error.txt; matched
            to result keys by name/suffix case-insensitively or by key
            literals in the method; an unattributable error blocks every
            mapped check of its service), or a failure was suppressed, or
            the practice needs manual review
    Only 1 is ever written to the WA Tool as a selected choice.
    """

    def __init__(self, data):
        super().__init__(data)
        self.isBeta = Config.get('beta', False)
        self.reportFilename = None
        self.WATools = None
        # questionId -> {"selected": [choiceId], "failed": [note]}
        self.ResultCache = {}
        self.unmatched = []
        # (questionId, choiceId) -> [comp, ...] for every BP that resolved to the choice
        self.choiceResults = {}
        self._mapDupTitles = None
        self.rawStatus = self._loadRawStatus()
        self.checkErrors = self._loadCheckErrors()
        self._raisedCache = {}

        cliParams = Config.get('_SS_PARAMS') or {}
        tmpParams = {}
        if cliParams.get('others'):
            try:
                cfg = json.loads(cliParams['others'])
                tmpParams = cfg.get('WA', {}) or {}
            except (ValueError, TypeError) as e:
                _warn(f"[WAFS2027]: Unable to parse --others: {e}")
                return

        if not tmpParams:
            return

        waTools = WATools2027()
        if waTools.preCheck(tmpParams):
            self.WATools = waTools
            self.WATools.init(tmpParams)
            self.WATools.createReportIfNotExists()
            self.WATools.listAnswers()

    # ------------------------------------------------------------------ #
    # Per-check outcome from the full scan results
    # ------------------------------------------------------------------ #
    @staticmethod
    def _loadRawStatus():
        """{service: {check: set(status)}} from api-raw.json, which Screener
        writes (every check result, including PASS and status 0) before the
        frameworks run. None when it cannot be read: then no best practice is
        treated as passed."""
        folder = Config.get('HTML_ACCOUNT_FOLDER_FULLPATH')
        if not folder:
            return None
        path = os.path.join(folder, 'api-raw.json')
        try:
            with open(path) as f:
                raw = json.load(f)
        except (OSError, ValueError) as e:
            _warn(f"[WAFS2027]: Unable to read scan results ({e}); best practices without "
                  f"failures are reported as not evaluated")
            return None

        out = {}
        for serv, ctx in (raw or {}).items():
            regions = ctx.get('results', ctx) if isinstance(ctx, dict) else {}
            checks = out.setdefault(serv, {})
            for _region, resources in (regions or {}).items():
                if not isinstance(resources, dict):
                    continue
                for _ident, results in resources.items():
                    if not isinstance(results, dict):
                        continue
                    for check, res in results.items():
                        try:
                            status = int(res[0])
                        except (TypeError, ValueError, IndexError, KeyError):
                            continue
                        if status == 0 and WAFS2027._isUnreadable(res):
                            status = UNREADABLE
                        checks.setdefault(check, set()).add(status)
        return out

    @staticmethod
    def _isUnreadable(res):
        try:
            msg = str(res[1] or '')
        except (IndexError, KeyError, TypeError):
            return False
        return bool(UNREADABLE_PATTERN.search(msg))

    @staticmethod
    def _loadCheckErrors():
        """{service: {methodName: set(string literals in the method)}} for
        driver check methods (_check<Name>) that raised during this scan.
        Evaluator records no result for a check that raised, only a traceback
        in __fork/error.txt, so a pass on another resource (or a pass from
        another mapped check) would otherwise hide the error."""
        path = os.path.join(_C.FORK_DIR, 'error.txt')
        out = {}
        try:
            with open(path, errors='replace') as f:
                text = f.read()
        except OSError:
            return out
        for block in text.split('Traceback (most recent call last):'):
            for m in _CHECK_FRAME.finditer(block):
                folder, method = m.group(2), m.group(3)
                serv = WAFS2027._folderToService(folder)
                methods = out.setdefault(serv, {})
                if method not in methods:
                    methods[method] = WAFS2027._methodLiterals(folder, m.group(1), method)
        return out

    @staticmethod
    def _folderToService(folder):
        """services/<folder> -> service name used by map.json, api-raw.json
        and the Reporter. Screener loads a Python keyword service from
        '<service>_' (Config.KEYWORD_SERVICES, e.g. lambda -> lambda_)."""
        folder = folder.lower()
        if folder.endswith('_') and folder[:-1] in Config.KEYWORD_SERVICES:
            return folder[:-1]
        return folder

    @staticmethod
    def _serviceToFolder(serv):
        """Inverse of _folderToService (same rule as Screener)."""
        serv = serv.lower()
        return serv + '_' if serv in Config.KEYWORD_SERVICES else serv

    @staticmethod
    def _methodLiterals(folder, tracePath, method):
        """String constants in the body of _check<method> and of the self.<helper>()
        methods it calls in the same driver file, transitively (result keys
        are often assigned through a variable, e.g. key = 'orgMgmt...', or by
        a helper, e.g. _checkPasswordPolicy -> passwordPolicyScoring writes
        passwordPolicyLength)."""
        fname = re.split(r'[/\\]', tracePath)[-1]
        path = os.path.join(_C.SERVICE_DIR, WAFS2027._serviceToFolder(WAFS2027._folderToService(folder)),
                            'drivers', fname)
        try:
            with open(path) as f:
                tree = ast.parse(f.read())
        except (OSError, SyntaxError, ValueError):
            return set()
        funcs = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs.setdefault(node.name, []).append(node)
        lits, seen, todo = set(), set(), ['_check' + method]
        while todo:
            name = todo.pop()
            if name in seen:
                continue
            seen.add(name)
            for node in funcs.get(name, []):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        lits.add(sub.value)
                    elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                          and isinstance(sub.func.value, ast.Name) and sub.func.value.id == 'self'):
                        todo.append(sub.func.attr)
        return lits

    @staticmethod
    def _methodMatchesKey(method, literals, key):
        """Whether result key `key` may be written by _check<method>. Result
        keys do not follow one convention: _checkOrgMgmtAccountHostsWorkloads
        writes 'orgMgmtAccountHostsWorkloads', AcmCommon._checkCertExpired
        writes 'acmCertExpired'. Matching is case-insensitive on equality or
        suffix (either way), or the key appears as a literal in the method."""
        if key in literals:
            return True
        # Underscores ignored: _check_code_signing_disabled vs lambdaCodeSigningDisabled.
        m, k = method.lower().replace('_', ''), key.lower().replace('_', '')
        if m == k:
            return True
        return (len(m) >= 4 and k.endswith(m)) or (len(k) >= 4 and m.endswith(k))

    def _mappedKeys(self, serv):
        keys = set()
        for sections in (getattr(self, 'map', None) or {}).get('mapping', {}).values():
            for maps in sections.values():
                for _m in maps or []:
                    s, _, c = str(_m).partition('.')
                    if s == serv and c and c != '$length':
                        keys.add(c)
        return keys

    def _checkRaised(self, serv, check):
        """True when a check method of `serv` that raised may have produced
        result key `check`. A raised method that matches none of the
        service's mapped or recorded result keys cannot be attributed, so it
        makes every mapped check of that service unreadable (never a false
        PASS)."""
        methods = self.checkErrors.get(self._folderToService(serv))
        if not methods:
            return False
        cache = self._raisedCache.get(serv)
        if cache is None:
            known = self._mappedKeys(serv) | set((self.rawStatus or {}).get(serv, {}).keys())
            matched, unattributed = set(), False
            for method, lits in methods.items():
                hits = {k for k in known if self._methodMatchesKey(method, lits, k)}
                if not hits:
                    unattributed = True
                matched |= hits
            cache = self._raisedCache[serv] = (matched, unattributed)
        matched, unattributed = cache
        if unattributed:
            return True
        if check in matched:
            return True
        # Keys not known up front (not mapped, not in raw) still get matched.
        return any(self._methodMatchesKey(m, l, check) for m, l in methods.items())

    def _checkOutcome(self, serv, check):
        if serv in self.data and check in (self.data[serv].get('summary') or {}):
            return CHECK_FAIL
        # A check that raised (on any resource) is unreadable, even when it
        # recorded no result at all: it must block a pass from another check.
        if self._checkRaised(serv, check):
            return CHECK_UNREADABLE
        if self.rawStatus is None:
            return CHECK_NOT_RUN
        statuses = self.rawStatus.get(serv, {}).get(check)
        if not statuses:
            return CHECK_NOT_RUN
        if -1 in statuses:
            return CHECK_SUPPRESSED
        # A pass on some resources does not cover resources whose data could
        # not be read.
        if UNREADABLE in statuses:
            return CHECK_UNREADABLE
        if 1 in statuses:
            return CHECK_PASS
        return CHECK_NOT_EVALUATED

    def getContent(self, _m):
        if not _m:
            return None
        serv, check = _m.split(".")
        if check == '$length':
            cnt = self.getResourceCount(serv)
            return {"c": f"{cnt} {serv} resource(s) scanned", "o": CHECK_EVIDENCE}

        outcome = self._checkOutcome(serv, check)
        if outcome == CHECK_FAIL:
            tmp = self.data[serv]['summary'][check]
            ln = tmp.get('__links', '') or []
            return {"c": check, "o": outcome, "d": tmp.get('shortDesc', ''),
                    "r": tmp.get('__affectedResources', {}) or {},
                    "l": "<br>".join(ln) if isinstance(ln, list) else str(ln)}
        return {"c": check, "o": outcome}

    _OUTCOME_LABEL = {
        CHECK_NOT_EVALUATED: 'Informational only',
        CHECK_UNREADABLE: 'Unable to evaluate',
        CHECK_SUPPRESSED: 'Failed, suppressed',
        CHECK_NOT_RUN: 'Not run',
    }

    def formatCheckAndLinks(self, packedData):
        links = []
        outcomes = []
        checks = ["<dl>"]
        for v in packedData:
            if not v:
                continue
            o = v.get('o')
            outcomes.append(o)
            if o == CHECK_FAIL:
                tmp = ['<ul>']
                for _reg, _affected in v['r'].items():
                    tmp.append("<li><b>[" + _reg + "]</b>" + ", ".join(_affected) + "</li>")
                tmp.append("</ul>")
                c = "<dt class='text-danger'><i class='fas fa-times'></i> [{}] - {}</dt>{}</dd>".format(
                    v['c'], v['d'], "".join(tmp))
                if v.get('l'):
                    links.append(v['l'])
            elif o == CHECK_PASS:
                c = "<dt class='text-success'><i class='fas fa-check'></i> [{}]</dt>".format(v['c'])
            elif o == CHECK_EVIDENCE:
                c = "<dt class='text-info'><i class='fas fa-info-circle'></i> [{}]</dt>".format(v['c'])
            else:
                c = "<dt class='text-muted'><i class='fas fa-question-circle'></i> [{}] - {}</dt>".format(
                    v['c'], self._OUTCOME_LABEL.get(o, 'Not run'))
            checks.append(c)
        checks.append("</dl>")

        if CHECK_FAIL in outcomes:
            comp = -1
        elif CHECK_UNREADABLE in outcomes or CHECK_SUPPRESSED in outcomes:
            # Data that could not be read (or a suppressed failure) on any
            # mapped check may hide a failure: never report the BP as met.
            comp = 0
        elif CHECK_PASS in outcomes:
            comp = 1
        else:
            comp = 0
        return ["".join(checks), "<br>".join(links), comp]

    # ------------------------------------------------------------------ #
    @staticmethod
    def splitSection(section):
        bpId, _, bpTitle = section.partition(' ')
        return bpId, bpTitle

    def _waActive(self):
        return self.WATools is not None and self.WATools.HASPERMISSION is not False

    def _hookPostItemActivity(self, title, section, checks, comp):
        if not self._waActive():
            return title, section, checks, comp

        bpId, bpTitle = self.splitSection(section)
        # A title shared by several BPs in the map (e.g. FND02-BP08 and
        # SEC02-BP05) is matched only within the BP's own pillar, so the two
        # can never resolve to the same choice.
        pillarFilter = None
        if normalizeTitle(bpTitle) in self._duplicateMapTitles():
            pillarFilter = self._pillarFilter(bpId)
        info = self.WATools.lookup(bpId, bpTitle, pillarFilter=pillarFilter)
        if info is None:
            self.unmatched.append(bpId)
            return title, section, checks, comp

        entry = self.ResultCache.setdefault(
            info['questionId'], {"choices": [], "failed": [], "passed": [], "notEvaluated": []})
        if info['choiceId'] not in entry['choices']:
            entry['choices'].append(info['choiceId'])
        self.choiceResults.setdefault((info['questionId'], info['choiceId']), []).append(comp)
        bucket = {-1: 'failed', 1: 'passed'}.get(comp, 'notEvaluated')
        note = f"{bpId} {bpTitle}"
        if note not in entry[bucket]:
            entry[bucket].append(note)

        return title, section, checks, comp

    @staticmethod
    def _pillarFilter(bpId):
        prefix = ''.join(ch for ch in (bpId or '').split('-')[0] if ch.isalpha()).upper()
        if prefix == 'FND':
            return lambda p: p not in STANDARD_PILLARS
        pillar = PREFIX_PILLAR.get(prefix)
        if pillar is None:
            return lambda p: False
        return lambda p: p == pillar

    def _duplicateMapTitles(self):
        if self._mapDupTitles is None:
            seen, dup = set(), set()
            for bps in (getattr(self, 'map', None) or {}).get('mapping', {}).values():
                for bp in bps:
                    t = normalizeTitle(self.splitSection(bp)[1])
                    (dup if t in seen else seen).add(t)
            self._mapDupTitles = dup
        return self._mapDupTitles

    def _hookPostItemsLoop(self):
        if not self._waActive():
            return

        if self.unmatched:
            _warn(f"[WAFS2027]: {len(self.unmatched)} best practices not found in the WA Tool lens "
                  f"(not written): {', '.join(self.unmatched[:10])}{' ...' if len(self.unmatched) > 10 else ''}")

        for questionId, res in self.ResultCache.items():
            # A choice is selected only when every BP that resolved to it
            # passed; any failure withdraws it.
            results = {c: self.choiceResults.get((questionId, c), []) for c in res['choices']}
            selected = [c for c, r in results.items() if r and all(x == 1 for x in r)]
            failedChoices = [c for c, r in results.items() if -1 in r]
            body = []
            for key, heading in (('failed', 'Best practices with failed SS checks:'),
                                 ('passed', 'Best practices that passed SS checks:'),
                                 ('notEvaluated', 'Best practices SS could not evaluate (review manually):')):
                if res[key]:
                    if body:
                        body.append('')
                    body += [heading] + [f"- {n}" for n in res[key]]
            try:
                self.WATools.updateAnswers(questionId, selected, body, failedChoices=failedChoices)
            except Exception as e:
                _warn(f"[WAFS2027]: Error updating answers for {questionId}: {e}")

    def _hookPostBuildContentDetail(self):
        if not self._waActive():
            return

        self.WATools.createMilestoneIfNotExists()

        try:
            acctFolder = Config.get('HTML_ACCOUNT_FOLDER_FULLPATH')
            wafrLocalDir = os.path.join(_C.ROOT_DIR, 'usecases', 'wa-summarizer', 'wafr_report')

            output_dirs = []
            if acctFolder:
                output_dirs.append(acctFolder)
            output_dirs.append(wafrLocalDir)

            written = self.WATools.generateReviewReport(output_dirs=output_dirs)
            if written:
                self.reportFilename = self.WATools.waInfo.get('LatestReportFilename')
        except (OSError, IOError) as e:
            _warn(f"[WAFS2027]: Filesystem error while saving review report: {e}")
            _warn(traceback.format_exc())
        except Exception as e:
            _warn(f"[WAFS2027]: Unable to generate review report: {e}")
            _warn(traceback.format_exc())
