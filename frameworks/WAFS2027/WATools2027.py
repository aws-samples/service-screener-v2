import re

from botocore.exceptions import BotoCoreError, ClientError

from frameworks.helper.WATools import WATools
from utils.Tools import _warn, _info

BP_ID_RE = re.compile(r'^\s*((?:SEC|FND|REL|OPS|PERF|COST|SUS)\d{2}-BP\d{2})\b[\s:.-]*', re.I)


def normalizeTitle(title):
    """Lower-case, strip a leading best-practice ID and non-alphanumerics, so
    'SEC01-BP01 Separate workloads using accounts' and
    'Separate workloads using accounts.' compare equal."""
    if not title:
        return ''
    t = BP_ID_RE.sub('', title)
    return re.sub(r'[^a-z0-9]+', ' ', t.lower()).strip()


class WATools2027(WATools):
    """WA Tool integration for the November 2026 Well-Architected Framework.

    Differences from the base WATools used by WAFS:
    - Best practices are matched to WA Tool choices by title (and ID when the
      choice title carries one), never by position, so renumbering or
      reordering in the lens cannot attach results to the wrong choice.
    - Choices are indexed across every pillar of the lens review, so practices
      that moved to Cloud Foundations are found wherever the lens places them.
    - Writes are skipped unless the workload's lens review is CURRENT, to avoid
      updating an older lens version whose practices differ.
    - Existing selected choices are preserved; SS only adds choices.
    """
    DEFAULT_REPORTNAME = 'SS_Report_2027'

    def __init__(self):
        super().__init__('security')
        self.choiceIndex = {}      # normalized title / BP ID -> choice info
        self.questions = {}        # questionId -> {'title', 'pillarId', 'selected', 'noneChoices'}
        self.lensVersion = None
        self.lensStatus = None
        self.canWrite = False

    def preCheck(self, params):
        if 'reportName' not in params:
            params['reportName'] = self.DEFAULT_REPORTNAME
        return super().preCheck(params)

    # ------------------------------------------------------------------ #
    def _lensReview(self):
        try:
            resp = self.waClient.get_lens_review(
                WorkloadId=self.waInfo['WorkloadId'],
                LensAlias=self.waInfo['LensesAlias'],
            )
        except (ClientError, BotoCoreError) as e:
            _warn(f"[WATools2027] get_lens_review failed: {e}")
            return None
        return resp.get('LensReview', {})

    def _listAnswersForPillar(self, pillarId):
        answers, token = [], None
        while True:
            args = {
                'WorkloadId': self.waInfo['WorkloadId'],
                'LensAlias': self.waInfo['LensesAlias'],
                'PillarId': pillarId,
                'MaxResults': 50,
            }
            if token:
                args['NextToken'] = token
            resp = self.waClient.list_answers(**args)
            answers.extend(resp.get('AnswerSummaries', []))
            token = resp.get('NextToken')
            if not token:
                return answers

    def listAnswers(self):
        if self.HASPERMISSION is False or not self.waInfo.get('WorkloadId'):
            return None

        review = self._lensReview()
        if review is None:
            self.HASPERMISSION = False
            return None

        self.lensVersion = review.get('LensVersion')
        self.lensStatus = review.get('LensStatus')
        self.canWrite = self.lensStatus == 'CURRENT'
        if not self.canWrite:
            _warn(f"[WATools2027] Workload lens review is {self.lensStatus} (version {self.lensVersion}). "
                  f"Results will be shown in the report but NOT written to the WA Tool. "
                  f"Upgrade the lens review in the WA Tool console, or use a new reportName.")

        pillars = [p.get('PillarId') for p in review.get('PillarReviewSummaries', []) if p.get('PillarId')]
        if not pillars:
            pillars = ['security']

        for pillarId in pillars:
            try:
                answers = self._listAnswersForPillar(pillarId)
            except (ClientError, BotoCoreError) as e:
                _warn(f"[WATools2027] list_answers failed for pillar {pillarId}: {e}")
                continue
            for ans in answers:
                qid = ans.get('QuestionId')
                self.questions[qid] = {
                    'title': ans.get('QuestionTitle', ''),
                    'pillarId': pillarId,
                    'selected': list(ans.get('SelectedChoices', [])),
                    'noneChoices': set(),
                }
                for ch in ans.get('Choices', []):
                    if normalizeTitle(ch.get('Title')).startswith('none of these'):
                        self.questions[qid]['noneChoices'].add(ch.get('ChoiceId'))
                        continue
                    info = {
                        'questionId': qid,
                        'questionTitle': ans.get('QuestionTitle', ''),
                        'choiceId': ch.get('ChoiceId'),
                        'choiceTitle': ch.get('Title', ''),
                        'pillarId': pillarId,
                    }
                    m = BP_ID_RE.match(ch.get('Title', '') or '')
                    if m:
                        self.choiceIndex.setdefault(m.group(1).upper(), info)
                    key = normalizeTitle(ch.get('Title'))
                    if key:
                        self.choiceIndex.setdefault(key, info)

        _info(f"[WATools2027] Indexed {len(self.questions)} questions across {len(pillars)} pillars "
              f"(lens version {self.lensVersion}, status {self.lensStatus})")
        return self.choiceIndex

    def lookup(self, bpId, bpTitle):
        """Return the WA Tool choice for a best practice, or None."""
        return self.choiceIndex.get(normalizeTitle(bpTitle)) or self.choiceIndex.get((bpId or '').upper())

    def updateAnswers(self, questionId, selectedChoices, unselectedNotes):
        if not self.canWrite:
            return None
        q = self.questions.get(questionId, {})
        merged = list(dict.fromkeys(list(q.get('selected', [])) + list(selectedChoices or [])))
        # "None of these" cannot be combined with other choices.
        if len(merged) > 1:
            merged = [c for c in merged if c not in q.get('noneChoices', set())]
        return super().updateAnswers(questionId, merged, unselectedNotes)
