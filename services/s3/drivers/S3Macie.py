import threading
import urllib.parse
from datetime import date

import boto3
import botocore

from utils.Config import Config
from utils.Policy import Policy
from utils.Tools import _warn
from services.Evaluator import Evaluator

class S3Macie(Evaluator):
    def __init__(self, macieV2Client):
        super().__init__()
        self.macieV2Client = macieV2Client
        
        self._resourceName = 'Macie'
        # get_macie_session is shared by several checks that run concurrently.
        self._sessionLock = threading.Lock()

        self.init()
    
    def _checkMacieEnable(self):
        try:
            self.macieV2Client.list_findings()
        except self.macieV2Client.exceptions.AccessDeniedException as e:
            self.results['MacieToEnable'] = [-1, None]
        except botocore.exceptions.EndpointConnectionError as connErr:
            # Handle regions where Macie2 is not available
            # Service unavailability is environmental, not a finding - just log and skip
            _warn(f"Macie2 service not available in this region: {str(connErr)}")
            # Don't create result entry - this prevents "rule not available in reporter" warning
            return
        except Exception as e:
            # Handle any other unexpected errors
            # Operational errors are not findings - just log and skip
            _warn(f"Error checking Macie2 status: {str(e)}")
            # Don't create result entry - this prevents "rule not available in reporter" warning
            return
    # ------------------------------------------------------------------
    # WAFS2027 checks. All are read-only and only meaningful when Macie is
    # enabled in this account/Region; Macie-not-enabled itself is reported by
    # MacieToEnable, so these record INFO (0) rather than a second finding.
    # ------------------------------------------------------------------
    _SESSION_NOT_FETCHED = object()

    @staticmethod
    def _errCode(e):
        return e.response.get('Error', {}).get('Code', 'Unknown')

    @staticmethod
    def _isMacieNotEnabled(e):
        err = e.response.get('Error', {})
        return err.get('Code') == 'AccessDeniedException' and 'not enabled' in (err.get('Message') or '').lower()

    def getMacieSessionStatus(self):
        """Returns (status, unevaluableResult). status is 'ENABLED'/'PAUSED' or
        None; when None, unevaluableResult is the [0, msg] to record."""
        with self._sessionLock:
            return self._fetchMacieSessionStatus()

    def _fetchMacieSessionStatus(self):
        cached = getattr(self, '_macieSession', S3Macie._SESSION_NOT_FETCHED)
        if cached is not S3Macie._SESSION_NOT_FETCHED:
            return cached
        try:
            resp = self.macieV2Client.get_macie_session()
            out = (resp.get('status'), None)
        except botocore.exceptions.ClientError as e:
            if S3Macie._isMacieNotEnabled(e):
                out = (None, [0, 'Macie not enabled in this Region'])
            else:
                out = (None, [0, f'Unable to evaluate ({S3Macie._errCode(e)})'])
        except botocore.exceptions.EndpointConnectionError:
            out = (None, [0, 'Unable to evaluate (Macie endpoint not available in this Region)'])
        self._macieSession = out
        return out

    def _requireMacieEnabled(self, key):
        status, unevaluable = self.getMacieSessionStatus()
        if status is None:
            self.results[key] = unevaluable
            return False
        if status != 'ENABLED':
            self.results[key] = [0, f'Macie session status is {status}']
            return False
        return True

    def _checkMacieAutomatedDiscovery(self):
        key = 'macieAutomatedDiscoveryDisabled'
        if not self._requireMacieEnabled(key):
            return
        try:
            resp = self.macieV2Client.get_automated_discovery_configuration()
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f'Unable to evaluate ({S3Macie._errCode(e)})']
            return
        status = resp.get('status')
        if status == 'ENABLED':
            self.results[key] = [1, 'Automated sensitive data discovery enabled']
        else:
            self.results[key] = [-1, f'Automated sensitive data discovery is {status or "not configured"}']

    def _checkMacieOrgAutoEnable(self):
        key = 'macieOrgAutoEnableOff'
        status, unevaluable = self.getMacieSessionStatus()
        if status is None:
            self.results[key] = unevaluable
            return
        try:
            resp = self.macieV2Client.describe_organization_configuration()
        except botocore.exceptions.ClientError as e:
            code = S3Macie._errCode(e)
            # Only the Macie delegated administrator can read the org config;
            # standalone/member accounts get AccessDenied/Validation errors.
            if code in ('AccessDeniedException', 'ValidationException', 'ResourceNotFoundException', 'ConflictException'):
                self.results[key] = [0, 'Not evaluable from member account']
            else:
                self.results[key] = [0, f'Unable to evaluate ({code})']
            return
        autoEnable = resp.get('autoEnable')
        if autoEnable is True:
            self.results[key] = [1, 'New organization accounts are auto-enabled']
        elif autoEnable is False:
            extra = ' (max account limit reached)' if resp.get('maxAccountLimitReached') else ''
            self.results[key] = [-1, 'Macie is not auto-enabled for new organization accounts' + extra]
        else:
            self.results[key] = [0, 'Unable to evaluate (autoEnable not returned)']

    # Unarchived, non-sample sensitive-data (CLASSIFICATION) findings.
    _OPEN_CLASSIFICATION_CRITERIA = {'criterion': {
        'category': {'eq': ['CLASSIFICATION']},
        'archived': {'eq': ['false']},
        'sample': {'eq': ['false']},
    }}

    def _checkMacieSensitiveDataFindings(self):
        key = 'macieSensitiveDataFindingsOpen'
        if not self._requireMacieEnabled(key):
            return
        try:
            resp = self.macieV2Client.list_findings(
                findingCriteria=S3Macie._OPEN_CLASSIFICATION_CRITERIA, maxResults=1)
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f'Unable to evaluate ({S3Macie._errCode(e)})']
            return
        if not resp.get('findingIds'):
            self.results[key] = [1, 'No unarchived sensitive data findings']
            return

        # Enrichment only: counts by finding type. Failure here never changes the verdict.
        detail = ''
        try:
            stats = self.macieV2Client.get_finding_statistics(
                findingCriteria=S3Macie._OPEN_CLASSIFICATION_CRITERIA, groupBy='type')
            groups = [g for g in stats.get('countsByGroup', []) if g.get('count')]
            if groups:
                total = sum(g['count'] for g in groups)
                detail = f'{total} finding(s): ' + ', '.join(f"{g.get('groupKey')}={g['count']}" for g in groups[:5])
        except botocore.exceptions.ClientError:
            pass
        self.results[key] = [-1, detail or 'Unarchived sensitive data findings present']
