import botocore

from utils.Tools import _pi
from services.Service import Service

from services.fis.drivers.FisCommon import FisCommon


class Fis(Service):
    """
    AWS Fault Injection Service (FIS) scanner.

    FIS experiments are regional and the check concerns whether the account
    practises resilience testing at all, so discovery produces one
    'FIS::Account' descriptor per region.

    Read-only calls:
      - list_experiments           (paginated, capped by MAX_PAGES)
      - list_experiment_templates  (paginated, capped by MAX_PAGES; context only)
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## FIS retains experiment history for a limited period, so the list is
    ## naturally bounded; the cap is a safety net. 100 per page x 20 pages.
    MAX_PAGES = 20

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.fisClient = ssBoto.client('fis', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        detail = {
            '_region': self.region,
            '_experiments': None,
            '_experimentsError': None,
            '_experimentsCapped': False,
            '_templateCount': None,
        }

        try:
            detail['_experiments'], detail['_experimentsCapped'] = \
                self._listAll('list_experiments', 'experiments')
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"FIS not available in region {self.region}: {e}")
            return None
        except botocore.exceptions.ClientError as e:
            detail['_experimentsError'] = self._errorCode(e)
            self._logClientError('list_experiments', e)

        try:
            templates, _ = self._listAll('list_experiment_templates',
                                         'experimentTemplates')
            detail['_templateCount'] = len(templates)
        except (botocore.exceptions.ClientError,
                botocore.exceptions.EndpointConnectionError):
            pass

        _pi('Fis', f"FIS experiment history in {self.region}")
        return detail

    def _listAll(self, op, key):
        items, pages, capped = [], 0, False
        paginator = self.fisClient.get_paginator(op)
        for page in paginator.paginate(PaginationConfig={'PageSize': 100}):
            items += page.get(key, []) or []
            pages += 1
            if pages >= self.MAX_PAGES:
                capped = bool(page.get('nextToken'))
                break
        return items, capped

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}
        detail = self.getResources()
        if detail is None:
            return objs
        try:
            obj = FisCommon(detail)
            obj.run(self.__class__)
            objs['FIS::Account'] = obj.getInfo()
            del obj
        except Exception as e:
            print(f"Error processing FIS posture in {self.region}: {e}")
        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _errorCode(error):
        return error.response.get('Error', {}).get('Code', 'Unknown')

    def _logClientError(self, where, error):
        code = self._errorCode(error)
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Fis {where}: {code} - {msg}")
