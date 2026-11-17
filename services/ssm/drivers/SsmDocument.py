import botocore

from services.Evaluator import Evaluator


class SsmDocument(Evaluator):
    """
    Per self-owned SSM document checks.

      ssmDocumentPublic -- the document is shared publicly (FSBP SSM.4)

    The region-wide "block public sharing" service setting (FSBP SSM.7) is
    reported under the same result key by the region-scoped
    SsmSessionManager driver, so one key covers both halves of the exposure.

    Input:
      doc -- a list_documents(Owner=Self) DocumentIdentifier plus '_region'.

    API used (read-only): ssm.describe_document_permission.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not evaluable. Only -1 surfaces as a finding.
    """

    ## AccountIds value that marks a document as shared with every AWS account.
    PUBLIC_ACCOUNT = 'all'

    def __init__(self, doc, ssmClient):
        super().__init__()
        self.doc = doc
        self.ssmClient = ssmClient

        self.name = doc.get('Name', 'unknown')
        self._resourceName = self.name

        self.addII('documentName', self.name)
        self.addII('region', doc.get('_region', 'N/A'))
        self.addII('documentType', doc.get('DocumentType') or 'N/A')
        self.addII('documentVersion', str(doc.get('DocumentVersion') or 'N/A'))

    def _checkSsmDocumentPublic(self):
        accountIds = []
        try:
            ## describe_document_permission has no paginator; follow NextToken.
            kwargs = {'Name': self.name, 'PermissionType': 'Share'}
            while True:
                resp = self.ssmClient.describe_document_permission(**kwargs)
                accountIds.extend(resp.get('AccountIds', []) or [])
                for info in resp.get('AccountSharingInfoList', []) or []:
                    if info.get('AccountId'):
                        accountIds.append(info['AccountId'])
                token = resp.get('NextToken')
                if not token:
                    break
                kwargs['NextToken'] = token
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            self.results['ssmDocumentPublic'] = [
                0, f"Unable to evaluate ({code})"
            ]
            return

        if self.PUBLIC_ACCOUNT in [str(a).lower() for a in accountIds]:
            self.results['ssmDocumentPublic'] = [
                -1,
                f"SSM document '{self.name}' is shared publicly (AccountIds "
                "contains 'all') — any AWS account can read its content and "
                "run it"
            ]
            return

        shared = sorted({a for a in accountIds if a})
        if shared:
            msg = (f"SSM document '{self.name}' is not public; shared with "
                   f"{len(shared)} specific account(s)")
        else:
            msg = f"SSM document '{self.name}' is not shared"
        self.results['ssmDocumentPublic'] = [1, msg]
