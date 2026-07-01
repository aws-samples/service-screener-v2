import json

from services.Evaluator import Evaluator


class SnsCommon(Evaluator):
    """
    All 12 SNS checks.

    Input:
      topic -- dict produced by Sns.py._describeTopic. Keys:
        '_arn', '_name', '_attributes' (raw GetTopicAttributes response body),
        '_tags' (list of {'Key','Value'}), '_subscriptions' (each a dict with
        'Protocol','Endpoint','SubscriptionArn','_attributes').
      snsClient -- boto3 SNS client (kept for future extension).
    """

    AWS_MANAGED_KMS_ALIAS = 'alias/aws/sns'
    DLQ_ELIGIBLE_PROTOCOLS = {'sqs', 'lambda', 'firehose'}
    INSECURE_HTTP_PROTOCOL = 'http'

    # Conditions that legitimately scope a Principal:* statement.
    SCOPING_CONDITION_KEYS = {
        'aws:SourceAccount', 'aws:SourceArn', 'aws:SourceOwner',
        'aws:PrincipalOrgID', 'aws:PrincipalOrgPaths',
        'aws:PrincipalAccount', 'aws:PrincipalArn',
    }

    # Feedback-role attribute names — presence of any indicates delivery-status logging is on.
    DELIVERY_FEEDBACK_KEYS = (
        'HTTPSuccessFeedbackRoleArn', 'HTTPFailureFeedbackRoleArn',
        'SQSSuccessFeedbackRoleArn', 'SQSFailureFeedbackRoleArn',
        'LambdaSuccessFeedbackRoleArn', 'LambdaFailureFeedbackRoleArn',
        'FirehoseSuccessFeedbackRoleArn', 'FirehoseFailureFeedbackRoleArn',
        'ApplicationSuccessFeedbackRoleArn', 'ApplicationFailureFeedbackRoleArn',
    )

    def __init__(self, topic, snsClient):
        super().__init__()
        self.topic = topic
        self.snsClient = snsClient

        self._resourceName = topic.get('_name', 'unknown')
        self.attrs = topic.get('_attributes') or {}
        self.subscriptions = topic.get('_subscriptions') or []
        self._policy = self._parsePolicy(self.attrs.get('Policy'))

        self.addII('topicArn', topic.get('_arn', 'N/A'))
        self.addII('name', self._resourceName)
        self.addII('kmsMasterKeyId', self.attrs.get('KmsMasterKeyId', 'None'))
        self.addII('signatureVersion', self.attrs.get('SignatureVersion', '1'))
        self.addII('tracingConfig', self.attrs.get('TracingConfig', 'PassThrough'))
        self.addII('subscriptionsConfirmed', self.attrs.get('SubscriptionsConfirmed', '0'))
        self.addII('fifoTopic', self.attrs.get('FifoTopic', 'false'))

    # ------------------------------------------------------------------ #
    # 1. Encryption at rest
    # ------------------------------------------------------------------ #
    def _checkSnsEncryptionAtRest(self):
        kmsId = self.attrs.get('KmsMasterKeyId')
        if kmsId:
            self.results['snsEncryptionAtRest'] = [1, f"Encrypted with {kmsId}"]
        else:
            self.results['snsEncryptionAtRest'] = [-1, "No KmsMasterKeyId configured"]

    # ------------------------------------------------------------------ #
    # 2. Encryption not CMK (using default aws/sns key)
    # ------------------------------------------------------------------ #
    def _checkSnsEncryptionNotCMK(self):
        kmsId = self.attrs.get('KmsMasterKeyId')
        if not kmsId:
            # Distinct concern from #1; when unencrypted, this check is not applicable.
            self.results['snsEncryptionNotCMK'] = [
                0, "Topic is unencrypted — see snsEncryptionAtRest"
            ]
            return

        # Match either short-form or full ARN of the AWS-managed alias.
        if self.AWS_MANAGED_KMS_ALIAS in kmsId:
            self.results['snsEncryptionNotCMK'] = [
                -1, f"Using AWS-managed key ({kmsId}); customer-managed CMK preferred"
            ]
        else:
            self.results['snsEncryptionNotCMK'] = [1, f"Customer-managed key: {kmsId}"]

    # ------------------------------------------------------------------ #
    # 3. Public / wildcard-principal access
    # ------------------------------------------------------------------ #
    def _checkSnsPublicAccess(self):
        if self._policy is None:
            self.results['snsPublicAccess'] = [0, "No topic policy present"]
            return

        offending = []
        for i, stmt in enumerate(self._policyStatements()):
            if stmt.get('Effect') != 'Allow':
                continue
            if not self._principalIsWildcard(stmt.get('Principal')):
                continue
            if self._conditionScopes(stmt.get('Condition')):
                continue
            sid = stmt.get('Sid', f"stmt{i}")
            offending.append(sid)

        if offending:
            self.results['snsPublicAccess'] = [
                -1, f"Wildcard-principal Allow without scoping Condition: {', '.join(offending)}"
            ]
        else:
            self.results['snsPublicAccess'] = [1, "No open wildcard-principal Allow statements"]

    # ------------------------------------------------------------------ #
    # 4. HTTPS not enforced by policy
    # ------------------------------------------------------------------ #
    def _checkSnsNoHttpsEnforcement(self):
        if self._policy is None:
            self.results['snsNoHttpsEnforcement'] = [
                -1, "No topic policy — cannot deny non-TLS traffic"
            ]
            return

        if self._policyHasSecureTransportDeny():
            self.results['snsNoHttpsEnforcement'] = [
                1, "Deny statement for aws:SecureTransport=false present"
            ]
        else:
            self.results['snsNoHttpsEnforcement'] = [
                -1, "No Deny statement for non-TLS traffic (aws:SecureTransport=false)"
            ]

    # ------------------------------------------------------------------ #
    # 5. Insecure (HTTP) subscription
    # ------------------------------------------------------------------ #
    def _checkSnsInsecureSubscription(self):
        offending = []
        for s in self.subscriptions:
            if s.get('Protocol') == self.INSECURE_HTTP_PROTOCOL:
                offending.append(s.get('Endpoint', '(unknown endpoint)'))

        if offending:
            self.results['snsInsecureSubscription'] = [
                -1, f"HTTP subscriptions: {', '.join(offending[:5])}"
                + (f" (+{len(offending)-5} more)" if len(offending) > 5 else "")
            ]
        else:
            self.results['snsInsecureSubscription'] = [
                1, "No HTTP subscriptions"
            ]

    # ------------------------------------------------------------------ #
    # 6. Deprecated SignatureVersion
    # ------------------------------------------------------------------ #
    def _checkSnsSignatureVersionOld(self):
        sig = str(self.attrs.get('SignatureVersion', '1'))
        if sig == '1':
            self.results['snsSignatureVersionOld'] = [
                -1, "SignatureVersion=1 (SHA-1, deprecated)"
            ]
        else:
            self.results['snsSignatureVersionOld'] = [
                1, f"SignatureVersion={sig}"
            ]

    # ------------------------------------------------------------------ #
    # 7. Subscription without DLQ
    # ------------------------------------------------------------------ #
    def _checkSnsSubscriptionNoDlq(self):
        eligible = [s for s in self.subscriptions
                    if s.get('Protocol') in self.DLQ_ELIGIBLE_PROTOCOLS]
        if not eligible:
            self.results['snsSubscriptionNoDlq'] = [
                0, "No DLQ-eligible subscriptions (sqs/lambda/firehose)"
            ]
            return

        missing = []
        for s in eligible:
            attrs = s.get('_attributes') or {}
            rp = attrs.get('RedrivePolicy')
            if not rp:
                proto = s.get('Protocol', 'unknown')
                endpoint = s.get('Endpoint', '(no endpoint)')
                missing.append(f"{proto}:{endpoint.split(':')[-1]}")

        if missing:
            self.results['snsSubscriptionNoDlq'] = [
                -1, f"Subscription(s) without DLQ: {', '.join(missing[:5])}"
                + (f" (+{len(missing)-5} more)" if len(missing) > 5 else "")
            ]
        else:
            self.results['snsSubscriptionNoDlq'] = [
                1, f"All {len(eligible)} eligible subscription(s) have DLQ"
            ]

    # ------------------------------------------------------------------ #
    # 8. Subscription in PendingConfirmation
    # ------------------------------------------------------------------ #
    def _checkSnsPendingSubscription(self):
        pending = []
        for s in self.subscriptions:
            arn = s.get('SubscriptionArn', '')
            # SNS returns literal 'PendingConfirmation' as the SubscriptionArn
            # for unconfirmed subs.
            if arn == 'PendingConfirmation':
                proto = s.get('Protocol', 'unknown')
                endpoint = s.get('Endpoint', '(no endpoint)')
                pending.append(f"{proto}:{endpoint}")

        if pending:
            self.results['snsPendingSubscription'] = [
                -1, f"Pending subscription(s): {', '.join(pending[:5])}"
                + (f" (+{len(pending)-5} more)" if len(pending) > 5 else "")
            ]
        else:
            self.results['snsPendingSubscription'] = [
                1, "No pending subscriptions"
            ]

    # ------------------------------------------------------------------ #
    # 9. Delivery-status logging disabled
    # ------------------------------------------------------------------ #
    def _checkSnsDeliveryStatusLoggingDisabled(self):
        configured = [k for k in self.DELIVERY_FEEDBACK_KEYS if self.attrs.get(k)]
        if configured:
            self.results['snsDeliveryStatusLoggingDisabled'] = [
                1, f"Delivery-status logging configured: {len(configured)} role(s)"
            ]
        else:
            self.results['snsDeliveryStatusLoggingDisabled'] = [
                -1, "No delivery-status feedback role configured for any protocol"
            ]

    # ------------------------------------------------------------------ #
    # 10. X-Ray tracing disabled
    # ------------------------------------------------------------------ #
    def _checkSnsTracingDisabled(self):
        tracing = self.attrs.get('TracingConfig', 'PassThrough')
        if tracing == 'Active':
            self.results['snsTracingDisabled'] = [1, "TracingConfig=Active"]
        else:
            self.results['snsTracingDisabled'] = [
                -1, f"TracingConfig={tracing} (should be Active)"
            ]

    # ------------------------------------------------------------------ #
    # 11. Unused topic (0 confirmed subscriptions)
    # ------------------------------------------------------------------ #
    def _checkSnsUnusedTopic(self):
        try:
            confirmed = int(self.attrs.get('SubscriptionsConfirmed', '0'))
        except (TypeError, ValueError):
            confirmed = 0
        if confirmed == 0:
            self.results['snsUnusedTopic'] = [
                -1, "SubscriptionsConfirmed=0 — topic has no subscribers"
            ]
        else:
            self.results['snsUnusedTopic'] = [
                1, f"{confirmed} confirmed subscription(s)"
            ]

    # ------------------------------------------------------------------ #
    # 12. No tags
    # ------------------------------------------------------------------ #
    def _checkSnsResourcesWithoutTags(self):
        tags = self.topic.get('_tags') or []
        if not tags:
            self.results['snsResourcesWithoutTags'] = [-1, "No tags applied"]
        else:
            keys = [t.get('Key') for t in tags if t.get('Key')]
            self.results['snsResourcesWithoutTags'] = [
                1, f"{len(keys)} tag(s): {', '.join(keys[:5])}"
            ]

    # ------------------------------------------------------------------ #
    # Policy parsing helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parsePolicy(raw):
        if not raw:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def _policyStatements(self):
        if self._policy is None:
            return []
        stmts = self._policy.get('Statement', [])
        if isinstance(stmts, dict):
            return [stmts]
        return stmts if isinstance(stmts, list) else []

    @staticmethod
    def _principalIsWildcard(principal):
        """Return True if the Principal grants access to '*' (any AWS identity)."""
        if principal is None:
            return False
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == '*':
                    return True
                if isinstance(v, list) and '*' in v:
                    return True
        return False

    def _conditionScopes(self, condition):
        """Return True if the Condition block contains any recognised scoping key."""
        if not condition or not isinstance(condition, dict):
            return False
        for op_block in condition.values():
            if not isinstance(op_block, dict):
                continue
            for key in op_block.keys():
                if key in self.SCOPING_CONDITION_KEYS:
                    return True
        return False

    def _policyHasSecureTransportDeny(self):
        """Look for the standard pattern: Effect=Deny AND aws:SecureTransport=false."""
        for stmt in self._policyStatements():
            if stmt.get('Effect') != 'Deny':
                continue
            cond = stmt.get('Condition') or {}
            for op, op_block in cond.items():
                if not isinstance(op_block, dict):
                    continue
                val = op_block.get('aws:SecureTransport')
                if val is None:
                    continue
                # Normalize to a list of stringified values
                if isinstance(val, list):
                    vals = [str(v).lower() for v in val]
                else:
                    vals = [str(val).lower()]
                if 'false' in vals:
                    return True
        return False
