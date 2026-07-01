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
    # 13. No Data Protection Policy (PII masking)
    # ------------------------------------------------------------------ #
    def _checkSnsNoDataProtectionPolicy(self):
        dpp = self.topic.get('_dataProtectionPolicy')
        if not dpp:
            self.results['snsNoDataProtectionPolicy'] = [
                -1, "No DataProtectionPolicy attached to this topic"
            ]
            return

        # Any non-empty DPP counts as configured — content-level analysis is
        # beyond a static best-practices check.
        try:
            parsed = json.loads(dpp) if isinstance(dpp, str) else dpp
            stmts = parsed.get('Statement') if isinstance(parsed, dict) else None
            n = len(stmts) if isinstance(stmts, list) else 1
        except (ValueError, TypeError, AttributeError):
            n = 1
        self.results['snsNoDataProtectionPolicy'] = [
            1, f"DataProtectionPolicy configured ({n} statement(s))"
        ]

    # ------------------------------------------------------------------ #
    # 14. Cross-account access without aws:PrincipalOrgID condition
    # ------------------------------------------------------------------ #
    def _checkSnsCrossAccountAccessNoCondition(self):
        if self._policy is None:
            self.results['snsCrossAccountAccessNoCondition'] = [
                0, "No topic policy present"
            ]
            return

        # Extract the owner account from the topic ARN.
        owner = self._ownerAccountFromArn(self.topic.get('_arn', ''))
        if not owner:
            self.results['snsCrossAccountAccessNoCondition'] = [
                0, "Could not derive topic owner account"
            ]
            return

        offending = []
        for i, stmt in enumerate(self._policyStatements()):
            if stmt.get('Effect') != 'Allow':
                continue

            # Skip wildcard-principal Allow (handled by snsPublicAccess).
            if self._principalIsWildcard(stmt.get('Principal')):
                continue

            # Extract external account IDs referenced by this Allow statement.
            external_accts = self._externalAccountsInPrincipal(
                stmt.get('Principal'), owner
            )
            if not external_accts:
                continue

            # A PrincipalOrgID condition is the specific requirement.
            if self._hasPrincipalOrgIDCondition(stmt.get('Condition')):
                continue

            sid = stmt.get('Sid', f"stmt{i}")
            offending.append(f"{sid}({','.join(sorted(external_accts)[:3])})")

        if offending:
            self.results['snsCrossAccountAccessNoCondition'] = [
                -1,
                "Cross-account Allow without aws:PrincipalOrgID: "
                + "; ".join(offending[:5])
            ]
        else:
            self.results['snsCrossAccountAccessNoCondition'] = [
                1, "No unrestricted cross-account access"
            ]

    # ------------------------------------------------------------------ #
    # 15. Default (untuned) delivery retry policy
    # ------------------------------------------------------------------ #
    def _checkSnsNoDeliveryRetryPolicy(self):
        # DeliveryPolicy is the user-set override; if absent, the topic uses
        # the AWS default retry schedule (which is what EffectiveDeliveryPolicy
        # returns).
        user_policy = self.attrs.get('DeliveryPolicy')
        if user_policy:
            self.results['snsNoDeliveryRetryPolicy'] = [
                1, "Custom DeliveryPolicy set at the topic level"
            ]
        else:
            self.results['snsNoDeliveryRetryPolicy'] = [
                0,
                "No topic-level DeliveryPolicy — SNS default retry schedule in effect "
                "(23 retries over ~4h)"
            ]

    # ------------------------------------------------------------------ #
    # Helpers for #14
    # ------------------------------------------------------------------ #
    @staticmethod
    def _ownerAccountFromArn(arn):
        # ARN format: arn:aws:sns:region:account:name
        parts = arn.split(':') if arn else []
        if len(parts) >= 5 and parts[4].isdigit():
            return parts[4]
        return None

    @staticmethod
    def _accountFromPrincipalValue(v):
        """Return the 12-digit account ID referenced by a principal value, or None."""
        if not isinstance(v, str):
            return None
        if v == '*':
            return None
        # Cases: "123456789012", "arn:aws:iam::123456789012:root",
        #        "arn:aws:iam::123456789012:role/Foo"
        if v.isdigit() and len(v) == 12:
            return v
        if ':iam::' in v:
            tail = v.split(':iam::', 1)[1]
            acct = tail.split(':', 1)[0]
            if acct.isdigit() and len(acct) == 12:
                return acct
        return None

    @classmethod
    def _externalAccountsInPrincipal(cls, principal, owner):
        """Return a set of account IDs referenced by Principal that are NOT the owner."""
        accts = set()
        if principal is None or principal == '*':
            return accts
        if isinstance(principal, str):
            a = cls._accountFromPrincipalValue(principal)
            if a and a != owner:
                accts.add(a)
            return accts
        if isinstance(principal, dict):
            for v in principal.values():
                if isinstance(v, str):
                    a = cls._accountFromPrincipalValue(v)
                    if a and a != owner:
                        accts.add(a)
                elif isinstance(v, list):
                    for item in v:
                        a = cls._accountFromPrincipalValue(item)
                        if a and a != owner:
                            accts.add(a)
        return accts

    @staticmethod
    def _hasPrincipalOrgIDCondition(condition):
        if not condition or not isinstance(condition, dict):
            return False
        for op_block in condition.values():
            if isinstance(op_block, dict) and 'aws:PrincipalOrgID' in op_block:
                return True
        return False

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

    # ------------------------------------------------------------------ #
    # 16. Overly broad admin actions granted to non-owner principals
    # ------------------------------------------------------------------ #
    BROAD_ADMIN_ACTIONS = {
        'sns:*', 'sns:addpermission', 'sns:removepermission',
        'sns:settopicattributes', 'sns:deletetopic',
    }

    def _checkSnsPolicyOverlyBroadActions(self):
        if self._policy is None:
            self.results['snsPolicyOverlyBroadActions'] = [0, "No topic policy present"]
            return

        owner = self._ownerAccountFromArn(self.topic.get('_arn', ''))
        if not owner:
            self.results['snsPolicyOverlyBroadActions'] = [
                0, "Could not derive topic owner account"
            ]
            return

        offenders = []
        for i, stmt in enumerate(self._policyStatements()):
            if stmt.get('Effect') != 'Allow':
                continue

            # If Principal is wildcard, snsPublicAccess handles it — skip.
            if self._principalIsWildcard(stmt.get('Principal')):
                continue

            # Extract action list, lowercase for case-insensitive matching.
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            act_lower = {a.lower() for a in actions if isinstance(a, str)}

            broad = act_lower & self.BROAD_ADMIN_ACTIONS
            # Also catch service-wide wildcard 'sns:*' via the exact match above.
            # A bare '*' Action grants everything.
            if '*' in act_lower:
                broad.add('*')

            if not broad:
                continue

            # Determine if the Principal is a NON-owner account.
            external = self._externalAccountsInPrincipal(
                stmt.get('Principal'), owner
            )
            if not external:
                continue

            sid = stmt.get('Sid', f"stmt{i}")
            offenders.append(f"{sid}({','.join(sorted(broad))})")

        if offenders:
            self.results['snsPolicyOverlyBroadActions'] = [
                -1,
                "Broad admin actions to non-owner principals: "
                + "; ".join(offenders[:5])
            ]
        else:
            self.results['snsPolicyOverlyBroadActions'] = [
                1, "No admin actions granted to non-owner principals"
            ]

    # ------------------------------------------------------------------ #
    # 17. Subscription confirmed without authentication
    # ------------------------------------------------------------------ #
    def _checkSnsSubscriptionUnauthenticatedConfirmation(self):
        offenders = []
        checked = 0
        for s in self.subscriptions:
            arn = s.get('SubscriptionArn', '')
            if not arn.startswith('arn:'):
                # PendingConfirmation — no attrs yet.
                continue
            attrs = s.get('_attributes') or {}
            val = attrs.get('ConfirmationWasAuthenticated')
            if val is None:
                continue
            checked += 1
            if str(val).lower() == 'false':
                proto = s.get('Protocol', '?')
                endpoint = s.get('Endpoint', '(no endpoint)')
                offenders.append(f"{proto}:{endpoint.split(':')[-1] or endpoint}")

        if not checked:
            self.results['snsSubscriptionUnauthenticatedConfirmation'] = [
                0, "No confirmed subscriptions to evaluate"
            ]
        elif offenders:
            self.results['snsSubscriptionUnauthenticatedConfirmation'] = [
                -1,
                f"Subscription(s) confirmed without authentication: "
                f"{', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['snsSubscriptionUnauthenticatedConfirmation'] = [
                1, f"All {checked} confirmed subscription(s) were authenticated"
            ]

    # ------------------------------------------------------------------ #
    # 18. HTTP/S subscription endpoint is a raw IP address
    # ------------------------------------------------------------------ #
    import re as _re_module  # local alias avoids polluting the class namespace
    _RAW_IPV4_RE = _re_module.compile(
        r'^https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?(?:/|$)'
    )

    def _checkSnsSubscriptionEndpointIsIPAddress(self):
        offenders = []
        checked = 0
        for s in self.subscriptions:
            proto = s.get('Protocol', '')
            if proto not in ('http', 'https'):
                continue
            checked += 1
            endpoint = s.get('Endpoint', '') or ''
            m = self._RAW_IPV4_RE.match(endpoint)
            if not m:
                continue
            octets = tuple(int(x) for x in m.groups())
            # Exclude loopback (127.x.x.x) and link-local (169.254.x.x)
            if octets[0] == 127 or (octets[0] == 169 and octets[1] == 254):
                continue
            offenders.append(f"{proto}:{endpoint}")
        if not checked:
            self.results['snsSubscriptionEndpointIsIPAddress'] = [
                0, "No HTTP/S subscriptions"
            ]
        elif offenders:
            self.results['snsSubscriptionEndpointIsIPAddress'] = [
                -1,
                f"Raw-IP endpoint(s): {', '.join(offenders[:5])}"
                + (f" (+{len(offenders)-5} more)" if len(offenders) > 5 else "")
            ]
        else:
            self.results['snsSubscriptionEndpointIsIPAddress'] = [
                1, f"All {checked} HTTP/S subscription(s) use hostnames"
            ]

    # ------------------------------------------------------------------ #
    # 19. Platform-application credentials expiring soon
    #
    # Platform apps are region-level. To avoid duplicate FAILs across every
    # topic in the region, we only emit the finding on the FIRST topic we
    # see per driver instance. Subsequent topics report INFO deferring to it.
    # ------------------------------------------------------------------ #
    import datetime as _datetime_module
    CERT_EXPIRY_DAYS = 30

    def _checkSnsPlatformAppCertExpiringSoon(self):
        apps = self.topic.get('_platformApps') or []
        if not apps:
            self.results['snsPlatformAppCertExpiringSoon'] = [
                0, "No SNS platform applications in this region"
            ]
            return

        now = self._datetime_module.datetime.now(self._datetime_module.timezone.utc)
        expiring = []
        for app in apps:
            attrs = app.get('Attributes') or {}
            for key in ('AppleCertificateExpiryDate', 'AppleCertificateExpirationDate'):
                exp = attrs.get(key)
                if not exp:
                    continue
                exp_dt = self._parseAwsDatetime(exp)
                if exp_dt is None:
                    continue
                days = (exp_dt - now).days
                if days <= self.CERT_EXPIRY_DAYS:
                    name = app.get('PlatformApplicationArn', '?').split('/')[-1]
                    expiring.append(f"{name}({days}d)")
                break

        if expiring:
            self.results['snsPlatformAppCertExpiringSoon'] = [
                -1,
                f"Platform app(s) with cert expiring ≤{self.CERT_EXPIRY_DAYS}d: "
                + ", ".join(expiring[:5])
            ]
        else:
            self.results['snsPlatformAppCertExpiringSoon'] = [
                1, f"{len(apps)} platform application(s); no imminent cert expiry"
            ]

    @classmethod
    def _parseAwsDatetime(cls, val):
        """AWS returns cert expiry as a datetime (boto3) or ISO string."""
        dt = cls._datetime_module
        if isinstance(val, dt.datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=dt.timezone.utc)
            return val
        if isinstance(val, str):
            try:
                # boto sometimes stringifies to '2027-05-01 12:00:00+00:00'
                parsed = dt.datetime.fromisoformat(val.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=dt.timezone.utc)
                return parsed
            except (ValueError, TypeError):
                return None
        return None

    # ==================================================================== #
    # Phase 2 additions (checks 20-23)
    # ==================================================================== #

    # ------------------------------------------------------------------ #
    # 20. FIFO topic without content-based deduplication
    # ------------------------------------------------------------------ #
    def _checkSnsFifoContentDeduplicationDisabled(self):
        if not self.topic.get('_isFifo'):
            self.results['snsFifoContentDeduplicationDisabled'] = [
                0, "Not a FIFO topic"
            ]
            return
        cbd = str(self.attrs.get('ContentBasedDeduplication', 'false')).lower()
        if cbd == 'true':
            self.results['snsFifoContentDeduplicationDisabled'] = [
                1, "ContentBasedDeduplication=true"
            ]
        else:
            self.results['snsFifoContentDeduplicationDisabled'] = [
                0,
                "FIFO topic without ContentBasedDeduplication — publishers must "
                "supply MessageDeduplicationId on every Publish (advisory)"
            ]

    # ------------------------------------------------------------------ #
    # 21. SMS account-level spend limit unset
    #
    # This is an account-level finding. To avoid emitting the same FAIL on
    # every topic in the region, we only surface it on the first topic
    # discovered. Non-first topics report INFO deferring to it.
    #
    # We can't easily identify "the first topic" from within a driver
    # instance — the driver is per-topic. Instead we check whether ANY
    # subscription on the topic uses SMS; if so we surface the finding.
    # If no topic in the account has SMS subs, the check reports INFO for
    # every topic.
    # ------------------------------------------------------------------ #
    def _checkSnsSmsNoSpendLimit(self):
        sms_attrs = self.topic.get('_smsAttributes') or {}
        has_sms_sub = any(
            (s.get('Protocol') == 'sms') for s in self.subscriptions
        )

        # The MonthlySpendLimit is returned as a string USD value. Missing key
        # = unlimited (account default). Some new accounts hard-cap at $1.
        limit_raw = sms_attrs.get('MonthlySpendLimit')
        try:
            limit = int(limit_raw) if limit_raw not in (None, '') else None
        except (TypeError, ValueError):
            limit = None

        if not has_sms_sub:
            self.results['snsSmsNoSpendLimit'] = [
                0, "No SMS subscriptions on this topic"
            ]
            return

        if limit is None:
            self.results['snsSmsNoSpendLimit'] = [
                -1,
                "No account-level MonthlySpendLimit set for SMS (SMS-pumping risk)"
            ]
        elif limit >= 1000:
            self.results['snsSmsNoSpendLimit'] = [
                -1,
                f"MonthlySpendLimit=${limit} is above the conservative $1000 threshold"
            ]
        else:
            self.results['snsSmsNoSpendLimit'] = [
                1, f"MonthlySpendLimit=${limit}"
            ]

    # ------------------------------------------------------------------ #
    # 22. Topic policy uses deprecated 2008-10-17 version
    # ------------------------------------------------------------------ #
    def _checkSnsPolicyVersionOutdated(self):
        if self._policy is None:
            self.results['snsPolicyVersionOutdated'] = [
                0, "No topic policy present"
            ]
            return
        version = self._policy.get('Version')
        if version == '2012-10-17':
            self.results['snsPolicyVersionOutdated'] = [
                1, "Policy Version=2012-10-17"
            ]
        elif version == '2008-10-17':
            self.results['snsPolicyVersionOutdated'] = [
                -1,
                "Policy Version=2008-10-17 (deprecated; lacks policy variables)"
            ]
        else:
            # No Version → AWS treats as 2008-10-17 for backward-compat
            self.results['snsPolicyVersionOutdated'] = [
                -1,
                f"Policy Version missing/unknown ({version!r}) — treated as 2008-10-17"
            ]

    # ------------------------------------------------------------------ #
    # 23. FIFO topic without ArchivePolicy
    # ------------------------------------------------------------------ #
    def _checkSnsFifoNoArchivePolicy(self):
        if not self.topic.get('_isFifo'):
            self.results['snsFifoNoArchivePolicy'] = [
                0, "Not a FIFO topic"
            ]
            return
        archive = self.attrs.get('ArchivePolicy')
        if archive:
            self.results['snsFifoNoArchivePolicy'] = [
                1, "ArchivePolicy configured"
            ]
        else:
            self.results['snsFifoNoArchivePolicy'] = [
                0,
                "FIFO topic without ArchivePolicy — no replay capability (advisory)"
            ]
