import functools
import re

from services.Evaluator import Evaluator


class CognitoIdentityPool(Evaluator):
    """
    Checks for Amazon Cognito identity pools (Cognito Federated Identities).

    Input:
      pool -- output of cognito-identity DescribeIdentityPool with injected fields:
              pool['_roles']             -- GetIdentityPoolRoles response
                                            ({'Roles': {...}, 'RoleMappings': {...}}),
                                            or None when it could not be read
              pool['_rolesError']        -- error code when GetIdentityPoolRoles failed
              pool['_principalTagMaps']  -- {providerName: {'UseDefaults', 'PrincipalTags'}
                                            | None (not configured)
                                            | {'_error': code}}
              pool['_unauthRole']        -- role evaluation data for the
                                            unauthenticated role (see
                                            Cognito._fetchRoleEvaluation), or None
                                            when no unauthenticated role is set.
              pool['_resourceName']      -- unique display id (name + id)
              pool['_describeError']     -- error code when DescribeIdentityPool failed
    """

    # AWS managed policies that grant broad access by name (admin, and the
    # account-wide read / view job-function policies: anonymous read of every
    # service's data or configuration).
    BROAD_MANAGED_POLICY_NAMES = ('AdministratorAccess', 'PowerUserAccess', 'ReadOnlyAccess',
                                  'ViewOnlyAccess', 'SecurityAudit')

    def __init__(self, pool):
        super().__init__()
        self.pool = pool
        self._resourceName = pool.get('_resourceName') or pool.get('IdentityPoolId') or 'unknown'

        self.addII('name', pool.get('IdentityPoolName', 'N/A'))
        self.addII('identityPoolId', pool.get('IdentityPoolId', 'N/A'))
        self.addII('allowUnauthenticatedIdentities', bool(pool.get('AllowUnauthenticatedIdentities')))
        self.addII('allowClassicFlow', bool(pool.get('AllowClassicFlow')))
        self.addII('loginProviderCount', len(self.loginProviders(pool)))

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def loginProviders(pool):
        """Return the distinct identity-provider names configured on the pool
        (the names used by principal tag maps).

        Several app clients of one Cognito user pool share one ProviderName
        and are one sign-in source (one user directory), so they are counted
        once."""
        out = []
        for p in pool.get('CognitoIdentityProviders') or []:
            name = p.get('ProviderName')
            if name:
                out.append(name)
        out.extend((pool.get('SupportedLoginProviders') or {}).keys())
        out.extend(pool.get('OpenIdConnectProviderARNs') or [])
        out.extend(pool.get('SamlProviderARNs') or [])
        if pool.get('DeveloperProviderName'):
            out.append(pool['DeveloperProviderName'])
        seen, uniq = set(), []
        for n in out:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        return uniq

    @staticmethod
    def userPoolClientProviders(pool):
        """{providerName: ['<providerName>:<clientId>', ...]} for Cognito user
        pool providers - the client-qualified form used as role-mapping keys,
        tried as an alternative name for principal tag maps."""
        out = {}
        for p in pool.get('CognitoIdentityProviders') or []:
            name, cid = p.get('ProviderName'), p.get('ClientId')
            if name and cid:
                out.setdefault(name, [])
                q = f"{name}:{cid}"
                if q not in out[name]:
                    out[name].append(q)
        return out

    @staticmethod
    def _asList(v):
        if v is None:
            return []
        return v if isinstance(v, list) else [v]

    # Policy variables that make a resource / condition specific to the caller's
    # own Cognito identity (the documented per-identity least-privilege pattern).
    IDENTITY_VARS = ('${cognito-identity.amazonaws.com:sub}',)

    @classmethod
    def _mentionsIdentityVar(cls, value):
        if isinstance(value, str):
            return any(v in value for v in cls.IDENTITY_VARS)
        if isinstance(value, dict):
            return any(cls._mentionsIdentityVar(v) for v in value.values())
        if isinstance(value, list):
            return any(cls._mentionsIdentityVar(v) for v in value)
        return False

    # Condition keys that confine a request to the caller's own data when their
    # value is the caller's identity id (documented per-identity patterns).
    PER_IDENTITY_KEYS = ('dynamodb:leadingkeys', 's3:prefix')

    @classmethod
    def _conditionKeyedOnIdentity(cls, cond):
        """True when the Condition confines the caller to its own identity: a
        positive string match (StringEquals / StringLike / StringEqualsIgnoreCase,
        plain or ForAnyValue:) on a known per-identity key (dynamodb:LeadingKeys,
        s3:prefix) whose every value is ${cognito-identity.amazonaws.com:sub}-based.

        - Negated (StringNot*) and ...IfExists operators do not confine the caller.
        - dynamodb:LeadingKeys is multivalued: only ForAllValues: (with Null
          {key: 'false'}) confines the caller; plain and ForAnyValue: do not.
        - ForAllValues: evaluates to true when the key is absent from the request
          (e.g. dynamodb:DeleteTable / Scan carry no LeadingKeys), so it only
          counts when the same Condition also has Null {key: 'false'}.
        - Other keys (e.g. cognito-identity.amazonaws.com:sub itself, or keys the
          caller controls) are not accepted."""
        if not isinstance(cond, dict):
            return False
        nullFalse = set()
        for op, kv in cond.items():
            if str(op).lower() == 'null' and isinstance(kv, dict):
                for k, v in kv.items():
                    vals = cls._asList(v)
                    if vals and all(str(x).lower() == 'false' for x in vals):
                        nullFalse.add(str(k).lower())
        for op, kv in cond.items():
            if not isinstance(kv, dict):
                continue
            parts = str(op).split(':')
            if len(parts) > 2:
                continue
            qualifier = parts[0].lower() if len(parts) == 2 else ''
            base = parts[-1]
            if base not in ('StringEquals', 'StringLike', 'StringEqualsIgnoreCase'):
                continue
            if qualifier not in ('', 'foranyvalue', 'forallvalues'):
                continue
            for k, v in kv.items():
                key = str(k).lower()
                if key not in cls.PER_IDENTITY_KEYS:
                    continue
                if qualifier == 'forallvalues' and key not in nullFalse:
                    continue
                # dynamodb:LeadingKeys is multivalued (BatchGetItem/BatchWriteItem
                # carry several partition keys). Only ForAllValues + Null false
                # confines every key to the caller; a plain or ForAnyValue match
                # passes when just one key is the caller's own.
                if key == 'dynamodb:leadingkeys' and qualifier != 'forallvalues':
                    continue
                vals = cls._asList(v)
                if vals and all(isinstance(x, str) and cls._mentionsIdentityVar(x) for x in vals):
                    return True
        return False

    # (service, resource type) pairs whose ARN resource part '<type>/*' or
    # '<type>:*' names EVERY resource of that type in the account (e.g.
    # arn:aws:dynamodb:*:*:table/*). Restricted to known types: in other ARNs
    # (s3 'bucket/*', execute-api 'apiId/*') the first segment is a resource
    # name, and '<name>/*' is one shared resource, not all of them.
    ALL_OF_TYPE = {
        'dynamodb': ('table',), 'secretsmanager': ('secret',), 'lambda': ('function',),
        'kms': ('key', 'alias'), 'ssm': ('parameter', 'document'), 'kinesis': ('stream',),
        'firehose': ('deliverystream',), 'logs': ('log-group',),
        'iot': ('topic', 'topicfilter', 'client', 'thing'), 'appsync': ('apis',),
        'ecr': ('repository',), 'cognito-idp': ('userpool',), 'cognito-identity': ('identitypool',),
        'cognito-sync': ('identitypool',), 'states': ('statemachine', 'stateMachine'),
        'es': ('domain',), 'ec2': ('instance',), 'rekognition': ('collection',),
        'events': ('event-bus',), 'mobiletargeting': ('apps',), 'rds-db': ('dbuser',),
        'bedrock': ('knowledge-base', 'agent-alias', 'foundation-model'),
        'elasticfilesystem': ('file-system',),
    }

    @classmethod
    def _isUnscopedResource(cls, r):
        """'*', an ARN whose resource part is only '*' (e.g. arn:aws:s3:::*), or
        an ARN naming every resource of a known type (e.g. table/*, secret:*)."""
        if not isinstance(r, str):
            return True
        r = r.strip()
        if r == '*':
            return True
        parts = r.split(':', 5)
        if len(parts) != 6:
            return False
        if parts[5] in ('*', '*/*'):
            return True
        svc = parts[2].lower()
        for t in cls.ALL_OF_TYPE.get(svc, ()):
            for sep in ('/', ':'):
                head = t + sep
                if parts[5].startswith(head) and parts[5][len(head):] and \
                        set(parts[5][len(head):]) <= {'*', '/', ':'}:
                    return True
        return False

    @classmethod
    def resourceScope(cls, stmt):
        """'unscoped'    -- Resource '*' (or equivalent), NotResource, or no Resource
           'perIdentity' -- every Resource (or a Condition) is keyed on the caller's
                            ${cognito-identity.amazonaws.com:sub}
           'shared'      -- specific resources shared by every identity"""
        if 'NotResource' in stmt:
            return 'unscoped'
        res = cls._asList(stmt.get('Resource'))
        if not res or any(cls._isUnscopedResource(r) for r in res):
            ## A condition keyed on the identity still confines the caller to its own data
            ## (e.g. dynamodb:LeadingKeys = ${cognito-identity.amazonaws.com:sub}).
            if cls._conditionKeyedOnIdentity(stmt.get('Condition')):
                return 'perIdentity'
            return 'unscoped'
        if all(cls._mentionsIdentityVar(r) for r in res) or cls._conditionKeyedOnIdentity(stmt.get('Condition')):
            return 'perIdentity'
        return 'shared'

    @staticmethod
    def _isServiceWildcard(a):
        """'*', '<svc>:*' (or ':**'), or a colon-less glob such as 's3*' (IAM
        globbing matches every action of the service)."""
        if not isinstance(a, str):
            return False
        s = a.strip()
        if not s:
            return False
        if ':' not in s:
            return s.endswith('*')
        if s.count(':') != 1:
            return False
        name = s.split(':', 1)[1]
        return bool(name) and set(name) == {'*'}

    @staticmethod
    def _actionService(a):
        """Lower-cased service prefix of a wildcard action, or None for an
        all-services pattern ('*', '*:*')."""
        s = a.strip().lower()
        svc = (s.split(':', 1)[0] if ':' in s else s).rstrip('*')
        return svc or None

    @classmethod
    def denyLimits(cls, docs):
        """Collect unconditional Deny statements on Resource '*' across a role's policies.

        Returns {'all': bool, 'services': {svc}, 'notActionCaps': [[action, ...], ...],
                 'denied': [pattern, ...]}:
          all            -- Deny Action '*' (nothing is allowed)
          services       -- Deny '<svc>:*' (that service is not allowed)
          notActionCaps  -- Deny NotAction [...]: only those actions remain allowed
          denied         -- every denied Action pattern (lower-cased)
        Conditional or resource-scoped Deny statements are ignored (conservative)."""
        out = {'all': False, 'services': set(), 'notActionCaps': [], 'denied': []}
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            for stmt in cls._asList(doc.get('Statement')):
                if not isinstance(stmt, dict) or stmt.get('Effect') != 'Deny':
                    continue
                if stmt.get('Condition') or 'NotResource' in stmt:
                    continue
                if not any(r == '*' for r in cls._asList(stmt.get('Resource'))):
                    continue
                if 'NotAction' in stmt:
                    out['notActionCaps'].append([a for a in cls._asList(stmt['NotAction']) if isinstance(a, str)])
                    continue
                for a in cls._asList(stmt.get('Action')):
                    if not isinstance(a, str):
                        continue
                    a = a.strip().lower()
                    out['denied'].append(a)
                    if a == '*':
                        out['all'] = True
                    elif a.endswith(':*') and a.count(':') == 1:
                        out['services'].add(a[:-2])
        return out

    @classmethod
    def _stillBroad(cls, action, limits):
        """Is an allowed wildcard ('*', '<svc>:*' or a NotAction allow, given as '*')
        still a wildcard after the role's unconditional Deny statements?"""
        if limits['all']:
            return False
        svc = cls._actionService(action)
        if svc and svc in limits['services']:
            return False
        for cap in limits['notActionCaps']:
            ## Only actions listed in the Deny NotAction stay allowed.
            keep = []
            for c in cap:
                if not cls._isServiceWildcard(c):
                    continue
                cs = cls._actionService(c)
                if cs is None or ((svc is None or cs == svc) and cs not in limits['services']):
                    keep.append(c)
            if not keep:
                return False
        return True

    # Concrete actions that, granted to anonymous callers on every resource of
    # their type, read or change customer data, run code, send on the account's
    # behalf, or escalate privileges. A granted action or partial wildcard
    # (e.g. 's3:Get*') that matches any of these on all resources is broad.
    SENSITIVE_ACTIONS = {a.lower(): a for a in (
        # S3 object data and bucket control
        's3:GetObject', 's3:GetObjectVersion', 's3:GetObjectAcl', 's3:ListBucket', 's3:ListBucketVersions',
        's3:PutObject', 's3:PutObjectAcl', 's3:DeleteObject', 's3:DeleteObjectVersion', 's3:RestoreObject',
        's3:PutBucketPolicy', 's3:PutBucketAcl', 's3:DeleteBucket', 's3:DeleteBucketPolicy',
        's3-object-lambda:GetObject', 's3-object-lambda:ListBucket', 's3-object-lambda:PutObject',
        # DynamoDB item data and tables
        'dynamodb:GetItem', 'dynamodb:BatchGetItem', 'dynamodb:Query', 'dynamodb:Scan',
        'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:BatchWriteItem',
        'dynamodb:PartiQLSelect', 'dynamodb:PartiQLInsert', 'dynamodb:PartiQLUpdate', 'dynamodb:PartiQLDelete',
        'dynamodb:TransactGetItems', 'dynamodb:TransactWriteItems', 'dynamodb:DeleteTable',
        'dynamodb:UpdateTable', 'dynamodb:ExportTableToPointInTime', 'dynamodb:GetRecords',
        # Secrets, parameters, keys
        'secretsmanager:GetSecretValue', 'secretsmanager:BatchGetSecretValue', 'secretsmanager:PutSecretValue',
        'secretsmanager:UpdateSecret', 'secretsmanager:DeleteSecret', 'secretsmanager:PutResourcePolicy',
        'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath', 'ssm:GetParameterHistory',
        'ssm:PutParameter', 'ssm:DeleteParameter', 'ssm:SendCommand', 'ssm:StartSession',
        'kms:Decrypt', 'kms:GenerateDataKey', 'kms:Sign', 'kms:CreateGrant', 'kms:PutKeyPolicy',
        'kms:ScheduleKeyDeletion', 'kms:DisableKey',
        # Code execution and messaging on the account's behalf
        'lambda:InvokeFunction', 'lambda:InvokeFunctionUrl', 'lambda:GetFunction', 'lambda:UpdateFunctionCode',
        'lambda:UpdateFunctionConfiguration', 'lambda:AddPermission', 'lambda:CreateFunction',
        'lambda:DeleteFunction',
        'states:StartExecution', 'states:StartSyncExecution',
        'sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:PurgeQueue',
        'sqs:SetQueueAttributes', 'sqs:DeleteQueue',
        'sns:Publish', 'sns:Subscribe', 'sns:SetTopicAttributes', 'sns:DeleteTopic',
        'ses:SendEmail', 'ses:SendRawEmail', 'ses:SendTemplatedEmail', 'ses:SendBulkTemplatedEmail',
        'ses:SendBulkEmail',
        'mobiletargeting:SendMessages', 'mobiletargeting:SendUsersMessages', 'mobiletargeting:GetEndpoint',
        'mobiletargeting:GetUserEndpoints', 'mobiletargeting:DeleteEndpoint',
        'events:PutEvents', 'execute-api:Invoke', 'execute-api:ManageConnections', 'appsync:GraphQL',
        # Streams and logs
        'kinesis:GetRecords', 'kinesis:GetShardIterator', 'kinesis:PutRecord', 'kinesis:PutRecords',
        'kinesis:DeleteStream', 'firehose:PutRecord', 'firehose:PutRecordBatch',
        'kinesisvideo:GetMedia', 'kinesisvideo:GetClip',
        'logs:GetLogEvents', 'logs:FilterLogEvents', 'logs:StartQuery', 'logs:PutLogEvents',
        'logs:DeleteLogGroup',
        'iot:Publish', 'iot:Subscribe', 'iot:Receive', 'iot:GetThingShadow', 'iot:UpdateThingShadow',
        'iot:DeleteThingShadow', 'iot:GetRetainedMessage',
        # Databases, search, files, repositories, models
        'rds-db:connect', 'rds-data:ExecuteStatement', 'rds-data:BatchExecuteStatement',
        'redshift-data:ExecuteStatement', 'athena:StartQueryExecution', 'athena:GetQueryResults',
        'es:ESHttpGet', 'es:ESHttpPost', 'es:ESHttpPut', 'es:ESHttpDelete', 'aoss:APIAccessAll',
        'elasticfilesystem:ClientMount', 'elasticfilesystem:ClientWrite', 'elasticfilesystem:ClientRootAccess',
        'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage', 'ecr:PutImage',
        'codecommit:GitPull', 'codecommit:GitPush', 'codecommit:GetFile', 'codecommit:GetBlob',
        'rekognition:SearchFaces', 'rekognition:SearchFacesByImage', 'rekognition:IndexFaces',
        'rekognition:ListFaces', 'rekognition:DeleteFaces', 'rekognition:DeleteCollection',
        'polly:PutLexicon', 'polly:DeleteLexicon',
        'bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream', 'bedrock:InvokeAgent',
        'bedrock:Retrieve', 'bedrock:RetrieveAndGenerate',
        # Identity: other users' identities and data, privilege escalation
        'cognito-identity:GetOpenIdTokenForDeveloperIdentity', 'cognito-identity:LookupDeveloperIdentity',
        'cognito-identity:MergeDeveloperIdentities', 'cognito-identity:UnlinkDeveloperIdentity',
        'cognito-identity:DeleteIdentities', 'cognito-identity:SetIdentityPoolRoles',
        'cognito-identity:UpdateIdentityPool',
        'cognito-sync:ListRecords', 'cognito-sync:UpdateRecords', 'cognito-sync:ListDatasets',
        'cognito-sync:DescribeDataset', 'cognito-sync:DeleteDataset', 'cognito-sync:BulkPublish',
        'cognito-sync:SetCognitoEvents', 'cognito-sync:SetIdentityPoolConfiguration',
        'cognito-idp:ListUsers', 'cognito-idp:AdminGetUser', 'cognito-idp:AdminCreateUser',
        'cognito-idp:AdminDeleteUser', 'cognito-idp:AdminSetUserPassword', 'cognito-idp:AdminResetUserPassword',
        'cognito-idp:AdminUpdateUserAttributes', 'cognito-idp:AdminAddUserToGroup',
        'cognito-idp:AdminInitiateAuth', 'cognito-idp:AdminConfirmSignUp',
        'iam:PassRole', 'iam:CreateUser', 'iam:CreateAccessKey', 'iam:CreateLoginProfile',
        'iam:UpdateLoginProfile', 'iam:CreateRole', 'iam:UpdateAssumeRolePolicy', 'iam:AttachRolePolicy',
        'iam:PutRolePolicy', 'iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion', 'sts:AssumeRole',
        'ec2:RunInstances', 'ec2:TerminateInstances', 'ec2:GetPasswordData', 'ec2:ModifyInstanceAttribute',
        'ec2:AuthorizeSecurityGroupIngress', 'ec2:CreateKeyPair', 'ec2:ImportKeyPair',
    )}

    # Actions commonly granted to guests on Resource '*' that act only on the
    # caller's own request (stateless inference, analytics ingestion, the
    # caller's own identity) and expose no stored data. A trailing '*' covers
    # every action starting with the prefix. Anything on all resources that is
    # neither sensitive nor listed here is reported for review (0), not PASS.
    GUEST_SAFE_ACTIONS = tuple(a.lower() for a in (
        'mobileanalytics:PutEvents', 'mobiletargeting:PutEvents',
        'polly:SynthesizeSpeech', 'polly:DescribeVoices', 'polly:StartSpeechSynthesisStream',
        'rekognition:Detect*', 'rekognition:RecognizeCelebrities', 'rekognition:CompareFaces',
        'rekognition:GetCelebrityInfo',
        'translate:TranslateText', 'translate:TranslateDocument',
        'comprehend:Detect*', 'comprehend:BatchDetect*',
        'textract:DetectDocumentText', 'textract:AnalyzeDocument', 'textract:AnalyzeExpense',
        'textract:AnalyzeID',
        'transcribe:StartStreamTranscription', 'transcribe:StartStreamTranscriptionWebSocket',
        'cognito-identity:GetId', 'cognito-identity:GetCredentialsForIdentity', 'cognito-identity:GetOpenIdToken',
        'geo:SearchPlaceIndexFor*', 'geo:GetPlace', 'geo:GetMap*', 'geo:CalculateRoute*',
    ))

    @staticmethod
    @functools.lru_cache(maxsize=4096)
    def _globRegex(pattern):
        return re.compile(''.join('.*' if c == '*' else '.' if c == '?' else re.escape(c)
                                  for c in pattern.lower()))

    @classmethod
    def _globMatch(cls, action, pattern):
        """IAM action matching: case-insensitive, '*' any run, '?' one char."""
        return cls._globRegex(pattern).fullmatch(action.lower()) is not None

    @classmethod
    def _covers(cls, outer, inner):
        """Does action pattern `outer` match every action `inner` can match?
        Exact for concrete `inner`; for wildcard `inner`, only a literal-prefix
        `outer` ('svc:Prefix*' / '*') is recognised (otherwise False)."""
        o, i = outer.strip().lower(), inner.strip().lower()
        if o == i:
            return True
        if not any(c in i for c in '*?'):
            return cls._globMatch(i, o)
        if o.endswith('*') and not any(c in o[:-1] for c in '*?'):
            return i.startswith(o[:-1])
        return False

    @classmethod
    def _mayOverlap(cls, a, b):
        """Conservative: could patterns a and b match a common action?"""
        a, b = a.strip().lower(), b.strip().lower()
        if cls._covers(a, b) or cls._covers(b, a):
            return True
        if not any(c in a + b for c in '*?'):
            return False
        sa, sb = cls._actionService(a), cls._actionService(b)
        return sa is None or sb is None or sa == sb

    @classmethod
    def _effectiveActions(cls, action, limits):
        """Patterns of `action` still allowed after the role's unconditional
        Deny statements on Resource '*' (Deny '*', Deny '<svc>:*', Deny named
        actions, Deny NotAction caps)."""
        if limits['all']:
            return []
        current = [action.strip()]
        for cap in limits['notActionCaps']:
            nxt = []
            for p in current:
                for c in cap:
                    if cls._covers(c, p):
                        nxt.append(p)
                    elif cls._covers(p, c):
                        nxt.append(c.strip())
                    elif cls._mayOverlap(p, c):
                        nxt.append(p)
            current = list(dict.fromkeys(nxt))
        out = []
        for p in current:
            svc = cls._actionService(p)
            if svc and svc in limits['services']:
                continue
            if any(cls._covers(d, p) for d in limits.get('denied', ())):
                continue
            out.append(p)
        return out

    @classmethod
    def classifyAction(cls, pattern):
        """('sensitive', example) | ('safe', None) | ('unknown', None) for an
        action pattern granted on all resources."""
        p = pattern.strip().lower()
        hits = sorted(a for a in cls.SENSITIVE_ACTIONS if cls._globMatch(a, p))
        if hits:
            return 'sensitive', cls.SENSITIVE_ACTIONS[hits[0]]
        if any(cls._covers(s, p) for s in cls.GUEST_SAFE_ACTIONS):
            return 'safe', None
        return 'unknown', None

    @classmethod
    def policyFindings(cls, doc, limits=None):
        """(reasons, review) for one policy document granted to every guest.

        reasons -- broad grants (FAIL):
          - an Allow with Action '*' / '<service>:*' or NotAction on resources
            not confined to the caller's own identity (on all resources, or on
            specific resources shared by every guest, reported with the resource);
          - on all resources (Resource '*', arn:...:*, NotResource, or every
            resource of a type such as table/*): any action or partial wildcard
            (e.g. 's3:Get*') matching a data-access / execution / privilege
            action in SENSITIVE_ACTIONS.
        review  -- actions on all resources that are neither sensitive nor known
          guest-safe (GUEST_SAFE_ACTIONS); reported for review, not PASS.

        - Wildcards on resources (or conditions) keyed on
          ${cognito-identity.amazonaws.com:sub} are the documented per-identity
          pattern (e.g. cognito-sync:* on .../identity/${...:sub}/*) and are skipped.
        - Named actions and partial wildcards on specific shared resources
          (e.g. s3:GetObject on one public bucket) are not reported.
        - Unconditional Deny statements on Resource '*' (limits) narrow the allows."""
        reasons, review = [], []
        if not isinstance(doc, dict):
            return reasons, review
        limits = limits or {'all': False, 'services': set(), 'notActionCaps': [], 'denied': []}
        for stmt in cls._asList(doc.get('Statement')):
            if not isinstance(stmt, dict) or stmt.get('Effect') != 'Allow':
                continue
            scope = cls.resourceScope(stmt)
            if scope == 'perIdentity':
                continue
            suffix = ''
            if scope == 'shared':
                res = [r for r in cls._asList(stmt.get('Resource')) if isinstance(r, str)]
                suffix = f" on {res[0]}" + (f" (+{len(res) - 1})" if len(res) > 1 else '') + \
                         " (shared by all guests)"
            if 'NotAction' in stmt:
                if cls._stillBroad('*', limits):
                    reasons.append('Allow with NotAction' + suffix)
                elif scope == 'unscoped':
                    cls._classifyInto('*', 'Allow with NotAction', limits, reasons, review)
                continue
            for a in cls._asList(stmt.get('Action')):
                if not isinstance(a, str) or not a.strip():
                    continue
                a = a.strip()
                if cls._isServiceWildcard(a) and cls._stillBroad(a, limits):
                    reasons.append(f"Action '{a}'" + suffix)
                    continue
                if scope == 'unscoped':
                    cls._classifyInto(a, f"Action '{a}'", limits, reasons, review)
        return reasons, review

    @classmethod
    def _classifyInto(cls, action, label, limits, reasons, review):
        for eff in cls._effectiveActions(action, limits):
            kind, example = cls.classifyAction(eff)
            narrowed = '' if eff.lower() == action.lower() else f" (narrowed by Deny to '{eff}')"
            if kind == 'sensitive':
                inc = '' if example.lower() == eff.lower() else f", includes {example}"
                reasons.append(f"{label}{narrowed} on all resources{inc}")
            elif kind == 'unknown':
                review.append(f"{label}{narrowed} on all resources")

    @classmethod
    def policyBroadReasons(cls, doc, limits=None):
        """Broad-grant reasons of policyFindings (see there)."""
        return cls.policyFindings(doc, limits)[0]

    @classmethod
    def roleFindings(cls, role):
        """(reasons, review) for a role evaluation dict (see policyFindings)."""
        reasons, review = [], []
        pols = role.get('policies') or []
        limits = cls.denyLimits([p.get('document') for p in pols])
        for pol in pols:
            name = pol.get('name') or '?'
            if pol.get('managedByAws') and (
                    name in cls.BROAD_MANAGED_POLICY_NAMES or name.endswith('FullAccess')):
                if not limits['all']:
                    reasons.append(f"AWS managed policy {name}")
                continue
            rs, rv = cls.policyFindings(pol.get('document'), limits)
            reasons.extend(f"{name}: {r}" for r in rs)
            review.extend(f"{name}: {r}" for r in rv)
        return reasons, review

    @classmethod
    def roleBroadReasons(cls, role):
        """Return the list of reasons a role evaluation dict grants broad access."""
        return cls.roleFindings(role)[0]

    @classmethod
    def isLegacyDefaultGuestRole(cls, role):
        """The role the Cognito console used to create for guests
        (Cognito_<pool>Unauth_Role: mobileanalytics:PutEvents + cognito-sync:* on '*')."""
        name = role.get('roleName') or ''
        if not (name.startswith('Cognito_') and name.endswith('Unauth_Role')):
            return False
        actions = set()
        for pol in role.get('policies') or []:
            doc = pol.get('document')
            if pol.get('managedByAws') or not isinstance(doc, dict):
                return False
            for stmt in cls._asList(doc.get('Statement')):
                if isinstance(stmt, dict) and stmt.get('Effect') == 'Allow':
                    if 'NotAction' in stmt:
                        return False
                    actions |= {a.strip().lower() for a in cls._asList(stmt.get('Action')) if isinstance(a, str)}
        return bool(actions) and actions <= {'mobileanalytics:putevents', 'cognito-sync:*'}

    # ------------------------------------------------------------------ #
    # Guest (unauthenticated) role is broad
    # ------------------------------------------------------------------ #
    def _checkCognitoIdentityPoolGuestRoleBroad(self):
        key = 'cognitoIdentityPoolGuestRoleBroad'
        if self.pool.get('_describeError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_describeError']})"]
            return
        if not self.pool.get('AllowUnauthenticatedIdentities'):
            self.results[key] = [1, "Unauthenticated (guest) identities are disabled"]
            return
        if self.pool.get('_rolesError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_rolesError']})"]
            return
        role = self.pool.get('_unauthRole')
        if not role:
            self.results[key] = [
                1, "Guest access enabled but no unauthenticated role is set (no credentials issued)"
            ]
            return
        roleName = role.get('roleName') or role.get('roleArn') or '?'
        if role.get('crossAccount'):
            self.results[key] = [
                0, f"Guest role {roleName} belongs to another account and was not evaluated"
            ]
            return
        if role.get('error'):
            self.results[key] = [0, f"Unable to evaluate ({role['error']})"]
            return

        reasons, review = self.roleFindings(role)
        if not reasons and role.get('policyErrors'):
            self.results[key] = [0, f"Unable to evaluate ({role['policyErrors'][0]})"]
            return
        if not reasons and review:
            more = f" (+{len(review) - 3} more)" if len(review) > 3 else ""
            self.results[key] = [
                0, f"Guest role {roleName} grants actions on all resources that are not known to be "
                   f"guest-safe ({'; '.join(review[:3])}{more}); review that anonymous callers "
                   "cannot read or change data with them"
            ]
            return
        if not reasons:
            self.results[key] = [
                1, f"Guest role {roleName} has no broad permissions (no wildcard, full-access, or "
                   "data-access actions on all resources)"
            ]
            return

        boundary = role.get('boundary')
        if boundary:
            if boundary.get('error'):
                self.results[key] = [
                    0, f"Guest role {roleName} has broad policies but its permissions boundary "
                       f"could not be read: Unable to evaluate ({boundary['error']})"
                ]
                return
            bReasons = self.roleBroadReasons({'policies': [boundary]})
            if not bReasons:
                self.results[key] = [
                    0, f"Guest role {roleName} has broad policies ({'; '.join(reasons[:3])}) "
                       f"but is capped by permissions boundary {boundary.get('name')}; review"
                ]
                return

        detail = f"{'; '.join(reasons[:3])}" + (f" (+{len(reasons) - 3} more)" if len(reasons) > 3 else "")
        if self.isLegacyDefaultGuestRole(role):
            self.results[key] = [
                -1, f"Anonymous identities receive the legacy console-default guest role {roleName} "
                    f"({detail}): the grant is not limited to the caller's own identity. "
                    "Scope cognito-sync resources to ${cognito-identity.amazonaws.com:sub} or "
                    "remove it"
            ]
            return
        self.results[key] = [
            -1, f"Anonymous identities receive role {roleName} with broad access: {detail}"
        ]

    # ------------------------------------------------------------------ #
    # Several sign-in sources share one authenticated role (no role mapping)
    # ------------------------------------------------------------------ #
    def _checkCognitoIdentityPoolNoRoleMapping(self):
        key = 'cognitoIdentityPoolNoRoleMapping'
        if self.pool.get('_describeError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_describeError']})"]
            return
        if self.pool.get('_rolesError'):
            self.results[key] = [0, f"Unable to evaluate ({self.pool['_rolesError']})"]
            return
        rolesResp = self.pool.get('_roles') or {}
        roles = rolesResp.get('Roles') or {}
        mappings = rolesResp.get('RoleMappings') or {}
        providers = self.loginProviders(self.pool)

        if mappings:
            self.results[key] = [1, f"{len(mappings)} role mapping(s) configured"]
            return

        tagMaps = self.pool.get('_principalTagMaps') or {}
        abac, errors = [], []
        for name, m in tagMaps.items():
            if m is None:
                continue
            if m.get('_error'):
                errors.append(m['_error'])
            elif m.get('UseDefaults') or m.get('PrincipalTags'):
                abac.append(name)
        if abac:
            self.results[key] = [
                1, f"Attribute-based access control (principal tags) configured for "
                   f"{len(abac)} provider(s)"
            ]
            return

        if not roles.get('authenticated'):
            self.results[key] = [0, "No authenticated role or role mapping configured"]
            return
        if len(providers) < 2:
            self.results[key] = [
                0, f"Single sign-in source ({len(providers)}) uses the default authenticated role; "
                   "acceptable when one role fits every user"
            ]
            return
        if errors:
            self.results[key] = [0, f"Unable to evaluate ({errors[0]})"]
            return
        self.results[key] = [
            -1, f"{len(providers)} sign-in sources share the default authenticated role with no "
                "role mapping or principal-tag (ABAC) mapping"
        ]
