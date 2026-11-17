"""
Pure helpers used by the IAM drivers to evaluate role trust policies and
identity policies. Kept free of boto3 so they can be unit tested directly.
"""
import fnmatch
import json
import re

from utils import PolicyPrincipal

WEB_IDENTITY_ACTION = 'sts:AssumeRoleWithWebIdentity'

# Positive-match string operators that can restrict an OIDC "sub" claim.
# Negated operators (StringNotEquals / StringNotLike) never restrict who can
# assume the role. ForAnyValue/ForAllValues prefixes and the IfExists suffix are
# tolerated because "sub" is always present in an OIDC token.
_SUB_OPERATORS = frozenset(('stringequals', 'stringequalsignorecase', 'stringlike'))

# OIDC providers whose issuer is shared by many tenants (any customer can mint a
# token from it) or, for EKS, by every service account in the cluster. For
# these, the audience claim does not identify the caller, so the trust policy
# must pin "sub" to the caller's own identity (org / repo / project /
# namespace). Each entry: (issuer host match, regex the literal prefix of the
# sub value - everything before the first wildcard - must match). The regexes
# require a delimiter after the identity value so that a prefix wildcard such
# as "repo:my-org*" (which also matches an attacker's "my-org-evil") is not
# accepted as restricted.
_MULTI_TENANT_OIDC = (
    # GitHub Actions: repo:<owner>/<repo>:... or customised claims such as
    # repository_owner:<owner>:... / repository_owner_id:<id>:...
    (lambda host: host == 'token.actions.githubusercontent.com'
        or host.startswith('token.actions.githubusercontent.com/'),
     re.compile(r'(^|:)(repo|repository|job_workflow_ref):[^/:*?]+/'
                r'|(^|:)(repository_owner|repository_owner_id|repository_id|enterprise|enterprise_id):[^:*?]+:')),
    # GitLab.com (self-managed GitLab issuers are single tenant)
    (lambda host: host == 'gitlab.com',
     re.compile(r'(^|:)project_path:[^/:*?]+/|(^|:)(namespace_path|namespace_id|project_id):[^:*?]+:')),
    # HCP Terraform / Terraform Cloud
    (lambda host: host == 'app.terraform.io',
     re.compile(r'(^|:)organization:[^:*?]+:')),
    # Buildkite
    (lambda host: host == 'agent.buildkite.com',
     re.compile(r'(^|:)organization:[^:*?]+:')),
    # Amazon EKS IRSA: system:serviceaccount:<namespace>:<name>
    (lambda host: bool(re.match(r'^oidc\.eks\.[a-z0-9-]+\.amazonaws\.com(\.cn)?/id/', host)),
     re.compile(r'^system:serviceaccount:[^:*?]+:')),
)


def _asList(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _multiTenantRule(host):
    for match, rule in _MULTI_TENANT_OIDC:
        if match(host):
            return rule
    return None


def oidcProvidersInStatement(statement):
    """Return the issuer hosts of IAM OIDC providers in an Allow statement's
    Federated principal (e.g. 'token.actions.githubusercontent.com')."""
    if not isinstance(statement, dict) or str(statement.get('Effect', '')).lower() != 'allow':
        return []
    principal = statement.get('Principal')
    if not isinstance(principal, dict):
        return []
    hosts = []
    for fed in _asList(principal.get('Federated')):
        if isinstance(fed, str) and ':oidc-provider/' in fed:
            hosts.append(fed.split(':oidc-provider/', 1)[1])
    return hosts


def subConditionValues(condition, host):
    """Values of positive-match conditions on '<host>:sub' (case-insensitive)."""
    values = []
    if not isinstance(condition, dict):
        return values
    target = (host + ':sub').lower()
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        for prefix in ('foranyvalue:', 'forallvalues:'):
            if op.startswith(prefix):
                op = op[len(prefix):]
        if op.endswith('ifexists'):
            op = op[:-len('ifexists')]
        if op not in _SUB_OPERATORS:
            continue
        for key, value in block.items():
            if str(key).lower() == target:
                values.extend(v for v in _asList(value) if isinstance(v, str))
    return values


def subValueIsUnrestricted(value, rule):
    """True if a sub value lets callers outside the intended identity match.
    The literal part before the first wildcard must bind the caller's own
    org / repo / project / namespace (rule). A value without wildcards is an
    exact match and therefore restricted."""
    if '*' not in value and '?' not in value:
        return value == ''
    literal = re.split(r'[*?]', value, maxsplit=1)[0]
    return not rule.search(literal)


def evaluateOidcTrust(trustDoc):
    """
    Evaluate a role trust policy for web-identity (OIDC) federation.

    Returns (findings, notes):
      findings: list of strings for statements trusting a multi-tenant / EKS
                OIDC provider without a sub condition, or with a sub value
                that does not pin the caller's identity.
      notes:    list of strings for statements trusting other (single tenant)
                OIDC providers without a sub condition - audience-bound only,
                reported as informational.
    Returns (None, None) when the policy has no OIDC web-identity trust.
    """
    findings, notes = [], []
    found = False
    for stmt in PolicyPrincipal.iterStatements(trustDoc):
        hosts = oidcProvidersInStatement(stmt)
        if not hosts or not PolicyPrincipal.statementAllowsAction(stmt, [WEB_IDENTITY_ACTION]):
            continue
        for host in hosts:
            found = True
            values = subConditionValues(stmt.get('Condition'), host)
            rule = _multiTenantRule(host)
            if rule is None:
                if not values or all(set(v) <= {'*', '?'} for v in values):
                    notes.append('{}: no {}:sub condition (audience-bound only)'.format(host, host))
                continue
            if not values:
                findings.append('{}: no {}:sub condition'.format(host, host))
                continue
            loose = [v for v in values if subValueIsUnrestricted(v, rule)]
            if loose:
                findings.append('{}: sub allows any identity ({})'.format(host, ', '.join(loose)))
    if not found:
        return None, None
    return findings, notes


TRUST_ASSUME_ACTIONS = ['sts:AssumeRole']


def trustAllowsAnyPrincipal(trustDoc):
    """Statements (as short descriptions) of a role trust policy that allow
    sts:AssumeRole to any AWS principal ("*", {"AWS": "*"}, list forms,
    NotPrincipal) without a scoping condition (aws:PrincipalOrgID,
    aws:PrincipalAccount, aws:PrincipalArn, aws:SourceAccount, ...).
    sts:ExternalId alone is NOT treated as scoping: AWS documents the
    external ID as not being a secret."""
    out = []
    for idx, stmt in enumerate(PolicyPrincipal.iterStatements(trustDoc)):
        if not PolicyPrincipal.statementIsPublic(stmt):
            continue
        if not PolicyPrincipal.statementAllowsAction(stmt, TRUST_ASSUME_ACTIONS):
            continue
        sid = stmt.get('Sid') or '#{}'.format(idx + 1)
        out.append('statement {}'.format(sid))
    return out


# --------------------------------------------------------------------------- #
# Broad secret read access in identity policies
# --------------------------------------------------------------------------- #
SECRET_READ_ACTIONS = {
    'secretsmanager:GetSecretValue': ('secretsmanager', 'secret:ss-probe-AbCdEf'),
    'secretsmanager:BatchGetSecretValue': ('secretsmanager', 'secret:ss-probe-AbCdEf'),
    'ssm:GetParameter': ('ssm', 'parameter/ss-probe'),
    'ssm:GetParameters': ('ssm', 'parameter/ss-probe'),
    'ssm:GetParametersByPath': ('ssm', 'parameter/ss-probe'),
    'ssm:GetParameterHistory': ('ssm', 'parameter/ss-probe'),
}

_SCOPING_OPERATORS = frozenset(('stringequals', 'stringequalsignorecase', 'stringlike', 'arnequals', 'arnlike'))


def _resourcePatternMatchesAny(pattern, service, resourcePart):
    """True if an IAM Resource pattern covers an arbitrary resource of this
    service in any region/account (region/account segments are ignored, so a
    pattern scoped to the own account still counts as 'all secrets')."""
    if not isinstance(pattern, str):
        return False
    p = pattern.lower()
    if p == '*':
        return True
    parts = p.split(':', 5)
    if len(parts) < 6 or parts[0] != 'arn':
        return fnmatch.fnmatchcase('arn:aws:{}:r:a:{}'.format(service, resourcePart), p)
    return fnmatch.fnmatchcase(service, parts[2]) and fnmatch.fnmatchcase(resourcePart.lower(), parts[5])


def _conditionScopesResource(condition):
    """True if a Condition limits which secrets/parameters can be read
    (resource tags or explicit secret IDs) with a concrete value."""
    if not isinstance(condition, dict):
        return False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            continue
        op = operator.lower()
        if op.startswith('forallvalues:') or op.endswith('ifexists'):
            continue
        if op.startswith('foranyvalue:'):
            op = op[len('foranyvalue:'):]
        if op not in _SCOPING_OPERATORS:
            continue
        for key, value in block.items():
            k = str(key).lower()
            if 'resourcetag/' in k or k in ('secretsmanager:secretid', 'secretsmanager:resourcetag'):
                vals = _asList(value)
                if vals and not any(isinstance(v, str) and set(v) <= {'*', '?'} for v in vals):
                    return True
    return False


def broadSecretReadActions(policyDoc):
    """Secret-read actions an identity policy allows on all secrets /
    parameters. Statements granting Action "*" (full administrator) are
    skipped - those are reported by the administrator-access checks."""
    found = set()
    for stmt in PolicyPrincipal.iterStatements(policyDoc):
        if str(stmt.get('Effect', '')).lower() != 'allow':
            continue
        if 'Action' in stmt and any(a == '*' for a in _asList(stmt.get('Action'))):
            continue
        if _conditionScopesResource(stmt.get('Condition')):
            continue
        for action, (service, resourcePart) in SECRET_READ_ACTIONS.items():
            if not PolicyPrincipal.statementAllowsAction(stmt, [action]):
                continue
            if 'NotResource' in stmt:
                excluded = _asList(stmt.get('NotResource'))
                broad = not any(_resourcePatternMatchesAny(p, service, resourcePart) for p in excluded)
            else:
                broad = any(_resourcePatternMatchesAny(p, service, resourcePart) for p in _asList(stmt.get('Resource')))
            if broad:
                found.add(action)
    return sorted(found)


# --------------------------------------------------------------------------- #
# Privilege escalation from service-trusted (workload) roles
# --------------------------------------------------------------------------- #
# Compute / orchestration services whose code runs with the role's credentials.
WORKLOAD_SERVICE_PRINCIPALS = ('lambda', 'ecs-tasks', 'ec2', 'codebuild', 'states')

# IAM actions that let a principal grant itself (or a role it can use) more
# permissions. Value: the IAM resource type the action applies to, used to
# decide whether the statement's Resource covers *any* such resource.
ESCALATION_ACTIONS = {
    'iam:PutRolePolicy': 'role',
    'iam:AttachRolePolicy': 'role',
    'iam:UpdateAssumeRolePolicy': 'role',
    'iam:PassRole': 'role',
    'iam:CreatePolicyVersion': 'policy',
    'iam:SetDefaultPolicyVersion': 'policy',
    'iam:PutUserPolicy': 'user',
    'iam:AttachUserPolicy': 'user',
    'iam:CreateAccessKey': 'user',
    'iam:CreateLoginProfile': 'user',
    'iam:UpdateLoginProfile': 'user',
    'iam:AddUserToGroup': 'group',
    'iam:PutGroupPolicy': 'group',
    'iam:AttachGroupPolicy': 'group',
}


def workloadServicesTrusted(trustDoc):
    """Workload service principals (e.g. 'lambda.amazonaws.com') an Allow
    statement of the trust policy lets assume the role."""
    found = set()
    for stmt in PolicyPrincipal.iterStatements(trustDoc):
        if str(stmt.get('Effect', '')).lower() != 'allow':
            continue
        if not PolicyPrincipal.statementAllowsAction(stmt, TRUST_ASSUME_ACTIONS):
            continue
        principal = stmt.get('Principal')
        if not isinstance(principal, dict):
            continue
        for svc in _asList(principal.get('Service')):
            if not isinstance(svc, str):
                continue
            name = svc.lower().split('.amazonaws.com', 1)[0]
            if name in WORKLOAD_SERVICE_PRINCIPALS:
                found.add(svc)
    return sorted(found)


def _resourcesCover(stmt, resourceType):
    probe = '{}/ss-probe'.format(resourceType)
    if 'NotResource' in stmt:
        return not any(_resourcePatternMatchesAny(p, 'iam', probe) for p in _asList(stmt.get('NotResource')))
    return any(_resourcePatternMatchesAny(p, 'iam', probe) for p in _asList(stmt.get('Resource')))


def isFullAdmin(policyDoc):
    """True if an Allow statement grants Action "*" on Resource "*" without
    a Condition."""
    for stmt in PolicyPrincipal.iterStatements(policyDoc):
        if str(stmt.get('Effect', '')).lower() != 'allow' or stmt.get('Condition'):
            continue
        if '*' in _asList(stmt.get('Action')) and '*' in _asList(stmt.get('Resource')):
            return True
    return False


def escalationActions(policyDocs, ignoreResource=False):
    """IAM privilege-escalation actions granted by a set of identity policy
    documents on all roles / users / groups / policies.

    Conservative to avoid false positives:
    - Allow statements with any Condition are treated as scoped (e.g.
      iam:PassRole limited by iam:PassedToService, ResourceTag conditions).
    - Resources scoped to specific names or name prefixes are not broad.
    - An unconditional Deny on all resources removes the action.
    ignoreResource=True is used for permissions boundaries, where any Allow
    of the action keeps it available."""
    allowed, denied = set(), set()
    for doc in policyDocs:
        for stmt in PolicyPrincipal.iterStatements(doc):
            effect = str(stmt.get('Effect', '')).lower()
            if stmt.get('Condition'):
                continue
            for action, rtype in ESCALATION_ACTIONS.items():
                if not PolicyPrincipal.statementAllowsAction(stmt, [action]):
                    continue
                covers = _resourcesCover(stmt, rtype)
                if effect == 'allow' and (ignoreResource or covers):
                    allowed.add(action)
                elif effect == 'deny' and covers:
                    denied.add(action)
    return sorted(allowed - denied)


# --------------------------------------------------------------------------- #
# WAFS2027 identity checks (chunk 3)
# --------------------------------------------------------------------------- #
# Global condition keys that tie a request to a network location.
NETWORK_CONDITION_KEYS = frozenset((
    'aws:sourceip', 'aws:sourcevpc', 'aws:sourcevpce', 'aws:vpcsourceip', 'aws:sourcevpcarn'))


def statementNetworkConditionKeys(stmt):
    """Network condition keys used by a statement's Condition block."""
    found = set()
    condition = stmt.get('Condition')
    if not isinstance(condition, dict):
        return found
    for block in condition.values():
        if not isinstance(block, dict):
            continue
        for key in block:
            if str(key).lower() in NETWORK_CONDITION_KEYS:
                found.add(str(key))
    return found


def networkContainment(policyDocs):
    """How a set of identity policies ties long-term credentials to a
    network location. Returns (contained, reason):
    - a Deny statement conditioned on a network key (the usual "deny unless
      from my IP / VPC endpoint" guard), or
    - every Allow statement carries a network condition.
    No Allow statement at all returns (None, ...): the identity policies grant
    nothing, so there is nothing to contain."""
    allows, conditionedAllows = 0, 0
    for doc in policyDocs:
        for stmt in PolicyPrincipal.iterStatements(doc):
            effect = str(stmt.get('Effect', '')).lower()
            keys = statementNetworkConditionKeys(stmt)
            if effect == 'deny' and keys:
                return True, 'Deny statement conditioned on {}'.format(', '.join(sorted(keys)))
            if effect == 'allow':
                allows += 1
                if keys:
                    conditionedAllows += 1
    if allows == 0:
        return None, 'identity policies grant no permissions'
    if allows == conditionedAllows:
        return True, 'every Allow statement has a network condition'
    return False, '{} of {} Allow statement(s) without a network condition and no network Deny guard'.format(
        allows - conditionedAllows, allows)


# Tag keys (normalised: lower-case, separators removed) that record a data
# classification / sensitivity level.
_CLASSIFICATION_KEY_RE = re.compile(r'classification|sensitivity|confidentiality')


def isClassificationTagKey(key):
    norm = re.sub(r'[\s_\-:./]+', '', str(key).lower())
    return bool(_CLASSIFICATION_KEY_RE.search(norm))


MFA_DEACTIVATION_EVENT = 'DeactivateMFADevice'
IAM_EVENT_SOURCE = 'iam.amazonaws.com'
CLOUDTRAIL_API_DETAIL_TYPE = 'AWS API Call via CloudTrail'


def _eventValueMatches(patternValues, value):
    """EventBridge pattern field (a list of values / matcher objects) matches value."""
    if not isinstance(patternValues, list):
        patternValues = [patternValues]
    for pv in patternValues:
        if isinstance(pv, str):
            if pv == value:
                return True
        elif isinstance(pv, dict):
            if 'prefix' in pv:
                p = pv['prefix']
                if isinstance(p, dict) and 'equals-ignore-case' in p:
                    if value.lower().startswith(str(p['equals-ignore-case']).lower()):
                        return True
                elif isinstance(p, str) and value.startswith(p):
                    return True
            elif 'suffix' in pv:
                s = pv['suffix']
                if isinstance(s, dict) and 'equals-ignore-case' in s:
                    if value.lower().endswith(str(s['equals-ignore-case']).lower()):
                        return True
                elif isinstance(s, str) and value.endswith(s):
                    return True
            elif 'equals-ignore-case' in pv:
                if str(pv['equals-ignore-case']).lower() == value.lower():
                    return True
            elif 'wildcard' in pv:
                if fnmatch.fnmatchcase(value, str(pv['wildcard'])):
                    return True
            elif 'anything-but' in pv:
                ab = pv['anything-but']
                if isinstance(ab, (str, int, float)):
                    if str(ab) != value:
                        return True
                elif isinstance(ab, list):
                    if value not in [str(x) for x in ab]:
                        return True
                elif isinstance(ab, dict) and 'prefix' in ab:
                    if not value.startswith(str(ab['prefix'])):
                        return True
    return False


def eventPatternMatchesMfaDeactivation(patternText):
    """True if an EventBridge event pattern matches the CloudTrail
    DeactivateMFADevice API call event. Other detail fields are ignored
    (treated as not narrowing). A pattern must name the IAM source or the
    event name to count."""
    try:
        pattern = json.loads(patternText) if isinstance(patternText, str) else patternText
    except (TypeError, ValueError):
        return False
    if not isinstance(pattern, dict):
        return False
    detail = pattern.get('detail') if isinstance(pattern.get('detail'), dict) else {}
    named = False
    if 'source' in pattern:
        if not _eventValueMatches(pattern['source'], 'aws.iam'):
            return False
        named = True
    if 'detail-type' in pattern and not _eventValueMatches(pattern['detail-type'], CLOUDTRAIL_API_DETAIL_TYPE):
        return False
    if 'eventSource' in detail:
        if not _eventValueMatches(detail['eventSource'], IAM_EVENT_SOURCE):
            return False
        named = True
    if 'eventName' in detail:
        if not _eventValueMatches(detail['eventName'], MFA_DEACTIVATION_EVENT):
            return False
        named = True
    return named


_MF_EVENTNAME_RE = re.compile(r'\$\.eventName\s*(!?=)\s*["\']?([A-Za-z0-9*]+)["\']?')
_MF_EVENTSOURCE_IAM_RE = re.compile(r'\$\.eventSource\s*=\s*["\']?iam\.amazonaws\.com["\']?')


def metricFilterMatchesMfaDeactivation(filterPattern):
    """True if a CloudWatch Logs metric filter pattern on CloudTrail logs
    selects DeactivateMFADevice events: an `$.eventName = DeactivateMFADevice`
    term, or an `$.eventSource = iam.amazonaws.com` term with no eventName
    term at all (all IAM API calls)."""
    if not filterPattern:
        return False
    terms = _MF_EVENTNAME_RE.findall(filterPattern)
    for op, val in terms:
        if op == '=' and fnmatch.fnmatchcase(MFA_DEACTIVATION_EVENT, val):
            return True
    if not terms and _MF_EVENTSOURCE_IAM_RE.search(filterPattern):
        return True
    return False
