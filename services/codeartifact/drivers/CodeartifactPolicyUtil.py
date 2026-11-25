"""
Shared resource-policy evaluation for CodeArtifact domain and repository
permission policies. Not a driver (holds no _check methods).
"""
import botocore

from utils import PolicyPrincipal


def _asList(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def evaluateBroadPolicy(fetch, resourceLabel):
    """
    fetch: zero-arg callable returning the get_*_permissions_policy response.
    Returns a [status, message] result for codeartifactRepoPolicyBroad.

    -1 when any Allow statement applies to any principal ("*", {"AWS": "*"},
       NotPrincipal) and is not scoped by a positive aws:PrincipalOrgID /
       aws:PrincipalAccount / aws:PrincipalArn / aws:Source* condition
       (utils.PolicyPrincipal.statementIsPublic).
     1 when no policy is attached, or no statement is broad.
     0 when the policy cannot be read or parsed.
    """
    try:
        resp = fetch()
    except botocore.exceptions.ClientError as e:
        code = e.response.get('Error', {}).get('Code', 'Unknown')
        if code == 'ResourceNotFoundException':
            return [1, f"No resource policy is attached to {resourceLabel}; "
                       "access is limited to IAM principals of the owning account"]
        return [0, f"Unable to evaluate ({code})"]

    doc = (resp.get('policy') or {}).get('document')
    if not doc:
        return [1, f"No resource policy is attached to {resourceLabel}"]
    if PolicyPrincipal.parsePolicy(doc) is None:
        return [0, "Unable to evaluate (policy document could not be parsed)"]

    broad = []
    for stmt in PolicyPrincipal.iterStatements(doc):
        if PolicyPrincipal.statementIsPublic(stmt):
            sid = stmt.get('Sid') or '(no Sid)'
            actions = _asList(stmt.get('Action')) or \
                ['NotAction:' + ','.join(map(str, _asList(stmt.get('NotAction'))))]
            broad.append(f"{sid} [{', '.join(map(str, actions[:5]))}]")
    if broad:
        return [-1, f"The resource policy on {resourceLabel} allows any principal without an "
                    f"aws:PrincipalOrgID / aws:PrincipalAccount (or equivalent) condition: "
                    f"{'; '.join(broad[:5])}"]
    return [1, f"The resource policy on {resourceLabel} does not grant access to any "
               "unscoped principal"]
