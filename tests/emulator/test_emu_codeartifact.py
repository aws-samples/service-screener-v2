"""Flag -> fix -> re-run tests for the CodeArtifact checks against the AWS Emulator.

The emulator does not implement codeartifact.list_repositories; the service
also discovers repositories with list_repositories_in_domain (implemented),
so the domain and repository checks are fully testable here.
codeartifactNotUsed reports INFO while list_repositories is unreadable.
"""
import json

import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck



def _policy(arn, condition=None):
    stmt = {'Sid': 'Broad', 'Effect': 'Allow', 'Principal': {'AWS': ['*']},
            'Action': ['codeartifact:ReadFromRepository', 'codeartifact:GetAuthorizationToken'],
            'Resource': '*'}
    if condition:
        stmt['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})


ORG_SCOPE = {'StringEquals': {'aws:PrincipalOrgID': 'o-abcdef1234'}}


def _cleanup(ca, domain, repos):
    for r in repos:
        try:
            ca.delete_repository(domain=domain, repository=r)
        except Exception:
            pass
    try:
        ca.delete_domain(domain=domain)
    except Exception:
        pass


def test_codeartifact_domain_policy_broad(emu, uid):
    ca = emu.client('codeartifact')
    domain = f'ss-dom-{uid}'
    arn = ca.create_domain(domain=domain)['domain']['arn']
    try:
        assertFlagFixCycle(
            emu, 'codeartifact', 'codeartifactRepoPolicyBroad', f'CodeArtifact::{domain}',
            lambda: ca.put_domain_permissions_policy(domain=domain, policyDocument=_policy(arn)),
            lambda: ca.put_domain_permissions_policy(domain=domain, policyDocument=_policy(arn, ORG_SCOPE)))
    finally:
        _cleanup(ca, domain, [])


def test_codeartifact_repo_policy_broad(emu, uid):
    ca = emu.client('codeartifact')
    domain, repo = f'ss-dom-{uid}', 'internal'
    ca.create_domain(domain=domain)
    arn = ca.create_repository(domain=domain, repository=repo)['repository']['arn']
    try:
        assertFlagFixCycle(
            emu, 'codeartifact', 'codeartifactRepoPolicyBroad', f'{domain}/{repo}',
            lambda: ca.put_repository_permissions_policy(domain=domain, repository=repo,
                                                         policyDocument=_policy(arn)),
            lambda: ca.delete_repository_permissions_policy(domain=domain, repository=repo))
    finally:
        _cleanup(ca, domain, [repo])


def test_codeartifact_package_origin_unrestricted(emu, uid):
    """Package lives in a downstream repo whose upstream has public:npmjs, so the
    check must follow the upstream chain to find the external connection."""
    ca = emu.client('codeartifact')
    domain, up, down = f'ss-dom-{uid}', 'npm-store', 'internal'
    ca.create_domain(domain=domain)
    ca.create_repository(domain=domain, repository=up)
    ca.associate_external_connection(domain=domain, repository=up, externalConnection='public:npmjs')
    ca.create_repository(domain=domain, repository=down, upstreams=[{'repositoryName': up}])

    def setOrigin(upstream):
        ca.put_package_origin_configuration(domain=domain, repository=down, format='npm',
                                            namespace='acme', package='internal-lib',
                                            restrictions={'publish': 'ALLOW', 'upstream': upstream})
    try:
        assertFlagFixCycle(emu, 'codeartifact', 'codeartifactPackageOriginUnrestricted',
                           f'{domain}/{down}', lambda: setOrigin('ALLOW'), lambda: setOrigin('BLOCK'))
    finally:
        _cleanup(ca, domain, [down, up])


def test_codeartifact_not_used(emu, uid):
    """The emulator does not implement list_repositories. With no owned domain
    the account may still administer repositories in a shared domain, so the
    check must not FAIL on that unreadable listing. The FAIL state (both
    listings readable and empty) is covered by tests/test_low_mix2.py."""
    ca = emu.client('codeartifact')
    if ca.list_domains().get('domains'):
        pytest.skip('emulator already has CodeArtifact domains; cannot assert the "not used" state')
    domain = f'ss-dom-{uid}'
    try:
        before = runCheck(emu, 'codeartifact', 'codeartifactNotUsed', 'CodeArtifact::Account')
        res = before.results['CodeArtifact::Account']['codeartifactNotUsed']
        assert res[0] == 0 and res[1].startswith('Unable to evaluate ('), res
        ca.create_domain(domain=domain)
        after = runCheck(emu, 'codeartifact', 'codeartifactNotUsed', 'CodeArtifact::Account')
        assert after.statuses() == {'CodeArtifact::Account': 1}
    finally:
        _cleanup(ca, domain, [])
