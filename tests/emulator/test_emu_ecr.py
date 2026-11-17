"""Flag -> fix -> re-run tests for ECR checks against the local AWS Emulator."""
import pytest

from tests.emulator.conftest import assertFlagFixCycle, runCheck


def _clearSigning(emu):
    """Remove the ECR managed signing config; return the original (or None)."""
    ecr = emu.client('ecr')
    original = None
    try:
        original = ecr.get_signing_configuration().get('signingConfiguration')
        ecr.delete_signing_configuration()
    except ecr.exceptions.SigningConfigurationNotFoundException:
        pass
    return original


def _activeNotationProfiles(emu):
    signer = emu.client('signer')
    out = []
    for page in signer.get_paginator('list_signing_profiles').paginate(statuses=['Active']):
        for p in page.get('profiles', []):
            if (p.get('platformId') or '').startswith('Notation-OCI'):
                out.append(p['profileName'])
    return out


def _onlyRepo(emu, repo):
    ecr = emu.client('ecr')
    names = [r['repositoryName']
             for page in ecr.get_paginator('describe_repositories').paginate()
             for r in page['repositories']]
    if names != [repo]:
        pytest.skip(f'registry-level check anchors on the first repo; other repos present: {names}')


def test_ecr_image_signing_via_managed_signing(emu, uid):
    ecr = emu.client('ecr')
    signer = emu.client('signer')
    repo = f'ss-test-{uid}'
    profile = f'sstest{uid}'
    if _activeNotationProfiles(emu):
        pytest.skip('pre-existing active Notation-OCI profiles in emulator')
    ecr.create_repository(repositoryName=repo)
    original = None
    try:
        _onlyRepo(emu, repo)

        def misconfigure():
            nonlocal original
            original = _clearSigning(emu)

        def fix():
            arn = signer.put_signing_profile(
                profileName=profile, platformId='Notation-OCI-SHA384-ECDSA')['arn']
            ecr.put_signing_configuration(signingConfiguration={'rules': [{
                'signingProfileArn': arn,
                'repositoryFilters': [{'filter': '*', 'filterType': 'WILDCARD_MATCH'}]}]})
            # Cancel the profile so only the managed-signing PASS path is exercised.
            signer.cancel_signing_profile(profileName=profile)
            assert not _activeNotationProfiles(emu)

        before, after = assertFlagFixCycle(
            emu, 'ecr', 'ecrImageSigningNotConfigured', repo, misconfigure, fix)
        res = runCheck(emu, 'ecr', 'ecrImageSigningNotConfigured', repo)
        msgs = [v['ecrImageSigningNotConfigured'][1] for v in res.results.values()]
        assert any('managed signing configured' in m for m in msgs), msgs
    finally:
        try:
            ecr.delete_signing_configuration()
        except Exception:
            pass
        if original and original.get('rules'):
            ecr.put_signing_configuration(signingConfiguration=original)
        try:
            signer.cancel_signing_profile(profileName=profile)
        except Exception:
            pass
        ecr.delete_repository(repositoryName=repo, force=True)


def test_ecr_image_signing_via_signer_notation_profile(emu, uid):
    ecr = emu.client('ecr')
    signer = emu.client('signer')
    repo = f'ss-test-{uid}'
    profile = f'sstest{uid}'
    if _activeNotationProfiles(emu):
        pytest.skip('pre-existing active Notation-OCI profiles in emulator')
    ecr.create_repository(repositoryName=repo)
    original = None
    try:
        _onlyRepo(emu, repo)

        def misconfigure():
            nonlocal original
            original = _clearSigning(emu)
            # A non-Notation profile must NOT count as container signing.
            signer.put_signing_profile(profileName=f'{profile}lambda', platformId='AWSLambda-SHA384-ECDSA')

        def fix():
            signer.put_signing_profile(profileName=profile, platformId='Notation-OCI-SHA384-ECDSA')

        assertFlagFixCycle(emu, 'ecr', 'ecrImageSigningNotConfigured', repo, misconfigure, fix)
        res = runCheck(emu, 'ecr', 'ecrImageSigningNotConfigured', repo)
        msgs = [v['ecrImageSigningNotConfigured'][1] for v in res.results.values()]
        assert any('Notation-OCI' in m and profile in m for m in msgs), msgs
    finally:
        for p in (profile, f'{profile}lambda'):
            try:
                signer.cancel_signing_profile(profileName=p)
            except Exception:
                pass
        if original and original.get('rules'):
            ecr.put_signing_configuration(signingConfiguration=original)
        ecr.delete_repository(repositoryName=repo, force=True)
