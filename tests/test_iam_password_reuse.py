"""passwordPolicyReuse must flag WEAK reuse prevention, not strong.

Regression: since f771a1a the check set passwordPolicyReuse=[-1] when
PasswordReusePrevention >= 6 (the compliant state) and stayed silent when it
was below 6 or not configured.
"""
import pytest

from services.iam.drivers.IamAccount import IamAccount


def _score(policy):
    acct = object.__new__(IamAccount)
    acct.results = {}
    acct.passwordPolicyScoring(policy)
    return acct.results


BASE = {'MinimumPasswordLength': 14, 'RequireSymbols': True, 'RequireNumbers': True,
        'RequireUppercaseCharacters': True, 'RequireLowercaseCharacters': True,
        'AllowUsersToChangePassword': True, 'ExpirePasswords': False}


@pytest.mark.parametrize('reuse', [6, 24])
def test_strong_reuse_prevention_not_flagged(reuse):
    assert 'passwordPolicyReuse' not in _score({**BASE, 'PasswordReusePrevention': reuse})


@pytest.mark.parametrize('reuse', [1, 5])
def test_weak_reuse_prevention_flagged(reuse):
    assert _score({**BASE, 'PasswordReusePrevention': reuse})['passwordPolicyReuse'] == [-1, reuse]


def test_reuse_prevention_not_configured_flagged():
    # IAM omits PasswordReusePrevention when reuse prevention is off.
    assert _score(dict(BASE))['passwordPolicyReuse'][0] == -1
