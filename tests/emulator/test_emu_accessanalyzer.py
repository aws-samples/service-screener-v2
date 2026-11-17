"""Flag -> fix -> re-run tests for accessanalyzer checks the emulator supports."""
from tests.emulator.conftest import assertFlagFixCycle, runCheck

EXTERNAL_ACCOUNT = '111122223333'


def test_ram_share_external_principals(emu, uid):
    ram = emu.client('ram')
    name = f'ss-test-{uid}'
    arn = ram.create_resource_share(name=name, allowExternalPrincipals=False)['resourceShare']['resourceShareArn']
    try:
        def misconfigure():
            ram.update_resource_share(resourceShareArn=arn, allowExternalPrincipals=True)
            ram.associate_resource_share(resourceShareArn=arn, principals=[EXTERNAL_ACCOUNT])

        def fix():
            ram.disassociate_resource_share(resourceShareArn=arn, principals=[EXTERNAL_ACCOUNT])
            ram.update_resource_share(resourceShareArn=arn, allowExternalPrincipals=False)

        assertFlagFixCycle(emu, 'accessanalyzer', 'ramShareExternalPrincipals', name, misconfigure, fix)
    finally:
        ram.delete_resource_share(resourceShareArn=arn)


def test_ram_share_allow_external_without_external_principal_passes(emu, uid):
    """allowExternalPrincipals alone (no external principal associated) is not a finding."""
    ram = emu.client('ram')
    name = f'ss-test-{uid}'
    arn = ram.create_resource_share(name=name, allowExternalPrincipals=True)['resourceShare']['resourceShareArn']
    try:
        st = runCheck(emu, 'accessanalyzer', 'ramShareExternalPrincipals', name).statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        ram.delete_resource_share(resourceShareArn=arn)


def test_ram_share_standard_feature_set_passes(emu, uid):
    """The emulator only creates STANDARD shares (CREATED_FROM_POLICY cannot be
    produced and promote is NotImplemented); the flag side is in
    tests/test_stub_accessanalyzer.py."""
    ram = emu.client('ram')
    name = f'ss-test-{uid}'
    arn = ram.create_resource_share(name=name)['resourceShare']['resourceShareArn']
    try:
        st = runCheck(emu, 'accessanalyzer', 'ramSharesNotPromoted', name).statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        ram.delete_resource_share(resourceShareArn=arn)


def test_unused_findings_not_implemented_is_not_a_pass(emu, uid):
    """list_findings_v2 is NotImplemented in the emulator: the check must report
    'Unable to evaluate', never PASS."""
    aa = emu.client('accessanalyzer')
    name = f'ss-test-{uid}'
    aa.create_analyzer(analyzerName=name, type='ACCOUNT_UNUSED_ACCESS')
    try:
        res = runCheck(emu, 'accessanalyzer', 'aaUnusedAccessFindingsOpen', 'Account')
        v = res.results['AccessAnalyzer::Account']['aaUnusedAccessFindingsOpen']
        assert v[0] == 0 and v[1].startswith('Unable to evaluate'), v
    finally:
        aa.delete_analyzer(analyzerName=name)
