"""Flag -> fix -> re-run emulator tests for Amazon Inspector checks.

Only inspectorSuppressionBroad is emulator-testable: the emulator implements
inspector2 create_filter/update_filter/list_filters/delete_filter but not
list_findings, describe_organization_configuration or list_members (those
checks are covered by tests/test_stub_inspector.py).
"""
from tests.emulator.conftest import assertFlagFixCycle


def test_inspector_suppression_broad(emu, uid):
    ins = emu.client('inspector2')
    name = f'ss-test-supp-{uid}'
    state = {}
    try:
        def misconfigure():
            r = ins.create_filter(
                name=name, action='SUPPRESS',
                filterCriteria={'severity': [
                    {'comparison': 'EQUALS', 'value': 'LOW'},
                    {'comparison': 'EQUALS', 'value': 'MEDIUM'}]})
            state['arn'] = r['arn']

        def fix():
            ## Scope the rule to one accepted vulnerability on tagged resources.
            ins.update_filter(
                filterArn=state['arn'],
                filterCriteria={
                    'severity': [{'comparison': 'EQUALS', 'value': 'LOW'}],
                    'vulnerabilityId': [{'comparison': 'EQUALS', 'value': 'CVE-2023-0001'}],
                })

        before, after = assertFlagFixCycle(emu, 'inspector', 'inspectorSuppressionBroad',
                                           'Account', misconfigure, fix)
    finally:
        if state.get('arn'):
            try:
                ins.delete_filter(arn=state['arn'])
            except Exception:
                pass
