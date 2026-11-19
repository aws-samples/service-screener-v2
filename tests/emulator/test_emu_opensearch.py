"""Flag -> fix -> re-run tests for opensearch.AccessPolicyPublic against the AWS Emulator."""
import json
import time

from tests.emulator.conftest import assertFlagFixCycle, runCheck


def _waitIdle(osc, name, timeout=120):
    # Opensearch.getResources() skips domains that are still Processing.
    end = time.time() + timeout
    while time.time() < end:
        if not osc.describe_domain(DomainName=name)['DomainStatus'].get('Processing'):
            return
        time.sleep(1)
    raise AssertionError(f'domain {name} still processing after {timeout}s')


def _policy(name, statement_extra=None):
    stmt = {'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'es:*',
            'Resource': f'arn:aws:es:us-east-1:000000000000:domain/{name}/*'}
    stmt.update(statement_extra or {})
    return json.dumps({'Version': '2012-10-17', 'Statement': [stmt]})


def _createDomain(osc, name, policy):
    osc.create_domain(DomainName=name, EngineVersion='OpenSearch_2.11',
                      ClusterConfig={'InstanceType': 'r6g.large.search', 'InstanceCount': 1},
                      EBSOptions={'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10},
                      AccessPolicies=policy)
    _waitIdle(osc, name)


def _setPolicy(osc, name, policy):
    _waitIdle(osc, name)
    osc.update_domain_config(DomainName=name, AccessPolicies=policy)
    _waitIdle(osc, name)


def test_opensearch_access_policy_public_ip_scoped_fix(emu, uid):
    osc = emu.client('opensearch')
    name = f'ss-os-{uid}'
    # Start from an IAM-principal-only policy, then make it public.
    _createDomain(osc, name, json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::000000000000:root'},
        'Action': 'es:*', 'Resource': f'arn:aws:es:us-east-1:000000000000:domain/{name}/*'}]}))
    try:
        def misconfigure():
            _setPolicy(osc, name, _policy(name))

        def fix():
            _setPolicy(osc, name, _policy(name, {'Condition': {'IpAddress': {'aws:SourceIp': ['203.0.113.0/24']}}}))

        assertFlagFixCycle(emu, 'opensearch', 'AccessPolicyPublic', name, misconfigure, fix)

        # 0.0.0.0/0 is not a restriction -> flagged again.
        _setPolicy(osc, name, _policy(name, {'Condition': {'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}}}))
        st = runCheck(emu, 'opensearch', 'AccessPolicyPublic', name).statuses()
        assert st and all(s == -1 for s in st.values()), st

        # Removing the resource policy entirely -> not flagged.
        _setPolicy(osc, name, '')
        st = runCheck(emu, 'opensearch', 'AccessPolicyPublic', name).statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        try:
            osc.delete_domain(DomainName=name)
        except Exception:
            pass


def test_opensearch_access_policy_public_list_principal_org_fix(emu, uid):
    osc = emu.client('opensearch')
    name = f'ss-os2-{uid}'
    _createDomain(osc, name, '')
    try:
        def misconfigure():
            _setPolicy(osc, name, _policy(name, {'Principal': '*', 'Action': ['es:ESHttpGet']}))

        def fix():
            _setPolicy(osc, name, _policy(name, {
                'Principal': '*', 'Action': ['es:ESHttpGet'],
                'Condition': {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123def4'}}}))

        assertFlagFixCycle(emu, 'opensearch', 'AccessPolicyPublic', name, misconfigure, fix)
    finally:
        try:
            osc.delete_domain(DomainName=name)
        except Exception:
            pass


def test_opensearch_fgac_open_policy_is_info(emu, uid):
    """Open es:ESHttp* policy is -1 without FGAC; with FGAC (anonymous auth disabled) every
    request must authenticate, so it is INFO (network exposure only), never PASS or High FAIL."""
    osc = emu.client('opensearch')
    name = f'ss-os3-{uid}'
    openPolicy = _policy(name, {'Action': 'es:ESHttp*'})
    _createDomain(osc, name, openPolicy)
    fgacName = f'ss-os4-{uid}'
    try:
        st = runCheck(emu, 'opensearch', 'AccessPolicyPublic', name).statuses()
        assert st and all(s == -1 for s in st.values()), st

        osc.create_domain(DomainName=fgacName, EngineVersion='OpenSearch_2.11',
                          ClusterConfig={'InstanceType': 'r6g.large.search', 'InstanceCount': 1},
                          EBSOptions={'EBSEnabled': True, 'VolumeType': 'gp3', 'VolumeSize': 10},
                          NodeToNodeEncryptionOptions={'Enabled': True},
                          EncryptionAtRestOptions={'Enabled': True},
                          DomainEndpointOptions={'EnforceHTTPS': True},
                          AdvancedSecurityOptions={'Enabled': True, 'InternalUserDatabaseEnabled': True,
                                                   'MasterUserOptions': {'MasterUserName': 'admin',
                                                                         'MasterUserPassword': 'Passw0rd!Passw0rd'}},
                          AccessPolicies=_policy(fgacName, {'Action': 'es:ESHttp*'}))
        _waitIdle(osc, fgacName)
        st = runCheck(emu, 'opensearch', 'AccessPolicyPublic', fgacName).statuses()
        assert st and all(s == 0 for s in st.values()), st
    finally:
        for n in (name, fgacName):
            try:
                osc.delete_domain(DomainName=n)
            except Exception:
                pass
