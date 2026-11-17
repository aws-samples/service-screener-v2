"""Flag -> fix -> re-run tests for Route 53 Resolver DNS Firewall content checks."""
from tests.emulator.conftest import assertFlagFixCycle, runCheck


def test_route53_dns_firewall_no_block_rules(emu, uid):
    r = emu.client('route53resolver')
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.77.0.0/16')['Vpc']['VpcId']
    dl = r.create_firewall_domain_list(CreatorRequestId=f'dl-{uid}', Name=f'ss-dl-{uid}')['FirewallDomainList']['Id']
    r.update_firewall_domains(FirewallDomainListId=dl, Operation='ADD', Domains=['bad.example.com.'])
    rg = r.create_firewall_rule_group(CreatorRequestId=f'rg-{uid}', Name=f'ss-rg-{uid}')['FirewallRuleGroup']['Id']
    assoc = None
    try:
        def misconfigure():
            nonlocal assoc
            r.create_firewall_rule(CreatorRequestId=f'r-{uid}', FirewallRuleGroupId=rg,
                                   FirewallDomainListId=dl, Priority=100, Action='ALERT',
                                   Name=f'ss-r-{uid}')
            assoc = r.associate_firewall_rule_group(
                CreatorRequestId=f'a-{uid}', FirewallRuleGroupId=rg, VpcId=vpc,
                Priority=101, Name=f'ss-a-{uid}')['FirewallRuleGroupAssociation']['Id']

        def fix():
            r.update_firewall_rule(FirewallRuleGroupId=rg, FirewallDomainListId=dl,
                                   Action='BLOCK', BlockResponse='NODATA')

        before, after = assertFlagFixCycle(emu, 'route53', 'dnsFirewallNoBlockRules', vpc, misconfigure, fix)
        assert all(k.endswith(vpc) for k in before)
    finally:
        if assoc:
            try:
                r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=assoc)
            except Exception:
                pass
        for fn in (lambda: r.delete_firewall_rule(FirewallRuleGroupId=rg, FirewallDomainListId=dl),
                   lambda: r.delete_firewall_rule_group(FirewallRuleGroupId=rg),
                   lambda: r.delete_firewall_domain_list(FirewallDomainListId=dl),
                   lambda: ec2.delete_vpc(VpcId=vpc)):
            try:
                fn()
            except Exception:
                pass


def test_route53_dns_firewall_alert_group_plus_block_group_passes(emu, uid):
    """A VPC with an ALERT-only group AND a BLOCK group is enforcing -> not flagged."""
    r = emu.client('route53resolver')
    ec2 = emu.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.78.0.0/16')['Vpc']['VpcId']
    dl = r.create_firewall_domain_list(CreatorRequestId=f'dl2-{uid}', Name=f'ss-dl2-{uid}')['FirewallDomainList']['Id']
    rgs, assocs = [], []
    try:
        for i, action in enumerate(('ALERT', 'BLOCK')):
            rg = r.create_firewall_rule_group(CreatorRequestId=f'rg{i}-{uid}', Name=f'ss-rg{i}-{uid}')['FirewallRuleGroup']['Id']
            rgs.append(rg)
            kw = {'BlockResponse': 'NODATA'} if action == 'BLOCK' else {}
            r.create_firewall_rule(CreatorRequestId=f'r{i}-{uid}', FirewallRuleGroupId=rg,
                                   FirewallDomainListId=dl, Priority=100, Action=action,
                                   Name=f'ss-r{i}-{uid}', **kw)
            assocs.append(r.associate_firewall_rule_group(
                CreatorRequestId=f'a{i}-{uid}', FirewallRuleGroupId=rg, VpcId=vpc,
                Priority=101 + i, Name=f'ss-a{i}-{uid}')['FirewallRuleGroupAssociation']['Id'])
        st = runCheck(emu, 'route53', 'dnsFirewallNoBlockRules', vpc).statuses()
        assert st and all(s == 1 for s in st.values()), st
    finally:
        for a in assocs:
            try:
                r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=a)
            except Exception:
                pass
        for rg in rgs:
            for fn in (lambda: r.delete_firewall_rule(FirewallRuleGroupId=rg, FirewallDomainListId=dl),
                       lambda: r.delete_firewall_rule_group(FirewallRuleGroupId=rg)):
                try:
                    fn()
                except Exception:
                    pass
        for fn in (lambda: r.delete_firewall_domain_list(FirewallDomainListId=dl),
                   lambda: ec2.delete_vpc(VpcId=vpc)):
            try:
                fn()
            except Exception:
                pass
