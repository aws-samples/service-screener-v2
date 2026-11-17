from services.Evaluator import Evaluator

ANY_DEST = ('0.0.0.0/0', '::/0')


def classifyDataTierEni(eni):
    """'RDS' | 'ElastiCache' | 'Redshift' | 'OpenSearch' | None for network interfaces
    owned by managed data stores (RDS also covers Aurora, Neptune and DocumentDB)."""
    requester = eni.get('RequesterId') or ''
    desc = eni.get('Description') or ''
    if requester == 'amazon-rds' or desc == 'RDSNetworkInterface':
        return 'RDS'
    if requester == 'amazon-elasticache' or desc.startswith('ElastiCache '):
        return 'ElastiCache'
    if requester == 'amazon-redshift' or desc == 'RedshiftNetworkInterface':
        return 'Redshift'
    if requester == 'amazon-elasticsearch' or desc.startswith('ES '):
        return 'OpenSearch'
    return None


def unrestrictedEgress(secGroup):
    """Egress permissions allowing all traffic (or all TCP/UDP ports) to 0.0.0.0/0 or ::/0."""
    out = []
    for perm in secGroup.get('IpPermissionsEgress', []) or []:
        proto = str(perm.get('IpProtocol'))
        if proto == '-1':
            what = 'all traffic'
        elif proto in ('tcp', 'udp') and perm.get('FromPort') == 0 and perm.get('ToPort') == 65535:
            what = f"all {proto} ports"
        else:
            continue
        dests = [r.get('CidrIp') for r in perm.get('IpRanges', []) or []] + \
                [r.get('CidrIpv6') for r in perm.get('Ipv6Ranges', []) or []]
        for d in dests:
            if d in ANY_DEST:
                out.append(f"{what} to {d}")
    return out


class Ec2DataTierSecGroup(Evaluator):
    """Security group attached to a managed data store's network interface
    (RDS / Aurora / Neptune / DocumentDB, ElastiCache, Redshift, OpenSearch).
    usage: {kind: [eniId, ...]}"""

    def __init__(self, secGroup, usage):
        super().__init__()
        self.secGroup = secGroup
        self.usage = usage or {}

        self._resourceName = secGroup['GroupId']

        self.init()

    def _checkSgUnrestrictedEgress(self):
        key = 'sgUnrestrictedEgress'
        kinds = ', '.join(f"{k} ({len(v)} ENI)" for k, v in sorted(self.usage.items()))
        rules = unrestrictedEgress(self.secGroup)
        if rules:
            self.results[key] = [-1, f"Data-tier SG used by {kinds} allows {'; '.join(rules)}"]
        else:
            self.results[key] = [1, f"Data-tier SG used by {kinds}: egress restricted"]
