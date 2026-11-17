import boto3
import botocore

from services.Evaluator import Evaluator

class Ec2NACL(Evaluator):
    def __init__(self, nacl, ec2Client):
        super().__init__()
        self.nacl = nacl
        self.ec2Client = ec2Client

        self._resourceName = nacl['NetworkAclId']

        self.init()
        return
    
    def _checkNACLAssociation(self):
        if not self.nacl['Associations']:
            self.results['NACLAssociated'] = [-1, self.nacl['NetworkAclId']]
            
        return
        
    def _checkNACLIngressSensitivePort(self):
        sensitivePort = [22, 3389]
        for entry in self.nacl['Entries']:
            if entry['RuleAction'] == 'allow' and entry['Egress'] == False:
                if ('CidrBlock' in entry and entry['CidrBlock'] == '0.0.0.0/0') or ('Ipv6CidrBlock' in entry and entry['Ipv6CidrBlock'] == '::/0'):
                    if 'PortRange' in entry:
                        portFrom = entry['PortRange']['From']
                        portTo = entry['PortRange']['To']
                        for port in sensitivePort:
                            if portFrom <= port and portTo >= port:
                                self.results['NACLSensitivePort'] = [-1, self.nacl['NetworkAclId']]
                                return
                            
        return

    def _checkNaclAllowAllIngress(self):
        """Custom (non-default) NACL associated with subnets whose inbound rules allow
        all protocols / all ports from 0.0.0.0/0 or ::/0 with no lower-numbered deny
        rule for that address family - the NACL adds no subnet-level filtering.
        Default NACLs allow all traffic by design and are reported as INFO only.
        Rules are evaluated in rule-number order; 32767 is the implicit deny."""
        key = 'naclAllowAllIngress'
        nacl = self.nacl
        if not nacl.get('Associations'):
            return  # not associated with any subnet: no effect (NACLAssociated)
        ingress = sorted((e for e in nacl.get('Entries', []) or []
                          if not e.get('Egress') and e.get('RuleNumber', 0) < 32767),
                         key=lambda e: e.get('RuleNumber', 0))
        open_ = []
        for famKey, anyCidr in (('CidrBlock', '0.0.0.0/0'), ('Ipv6CidrBlock', '::/0')):
            for e in ingress:
                if famKey not in e:
                    continue
                if e.get('RuleAction') == 'deny':
                    break  # some traffic of this family is filtered before any allow-all
                if e.get('RuleAction') == 'allow' and str(e.get('Protocol')) == '-1' and e.get(famKey) == anyCidr:
                    open_.append(f"rule {e.get('RuleNumber')} allows all traffic from {anyCidr}")
                    break
        subnets = len(nacl.get('Associations') or [])
        if not open_:
            self.results[key] = [1, 'Inbound rules restrict traffic']
        elif nacl.get('IsDefault'):
            self.results[key] = [0, f"Default NACL allows all inbound traffic by design ({'; '.join(open_)}); {subnets} subnet(s) rely on security groups only"]
        else:
            self.results[key] = [-1, f"{'; '.join(open_)} with no preceding deny rule; associated with {subnets} subnet(s)"]
