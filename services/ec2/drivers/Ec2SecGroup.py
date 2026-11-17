import ipaddress

import boto3
import botocore

from utils.Config import Config
from services.Service import Service
from services.Evaluator import Evaluator

class Ec2SecGroup(Evaluator):
    SENSITIVE_PORT = {
            'DNS':{
                'protocol': 'both',
                'port': [53]
            },
            'Mongo': {
                'protocol': 'tcp',
                'port': [27017, 27018, 27019]
            },
            'MSSQL': {
                'protocol': 'tcp',
                'port': [1433]
            },
            'MySQL': {
                'protocol': 'tcp',
                'port': [3306]
            },
            'NFS': {
                'protocol': 'tcp',
                'port': [2049]
            },
            'Oracle DB': {
                'protocol': 'tcp',
                'port': [1521]
            },
            'PostgreSQL': {
                'protocol': 'tcp',
                'port': [5432]
            },
            'RDP': {
                'protocol': 'tcp',
                'port': [3389]
            },
            'SMTP': {
                'protocol': 'tcp',
                'port': [25]
            },
            'SMPTS': {
                'protocol': 'tcp',
                'port': [465]
            },
            'SSH': {
                'protocol': 'tcp',
                'port': [22]
            }
        }
        
    # Ranges not routable on the internet: broad rules inside them are left alone.
    NON_PUBLIC_NETS = [ipaddress.ip_network(n) for n in
                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
                        'fc00::/7', 'fe80::/10')]
    BROAD_V4_PREFIX = 16   # shorter than /16 (> 65,536 addresses)
    BROAD_V6_PREFIX = 32   # shorter than /32 (more than an RIR allocation)

    NONENCRYPT_PORT = [
        21,
        80
    ];
    
    def __init__(self, secGroup, ec2Client):
        super().__init__()
        self.secGroup = secGroup
        self.ec2Client = ec2Client

        self._resourceName = secGroup['GroupId']

        self.init()
    
    # supporint function
    
    def hasPort(self, port, fromPort, toPort):
        if port in range(fromPort, toPort+1):
            return True
        
        return False
    
    def checkPortOpenToAll(self, secGroup, ruleName, inProtocol, inPortList):
        """Flag when one ingress permission both matches the protocol / a port in
        inPortList and is open to 0.0.0.0/0 or ::/0. Each permission is evaluated on
        its own (an open CIDR on one permission must not taint another permission's
        ports), and a tcp-only port is not matched by a udp permission."""
        if inProtocol == 'both':
            protocolArr = ['tcp', 'udp']
        elif inProtocol == 'all':
            protocolArr = ['-1']
        else:
            protocolArr = [inProtocol]

        for perm in secGroup['IpPermissions']:
            openIp = []
            for ipRange in perm.get('IpRanges', []):
                if ipRange.get('CidrIp') == '0.0.0.0/0':
                    openIp.append(ipRange['CidrIp'])
                    break

            for ipRange in perm.get('Ipv6Ranges', []):
                if ipRange.get('CidrIpv6') == '::/0':
                    openIp.append(ipRange['CidrIpv6'])
                    break

            if not openIp:
                continue
            permProtocol = str(perm.get('IpProtocol'))
            if permProtocol == '-1':
                self.results[ruleName] = [-1, ', '.join(openIp)]
                return
            if permProtocol not in protocolArr or 'FromPort' not in perm or 'ToPort' not in perm:
                continue
            for port in inPortList:
                if self.hasPort(port, perm['FromPort'], perm['ToPort']):
                    self.results[ruleName] = [-1, ', '.join(openIp)]
                    return

        return

    def checkAllPortOpen(self, secGroup, ruleName, inProtocol):
        if inProtocol == 'all':
            inProtocol = -1
        
            
        
        for perm in secGroup['IpPermissions']:
            if str(inProtocol) != str(perm['IpProtocol']):
                continue
            
            if inProtocol == -1:
                self.results[ruleName] = [-1, perm['IpProtocol']]
                return
            else:
                if perm['FromPort'] == 0 and perm['ToPort'] == 65535:
                    self.results[ruleName] = [-1, perm['IpProtocol']]
                    return
        return
            
    # checks
    def _checkDefaultSGInUsed(self):
        group = self.secGroup
        if group['GroupName'] == 'default':
            if 'inUsed' in group and group['inUsed'] == 'False':
                return
            
            self.results['SGDefaultInUsed'] = [-1, group['GroupName']]
            
        return
    
    def _checkSensitivePortOpenToAll(self):
        ruleName = 'SGSensitivePortOpenToAll'
        portList = self.SENSITIVE_PORT
        
        for port in portList.values():
            self.checkPortOpenToAll(self.secGroup, ruleName, port['protocol'], port['port'])
            
        return
    
    def _checkTCPAllPortOpen(self):
        ruleName = 'SGAllTCPOpen'
        protocol = 'tcp'
        self.checkAllPortOpen(self.secGroup, ruleName,protocol)
        return
        
    def _checkUDPAppPortOpen(self):
        ruleName = 'SGAllUDPOpen'
        protocol = 'udp'
        self.checkAllPortOpen(self.secGroup, ruleName,protocol)
        return
    
    def _checkAllPortOpen(self):
        ruleName = 'SGAllPortOpen'
        protocol = 'all'
        self.checkAllPortOpen(self.secGroup, ruleName,protocol)
        return
        
    def _checkAllPortOpenToAll(self):
        port = [-1]
        protocol = 'all'
        ruleName = 'SGAllPortOpenToAll'
        self.checkPortOpenToAll(self.secGroup, ruleName, protocol, port)
        
        return
    
    def _checkEncryptionInTransit(self):
        group = self.secGroup
        ruleName = 'SGEncryptionInTransit';
        
        for perm in group['IpPermissions']:
            if perm['IpProtocol'] == '-1':
                self.results[ruleName] = [-1, "All port allowed"]
                return
            
            fromPort = perm['FromPort']
            toPort = perm['ToPort']
            
            for port in self.NONENCRYPT_PORT:
                if port == fromPort or port == toPort or port in range(fromPort, toPort +1):
                    self.results[ruleName] = [-1, f"Port: {port}"]
                    return
        return

    def _checkSGRulesNumber(self):
        group = self.secGroup
        ruleNum = len(group['IpPermissions']) + len(group['IpPermissionsEgress'])
        if group.get('GroupName') == 'default':
            if ruleNum > 0:
                self.results['SGDefaultDisallowTraffic'] = [-1, '']
        else:
            if ruleNum >= 50:
                self.results['SGRuleNumber'] = [-1, ruleNum]
            
        return

    def _checkSgIngressBroadCidr(self):
        """Ingress from very broad public CIDRs that are not 0.0.0.0/0 / ::/0
        (those are evaluated by SGSensitivePortOpenToAll / SGAllPortOpenToAll):
        IPv4 prefixes shorter than /16 and IPv6 prefixes shorter than /32 that are not
        wholly inside RFC 1918 / CGNAT / link-local / ULA space (e.g. 0.0.0.0/1,
        52.0.0.0/8, 2000::/3). Broad private ranges such as 10.0.0.0/8 are not flagged."""
        key = 'sgIngressBroadCidr'
        broad = []
        for perm in self.secGroup.get('IpPermissions', []) or []:
            proto = str(perm.get('IpProtocol'))
            if proto == '-1':
                what = 'all traffic'
            elif 'FromPort' in perm and perm.get('FromPort') == perm.get('ToPort'):
                what = f"{proto} {perm.get('FromPort')}"
            else:
                what = f"{proto} {perm.get('FromPort')}-{perm.get('ToPort')}"
            cidrs = [r.get('CidrIp') for r in perm.get('IpRanges', []) or []] + \
                    [r.get('CidrIpv6') for r in perm.get('Ipv6Ranges', []) or []]
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except (ValueError, TypeError):
                    continue
                limit = self.BROAD_V4_PREFIX if net.version == 4 else self.BROAD_V6_PREFIX
                if net.prefixlen == 0 or net.prefixlen >= limit:
                    continue
                if any(net.version == n.version and net.subnet_of(n) for n in self.NON_PUBLIC_NETS):
                    continue
                broad.append(f"{what} from {cidr}")
        if broad:
            shown = '; '.join(broad[:5]) + (f" (+{len(broad) - 5} more)" if len(broad) > 5 else '')
            self.results[key] = [-1, shown]
        else:
            self.results[key] = [1, 'No ingress from broad public CIDRs']
