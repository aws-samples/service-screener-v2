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
        if inProtocol == 'both':
            protocolArr = ['tcp', 'udp']
        elif inProtocol == 'all':
            protocolArr = [-1]
        else:
            protocolArr = [inProtocol]
    
        openIp = []
        for perm in secGroup['IpPermissions']:
            for ipRange in perm['IpRanges']:
                if ipRange['CidrIp'] == '0.0.0.0/0':
                    openIp.append(ipRange['CidrIp'])
                    break
            
            for ipRange in perm['Ipv6Ranges']:
                if ipRange['CidrIpv6'] == '::/0':
                    openIp.append(ipRange['CidrIpv6'])
                    break
            
            if len(openIp) > 0:
                if perm['IpProtocol'] == '-1':
                    currentIp = ', '.join(openIp)
                    self.results[ruleName] = [-1, currentIp]
                    return
                else:
                    for port in inPortList:
                        if self.hasPort(port, perm['FromPort'], perm['ToPort']):
                            currentIp = ', '.join(openIp)
                            self.results[ruleName] = [-1, currentIp]
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