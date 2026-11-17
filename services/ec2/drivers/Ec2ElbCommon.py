import threading

import boto3
import botocore

import constants as _C

from utils.Config import Config
from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2SecGroup import Ec2SecGroup

class Ec2ElbCommon(Evaluator):
    def __init__(self, elb, sgList, elbClient, wafv2Client):
        super().__init__()
        self.elb = elb
        self.sgList = sgList
        self.wafv2Client = wafv2Client
        self.elbClient = elbClient

        self._resourceName = elb['LoadBalancerArn']

        self.init()

        self._lock = threading.RLock()
        self._listenersCache = None
        self._attributesCache = None

    def _getListeners(self):
        """Memoized, paginated describe_listeners - several checks need the
        listeners of the same LB, no need to fetch more than once."""
        with self._lock:
            if self._listenersCache is None:
                listeners = []
                paginator = self.elbClient.get_paginator('describe_listeners')
                for page in paginator.paginate(LoadBalancerArn = self.elb['LoadBalancerArn']):
                    listeners.extend(page.get('Listeners', []))
                self._listenersCache = listeners
            return self._listenersCache

    def _getAttributes(self):
        """Memoized describe_load_balancer_attributes as {key: value}."""
        with self._lock:
            if self._attributesCache is None:
                results = self.elbClient.describe_load_balancer_attributes(
                    LoadBalancerArn = self.elb['LoadBalancerArn']
                )
                self._attributesCache = {a['Key']: a.get('Value') for a in results.get('Attributes', [])}
            return self._attributesCache

    def _getSslPolicyProtocols(self, policyName):
        """SslProtocols of an elbv2 security policy. The full policy table is
        fetched once per region and cached; unknown names are looked up directly.
        Returns None if the policy cannot be resolved."""
        cacheKey = 'ec2::elbv2SslPolicies::' + self.elbClient.meta.region_name
        table = Config.get(cacheKey, None)
        if table is None:
            table = {}
            paginator = self.elbClient.get_paginator('describe_ssl_policies')
            for page in paginator.paginate():
                for pol in page.get('SslPolicies', []):
                    table[pol.get('Name')] = pol.get('SslProtocols', [])
            Config.set(cacheKey, table)

        if policyName in table:
            return table[policyName]
        try:
            resp = self.elbClient.describe_ssl_policies(Names = [policyName])
            for pol in resp.get('SslPolicies', []):
                if pol.get('Name') == policyName:
                    table[policyName] = pol.get('SslProtocols', [])
                    return table[policyName]
        except botocore.exceptions.ClientError:
            pass
        return None

    # checks
    def _checkListenerPortEncrypt(self):
        listeners = self._getListeners()
        for listener in listeners:
            if listener['Port'] in Ec2SecGroup.NONENCRYPT_PORT:
                self.results['ELBListenerInsecure'] = [-1, listener['Port']]
        
        return
    
    def _checkSecurityGroupNo(self):
        elb = self.elb
        
        if 'SecurityGroups' in elb and len(elb['SecurityGroups']) > 50:
            self.results['ELBListenerInsecure'] = [-1, len(elb['SecurityGroups'])]
            
        return
    
    def _checkCrossZoneLB(self):
        attrs = self._getAttributes()
        if attrs.get('load_balancing.cross_zone.enabled') == 'false':
            self.results['ELBCrossZone'] = [-1, 'Disabled']
        
        return
    
    def _checkWAFEnabled(self):
        if self.elb['Type'] != 'application':
            return
        
        wafv2Client = self.wafv2Client
        arn = self.elb['LoadBalancerArn']
        
        results = wafv2Client.get_web_acl_for_resource(
            ResourceArn = arn
        )
        
        if 'WebACL' not in results:
            self.results['ELBEnableWAF'] = [-1, 'Disabled']
        
        return
    
    def _checkALBSGPortMatch(self):
        ## NLB not supported
        if self.elb['Type'] != 'application':
            return
        
        listeners = self._getListeners()

        portList = []
        for listener in listeners:
            portList.append(listener.get('Port'))
            
        unmatchPortList = portList
        
        flaggedSGs = []
        for group in self.sgList:
            for perm in group.get('IpPermissions'):
                if perm.get('FromPort') != perm.get('ToPort') or perm.get('FromPort') not in portList:
                    flaggedSGs.append(group.get('GroupId'))
        
        if len(flaggedSGs) > 0:
            self.results['ELBSGRulesMatch'] = [-1, ', '.join(flaggedSGs)]
        
        return

    def _checkELBMultiAZ(self):
        """Check if load balancer is configured with multiple availability zones"""
        elb = self.elb
        
        # Get availability zones for the load balancer
        availabilityZones = elb.get('AvailabilityZones', [])
        
        # Count unique AZs
        uniqueAZs = set()
        for az in availabilityZones:
            if isinstance(az, dict):
                # For ALB/NLB, AvailabilityZones is a list of dicts with 'ZoneName'
                zoneName = az.get('ZoneName')
                if zoneName:
                    uniqueAZs.add(zoneName)
            else:
                # For Classic LB, it might be a simple list
                uniqueAZs.add(az)
        
        # Flag if fewer than 2 AZs
        if len(uniqueAZs) < 2:
            self.results['ELBMultiAZ'] = [-1, f"{len(uniqueAZs)} AZ"]
        
        return

    WEAK_TLS_PROTOCOLS = ('SSLv3', 'TLSv1', 'TLSv1.1')

    def _checkElbAccessLogsDisabled(self):
        """Access logs (access_logs.s3.enabled). ALB: always applicable.
        NLB: access logs only record TLS listener traffic, so only evaluated when
        the NLB has a TLS listener. GWLB: access logs not supported (no result)."""
        key = 'elbAccessLogsDisabled'
        lbType = self.elb.get('Type')
        try:
            if lbType == 'network':
                if not any(l.get('Protocol') == 'TLS' for l in self._getListeners()):
                    return
            elif lbType != 'application':
                return
            attrs = self._getAttributes()
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return

        enabled = attrs.get('access_logs.s3.enabled')
        if enabled == 'true':
            bucket = attrs.get('access_logs.s3.bucket') or ''
            self.results[key] = [1, f"Enabled{' (s3://' + bucket + ')' if bucket else ''}"]
        elif enabled == 'false':
            self.results[key] = [-1, 'Disabled']
        else:
            self.results[key] = [0, 'Unable to evaluate (access_logs.s3.enabled attribute not returned)']

    def _checkElbTlsPolicyOutdated(self):
        """HTTPS (ALB) / TLS (NLB) listeners whose security policy still allows
        TLS 1.0/1.1 (or SSLv3), resolved from describe_ssl_policies SslProtocols."""
        key = 'elbTlsPolicyOutdated'
        try:
            listeners = [l for l in self._getListeners() if l.get('Protocol') in ('HTTPS', 'TLS')]
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return
        if not listeners:
            return

        weak, unknown, good = [], [], []
        try:
            for l in listeners:
                label = f"{l.get('Protocol')}:{l.get('Port')}"
                policy = l.get('SslPolicy')
                if not policy:
                    unknown.append(f"{label} (no SslPolicy returned)")
                    continue
                protocols = self._getSslPolicyProtocols(policy)
                if protocols is None:
                    unknown.append(f"{label} ({policy} not resolvable)")
                    continue
                bad = [p for p in protocols if p in self.WEAK_TLS_PROTOCOLS]
                if bad:
                    weak.append(f"{label} {policy} allows {'/'.join(bad)}")
                else:
                    good.append(f"{label} {policy}")
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return

        if weak:
            self.results[key] = [-1, '; '.join(weak)]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate (' + '; '.join(unknown) + ')']
        else:
            self.results[key] = [1, '; '.join(good)]
