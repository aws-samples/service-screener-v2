import threading

import boto3
import botocore

import constants as _C

from utils.Config import Config
from services.ec2.acctCache import acctKey
from services.Evaluator import Evaluator, _isTransient
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

    def _getListeners(self):
        """Memoized, paginated describe_listeners - several checks need the
        listeners of the same LB, no need to fetch more than once (a failed
        call is cached too and re-raised to each check)."""
        def fetch():
            listeners = []
            paginator = self.elbClient.get_paginator('describe_listeners')
            for page in paginator.paginate(LoadBalancerArn = self.elb['LoadBalancerArn']):
                listeners.extend(page.get('Listeners', []))
            return listeners
        return self._memo(('describe_listeners', self.elb['LoadBalancerArn']), fetch)

    def _getAttributes(self):
        """Memoized describe_load_balancer_attributes as {key: value}."""
        def fetch():
            results = self.elbClient.describe_load_balancer_attributes(
                LoadBalancerArn = self.elb['LoadBalancerArn']
            )
            return {a['Key']: a.get('Value') for a in results.get('Attributes', [])}
        return self._memo(('describe_load_balancer_attributes', self.elb['LoadBalancerArn']), fetch)

    def _getSslPolicyProtocols(self, policyName):
        """SslProtocols of an elbv2 security policy. The full policy table is
        fetched once per region and cached; unknown names are looked up directly.
        Returns None if the policy cannot be resolved."""
        cacheKey = acctKey('ec2::elbv2SslPolicies::' + self.elbClient.meta.region_name)
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

    def _getTrustStore(self, arn):
        """describe_trust_stores for one trust store, memoized per region.
        Returns the TrustStore dict, or {'_error': code}."""
        cacheKey = acctKey('ec2::elbv2TrustStores::' + self.elbClient.meta.region_name)
        with self._lock:
            table = Config.get(cacheKey, None)
            if table is None:
                table = {}
                Config.set(cacheKey, table)
            if arn not in table:
                try:
                    resp = self.elbClient.describe_trust_stores(TrustStoreArns=[arn])
                    found = [t for t in resp.get('TrustStores', []) if t.get('TrustStoreArn') == arn]
                    table[arn] = found[0] if found else {'_error': 'TrustStoreNotFound'}
                except botocore.exceptions.ClientError as e:
                    err = {'_error': e.response['Error']['Code']}
                    if _isTransient(e):   # not cached: the next listener retries
                        return err
                    table[arn] = err
            return table[arn]

    def _checkAlbMtlsOff(self):
        """Mutual TLS on ALB HTTPS listeners.
        Whether mTLS is needed depends on the use case (service-to-service HTTPS
        without client certificates is common, browsers rarely hold certificates),
        so mTLS off is informational (0) for every scheme, and so is passthrough
        (the target must verify the forwarded certificate chain).
        It is a finding (-1) only when mTLS is configured in verify mode but
        weakened with IgnoreClientCertificateExpiry, so the listener accepts
        expired client certificates. Verify mode without that flag passes;
        a missing revocation list is noted in the message."""
        key = 'albMtlsOff'
        if self.elb.get('Type') != 'application':
            return
        try:
            listeners = [l for l in self._getListeners() if l.get('Protocol') == 'HTTPS']
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return
        if not listeners:
            return

        internal = self.elb.get('Scheme') == 'internal'
        off, passthrough, verify, weak = [], [], [], []
        for l in listeners:
            label = f"HTTPS:{l.get('Port')}"
            ma = l.get('MutualAuthentication') or {}
            mode = str(ma.get('Mode') or 'off').lower()
            if mode == 'verify':
                note = []
                tsArn = ma.get('TrustStoreArn')
                if tsArn:
                    ts = self._getTrustStore(tsArn)
                    if '_error' in ts:
                        note.append(f"trust store unreadable ({ts['_error']})")
                    else:
                        if ts.get('Status') and ts.get('Status') != 'ACTIVE':
                            note.append(f"trust store {ts.get('Status')}")
                        if not ts.get('TotalRevokedEntries'):
                            note.append('no revocation list')
                if ma.get('IgnoreClientCertificateExpiry'):
                    weak.append(label + (f" ({', '.join(note)})" if note else ''))
                    continue
                verify.append(label + (f" ({', '.join(note)})" if note else ''))
            elif mode == 'passthrough':
                passthrough.append(label)
            else:
                off.append(label)

        if weak:
            self.results[key] = [-1, f"mTLS verify accepts expired client certificates (IgnoreClientCertificateExpiry) on {', '.join(weak)}"]
        elif off:
            scheme = 'Internal' if internal else 'Internet-facing'
            self.results[key] = [0, f"{scheme} ALB without mTLS on {', '.join(off)} (informational; mTLS applies where clients can hold certificates)"]
        elif passthrough:
            self.results[key] = [0, f"mTLS passthrough on {', '.join(passthrough)}: targets must validate the forwarded client certificate"
                                    + (f"; verify on {', '.join(verify)}" if verify else '')]
        else:
            self.results[key] = [1, f"mTLS verify on {', '.join(verify)}"]

    def _checkAlbTargetGroupPlaintext(self):
        """ALB target groups using HTTP: traffic between the load balancer and the
        targets is not encrypted, even when the listener terminates HTTPS.
        TLS termination at the ALB with HTTP to targets inside the VPC is the
        standard pattern, so that case is informational (0). It is a finding (-1)
        only when an HTTP target group of type 'ip' has registered targets outside
        the load balancer's VPC (AvailabilityZone 'all': peered VPC, on-premises over
        VPN / Direct Connect), where the plaintext hop leaves the VPC."""
        key = 'albTargetGroupPlaintext'
        if self.elb.get('Type') != 'application':
            return
        try:
            groups = []
            paginator = self.elbClient.get_paginator('describe_target_groups')
            for page in paginator.paginate(LoadBalancerArn=self.elb['LoadBalancerArn']):
                groups.extend(page.get('TargetGroups', []))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return

        plainGroups = [g for g in groups if g.get('Protocol') == 'HTTP']
        plain = [g.get('TargetGroupName') for g in plainGroups]
        encrypted = [g.get('TargetGroupName') for g in groups if g.get('Protocol') == 'HTTPS']
        outside, unreadable = [], []
        for g in plainGroups:
            if g.get('TargetType') != 'ip':
                continue
            try:
                resp = self.elbClient.describe_target_health(TargetGroupArn=g['TargetGroupArn'])
            except botocore.exceptions.ClientError as e:
                unreadable.append(f"{g.get('TargetGroupName')} ({e.response['Error']['Code']})")
                continue
            ips = sorted({(d.get('Target') or {}).get('Id') for d in resp.get('TargetHealthDescriptions', [])
                          if str((d.get('Target') or {}).get('AvailabilityZone', '')).lower() == 'all'} - {None})
            if ips:
                shown = ', '.join(ips[:5]) + (f" (+{len(ips) - 5} more)" if len(ips) > 5 else '')
                outside.append(f"{g.get('TargetGroupName')} -> {shown}")

        if outside:
            self.results[key] = [-1, f"HTTP target group(s) with targets outside the VPC (plaintext leaves the VPC): {'; '.join(outside)}"]
        elif unreadable:
            self.results[key] = [0, f"HTTP target group(s): {', '.join(plain)}; Unable to evaluate target location of {', '.join(unreadable)}"]
        elif plain:
            self.results[key] = [0, f"HTTP target group(s) inside the VPC: {', '.join(plain)} (informational; TLS terminated at the ALB - use HTTPS where end-to-end encryption is required)"]
        elif encrypted:
            self.results[key] = [1, f"HTTPS target group(s): {', '.join(encrypted)}"]

    def _checkElbUsesIamOrImportedCert(self):
        """HTTPS/TLS listeners serving a certificate stored in IAM
        (arn:aws:iam::<acct>:server-certificate/...). IAM server certificates are
        not renewed automatically and cannot be managed / monitored like ACM
        certificates. ACM certificates imported by the customer are reported by
        acm.acmImportedCertNoAutoRenewal and are not repeated here."""
        key = 'elbUsesIamOrImportedCert'
        try:
            listeners = [l for l in self._getListeners() if l.get('Protocol') in ('HTTPS', 'TLS')]
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return
        if not listeners:
            return

        iam, unknown = [], []
        for l in listeners:
            label = f"{l.get('Protocol')}:{l.get('Port')}"
            arns = [c.get('CertificateArn') for c in (l.get('Certificates') or []) if c.get('CertificateArn')]
            try:
                for page in self.elbClient.get_paginator('describe_listener_certificates').paginate(ListenerArn=l['ListenerArn']):
                    arns.extend(c.get('CertificateArn') for c in page.get('Certificates', []) if c.get('CertificateArn'))
            except botocore.exceptions.ClientError as e:
                unknown.append(f"{label} additional certificates ({e.response['Error']['Code']})")
            for arn in sorted(set(arns)):
                if ':server-certificate/' in arn:
                    iam.append(f"{label} {arn.split(':server-certificate/', 1)[1]}")

        if iam:
            self.results[key] = [-1, f"IAM server certificate(s) in use: {'; '.join(iam)}"]
        elif unknown:
            self.results[key] = [0, f"Unable to evaluate ({'; '.join(unknown)})"]
        else:
            self.results[key] = [1, f"{len(listeners)} TLS listener(s) use ACM certificates"]
