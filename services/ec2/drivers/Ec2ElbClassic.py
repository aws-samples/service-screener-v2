import threading

import boto3
import botocore

import constants as _C

from utils.Config import Config
from services.Evaluator import Evaluator

class Ec2ElbClassic(Evaluator):
    WEAK_PROTOCOL_ATTRS = ('Protocol-SSLv2', 'Protocol-SSLv3', 'Protocol-TLSv1', 'Protocol-TLSv1.1')

    def __init__(self, elb, elbClient):
        super().__init__()
        self.elb = elb
        self.elbClient = elbClient

        self._resourceName = elb['LoadBalancerName']

        self.init()

        self._lock = threading.RLock()
        self._attributesCache = None

    def _getAttributes(self):
        """Memoized describe_load_balancer_attributes (used by several checks)."""
        with self._lock:
            if self._attributesCache is None:
                results = self.elbClient.describe_load_balancer_attributes(
                    LoadBalancerName = self.elb['LoadBalancerName']
                )
                self._attributesCache = results.get('LoadBalancerAttributes', {})
            return self._attributesCache

    def _checkClassicLoadBalancer(self):
        self.results['ELBClassicLB'] = ['-1', self.elb['LoadBalancerName']]
        return

    def _checkListenerPortEncrypt(self):
        listeners = self.elb['ListenerDescriptions']

        for listener in listeners:
            if listener['Listener']['Protocol'] in ['HTTP', 'TCP']:
                self.results['ELBListenerInsecure'] = ['-1', listener['Listener']['Protocol']]
        return

    def _checkSecurityGroupNo(self):
        if(len(self.elb['SecurityGroups']) > 50):
            self.results['ELBSGNumber'] = [-1, len(self.elb['SecurityGroups'])]

        return

    def _checkAttributes(self):
        attributes = self._getAttributes()

        if 'CrossZoneLoadBalancing' in attributes and attributes['CrossZoneLoadBalancing']['Enabled'] != 1:
            self.results['ELBCrossZone'] = ['-1', attributes['CrossZoneLoadBalancing']['Enabled']]

        if 'ConnectionDraining' in attributes and attributes['ConnectionDraining']['Enabled'] != 1:
            self.results['ELBConnectionDraining'] = ['-1', attributes['ConnectionDraining']['Enabled']]

        return

    def _checkElbAccessLogsDisabled(self):
        key = 'elbAccessLogsDisabled'
        try:
            attributes = self._getAttributes()
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return

        accessLog = attributes.get('AccessLog')
        if not isinstance(accessLog, dict) or 'Enabled' not in accessLog:
            self.results[key] = [0, 'Unable to evaluate (AccessLog attribute not returned)']
        elif accessLog['Enabled'] is True:
            bucket = accessLog.get('S3BucketName') or ''
            self.results[key] = [1, f"Enabled{' (s3://' + bucket + ')' if bucket else ''}"]
        else:
            self.results[key] = [-1, 'Disabled']

    @staticmethod
    def _protocolAttrs(policy):
        """(enabledProtocolAttrs, hasProtocolAttrs, referencePolicy) of an SSLNegotiationPolicyType policy."""
        enabled, hasProto, ref = set(), False, None
        for a in policy.get('PolicyAttributeDescriptions', []) or []:
            name = a.get('AttributeName', '') or ''
            if name.startswith('Protocol-'):
                hasProto = True
                if str(a.get('AttributeValue', '')).lower() == 'true':
                    enabled.add(name)
            elif name == 'Reference-Security-Policy':
                ref = a.get('AttributeValue')
        return (enabled, hasProto, ref)

    def _getSamplePolicyProtocols(self):
        """{predefined policy name: (enabledProtocolAttrs, hasProtocolAttrs, ref)} built from
        the ELB-defined sample policies (describe_load_balancer_policies without a load
        balancer name returns them with an 'ELBSample-' prefix). Cached per region."""
        cacheKey = 'ec2::clbSamplePolicies::' + self.elbClient.meta.region_name
        table = Config.get(cacheKey, None)
        if table is None:
            table = {}
            resp = self.elbClient.describe_load_balancer_policies()
            for pol in resp.get('PolicyDescriptions', []):
                name = pol.get('PolicyName', '') or ''
                if name.startswith('ELBSample-'):
                    name = name[len('ELBSample-'):]
                table[name] = self._protocolAttrs(pol)
            Config.set(cacheKey, table)
        return table

    def _checkElbTlsPolicyOutdated(self):
        """HTTPS/SSL listeners whose SSL negotiation policy enables SSLv3 / TLS 1.0 / TLS 1.1.
        Uses the policy's Protocol-* attributes; when only Reference-Security-Policy is
        returned, the predefined policy is resolved from the ELB sample policies."""
        key = 'elbTlsPolicyOutdated'
        secureListeners = [ld for ld in self.elb.get('ListenerDescriptions', []) or []
                           if str(ld.get('Listener', {}).get('Protocol', '')).upper() in ('HTTPS', 'SSL')]
        if not secureListeners:
            return

        weak, unknown, good = [], [], []
        try:
            resp = self.elbClient.describe_load_balancer_policies(LoadBalancerName = self.elb['LoadBalancerName'])
            policies = {p.get('PolicyName'): p for p in resp.get('PolicyDescriptions', [])}

            for ld in secureListeners:
                listener = ld.get('Listener', {})
                label = f"{listener.get('Protocol')}:{listener.get('LoadBalancerPort')}"
                sslPolicies = [policies[n] for n in (ld.get('PolicyNames') or [])
                               if n in policies and policies[n].get('PolicyTypeName') == 'SSLNegotiationPolicyType']
                if not sslPolicies:
                    unknown.append(f"{label} no SSL negotiation policy found")
                    continue

                pol = sslPolicies[0]
                enabled, hasProto, ref = self._protocolAttrs(pol)
                if not hasProto and ref:
                    sample = self._getSamplePolicyProtocols().get(ref)
                    if sample and sample[1]:
                        enabled, hasProto = sample[0], True
                desc = (pol.get('PolicyName') or '') + (f" ({ref})" if ref else '')
                if not hasProto:
                    unknown.append(f"{label} {desc} not resolvable")
                    continue

                bad = sorted(p[len('Protocol-'):] for p in enabled if p in self.WEAK_PROTOCOL_ATTRS)
                if bad:
                    weak.append(f"{label} {desc} allows {'/'.join(bad)}")
                else:
                    good.append(f"{label} {desc}")
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response['Error']['Code']})"]
            return

        if weak:
            self.results[key] = [-1, '; '.join(weak)]
        elif unknown:
            self.results[key] = [0, 'Unable to evaluate (' + '; '.join(unknown) + ')']
        else:
            self.results[key] = [1, '; '.join(good)]

    def _checkElbUsesIamOrImportedCert(self):
        """HTTPS/SSL listeners serving a certificate stored in IAM
        (SSLCertificateId arn:aws:iam::<acct>:server-certificate/...). ACM imported
        certificates are reported by acm.acmImportedCertNoAutoRenewal."""
        key = 'elbUsesIamOrImportedCert'
        listeners = [ld.get('Listener', {}) for ld in self.elb.get('ListenerDescriptions', []) or []
                     if str(ld.get('Listener', {}).get('Protocol', '')).upper() in ('HTTPS', 'SSL')]
        if not listeners:
            return
        iam = [f"{l.get('Protocol')}:{l.get('LoadBalancerPort')} {l['SSLCertificateId'].split(':server-certificate/', 1)[1]}"
               for l in listeners if ':server-certificate/' in str(l.get('SSLCertificateId') or '')]
        if iam:
            self.results[key] = [-1, f"IAM server certificate(s) in use: {'; '.join(iam)}"]
        else:
            self.results[key] = [1, f"{len(listeners)} TLS listener(s) use ACM certificates"]
