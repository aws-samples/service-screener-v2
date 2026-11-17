import threading

import botocore

from services.Evaluator import Evaluator


ACCESS_DENIED_CODES = (
    'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
    'UnauthorizedOperation', 'UnrecognizedClientException',
)


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'Unknown')
    return type(e).__name__


def listShieldProtections(shieldClient):
    """Return every Shield Advanced protection in the account (list_protections
    is global and paginated). Raises botocore errors to the caller."""
    out = []
    paginator = shieldClient.get_paginator('list_protections')
    for page in paginator.paginate():
        out.extend(page.get('Protections', []) or [])
    return out


def arnRegion(arn):
    parts = (arn or '').split(':')
    return parts[3] if len(parts) > 3 else ''


def isCloudFrontArn(arn):
    return ':cloudfront::' in (arn or '') and ':distribution/' in (arn or '')


def isAlbArn(arn):
    return ':elasticloadbalancing:' in (arn or '') and ':loadbalancer/app/' in (arn or '')


class Wafv2Shield(Evaluator):
    """
    Account-level AWS Shield Advanced posture (read-only).

    Shield Advanced is a global, account-wide subscription served from
    us-east-1. One instance of this driver runs per scanned region:
      - Regional internet-facing resources (ALB, CLB, associated EIPs) of the
        scanned region are always evaluated.
      - Global items (proactive engagement / emergency contacts, CloudFront
        distributions, public hosted zones) are evaluated only when
        `isGlobalRegion` is True (the first region of the scan claims it), so
        a multi-region scan never reports them twice.

    Every API used is read-only:
      shield.get_subscription_state / describe_subscription /
      describe_emergency_contact_settings / list_protections,
      elbv2.describe_load_balancers, elb.describe_load_balancers,
      ec2.describe_addresses, cloudfront.list_distributions,
      route53.list_hosted_zones.
    """

    def __init__(self, clients, region, accountId, partition='aws', isGlobalRegion=True):
        super().__init__()
        self.clients = clients or {}
        self.shield = self.clients.get('shield')
        self.region = region
        self.accountId = accountId or ''
        self.partition = partition or 'aws'
        self.isGlobalRegion = bool(isGlobalRegion)
        self._resourceName = 'ShieldAdvanced'
        self._lock = threading.Lock()
        self._state = None          # ('ACTIVE'|'INACTIVE', None) or (None, errCode)
        self._protections = None    # (list, None) or (None, errCode)

        self.addII('region', region)
        self.addII('globalItemsEvaluated', 'true' if self.isGlobalRegion else 'false')

    # ------------------------------------------------------------------ #
    # Cached lookups (checks run concurrently -> guard with a lock)
    # ------------------------------------------------------------------ #
    def _subscriptionState(self):
        with self._lock:
            if self._state is None:
                try:
                    resp = self.shield.get_subscription_state()
                    self._state = (resp.get('SubscriptionState'), None)
                except (botocore.exceptions.ClientError,
                        botocore.exceptions.EndpointConnectionError) as e:
                    self._state = (None, _errCode(e))
            return self._state

    def _getProtections(self):
        with self._lock:
            if self._protections is None:
                try:
                    self._protections = (listShieldProtections(self.shield), None)
                except (botocore.exceptions.ClientError,
                        botocore.exceptions.EndpointConnectionError) as e:
                    self._protections = (None, _errCode(e))
            return self._protections

    def _gate(self, rk):
        """Return True when Shield Advanced is ACTIVE; otherwise record the
        INFO/unable result for `rk` and return False."""
        state, err = self._subscriptionState()
        if err:
            self.results[rk] = [0, f'Unable to evaluate ({err})']
            return False
        if state != 'ACTIVE':
            self.results[rk] = [
                0, 'Shield Advanced is not subscribed (subscription is a cost decision; advisory only)'
            ]
            return False
        return True

    # ------------------------------------------------------------------ #
    # Proactive engagement / emergency contacts (SEC10-BP02)
    # ------------------------------------------------------------------ #
    def _checkShieldAdvancedNoProactiveEngagement(self):
        rk = 'shieldAdvancedNoProactiveEngagement'
        if not self.isGlobalRegion:
            return  # account-wide setting, reported once per scan
        if not self._gate(rk):
            return
        try:
            sub = (self.shield.describe_subscription().get('Subscription') or {})
        except botocore.exceptions.ClientError as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return
        try:
            contacts = self.shield.describe_emergency_contact_settings().get(
                'EmergencyContactList') or []
        except botocore.exceptions.ClientError as e:
            self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
            return

        status = sub.get('ProactiveEngagementStatus') or 'DISABLED'
        self.addII('proactiveEngagementStatus', status)
        self.addII('emergencyContactCount', len(contacts))
        problems = []
        if status != 'ENABLED':
            problems.append(f'proactive engagement is {status}')
        if not contacts:
            problems.append('no emergency contacts are configured')
        if problems:
            self.results[rk] = [
                -1, 'Shield Advanced is active but ' + ' and '.join(problems)
                + ' - the Shield Response Team cannot reach you during a DDoS event'
            ]
        else:
            self.results[rk] = [
                1, f'Proactive engagement ENABLED with {len(contacts)} emergency contact(s)'
            ]

    # ------------------------------------------------------------------ #
    # Internet-facing resources missing a Shield Advanced protection
    # ------------------------------------------------------------------ #
    def _collectPublicResources(self):
        """Return (resources, failedLookups). resources = [(label, arn)]."""
        res, failed = [], []
        region, acct, part = self.region, self.accountId, self.partition

        elbv2 = self.clients.get('elbv2')
        if elbv2 is not None:
            try:
                for page in elbv2.get_paginator('describe_load_balancers').paginate():
                    for lb in page.get('LoadBalancers', []) or []:
                        if lb.get('Type') == 'application' and lb.get('Scheme') == 'internet-facing' \
                                and lb.get('LoadBalancerArn'):
                            res.append((f"ALB {lb.get('LoadBalancerName')}", lb['LoadBalancerArn']))
            except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
                failed.append(f'elbv2.describe_load_balancers:{_errCode(e)}')

        elb = self.clients.get('elb')
        if elb is not None:
            try:
                for page in elb.get_paginator('describe_load_balancers').paginate():
                    for lb in page.get('LoadBalancerDescriptions', []) or []:
                        name = lb.get('LoadBalancerName')
                        if name and lb.get('Scheme') == 'internet-facing':
                            res.append((f'CLB {name}',
                                        f'arn:{part}:elasticloadbalancing:{region}:{acct}:loadbalancer/{name}'))
            except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
                failed.append(f'elb.describe_load_balancers:{_errCode(e)}')

        ec2 = self.clients.get('ec2')
        if ec2 is not None:
            try:
                for addr in ec2.describe_addresses().get('Addresses', []) or []:
                    alloc = addr.get('AllocationId')
                    # Only EIPs attached to something carry traffic; an idle
                    # allocation has no attack surface to protect.
                    if alloc and addr.get('Domain', 'vpc') == 'vpc' and \
                            (addr.get('AssociationId') or addr.get('NetworkInterfaceId')
                             or addr.get('InstanceId')):
                        res.append((f"EIP {addr.get('PublicIp', alloc)}",
                                    f'arn:{part}:ec2:{region}:{acct}:eip-allocation/{alloc}'))
            except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
                failed.append(f'ec2.describe_addresses:{_errCode(e)}')

        if self.isGlobalRegion:
            cf = self.clients.get('cloudfront')
            if cf is not None:
                try:
                    for page in cf.get_paginator('list_distributions').paginate():
                        for d in (page.get('DistributionList') or {}).get('Items', []) or []:
                            if d.get('ARN'):
                                res.append((f"CloudFront {d.get('Id')}", d['ARN']))
                except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
                    failed.append(f'cloudfront.list_distributions:{_errCode(e)}')

            r53 = self.clients.get('route53')
            if r53 is not None:
                try:
                    for page in r53.get_paginator('list_hosted_zones').paginate():
                        for z in page.get('HostedZones', []) or []:
                            if (z.get('Config') or {}).get('PrivateZone'):
                                continue
                            zid = (z.get('Id') or '').replace('/hostedzone/', '')
                            if zid:
                                res.append((f"HostedZone {(z.get('Name') or zid).rstrip('.')}",
                                            f'arn:{part}:route53:::hostedzone/{zid}'))
                except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
                    failed.append(f'route53.list_hosted_zones:{_errCode(e)}')
        return res, failed

    def _checkShieldAdvancedPublicResourcesUnprotected(self):
        rk = 'shieldAdvancedPublicResourcesUnprotected'
        if not self._gate(rk):
            return
        protections, err = self._getProtections()
        if err:
            self.results[rk] = [0, f'Unable to evaluate ({err})']
            return
        protected = {(p.get('ResourceArn') or '').lower() for p in protections}

        resources, failed = self._collectPublicResources()
        unprotected = [label for label, arn in resources if arn.lower() not in protected]
        self.addII('shieldProtectionCount', len(protections))

        if unprotected:
            msg = (f'{len(unprotected)} of {len(resources)} internet-facing resource(s) have no '
                   f'Shield Advanced protection: ' + ', '.join(unprotected[:5])
                   + (f' (+{len(unprotected) - 5} more)' if len(unprotected) > 5 else ''))
            if failed:
                msg += f" (could not enumerate: {', '.join(failed)})"
            self.results[rk] = [-1, msg]
        elif failed:
            self.results[rk] = [0, f"Unable to evaluate ({', '.join(failed)})"]
        elif not resources:
            self.results[rk] = [1, 'No internet-facing ALB/CLB/EIP/CloudFront/public hosted zone found']
        else:
            self.results[rk] = [
                1, f'All {len(resources)} internet-facing resource(s) have a Shield Advanced protection'
            ]


class Wafv2ShieldProtection(Evaluator):
    """
    One Shield Advanced protection on a CloudFront distribution or ALB.
    Checks that automatic application-layer (L7) DDoS mitigation is enabled.

    `protection` is an item from shield.list_protections (which already carries
    ApplicationLayerAutomaticResponseConfiguration); when that field is absent
    we confirm with shield.describe_protection before flagging.
    """

    def __init__(self, protection, shieldClient):
        super().__init__()
        self.protection = protection or {}
        self.shield = shieldClient
        arn = self.protection.get('ResourceArn', '')
        # Protection names are not unique; suffix the protected resource id.
        suffix = arn.split(':')[-1] if arn else self.protection.get('Id', '')
        name = self.protection.get('Name') or self.protection.get('Id') or 'protection'
        self._resourceName = f'{name} ({suffix})' if suffix else name
        self.addII('protectionId', self.protection.get('Id', 'N/A'))
        self.addII('resourceArn', arn or 'N/A')

    def _checkShieldAutoL7MitigationDisabled(self):
        rk = 'shieldAutoL7MitigationDisabled'
        cfg = self.protection.get('ApplicationLayerAutomaticResponseConfiguration')
        if cfg is None and self.protection.get('Id'):
            try:
                p = self.shield.describe_protection(ProtectionId=self.protection['Id']).get('Protection') or {}
                cfg = p.get('ApplicationLayerAutomaticResponseConfiguration')
            except botocore.exceptions.ClientError as e:
                self.results[rk] = [0, f'Unable to evaluate ({_errCode(e)})']
                return
        status = (cfg or {}).get('Status') or 'DISABLED'
        self.addII('l7AutoMitigation', status)
        if status == 'ENABLED':
            action = ', '.join((cfg.get('Action') or {}).keys()) or 'configured'
            self.results[rk] = [1, f'Automatic application-layer DDoS mitigation ENABLED (action: {action})']
        else:
            self.results[rk] = [
                -1, 'Shield Advanced protection has automatic application-layer DDoS mitigation '
                    f'{status} - L7 floods require manual WAF rule changes during an attack'
            ]
