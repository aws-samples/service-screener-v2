from services.Evaluator import Evaluator

INACTIVE_STATES = ('deleting', 'deleted')

# AWS Site-to-Site VPN defaults when a tunnel option list is not customised
# (https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html).
DEFAULT_IKE = ['ikev1', 'ikev2']
DEFAULT_INTEGRITY = ['SHA1', 'SHA2-256', 'SHA2-384', 'SHA2-512']
DEFAULT_PHASE1_DH = [2, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]
DEFAULT_PHASE2_DH = [2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24]

WEAK_DH = {1, 2, 5}         # 768/1024/1536-bit MODP
MODP_2048_OR_WEAKER = {1, 2, 5, 14}


def _values(opts, key):
    return [v.get('Value') for v in (opts.get(key) or []) if isinstance(v, dict) and v.get('Value') is not None]


def weakTunnelSettings(opts):
    """List of weak settings a tunnel still accepts. An empty option list means the
    AWS default list is in effect (which includes IKEv1, SHA1 and DH group 2)."""
    weak = []

    ike = _values(opts, 'IkeVersions')
    if not ike:
        weak.append('IKEv1 allowed (default IKE versions)')
    elif any(str(v).lower() == 'ikev1' for v in ike):
        weak.append('IKEv1 allowed')

    for phase in ('Phase1', 'Phase2'):
        integ = _values(opts, f'{phase}IntegrityAlgorithms')
        if not integ:
            weak.append(f'{phase} SHA1 allowed (default integrity algorithms)')
        elif any(str(v).upper() == 'SHA1' for v in integ):
            weak.append(f'{phase} SHA1 allowed')

        groups = _values(opts, f'{phase}DHGroupNumbers')
        default = not groups
        if default:
            groups = DEFAULT_PHASE1_DH if phase == 'Phase1' else DEFAULT_PHASE2_DH
        tag = ' (default DH groups)' if default else ''
        try:
            groups = {int(g) for g in groups}
        except (TypeError, ValueError):
            continue
        weakGroups = sorted(groups & WEAK_DH)
        if weakGroups:
            weak.append(f"{phase} DH group(s) {','.join(map(str, weakGroups))} allowed{tag}")
        elif groups and groups <= MODP_2048_OR_WEAKER:
            weak.append(f'{phase} only DH group 14 (2048-bit MODP) offered')
    return weak


class Ec2VpnConnection(Evaluator):
    """Site-to-Site VPN tunnels should only accept IKEv2, SHA2 integrity and strong
    DH groups. Weak options remain negotiable while they are in the allowed lists,
    even when the customer gateway would prefer stronger ones."""

    def __init__(self, vpn):
        super().__init__()
        self.vpn = vpn
        self._resourceName = vpn['VpnConnectionId']
        self.init()

    def _checkVpnWeakTunnelCrypto(self):
        key = 'vpnWeakTunnelCrypto'
        vpn = self.vpn
        if str(vpn.get('State', '')).lower() in INACTIVE_STATES:
            return
        tunnels = (vpn.get('Options') or {}).get('TunnelOptions') or []
        if not tunnels:
            self.results[key] = [0, 'Unable to evaluate (tunnel options not returned)']
            return

        findings = []
        for i, t in enumerate(tunnels, 1):
            weak = weakTunnelSettings(t)
            if weak:
                findings.append(f"tunnel {t.get('OutsideIpAddress') or i}: {'; '.join(weak)}")
        if findings:
            self.results[key] = [-1, ' | '.join(findings)]
        else:
            self.results[key] = [1, f"{len(tunnels)} tunnel(s) restricted to IKEv2, SHA2 and strong DH groups"]
