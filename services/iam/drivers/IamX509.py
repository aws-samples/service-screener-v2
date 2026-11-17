"""
Minimal, dependency-free reader for the validity period of PEM encoded X.509
certificates (used for IAM Roles Anywhere CERTIFICATE_BUNDLE trust anchors).
Only the DER structure up to tbsCertificate.validity is walked; signatures are
not verified.
"""
import base64
import binascii
import datetime
import re

_PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', re.S)


def _tlv(data, i):
    """Return (tag, contentStart, contentLength) of the DER element at i."""
    if i + 2 > len(data):
        raise ValueError('truncated DER')
    tag = data[i]
    length = data[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or i + n > len(data):
            raise ValueError('unsupported DER length')
        length = int.from_bytes(data[i:i + n], 'big')
        i += n
    if i + length > len(data):
        raise ValueError('truncated DER')
    return tag, i, length


def _parseTime(tag, raw):
    s = raw.decode('ascii')
    if not s.endswith('Z'):
        raise ValueError('non-UTC certificate time')
    s = s[:-1]
    if tag == 0x17:  # UTCTime YYMMDDHHMM[SS]Z
        year = int(s[0:2])
        year += 1900 if year >= 50 else 2000
        rest = s[2:]
    elif tag == 0x18:  # GeneralizedTime YYYYMMDDHHMM[SS]Z
        year = int(s[0:4])
        rest = s[4:]
    else:
        raise ValueError('unexpected time tag')
    rest = rest.split('.')[0]
    if len(rest) == 8:
        rest += '00'
    return datetime.datetime(year, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                             int(rest[6:8]), int(rest[8:10]), tzinfo=datetime.timezone.utc)


def derValidity(der):
    """(notBefore, notAfter) as aware UTC datetimes for a DER certificate."""
    tag, i, _ = _tlv(der, 0)               # Certificate
    if tag != 0x30:
        raise ValueError('not a certificate')
    tag, i, _ = _tlv(der, i)               # tbsCertificate
    if tag != 0x30:
        raise ValueError('not a certificate')
    tag, start, length = _tlv(der, i)
    if tag == 0xA0:                        # [0] version (optional)
        i = start + length
        tag, start, length = _tlv(der, i)
    # serialNumber, signature AlgorithmIdentifier, issuer Name
    for expected in (0x02, 0x30, 0x30):
        if tag != expected:
            raise ValueError('unexpected tbsCertificate layout')
        i = start + length
        tag, start, length = _tlv(der, i)
    if tag != 0x30:                        # validity
        raise ValueError('unexpected tbsCertificate layout')
    t1, s1, l1 = _tlv(der, start)
    t2, s2, l2 = _tlv(der, s1 + l1)
    return _parseTime(t1, der[s1:s1 + l1]), _parseTime(t2, der[s2:s2 + l2])


def pemCertificates(pemData):
    """List of (notBefore, notAfter, error) for every certificate in a PEM
    bundle. error is a string when a block cannot be decoded."""
    if isinstance(pemData, bytes):
        pemData = pemData.decode('ascii', errors='ignore')
    out = []
    for block in _PEM_RE.findall(pemData or ''):
        try:
            der = base64.b64decode(''.join(block.split()), validate=True)
            nb, na = derValidity(der)
            out.append((nb, na, None))
        except (ValueError, binascii.Error, IndexError, UnicodeDecodeError) as e:
            out.append((None, None, str(e) or 'unreadable certificate'))
    return out
