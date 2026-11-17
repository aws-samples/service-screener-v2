"""Credential pattern scan for EC2 user data (instances and launch templates).

Only the pattern *labels* are ever returned - matched values are never echoed
into results, reports or logs.

Patterns are deliberately narrow to keep false positives low:
- AWS access key IDs: AKIA/ASIA followed by exactly 16 upper-case alphanumerics.
- AWS secret access key: an aws_secret_access_key / secretAccessKey style name
  assigned a 40-character literal (variable references such as $VAR or
  $(aws secretsmanager ...) do not match).
- PEM private keys: any '-----BEGIN ... PRIVATE KEY-----' header.
- Passwords: password / passwd assigned a literal of 4+ characters; values that
  start with $, %, {, < (variable / template / placeholder references) do not match.
  Boolean / null values (true/false/yes/no/null/none/...) and the cloud-init key
  'lock_passwd' (a boolean account-lock flag) are not credentials and do not match.
"""
import base64
import binascii
import gzip
import io
import re

# Boolean / null-like values are settings, not credentials (e.g. cloud-init
# 'lock_passwd: false', 'password: null').
_NON_SECRET_VALUES = r'(?:true|false|yes|no|null|none|nil|on|off|disabled?|enabled?)'

PATTERNS = (
    ('AWS access key ID', re.compile(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('AWS secret access key', re.compile(
        r'(?i)(?:aws_?)?secret_?access_?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')),
    ('private key (PEM)', re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----')),
    ('password literal', re.compile(
        r'(?i)(?<![a-z])(?<!lock_)(?:password|passwd)["\']?\s*[:=]\s*["\']?(?![$%{<\s"\'`])'
        r'(?!' + _NON_SECRET_VALUES + r'(?:[\s"\'`;,]|$))[^\s"\'`;]{4,}')),
)

# EC2 user data is limited to 16 KB before base64; bound decompression anyway.
_MAX_TEXT = 1024 * 1024


def decodeUserData(value):
    """Base64 user data (as returned by DescribeInstanceAttribute /
    DescribeLaunchTemplateVersions) -> text. gzip-compressed user data (supported
    by cloud-init) is decompressed. Returns '' for empty input."""
    if not value:
        return ''
    raw = value.encode() if isinstance(value, str) else value
    try:
        data = base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        data = raw
    if data[:2] == b'\x1f\x8b':
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                data = f.read(_MAX_TEXT)
        except (OSError, EOFError):
            pass
    return data[:_MAX_TEXT].decode('utf-8', errors='replace')


def findSecrets(text):
    """List of pattern labels found in text (never the matched values)."""
    if not text:
        return []
    return [label for label, rx in PATTERNS if rx.search(text)]
