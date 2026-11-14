import json
import os
from datetime import datetime, timezone

import constants as _C


class IamRoleLastUsedCache:
    """Persistent, cross-run cache of IAM role RoleLastUsed data, keyed by
    account. RoleLastUsed doesn't change fast enough to need a fresh
    get_role() call on every scan - a stale-by-a-day value is fine for an
    "is this role idle" check. Separate from utils/Checkpoint.py, which is
    scoped to one run and wiped on every fresh scan; this cache is meant to
    survive across runs, so it lives outside __fork/.
    """

    DEFAULT_TTL_HOURS = 24

    @staticmethod
    def _cacheFilePath(accountId):
        return os.path.join(_C.IAM_ROLE_CACHE_DIR, str(accountId), 'roles_last_used.json')

    @staticmethod
    def load(accountId, ttlHours=DEFAULT_TTL_HOURS):
        path = IamRoleLastUsedCache._cacheFilePath(accountId)
        if not os.path.exists(path):
            return {}

        try:
            ageSeconds = datetime.now(timezone.utc).timestamp() - os.path.getmtime(path)
            if ageSeconds > ttlHours * 3600:
                return {}
        except OSError:
            return {}

        try:
            with open(path, 'r', encoding='utf-8') as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

        result = {}
        for roleName, entry in raw.items():
            lastUsed = {}
            if entry.get('LastUsedDate'):
                try:
                    lastUsed['LastUsedDate'] = datetime.fromisoformat(entry['LastUsedDate'])
                except ValueError:
                    continue
            if entry.get('Region'):
                lastUsed['Region'] = entry['Region']
            result[roleName] = lastUsed
        return result

    @staticmethod
    def save(accountId, roleLastUsedByName):
        path = IamRoleLastUsedCache._cacheFilePath(accountId)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        serializable = {}
        for roleName, roleLastUsed in roleLastUsedByName.items():
            entry = {}
            lastUsedDate = (roleLastUsed or {}).get('LastUsedDate')
            if lastUsedDate:
                entry['LastUsedDate'] = lastUsedDate.isoformat()
            region = (roleLastUsed or {}).get('Region')
            if region:
                entry['Region'] = region
            serializable[roleName] = entry

        with open(path, 'w', encoding='utf-8') as f:
            json.dump(serializable, f)
