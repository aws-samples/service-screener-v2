"""
Cache manager for Service Screener scan results.

Reads from:
  - __fork/          (intermediate per-service results)
  - adminlte/aws/res/{account_id}/  (final api-full.json)

Cache strategy:
  - First call with no cache → triggers scan
  - Subsequent calls → reads from cache
  - Returns cache age metadata so the AI client can decide freshness
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path

# Base directory of service-screener-v2
BASE_DIR = Path(__file__).parent.parent
FORK_DIR = BASE_DIR / "__fork"
ADMINLTE_DIR = BASE_DIR / "adminlte" / "aws"
CACHE_DIR = BASE_DIR / ".mcp_cache"


class CacheManager:
    def __init__(self):
        self.cache_dir = CACHE_DIR
        self.cache_dir.mkdir(exist_ok=True)

    def get_scan_results(self, account_id: str = None) -> dict | None:
        """
        Get cached scan results. Checks multiple locations:
        1. .mcp_cache/{account_id}/api-full.json  (MCP-managed cache)
        2. adminlte/aws/res/{account_id}/api-full.json  (native screener output)
        3. __fork/*.json  (intermediate results from last run)
        
        Returns None if no cache exists.
        """
        # Try MCP cache first
        if account_id:
            mcp_cache = self.cache_dir / account_id / "api-full.json"
            if mcp_cache.exists():
                return self._load_with_metadata(mcp_cache)

        # Try native screener output
        if account_id:
            native_path = ADMINLTE_DIR / account_id / "api-full.json"
            if native_path.exists():
                return self._load_with_metadata(native_path)

        # Try finding any account folder in adminlte output
        if ADMINLTE_DIR.exists():
            for entry in ADMINLTE_DIR.iterdir():
                # Account folders are numeric IDs; skip 'res' and other non-account dirs
                if entry.is_dir() and entry.name.isdigit():
                    api_file = entry / "api-full.json"
                    if api_file.exists():
                        return self._load_with_metadata(api_file)

        # Try __fork directory (intermediate results)
        if FORK_DIR.exists():
            return self._load_from_fork()

        return None

    def save_scan_results(self, account_id: str, results: dict):
        """Save scan results to MCP cache."""
        cache_path = self.cache_dir / account_id
        cache_path.mkdir(parents=True, exist_ok=True)

        output = {
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "account_id": account_id,
            "results": results
        }

        with open(cache_path / "api-full.json", "w") as f:
            json.dump(output, f, indent=2)

    def get_cache_age_seconds(self, account_id: str = None) -> float | None:
        """Return age of cache in seconds, or None if no cache."""
        paths_to_check = []
        
        if account_id:
            paths_to_check.append(self.cache_dir / account_id / "api-full.json")
            paths_to_check.append(ADMINLTE_DIR / account_id / "api-full.json")

        for path in paths_to_check:
            if path.exists():
                mtime = path.stat().st_mtime
                return time.time() - mtime

        return None

    def _load_with_metadata(self, path: Path) -> dict:
        """Load JSON and attach cache metadata."""
        with open(path) as f:
            data = json.load(f)

        mtime = path.stat().st_mtime
        return {
            "source": str(path),
            "scanned_at": datetime.fromtimestamp(mtime).isoformat() + "Z",
            "age_seconds": time.time() - mtime,
            "data": data
        }

    def _load_from_fork(self) -> dict:
        """Load intermediate results from __fork directory."""
        results = {}
        for file in FORK_DIR.iterdir():
            if file.suffix == ".json" and not file.name.startswith("."):
                name = file.stem
                # Skip non-result files
                if name in ["sess-uuid"] or "stat" in name or "charts" in name:
                    continue
                try:
                    with open(file) as f:
                        results[name] = json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue

        if not results:
            return None

        mtime = max(f.stat().st_mtime for f in FORK_DIR.iterdir() if f.suffix == ".json")
        return {
            "source": str(FORK_DIR),
            "scanned_at": datetime.fromtimestamp(mtime).isoformat() + "Z",
            "age_seconds": time.time() - mtime,
            "data": results
        }

    def has_cache(self, account_id: str = None) -> bool:
        """Check if any scan results exist."""
        return self.get_scan_results(account_id) is not None


# Singleton
cache_manager = CacheManager()
