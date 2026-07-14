"""
Scanner wrapper — triggers service-screener-v2 main.py as a subprocess.

Supports both sync (blocking) and async (background) scan modes.
Tracks progress by monitoring __fork/ directory for completed services.
"""

import subprocess
import sys
import os
import json
import time
import threading
from sys import platform
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
MAIN_PY = BASE_DIR / "main.py"
FORK_DIR = BASE_DIR / "__fork"

# Track background scan state
_scan_state = {
    "running": False,
    "started_at": None,
    "pid": None,
    "process": None,
    "result": None,
    "error": None,
    "services_requested": [],
    "regions_requested": [],
}


class ScanError(Exception):
    pass


def _build_scan_cmd(
    regions: list[str] = None,
    services: list[str] = None,
    frameworks: list[str] = None,
    profile: str = None,
) -> list[str]:
    """Build the scan command list."""
    cmd = [sys.executable, str(MAIN_PY)]

    if regions:
        cmd.extend(["--regions", ",".join(regions)])
    if services:
        cmd.extend(["--services", ",".join(services)])
    if frameworks:
        cmd.extend(["--frameworks", ",".join(frameworks)])
    if profile:
        cmd.extend(["--profile", profile])

    # macOS requires --sequential 1 (multiprocess fork issues) and --beta 1
    if platform == "darwin":
        cmd.extend(["--sequential", "1"])
        cmd.extend(["--beta", "1"])

    return cmd


def _get_completed_services() -> list[str]:
    """Check __fork/ for completed service result files."""
    completed = []
    if FORK_DIR.exists():
        for f in FORK_DIR.iterdir():
            # Service result files are {service}.json (not .stat.json, not .charts.json)
            if (f.suffix == ".json" 
                and not f.name.startswith(".")
                and ".stat" not in f.name
                and ".charts" not in f.name
                and f.name not in ["sess-uuid", "api.json"]):
                completed.append(f.stem)
    return sorted(completed)


def run_scan(
    regions: list[str] = None,
    services: list[str] = None,
    frameworks: list[str] = None,
    profile: str = None,
    timeout: int = 600,
) -> dict:
    """
    Run a Service Screener scan synchronously (blocking).
    """
    cmd = _build_scan_cmd(regions, services, frameworks, profile)

    try:
        result = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            raise ScanError(
                f"Scan failed (exit code {result.returncode}): {result.stderr[-500:]}"
            )

        return {
            "status": "completed",
            "message": "Scan completed successfully",
            "stdout_tail": result.stdout[-200:] if result.stdout else "",
        }

    except subprocess.TimeoutExpired:
        raise ScanError(f"Scan timed out after {timeout} seconds")
    except FileNotFoundError:
        raise ScanError(f"main.py not found at {MAIN_PY}")


def run_scan_async(
    regions: list[str] = None,
    services: list[str] = None,
    frameworks: list[str] = None,
    profile: str = None,
) -> dict:
    """
    Start a Service Screener scan in the background (non-blocking).
    Returns immediately with status. Use get_scan_progress() to check.
    """
    global _scan_state

    if _scan_state["running"]:
        elapsed = time.time() - _scan_state["started_at"]
        return {
            "status": "already_running",
            "message": "A scan is already in progress.",
            "started_at": _scan_state["started_at"],
            "elapsed_seconds": round(elapsed, 1),
        }

    # Determine which services will be scanned
    if services:
        requested_services = services
    else:
        requested_services = get_available_services()

    cmd = _build_scan_cmd(regions, services, frameworks, profile)

    # Start subprocess in background
    process = subprocess.Popen(
        cmd,
        cwd=str(BASE_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    _scan_state["running"] = True
    _scan_state["started_at"] = time.time()
    _scan_state["pid"] = process.pid
    _scan_state["process"] = process
    _scan_state["result"] = None
    _scan_state["error"] = None
    _scan_state["services_requested"] = requested_services
    _scan_state["regions_requested"] = regions or []

    # Monitor in a background thread
    def _monitor():
        global _scan_state
        try:
            stdout, stderr = process.communicate(timeout=600)
            if process.returncode == 0:
                _scan_state["result"] = {
                    "status": "completed",
                    "message": "Scan completed successfully",
                    "duration_seconds": round(time.time() - _scan_state["started_at"], 1),
                    "services_scanned": len(_scan_state["services_requested"]),
                }
            else:
                _scan_state["error"] = f"Exit code {process.returncode}: {stderr[-500:]}"
        except subprocess.TimeoutExpired:
            process.kill()
            _scan_state["error"] = "Scan timed out after 600 seconds"
        except Exception as e:
            _scan_state["error"] = str(e)
        finally:
            _scan_state["running"] = False

    thread = threading.Thread(target=_monitor, daemon=True)
    thread.start()

    return {
        "status": "started",
        "message": (
            f"Scan started in background for {len(requested_services)} services. "
            f"Estimated time: {len(requested_services) * 15}-{len(requested_services) * 20} seconds. "
            f"Use get_scan_status to check progress."
        ),
        "pid": process.pid,
        "services_to_scan": requested_services,
        "estimated_seconds": len(requested_services) * 15,
    }


def get_scan_progress() -> dict:
    """
    Check the status of a background scan with progress details.
    Reports which services have completed by checking __fork/ directory.
    """
    if _scan_state["running"]:
        elapsed = time.time() - _scan_state["started_at"]
        total_services = len(_scan_state["services_requested"])
        completed_services = _get_completed_services()
        completed_count = len(completed_services)

        # Calculate progress
        progress_pct = round((completed_count / total_services * 100), 0) if total_services > 0 else 0

        return {
            "status": "running",
            "elapsed_seconds": round(elapsed, 1),
            "pid": _scan_state["pid"],
            "progress": f"{completed_count}/{total_services} services",
            "progress_percent": progress_pct,
            "completed_services": completed_services,
            "remaining_services": [
                s for s in _scan_state["services_requested"]
                if s not in completed_services
            ],
            "hint": (
                "Scan is still running. Check back in 30-60 seconds."
                if progress_pct < 80
                else "Almost done — check back in 15 seconds."
            ),
        }
    elif _scan_state["result"]:
        return _scan_state["result"]
    elif _scan_state["error"]:
        return {
            "status": "failed",
            "error": _scan_state["error"],
        }
    else:
        return {
            "status": "idle",
            "message": "No scan running or completed.",
        }


def get_available_services() -> list[str]:
    """Return list of supported services by scanning the services/ directory."""
    services_dir = BASE_DIR / "services"
    services = []
    for entry in services_dir.iterdir():
        if entry.is_dir() and not entry.name.startswith("_") and entry.name != "dashboard":
            name = entry.name.rstrip("_")
            services.append(name)
    return sorted(services)


def get_available_frameworks() -> list[str]:
    """Return list of supported compliance frameworks."""
    fw_dir = BASE_DIR / "frameworks"
    frameworks = []
    if fw_dir.exists():
        for entry in fw_dir.iterdir():
            if entry.is_dir() and not entry.name.startswith("_"):
                frameworks.append(entry.name)
    return sorted(frameworks)
