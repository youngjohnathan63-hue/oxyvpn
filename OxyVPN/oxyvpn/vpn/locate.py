"""Locate OpenVPN, read its version, and manage the virtual adapter."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

from ..paths import default_bin_dir

CREATE_NO_WINDOW = 0x08000000
ADAPTER_KEYWORDS = ("tap", "wintun", "openvpn")

CANDIDATES = [
    r"C:\Program Files\OpenVPN\bin\openvpn.exe",
    r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
]


def find_openvpn(configured: str = "") -> str:
    if configured:
        path = Path(configured)
        if path.is_file():
            return str(path)

    found = shutil.which("openvpn")
    if found:
        return found

    bundled = default_bin_dir() / "openvpn.exe"
    if bundled.is_file():
        return str(bundled)

    for candidate in CANDIDATES:
        if Path(candidate).is_file():
            return candidate

    for root in (r"C:\Program Files", r"C:\Program Files (x86)"):
        base = Path(root)
        if not base.is_dir():
            continue
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for child in children:
            if "openvpn" not in child.name.lower():
                continue
            for exe in child.rglob("openvpn.exe"):
                return str(exe)

    return ""


def _run(args, timeout=12) -> str:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def version_of(openvpn_path: str) -> str:
    if not openvpn_path:
        return ""
    lines = _run([openvpn_path, "--version"], timeout=10).splitlines()
    return lines[0].strip() if lines else ""


def parse_version(openvpn_path: str):
    """Return (major, minor) or (0, 0) when unknown."""
    match = re.search(r"OpenVPN\s+(\d+)\.(\d+)", version_of(openvpn_path))
    if not match:
        return (0, 0)
    return (int(match.group(1)), int(match.group(2)))


def _adapter_lines():
    """Yield lowercased interface lines that look like a VPN adapter."""
    text = _run(["netsh", "interface", "show", "interface"])
    for line in text.splitlines():
        lowered = line.lower()
        if any(key in lowered for key in ADAPTER_KEYWORDS):
            yield lowered


def adapter_present() -> bool:
    """True when a TAP/Wintun interface exists, whether up or down."""
    for _ in _adapter_lines():
        return True
    return False


def adapter_busy() -> bool:
    """True when a VPN adapter is still up (teardown lag / stray process)."""
    for lowered in _adapter_lines():
        # "connected" is a substring of "disconnected", so check that first
        if "disconnected" in lowered:
            continue
        if "connected" in lowered:
            return True
    return False


def wait_for_adapter_free(timeout: float = 12.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not adapter_busy():
            return True
        time.sleep(0.4)
    return not adapter_busy()


def kill_lingering_openvpn(exclude_pid: int = 0) -> bool:
    """Kill stray openvpn.exe processes still holding the TAP adapter."""
    listing = _run(["tasklist", "/fi", "imagename eq openvpn.exe", "/nh"], timeout=10)
    if "openvpn.exe" not in listing.lower():
        return False
    _run(["taskkill", "/f", "/im", "openvpn.exe"], timeout=12)
    time.sleep(0.6)
    return True