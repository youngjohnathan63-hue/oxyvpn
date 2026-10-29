"""Network probes: public IP, geo lookup, latency, DNS and adapter discovery."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass

USER_AGENT = "OxyVPN/2.1"
TIMEOUT = 6.0
CREATE_NO_WINDOW = 0x08000000

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
VPN_ADAPTER_HINTS = ("tap", "wintun", "openvpn", "vpn")


@dataclass
class PublicIP:
    ip: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    ok: bool = False
    error: str = ""


def _get(url: str, timeout: float = TIMEOUT) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _run(args, timeout=12) -> str:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return ""
    return proc.stdout or ""


def lookup_public_ip() -> PublicIP:
    result = PublicIP()
    try:
        result.ip = _get("https://api.ipify.org").decode("utf-8").strip()
        result.ok = bool(result.ip)
    except Exception as exc:
        result.error = str(exc)
        return result

    try:
        raw = json.loads(_get("http://ip-api.com/json/" + result.ip).decode("utf-8"))
        result.country = raw.get("country", "")
        result.city = raw.get("city", "")
        result.isp = raw.get("isp", "")
    except Exception:
        pass
    return result


def tcp_latency(host: str, port: int, timeout: float = 2.0) -> float:
    try:
        start = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return (time.perf_counter() - start) * 1000.0
    except OSError:
        return -1.0


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return ""


def _parse_ipconfig_addresses():
    """Yield (adapter_name_lowercased, ipv4) for every adapter."""
    text = _run(["ipconfig", "/all"])
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()

        if lowered.endswith(":") and "adapter" in lowered:
            current = lowered
            continue

        if "ipv4 address" not in lowered and "autoconfiguration ipv4" not in lowered:
            continue

        token = stripped.split(":", 1)[1].strip() if ":" in stripped else ""
        token = token.split("(")[0].strip().split("%")[0]
        if _IPV4.match(token):
            yield current, token


def physical_ipv4_addresses(exclude=None) -> list:
    """IPv4 addresses on adapters that are NOT the VPN tunnel.

    The kill switch is scoped to these so traffic travelling *inside* the
    tunnel (which leaves from the TAP address) is never blocked by our own
    firewall rule.
    """
    skip = set(exclude or [])
    found = []
    for adapter, address in _parse_ipconfig_addresses():
        if address in skip or address.startswith("127."):
            continue
        if any(hint in adapter for hint in VPN_ADAPTER_HINTS):
            continue
        if address not in found:
            found.append(address)
    return found


def dns_servers() -> list:
    text = _run(["ipconfig", "/all"])
    found = []
    capturing = False
    for line in text.splitlines():
        lowered = line.lower()
        if "dns servers" in lowered:
            capturing = True
            tail = line.split(":", 1)[1].strip() if ":" in line else ""
            for token in tail.split():
                token = token.split("%")[0]
                if _IPV4.match(token):
                    found.append(token)
            continue
        if capturing:
            token = line.strip().split(" ")[0] if line.strip() else ""
            token = token.split("%")[0]
            if _IPV4.match(token):
                found.append(token)
            elif token:
                capturing = False

    unique = []
    for address in found:
        if address not in unique and not address.startswith("127."):
            unique.append(address)
    return unique


def default_gateway() -> str:
    for line in _run(["ipconfig"]).splitlines():
        if "default gateway" in line.lower():
            token = line.split(":", 1)[1].strip() if ":" in line else ""
            token = token.split("%")[0]
            if _IPV4.match(token):
                return token
    return ""


def valid_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False