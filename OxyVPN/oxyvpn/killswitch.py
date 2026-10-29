"""Firewall kill switch built on Windows Firewall rules.

Two things make this work:

1. Windows Firewall gives BLOCK rules precedence over ALLOW rules, so the
   rule's remote-address set must be the COMPLEMENT of what stays reachable.

2. The rule is scoped with `localip=` to the PHYSICAL adapter addresses.
   While connected, app traffic leaves from the TAP address and is not
   matched at all - so we never block our own tunnel. Traffic leaking out
   the real NIC (tunnel down) still matches and still gets blocked.
"""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass

RULE_NAME = "OxyVPN-KillSwitch-Out"
CREATE_NO_WINDOW = 0x08000000

ALWAYS_ALLOWED = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
]


def _merge(ranges):
    if not ranges:
        return []
    ranges = sorted(ranges)
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def _to_cidrs(start, end):
    out = []
    while start <= end:
        prefix = 0
        while prefix < 32:
            span = 1 << (32 - prefix)
            if start % span == 0 and start + span - 1 <= end:
                break
            prefix += 1
        span = 1 << (32 - prefix)
        out.append("%s/%d" % (ipaddress.IPv4Address(start), prefix))
        start += span
    return out


def complement_cidrs(allowed):
    ranges = []
    for cidr in allowed:
        net = ipaddress.ip_network(cidr, strict=False)
        ranges.append((int(net.network_address), int(net.broadcast_address)))
    merged = _merge(ranges)

    gaps = []
    cursor = 0
    for start, end in merged:
        if start > cursor:
            gaps.append((cursor, start - 1))
        cursor = max(cursor, end + 1)
    if cursor <= 0xFFFFFFFF:
        gaps.append((cursor, 0xFFFFFFFF))

    out = []
    for start, end in gaps:
        out.extend(_to_cidrs(start, end))
    return out


def _netsh(args):
    try:
        proc = subprocess.run(
            ["netsh"] + args, capture_output=True, text=True,
            timeout=30, creationflags=CREATE_NO_WINDOW,
        )
    except Exception as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


@dataclass
class KillSwitchResult:
    ok: bool
    detail: str = ""


class KillSwitch:
    def __init__(self, extra_allowed=None, local_ips=None):
        self.extra_allowed = [a for a in (extra_allowed or []) if a]
        self.local_ips = [a for a in (local_ips or []) if a]
        self._armed = False

    @property
    def armed(self):
        return self._armed

    def allowed_cidrs(self):
        allowed = list(ALWAYS_ALLOWED)
        for extra in self.extra_allowed:
            allowed.append(extra if "/" in extra else extra + "/32")
        return allowed

    def arm(self) -> KillSwitchResult:
        self.clear()
        blocked = complement_cidrs(self.allowed_cidrs())
        if not blocked:
            return KillSwitchResult(False, "nothing to block")

        args = [
            "advfirewall", "firewall", "add", "rule",
            "name=" + RULE_NAME,
            "dir=out", "action=block", "protocol=any",
            "remoteip=" + ",".join(blocked),
            "profile=any", "enable=yes",
        ]
        if self.local_ips:
            args.append("localip=" + ",".join(self.local_ips))

        code, out = _netsh(args)
        if code != 0:
            return KillSwitchResult(False, out.strip())

        self._armed = True
        scope = ("%d physical adapter(s)" % len(self.local_ips)
                 if self.local_ips else "all adapters")
        return KillSwitchResult(
            True, "%d ranges blocked, scoped to %s" % (len(blocked), scope))

    def clear(self):
        _netsh(["advfirewall", "firewall", "delete", "rule", "name=" + RULE_NAME])
        self._armed = False

    def present(self):
        code, out = _netsh(["advfirewall", "firewall", "show", "rule",
                            "name=" + RULE_NAME])
        return code == 0 and RULE_NAME.lower() in out.lower()