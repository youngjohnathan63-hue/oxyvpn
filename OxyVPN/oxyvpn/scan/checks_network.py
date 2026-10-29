"""Network surface checks."""

from __future__ import annotations

import os
import re

from .models import Finding, Severity, Status
from .util import clean_path, powershell_json, reg_read, run, signature_map
import winreg

HOSTS = r"C:\Windows\System32\drivers\etc\hosts"

SUSPICIOUS_PORTS = {
    "4444": "Metasploit default handler",
    "1337": "common backdoor",
    "31337": "Back Orifice",
    "6667": "IRC (botnet C2)",
    "9001": "Tor / generic",
    "1080": "SOCKS proxy",
    "3389": "RDP",
    "5900": "VNC",
    "21": "FTP",
    "23": "Telnet",
    "135": "RPC",
    "139": "NetBIOS",
}

ALLOWED_EXTERNAL = {"svchost.exe", "system", "system idle process", "lsass.exe",
                    "services.exe", "wininit.exe", "spoolsv.exe", "dns.exe"}


def _netstat():
    code, out = run(["netstat", "-ano"], 40)
    listening = []
    established = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
            listening.append((parts[1], parts[3], parts[4] if len(parts) > 4 else ""))
        elif parts[0].upper() == "TCP" and parts[3].upper() == "ESTABLISHED":
            established.append((parts[1], parts[2], parts[4] if len(parts) > 4 else ""))
    return listening, established


def _process_names():
    rows = powershell_json(
        "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress", 45)
    out = {}
    for row in rows:
        try:
            out[int(row.get("Id"))] = (row.get("ProcessName", ""), row.get("Path", ""))
        except Exception:
            pass
    return out


def check_listening():
    listening, _ = _netstat()
    if not listening:
        return Finding("NET001", "Listening ports", "Network", Severity.INFO,
                       Status.INFO, "No listening TCP sockets")
    external = [l for l in listening if not l[0].startswith("127.")]
    details = ["%s  pid %s" % (addr, pid) for addr, _, pid in listening[:25]]
    if external:
        return Finding("NET001", "Listening ports", "Network", Severity.LOW,
                       Status.WARN, "%d port(s) reachable from the network" % len(external),
                       details, "Close anything you do not need exposed.")
    return Finding("NET001", "Listening ports", "Network", Severity.INFO, Status.PASS,
                   "%d listening socket(s), all loopback-bound" % len(listening), details)


def check_port_owners():
    listening, _ = _netstat()
    if not listening:
        return Finding("NET002", "Port owners", "Network", Severity.INFO,
                       Status.INFO, "Nothing to attribute")
    procs = _process_names()
    paths = [p for _, p in procs.values() if p and os.path.isfile(p)]
    sigs = signature_map(paths)

    unsigned = []
    unknown = []
    for addr, port, pid in listening:
        if addr.startswith("127."):
            continue
        try:
            entry = procs.get(int(pid))
        except ValueError:
            continue
        if entry is None:
            unknown.append("%s (pid %s)" % (addr, pid))
            continue
        name, path = entry
        if name.lower() in ALLOWED_EXTERNAL:
            continue
        if not path:
            unknown.append("%s -> %s (pid %s)" % (addr, name, pid))
            continue
        status, _signer = sigs.get(path, ("Unknown", ""))
        if status in ("NotSigned", "HashMismatch", "NotTrusted"):
            unsigned.append("%s -> %s (%s)" % (addr, path, status))

    if unsigned:
        return Finding("NET002", "Unsigned listeners", "Network", Severity.HIGH,
                       Status.WARN, "%d unsigned process(es) listening" % len(unsigned),
                       unsigned[:12],
                       "An unsigned binary accepting connections is worth a look.",
                       "\n".join(unsigned[:5]))
    if unknown:
        return Finding("NET002", "Port owners", "Network", Severity.LOW, Status.WARN,
                       "%d listener(s) could not be attributed" % len(unknown),
                       unknown[:12],
                       "Run the scan elevated so process paths are readable.")
    return Finding("NET002", "Port owners", "Network", Severity.INFO, Status.PASS,
                   "All external listeners are signed processes")


def check_suspicious_ports():
    listening, _ = _netstat()
    hits = []
    for addr, port, pid in listening:
        if addr.startswith("127."):
            continue
        number = port.rsplit(":", 1)[-1]
        if number in SUSPICIOUS_PORTS:
            hits.append("%s - %s (pid %s)" % (port, SUSPICIOUS_PORTS[number], pid))
    if hits:
        return Finding("NET003", "Notable listening ports", "Network", Severity.LOW,
                       Status.WARN, "%d notable port(s) open to the network" % len(hits),
                       hits, "Confirm each one is intentional.")
    return Finding("NET003", "Notable listening ports", "Network", Severity.INFO,
                   Status.PASS, "No notable ports exposed")


def check_hosts_file():
    if not os.path.isfile(HOSTS):
        return Finding("NET004", "Hosts file", "Network", Severity.INFO, Status.INFO,
                       "Hosts file missing")
    entries = []
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                stripped = line.split("#", 1)[0].strip()
                if stripped:
                    entries.append(stripped)
    except OSError:
        pass
    if not entries:
        return Finding("NET004", "Hosts file", "Network", Severity.INFO, Status.PASS,
                       "Hosts file has no active entries")
    if len(entries) > 40:
        return Finding("NET004", "Hosts file", "Network", Severity.MEDIUM, Status.WARN,
                       "%d hosts entries - likely a blocklist" % len(entries),
                       entries[:15],
                       "Large blocklists are normal, but check for redirects to "
                       "127.0.0.1 of domains you use.")
    return Finding("NET004", "Hosts file", "Network", Severity.INFO, Status.INFO,
                   "%d hosts entries" % len(entries), entries[:15])


def check_proxy():
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
    enable = reg_read(winreg.HKEY_CURRENT_USER, path, "ProxyEnable")
    server = reg_read(winreg.HKEY_CURRENT_USER, path, "ProxyServer")
    auto = reg_read(winreg.HKEY_CURRENT_USER, path, "AutoConfigURL")
    if auto:
        return Finding("NET005", "Proxy configuration", "Network", Severity.MEDIUM,
                       Status.WARN, "Automatic proxy config script is set",
                       [str(auto)],
                       "A PAC URL can silently redirect all your browsing - "
                       "and can be set by malware.")
    if enable == 1 and server:
        return Finding("NET005", "Proxy configuration", "Network", Severity.LOW,
                       Status.INFO, "Manual proxy configured: %s" % server)
    return Finding("NET005", "Proxy configuration", "Network", Severity.INFO,
                   Status.PASS, "No proxy configured")


def check_dns():
    rows = powershell_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Where-Object {$_.ServerAddresses} | "
        "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress", 45)
    details = []
    for row in rows:
        servers = row.get("ServerAddresses") or []
        if isinstance(servers, str):
            servers = [servers]
        details.append("%s: %s" % (row.get("InterfaceAlias", "?"), ", ".join(servers)))
    if not details:
        return Finding("NET006", "DNS servers", "Network", Severity.INFO, Status.INFO,
                       "No DNS servers reported")
    return Finding("NET006", "DNS servers", "Network", Severity.INFO, Status.INFO,
                   "DNS resolvers in use", details)


def check_smb_exposure():
    listening, _ = _netstat()
    exposed = [l for l in listening if not l[0].startswith("127.") and l[1].endswith(":445")]
    if exposed:
        return Finding("NET007", "SMB exposure", "Network", Severity.MEDIUM,
                       Status.WARN, "SMB (445) is reachable from the network",
                       ["File sharing is exposed - fine on a trusted LAN, risky "
                        "on public Wi-Fi."],
                       "Turn off File and Printer Sharing on untrusted networks.")
    return Finding("NET007", "SMB exposure", "Network", Severity.INFO, Status.PASS,
                   "SMB is not exposed")


CHECKS = [
    ("NET001", "Listening ports", check_listening),
    ("NET002", "Port owners", check_port_owners),
    ("NET003", "Notable ports", check_suspicious_ports),
    ("NET004", "Hosts file", check_hosts_file),
    ("NET005", "Proxy configuration", check_proxy),
    ("NET006", "DNS servers", check_dns),
    ("NET007", "SMB exposure", check_smb_exposure),
]