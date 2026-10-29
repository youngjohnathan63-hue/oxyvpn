"""System baseline checks."""

from __future__ import annotations

import os
import platform
import socket
import time

from .models import Finding, Severity, Status
from .util import reg_read, run, powershell_json, human_size
import winreg


def host_info():
    info = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "user": os.environ.get("USERNAME", ""),
    }
    code, out = run(["wmic", "os", "get", "Caption,BuildNumber,OSArchitecture,"
                     "InstallDate,LastBootUpTime", "/format:list"], 20)
    for line in out.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and value:
                info[key] = value
    return info


def _os(host):
    caption = host.get("Caption", "")
    build = host.get("BuildNumber", "")
    return "Operating system: %s (build %s)" % (caption or platform.platform(), build)


def check_os(host):
    return Finding("SYS001", "Operating system", "System", Severity.INFO, Status.INFO,
                   _os(host),
                   ["Architecture: %s" % host.get("OSArchitecture", host.get("arch", "")),
                    "Host: %s" % host.get("hostname", ""),
                    "User: %s" % host.get("user", "")])


def check_uptime(host):
    boot = host.get("LastBootUpTime", "")
    days = None
    if boot and len(boot) >= 8:
        try:
            stamp = time.mktime(time.strptime(boot.split(".")[0], "%Y%m%d%H%M%S"))
            days = (time.time() - stamp) / 86400.0
        except Exception:
            pass
    if days is None:
        return Finding("SYS002", "System uptime", "System", Severity.INFO,
                       Status.INFO, "Unknown")
    if days > 30:
        return Finding("SYS002", "System uptime", "System", Severity.LOW,
                       Status.WARN, "Up for %.0f days" % days,
                       ["Long uptimes mean pending reboots and stale patches "
                        "have not been applied."],
                       "Reboot when convenient.")
    return Finding("SYS002", "System uptime", "System", Severity.INFO,
                   Status.PASS, "Up for %.0f days" % days)


def check_patches():
    code, out = run(["wmic", "qfe", "get", "HotFixID", "/format:list"], 30)
    patches = [ln.split("=", 1)[1].strip() for ln in out.splitlines()
               if ln.startswith("HotFixID=") and ln.split("=", 1)[1].strip()]
    count = len(patches)
    if count == 0:
        return Finding("SYS003", "Installed updates", "System", Severity.HIGH,
                       Status.WARN, "No updates detected",
                       ["wmic reported zero hotfixes - patching may never have run."],
                       "Run Windows Update.")
    if count < 15:
        return Finding("SYS003", "Installed updates", "System", Severity.MEDIUM,
                       Status.WARN, "%d updates recorded" % count,
                       patches[-8:], "Run Windows Update to pick up missing patches.")
    return Finding("SYS003", "Installed updates", "System", Severity.INFO,
                   Status.PASS, "%d updates recorded" % count, patches[-8:])


def check_secure_boot():
    try:
        import ctypes
        firmware = ctypes.windll.kernel32.GetFirmwareType
        buf = ctypes.c_uint(0)
        # FirmwareType: 1=BIOS, 2=UEFI
        ctypes.windll.kernel32.GetFirmwareType(ctypes.byref(buf))
        if buf.value != 2:
            return Finding("SYS004", "Secure Boot", "System", Severity.LOW,
                           Status.INFO, "Legacy BIOS (no Secure Boot)",
                           ["UEFI with Secure Boot resists bootkits."])
    except Exception:
        pass

    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                     "UEFISecureBootEnabled")
    if value == 1:
        return Finding("SYS004", "Secure Boot", "System", Severity.INFO,
                       Status.PASS, "Secure Boot enabled")
    if value == 0:
        return Finding("SYS004", "Secure Boot", "System", Severity.MEDIUM,
                       Status.WARN, "Secure Boot disabled",
                       ["Bootkits and unsigned bootloaders can persist undetected."],
                       "Enable Secure Boot in firmware settings.")
    return Finding("SYS004", "Secure Boot", "System", Severity.INFO,
                   Status.INFO, "Not reported by firmware")


def check_bitlocker():
    code, out = run(["manage-bde", "-status"], 40)
    if code != 0 or not out:
        return Finding("SYS005", "Drive encryption", "System", Severity.INFO,
                       Status.INFO, "manage-bde unavailable")
    lowered = out.lower()
    protected = "protection on" in lowered
    if protected:
        return Finding("SYS005", "Drive encryption", "System", Severity.INFO,
                       Status.PASS, "System volume is encrypted (BitLocker)")
    return Finding("SYS005", "Drive encryption", "System", Severity.MEDIUM,
                   Status.WARN, "System volume is not encrypted",
                   ["Without encryption, anyone with physical access or a "
                    "live USB can read everything on the disk."],
                   "Enable BitLocker on the system drive.")


def check_disk_space():
    try:
        import ctypes
        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            "C:\\", None, ctypes.byref(total), ctypes.byref(free))
        if total.value:
            pct = free.value / float(total.value) * 100
            if pct < 8:
                return Finding("SYS006", "Free disk space", "System", Severity.MEDIUM,
                               Status.WARN, "Only %.1f%% free on C:" % pct,
                               ["Low free space breaks Windows Update and "
                                "shadow copies."], "Free up space on C:.")
            return Finding("SYS006", "Free disk space", "System", Severity.INFO,
                           Status.PASS,
                           "%.1f%% free on C: (%s)" % (pct, human_size(free.value)))
    except Exception:
        pass
    return Finding("SYS006", "Free disk space", "System", Severity.INFO,
                   Status.INFO, "Unavailable")


def check_time_sync():
    code, out = run(["w32tm", "/query", "/status"], 20)
    if "source:" not in out.lower():
        return Finding("SYS007", "Clock synchronisation", "System", Severity.LOW,
                       Status.INFO, "w32tm reported no source")
    if "free-running" in out.lower() or "local cmos clock" in out.lower():
        return Finding("SYS007", "Clock synchronisation", "System", Severity.LOW,
                       Status.WARN, "Clock is free-running, not synced",
                       ["A drifting clock breaks TLS certificate validation."],
                       "Point w32tm at a reliable NTP source.")
    return Finding("SYS007", "Clock synchronisation", "System", Severity.INFO,
                   Status.PASS, "Clock is synchronised")


CHECKS = [
    ("SYS001", "Operating system", check_os),
    ("SYS002", "System uptime", check_uptime),
    ("SYS003", "Installed updates", check_patches),
    ("SYS004", "Secure Boot", check_secure_boot),
    ("SYS005", "Drive encryption", check_bitlocker),
    ("SYS006", "Free disk space", check_disk_space),
    ("SYS007", "Clock synchronisation", check_time_sync),
]