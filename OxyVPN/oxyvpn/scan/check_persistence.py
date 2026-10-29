"""Autostart / persistence surface checks."""

from __future__ import annotations

import os
import winreg

from .models import Finding, Severity, Status
from .util import clean_path, expand, reg_enum_values, run, signature_map

RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
]

STARTUP_FOLDERS = [
    os.path.join(os.environ.get("APPDATA", ""),
                 r"Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.join(os.environ.get("PROGRAMDATA", ""),
                 r"Microsoft\Windows\Start Menu\Programs\Startup"),
]

RISKY_DIRS = ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\")


def _collect_entries():
    entries = []
    for hive, path, label in RUN_KEYS:
        for name, value in reg_enum_values(hive, path).items():
            if isinstance(value, str) and value.strip():
                entries.append((label, name, value))
    return entries


def check_run_keys():
    entries = _collect_entries()
    if not entries:
        return Finding("PER001", "Run keys", "Persistence", Severity.INFO,
                       Status.INFO, "No autostart registry entries")
    return Finding("PER001", "Run keys", "Persistence", Severity.INFO, Status.INFO,
                   "%d autostart registry entries" % len(entries),
                   ["%s -> %s" % (label, name) for label, name, _ in entries])


def check_run_targets():
    entries = _collect_entries()
    if not entries:
        return Finding("PER002", "Autostart targets", "Persistence", Severity.INFO,
                       Status.INFO, "Nothing to inspect")

    resolved = {}
    for label, name, raw in entries:
        target = clean_path(expand(raw))
        if target and os.path.isfile(target):
            resolved[target] = (label, name)

    sigs = signature_map(list(resolved.keys()))

    unsigned = []
    missing = []
    risky = []
    for target, (label, name) in resolved.items():
        status, signer = sigs.get(target, ("Unknown", ""))
        if status in ("NotSigned", "HashMismatch", "NotTrusted"):
            unsigned.append("%s -> %s (%s)" % (label, target, status))
        if any(frag in target.lower() for frag in RISKY_DIRS):
            risky.append("%s -> %s" % (label, target))
    for label, name, raw in entries:
        target = clean_path(expand(raw))
        if target and not os.path.isfile(target) and target.lower().endswith(".exe"):
            missing.append("%s -> %s" % (label, target))

    details = []
    if unsigned:
        details += ["Unsigned: " + u for u in unsigned[:12]]
    if risky:
        details += ["Runs from a risky folder: " + r for r in risky[:12]]
    if missing:
        details += ["Target missing: " + m for m in missing[:12]]

    if unsigned:
        return Finding("PER002", "Autostart targets", "Persistence", Severity.HIGH,
                       Status.WARN, "%d unsigned autostart binary(ies)" % len(unsigned),
                       details,
                       "Verify each unsigned entry - this is where most "
                       "persistent malware lives.", "\n".join(unsigned[:6]))
    if risky:
        return Finding("PER002", "Autostart targets", "Persistence", Severity.MEDIUM,
                       Status.WARN, "%d autostart entry(ies) run from Temp/AppData" % len(risky),
                       details, "Confirm these belong to software you installed.")
    if missing:
        return Finding("PER002", "Autostart targets", "Persistence", Severity.LOW,
                       Status.WARN, "%d autostart target(s) no longer exist" % len(missing),
                       details, "Clean up orphaned entries.")
    return Finding("PER002", "Autostart targets", "Persistence", Severity.INFO,
                   Status.PASS, "All %d autostart targets are signed" % len(resolved))


def check_startup_folders():
    files = []
    for folder in STARTUP_FOLDERS:
        if folder and os.path.isdir(folder):
            for name in os.listdir(folder):
                if name.lower() == "desktop.ini":
                    continue
                files.append(os.path.join(folder, name))
    if not files:
        return Finding("PER003", "Startup folders", "Persistence", Severity.INFO,
                       Status.PASS, "Startup folders are empty")
    return Finding("PER003", "Startup folders", "Persistence", Severity.INFO,
                   Status.INFO, "%d item(s) in Startup folders" % len(files),
                   files[:15])


def check_scheduled_tasks():
    code, out = run(["schtasks", "/query", "/fo", "csv", "/nh"], 60)
    rows = []
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) >= 3:
            name = parts[0].strip('"')
            status = parts[2].strip('"') if len(parts) > 2 else ""
            if name and "\\Microsoft\\" not in name:
                rows.append("%s [%s]" % (name, status))
    if not rows:
        return Finding("PER004", "Scheduled tasks", "Persistence", Severity.INFO,
                       Status.INFO, "No third-party scheduled tasks")
    severity = Severity.MEDIUM if len(rows) > 25 else Severity.INFO
    return Finding("PER004", "Scheduled tasks", "Persistence", severity, Status.INFO,
                   "%d non-Microsoft scheduled tasks" % len(rows),
                   rows[:20],
                   "Scheduled tasks are a favourite persistence mechanism - "
                   "check any you do not recognise.")


def check_winlogon():
    hive = winreg.HKEY_LOCAL_MACHINE
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    shell = reg_read(hive, path, "Shell", "explorer.exe")
    userinit = reg_read(hive, path, "Userinit", "")
    problems = []
    if shell and shell.strip().lower() != "explorer.exe":
        problems.append("Shell = %s" % shell)
    if userinit and "userinit.exe" not in userinit.lower():
        problems.append("Userinit = %s" % userinit)
    if problems:
        return Finding("PER005", "Winlogon integrity", "Persistence", Severity.HIGH,
                       Status.WARN, "Winlogon values have been modified",
                       problems,
                       "Malware commonly appends itself to Shell/Userinit. "
                       "Restore the defaults if you did not do this.",
                       "\n".join(problems))
    return Finding("PER005", "Winlogon integrity", "Persistence", Severity.INFO,
                   Status.PASS, "Shell and Userinit are stock values")


def check_image_hijack():
    """HKLM\\...\\Image File Execution Options entries that redirect binaries."""
    base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    hits = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            index = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(key, sub) as child:
                        debugger = winreg.QueryValueEx(child, "Debugger")[0]
                        if debugger:
                            hits.append("%s -> %s" % (sub, debugger))
                except OSError:
                    pass
    except OSError:
        pass
    if hits:
        return Finding("PER006", "Image hijacks", "Persistence", Severity.MEDIUM,
                       Status.WARN, "%d IFEO redirect(s) configured" % len(hits),
                       hits[:15],
                       "A Debugger entry silently runs another binary instead "
                       "of the original - legitimate, but also a known trick.")
    return Finding("PER006", "Image hijacks", "Persistence", Severity.INFO,
                   Status.PASS, "No Image File Execution Options redirects")


CHECKS = [
    ("PER001", "Run keys", check_run_keys),
    ("PER002", "Autostart targets", check_run_targets),
    ("PER003", "Startup folders", check_startup_folders),
    ("PER004", "Scheduled tasks", check_scheduled_tasks),
    ("PER005", "Winlogon integrity", check_winlogon),
    ("PER006", "Image hijacks", check_image_hijack),
]