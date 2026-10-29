"""Filesystem hygiene and masquerade checks."""

from __future__ import annotations

import os
import time

from .models import Finding, Severity, Status
from .util import human_size, signature_map

TEMP_DIRS = [os.environ.get("TEMP", ""), os.environ.get("TMP", ""),
             r"C:\Windows\Temp"]
APPDATA_DIRS = [os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")]
EXEC_EXTS = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".js",
             ".jse", ".wsf", ".hta", ".ps1", ".lnk")

LOOKALIKES = {
    "svch0st.exe": "svchost.exe",
    "scvhost.exe": "svchost.exe",
    "svhost.exe": "svchost.exe",
    "explorer.exe.exe": "explorer.exe",
    "lsasss.exe": "lsass.exe",
    "csrss.exe.exe": "csrss.exe",
    "chrome.exe.exe": "chrome.exe",
    "iexplore.exe.exe": "iexplore.exe",
}


def _list_execs(folder, limit=400):
    found = []
    if not folder or not os.path.isdir(folder):
        return found
    try:
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if os.path.isfile(path) and name.lower().endswith(EXEC_EXTS):
                found.append(path)
                if len(found) >= limit:
                    break
    except OSError:
        pass
    return found


def check_temp_executables():
    files = []
    for folder in TEMP_DIRS:
        files += _list_execs(folder)
    if not files:
        return Finding("FIL001", "Executables in Temp", "Files", Severity.INFO,
                       Status.PASS, "No executables left in Temp folders")
    now = time.time()
    recent = [f for f in files if now - os.path.getmtime(f) < 7 * 86400]
    severity = Severity.MEDIUM if recent else Severity.LOW
    return Finding("FIL001", "Executables in Temp", "Files", severity,
                   Status.WARN, "%d executable(s) in Temp (%d recent)"
                   % (len(files), len(recent)),
                   files[:20],
                   "Droppers very often stage in Temp. Check anything you do "
                   "not recognise.")


def check_appdata_executables():
    files = []
    for folder in APPDATA_DIRS:
        if folder and os.path.isdir(folder):
            try:
                for name in os.listdir(folder):
                    path = os.path.join(folder, name)
                    if os.path.isfile(path) and name.lower().endswith(EXEC_EXTS):
                        files.append(path)
            except OSError:
                pass
    if not files:
        return Finding("FIL002", "Executables in AppData", "Files", Severity.INFO,
                       Status.PASS, "No loose executables in AppData roots")
    return Finding("FIL002", "Executables in AppData", "Files", Severity.INFO,
                   Status.INFO, "%d executable(s) in AppData" % len(files),
                   files[:20])


def check_double_extensions():
    roots = [os.environ.get("USERPROFILE", ""), os.environ.get("TEMP", ""),
             os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")]
    hits = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        try:
            for entry in os.scandir(root):
                if not entry.is_file():
                    continue
                parts = entry.name.split(".")
                if len(parts) >= 3 and "." + parts[-1].lower() in (".exe", ".scr", ".com"):
                    hits.append(entry.path)
        except OSError:
            pass
    if hits:
        return Finding("FIL003", "Double extensions", "Files", Severity.MEDIUM,
                       Status.WARN, "%d file(s) with a decoy double extension" % len(hits),
                       hits[:20],
                       "invoice.pdf.exe style names are the oldest disguise there is.",
                       "\n".join(hits[:5]))
    return Finding("FIL003", "Double extensions", "Files", Severity.INFO, Status.PASS,
                   "No double-extension files found")


def check_drive_roots():
    hits = []
    drives = []
    for letter in "CDEFGH":
        root = letter + ":\\"
        if os.path.isdir(root):
            drives.append(root)
    for root in drives:
        for name in ("autorun.inf", "AutoRun.inf"):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                hits.append(path)
        for name in os.listdir(root) if os.path.isdir(root) else []:
            path = os.path.join(root, name)
            try:
                if os.path.isfile(path) and name.lower().endswith(EXEC_EXTS):
                    hits.append(path)
            except OSError:
                pass
    if hits:
        return Finding("FIL004", "Drive root clutter", "Files", Severity.LOW,
                       Status.WARN, "%d executable/autorun file(s) in a drive root" % len(hits),
                       hits[:15],
                       "autorun.inf in a drive root is a classic USB infection vector.")
    return Finding("FIL004", "Drive root clutter", "Files", Severity.INFO, Status.PASS,
                   "Drive roots are clean")


def check_system_masquerade():
    """svchost.exe / lsass.exe running from the wrong directory."""
    from .util import powershell_json
    rows = powershell_json(
        "Get-Process svchost,lsass,csrss,winlogon,services,lsm "
        "| Select-Object ProcessName,Path | ConvertTo-Json -Compress", 45)
    bad = []
    expected_dir = r"c:\windows\system32"
    for row in rows:
        name = (row.get("ProcessName") or "").lower() + ".exe"
        path = (row.get("Path") or "").lower()
        if not path:
            continue
        if os.path.dirname(path) != expected_dir:
            bad.append("%s -> %s" % (name, path))
    if bad:
        return Finding("FIL005", "Core process masquerade", "Files", Severity.HIGH,
                       Status.WARN, "%d core process(es) running from an odd path" % len(bad),
                       bad,
                       "Real svchost/lsass always live in System32. Anything else "
                       "is masquerading.",
                       "\n".join(bad))
    return Finding("FIL005", "Core process masquerade", "Files", Severity.INFO,
                   Status.PASS, "Core processes run from System32")


def check_lookalike_names():
    roots = [r"C:\Windows", r"C:\Windows\System32", os.environ.get("USERPROFILE", "")]
    hits = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root):
                if name.lower() in LOOKALIKES:
                    hits.append("%s  (looks like %s)" % (os.path.join(root, name),
                                                         LOOKALIKES[name.lower()]))
        except OSError:
            pass
    if hits:
        return Finding("FIL006", "Look-alike filenames", "Files", Severity.MEDIUM,
                       Status.WARN, "%d suspicious filename(s)" % len(hits), hits,
                       "Typosquatted system binary names are a common disguise.",
                       "\n".join(hits))
    return Finding("FIL006", "Look-alike filenames", "Files", Severity.INFO,
                   Status.PASS, "No look-alike system filenames")


def check_downloads_age():
    downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
    if not os.path.isdir(downloads):
        return Finding("FIL007", "Downloads folder", "Files", Severity.INFO,
                       Status.INFO, "No Downloads folder")
    now = time.time()
    recent = []
    try:
        for entry in os.scandir(downloads):
            if entry.is_file() and entry.name.lower().endswith(EXEC_EXTS):
                if now - entry.stat().st_mtime < 14 * 86400:
                    recent.append("%s  (%s)" % (entry.path, human_size(entry.stat().st_size)))
    except OSError:
        pass
    if recent:
        return Finding("FIL007", "Fresh downloads", "Files", Severity.INFO, Status.INFO,
                       "%d executable(s) downloaded in the last 14 days" % len(recent),
                       recent[:15])
    return Finding("FIL007", "Fresh downloads", "Files", Severity.INFO, Status.PASS,
                   "No recent executables in Downloads")


CHECKS = [
    ("FIL001", "Executables in Temp", check_temp_executables),
    ("FIL002", "Executables in AppData", check_appdata_executables),
    ("FIL003", "Double extensions", check_double_extensions),
    ("FIL004", "Drive root clutter", check_drive_roots),
    ("FIL005", "Core process masquerade", check_system_masquerade),
    ("FIL006", "Look-alike filenames", check_lookalike_names),
    ("FIL007", "Fresh downloads", check_downloads_age),
]