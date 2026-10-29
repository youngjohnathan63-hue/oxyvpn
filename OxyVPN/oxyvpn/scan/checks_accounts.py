"""Account and credential posture checks."""

from __future__ import annotations

from .models import Finding, Severity, Status
from .util import powershell_json, reg_read, run
import winreg


def check_local_users():
    rows = powershell_json(
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,"
        "PasswordLastSet,LastLogon | ConvertTo-Json -Compress", 45)
    if not rows:
        return Finding("ACC001", "Local accounts", "Accounts", Severity.INFO,
                       Status.INFO, "Could not enumerate local users")
    details = []
    enabled = 0
    for row in rows:
        if row.get("Enabled"):
            enabled += 1
            details.append("%s (password required: %s, last logon: %s)"
                           % (row.get("Name"), row.get("PasswordRequired"),
                              row.get("LastLogon") or "never"))
    return Finding("ACC001", "Local accounts", "Accounts", Severity.INFO, Status.INFO,
                   "%d enabled local account(s)" % enabled, details)


def check_admins():
    rows = powershell_json(
        "Get-LocalGroupMember -Group Administrators | "
        "Select-Object Name,PrincipalSource | ConvertTo-Json -Compress", 45)
    names = [r.get("Name", "?") for r in rows]
    if len(names) > 3:
        return Finding("ACC002", "Administrator group", "Accounts", Severity.MEDIUM,
                       Status.WARN, "%d accounts in Administrators" % len(names),
                       names,
                       "Keep this small - every admin account is a target.")
    return Finding("ACC002", "Administrator group", "Accounts", Severity.INFO,
                   Status.PASS, "%d account(s) in Administrators" % len(names), names)


def check_guest():
    code, out = run(["net", "user", "guest"], 25)
    lowered = out.lower()
    if "account active" in lowered:
        line = [l for l in out.splitlines() if "account active" in l.lower()]
        if line and "yes" in line[0].lower():
            return Finding("ACC003", "Guest account", "Accounts", Severity.MEDIUM,
                           Status.WARN, "Guest account is enabled",
                           ["Guest has no password by default."],
                           "net user guest /active:no")
    return Finding("ACC003", "Guest account", "Accounts", Severity.INFO, Status.PASS,
                   "Guest account is disabled")


def check_blank_passwords():
    code, out = run(["net", "accounts"], 25)
    if "no password required" in out.lower():
        line = [l for l in out.splitlines() if "no password required" in l.lower()]
        if line and "yes" in line[0].lower():
            return Finding("ACC004", "Blank passwords", "Accounts", Severity.MEDIUM,
                           Status.WARN, "Accounts may have blank passwords",
                           [], "net accounts /minpwlen:8")
    return Finding("ACC004", "Blank passwords", "Accounts", Severity.INFO, Status.PASS,
                   "Blank passwords are not permitted")


def check_password_policy():
    code, out = run(["net", "accounts"], 25)
    values = {}
    for line in out.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            values[key.strip().lower()] = value.strip()
    length = values.get("minimum password length", "")
    age = values.get("maximum password age", "")
    details = []
    problems = []
    try:
        if int(length) < 8:
            problems.append("Minimum password length is only %s" % length)
    except ValueError:
        pass
    if age and "unlimited" in age.lower():
        problems.append("Passwords never expire")
    if problems:
        return Finding("ACC005", "Password policy", "Accounts", Severity.MEDIUM,
                       Status.WARN, "; ".join(problems), details,
                       "net accounts /minpwlen:8")
    return Finding("ACC005", "Password policy", "Accounts", Severity.INFO, Status.PASS,
                   "Password policy: min length %s, max age %s" % (length or "?", age or "?"))


def check_autologon():
    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    user = reg_read(winreg.HKEY_LOCAL_MACHINE, path, "DefaultUserName")
    password = reg_read(winreg.HKEY_LOCAL_MACHINE, path, "DefaultPassword")
    if user and password:
        return Finding("ACC006", "Auto-logon", "Accounts", Severity.LOW, Status.WARN,
                       "Auto-logon is configured with a stored password",
                       ["The password sits in the registry in plaintext."],
                       "Use sysinternals Autologon to store it in LSA secrets instead.")
    if user:
        return Finding("ACC006", "Auto-logon", "Accounts", Severity.INFO, Status.INFO,
                       "Default user set to %s" % user)
    return Finding("ACC006", "Auto-logon", "Accounts", Severity.INFO, Status.PASS,
                   "No auto-logon configured")


def check_stored_credentials():
    code, out = run(["cmdkey", "/list"], 25)
    if "target:" in out.lower():
        entries = [l.strip() for l in out.splitlines() if l.strip().lower().startswith("target:")]
        return Finding("ACC007", "Stored credentials", "Accounts", Severity.INFO,
                       Status.INFO, "%d stored credential(s) in the vault" % len(entries),
                       entries[:15])
    return Finding("ACC007", "Stored credentials", "Accounts", Severity.INFO,
                   Status.PASS, "Credential vault is empty")


CHECKS = [
    ("ACC001", "Local accounts", check_local_users),
    ("ACC002", "Administrator group", check_admins),
    ("ACC003", "Guest account", check_guest),
    ("ACC004", "Blank passwords", check_blank_passwords),
    ("ACC005", "Password policy", check_password_policy),
    ("ACC006", "Auto-logon", check_autologon),
    ("ACC007", "Stored credentials", check_stored_credentials),
]