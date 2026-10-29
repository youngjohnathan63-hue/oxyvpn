"""Configuration hardening checks."""

from __future__ import annotations

import winreg

from .models import Finding, Severity, Status
from .util import powershell_json, reg_read, run


def _finding(cid, title, sev, status, summary, details=None, fix="", evidence=""):
    return Finding(cid, title, "Hardening", sev, status, summary,
                   details or [], fix, evidence)


def check_firewall():
    code, out = run(["netsh", "advfirewall", "show", "allprofiles", "state"], 25)
    lowered = out.lower()
    on = lowered.count("state                                 on")
    off = lowered.count("state                                 off")
    if "on" in lowered and off == 0:
        return _finding("HRD001", "Windows Firewall", Severity.INFO, Status.PASS,
                        "All profiles enabled")
    if off:
        return _finding("HRD001", "Windows Firewall", Severity.CRITICAL, Status.FAIL,
                        "%d profile(s) disabled" % off,
                        ["An inbound-only firewall is your first line against "
                         "network worms and exposed services."],
                        "netsh advfirewall set allprofiles state on")
    return _finding("HRD001", "Windows Firewall", Severity.MEDIUM, Status.WARN,
                    "State unclear")


def check_defender():
    rows = powershell_json(
        "Get-MpComputerStatus | Select-Object "
        "AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,"
        "AntispywareEnabled,BehaviorMonitorEnabled,IsTamperProtected "
        "| ConvertTo-Json -Compress", 45)
    if rows:
        row = rows[0]
        if not row.get("AntivirusEnabled"):
            return _finding("HRD002", "Antivirus engine", Severity.CRITICAL,
                            Status.FAIL, "Defender antivirus is disabled",
                            [], "Enable real-time protection in Windows Security.")
        if not row.get("RealTimeProtectionEnabled"):
            return _finding("HRD002", "Antivirus engine", Severity.CRITICAL,
                            Status.FAIL, "Real-time protection is OFF",
                            ["Files are only scanned on demand."],
                            "Turn real-time protection back on.")
        age = row.get("AntivirusSignatureAge")
        if isinstance(age, int) and age > 7:
            return _finding("HRD002", "Antivirus engine", Severity.MEDIUM, Status.WARN,
                            "Signatures are %d days old" % age,
                            [], "Run Windows Update to refresh definitions.")
        details = ["Real-time protection: on"]
        if row.get("BehaviorMonitorEnabled"):
            details.append("Behaviour monitoring: on")
        if row.get("IsTamperProtected"):
            details.append("Tamper protection: on")
        return _finding("HRD002", "Antivirus engine", Severity.INFO, Status.PASS,
                        "Defender active and up to date", details)

    # fall back to SecurityCenter2
    rows = powershell_json(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "| Select-Object displayName,productState | ConvertTo-Json -Compress", 45)
    if rows:
        names = [r.get("displayName", "?") for r in rows]
        return _finding("HRD002", "Antivirus engine", Severity.INFO, Status.INFO,
                        "Registered AV: " + ", ".join(names), names)
    return _finding("HRD002", "Antivirus engine", Severity.MEDIUM, Status.WARN,
                    "Could not query antivirus status")


def check_uac():
    enabled = reg_read(winreg.HKEY_LOCAL_MACHINE,
                       r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                       "EnableLUA")
    level = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                     "ConsentPromptBehaviorAdmin")
    if enabled == 0:
        return _finding("HRD003", "User Account Control", Severity.HIGH, Status.FAIL,
                        "UAC is disabled",
                        ["Everything runs with full administrator rights, so any "
                         "process can silently change the system."],
                        "Set EnableLUA=1 and reboot.")
    if level == 0:
        return _finding("HRD003", "User Account Control", Severity.MEDIUM, Status.WARN,
                        "UAC on but prompts are suppressed for admins",
                        [], "Raise ConsentPromptBehaviorAdmin to 5.")
    return _finding("HRD003", "User Account Control", Severity.INFO, Status.PASS,
                    "UAC enabled (prompt level %s)" % level)


def check_smb1():
    code, out = run(["powershell", "-NoProfile", "-Command",
                     "(Get-SmbServerConfiguration).EnableSMB1Protocol"], 40)
    value = out.strip().lower()
    if value.startswith("true"):
        return _finding("HRD004", "SMBv1 protocol", Severity.HIGH, Status.WARN,
                        "SMBv1 is enabled",
                        ["SMBv1 is the protocol exploited by EternalBlue/WannaCry "
                         "and has no place on a modern network."],
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false")
    if value.startswith("false"):
        return _finding("HRD004", "SMBv1 protocol", Severity.INFO, Status.PASS,
                        "SMBv1 disabled")
    return _finding("HRD004", "SMBv1 protocol", Severity.LOW, Status.INFO,
                    "Could not determine SMBv1 state")


def check_rdp():
    enabled = reg_read(winreg.HKEY_LOCAL_MACHINE,
                       r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                       "fDenyTSConnections")
    nla = reg_read(winreg.HKEY_LOCAL_MACHINE,
                   r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                   "UserAuthentication")
    if enabled == 0:
        if nla == 0:
            return _finding("HRD005", "Remote Desktop", Severity.HIGH, Status.WARN,
                            "RDP enabled without Network Level Authentication",
                            ["Pre-NLA RDP exposes the login screen to anyone who "
                             "can reach port 3389."],
                            "Enable NLA or disable RDP if unused.")
        return _finding("HRD005", "Remote Desktop", Severity.MEDIUM, Status.WARN,
                        "RDP enabled with NLA",
                        ["Consider restricting 3389 to your LAN."])
    return _finding("HRD005", "Remote Desktop", Severity.INFO, Status.PASS,
                    "RDP disabled")


def check_autorun():
    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                     "NoDriveTypeAutoRun")
    if value is not None and (value & 0xFF) == 0xFF:
        return _finding("HRD006", "AutoRun", Severity.INFO, Status.PASS,
                        "AutoRun disabled on all drive types")
    return _finding("HRD006", "AutoRun", Severity.MEDIUM, Status.WARN,
                    "AutoRun is active for at least some drive types",
                    ["USB sticks can launch a payload the moment they are "
                     "inserted via autorun.inf."],
                    "Set NoDriveTypeAutoRun=0xFF.")


def check_powershell_policy():
    code, out = run(["powershell", "-NoProfile", "-Command",
                     "Get-ExecutionPolicy -Scope LocalMachine"], 30)
    policy = out.strip().lower()
    if policy == "restricted":
        return _finding("HRD007", "PowerShell policy", Severity.LOW, Status.WARN,
                        "LocalMachine policy is Restricted",
                        ["Scripts cannot run at all - often bypassed per-call, "
                         "which weakens the control."])
    if policy == "unrestricted":
        return _finding("HRD007", "PowerShell policy", Severity.MEDIUM, Status.WARN,
                        "Execution policy is Unrestricted",
                        ["Any downloaded script runs without warning."],
                        "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine")
    return _finding("HRD007", "PowerShell policy", Severity.INFO, Status.PASS,
                    "Execution policy: %s" % (policy or "unknown"))


def check_powershell_v2():
    code, out = run(["powershell", "-NoProfile", "-Command",
                     "(Get-WindowsOptionalFeature -Online "
                     "-FeatureName MicrosoftWindowsPowerShellV2).State"], 60)
    if "enabled" in out.strip().lower():
        return _finding("HRD008", "PowerShell v2 engine", Severity.MEDIUM, Status.WARN,
                        "PowerShell 2.0 engine is installed",
                        ["PSv2 has no script block logging and can be used to "
                         "downgrade an attacker's traceability."],
                        "Disable-WindowsOptionalFeature -Online "
                        "-FeatureName MicrosoftWindowsPowerShellV2")
    return _finding("HRD008", "PowerShell v2 engine", Severity.INFO, Status.PASS,
                    "PowerShell v2 not present")


def check_wdigest():
    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                     "UseLogonCredential")
    if value == 1:
        return _finding("HRD009", "WDigest plaintext credentials", Severity.MEDIUM,
                        Status.WARN, "WDigest stores plaintext passwords in memory",
                        ["Mimikatz can lift them straight out of lsass."],
                        "Set UseLogonCredential=0 and reboot.")
    return _finding("HRD009", "WDigest plaintext credentials", Severity.INFO,
                    Status.PASS, "Plaintext credential caching off")


def check_lm_hash():
    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash")
    if value == 1:
        return _finding("HRD010", "LM hash storage", Severity.INFO, Status.PASS,
                        "LM hashes are not stored")
    return _finding("HRD010", "LM hash storage", Severity.MEDIUM, Status.WARN,
                    "LM hashes may be stored",
                    ["LM is trivially cracked, so a captured hash is effectively "
                     "a plaintext password."],
                    "Set NoLMHash=1.")


def check_smartscreen():
    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
                     "SmartScreenEnabled")
    if value and str(value).lower() in ("off", "0"):
        return _finding("HRD011", "SmartScreen", Severity.MEDIUM, Status.WARN,
                        "SmartScreen is off",
                        [], "Set SmartScreenEnabled to Warn.")
    return _finding("HRD011", "SmartScreen", Severity.INFO, Status.PASS,
                    "SmartScreen active (%s)" % (value or "default"))


def check_llmnr():
    value = reg_read(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                     "EnableMulticast")
    if value == 0:
        return _finding("HRD012", "LLMNR", Severity.INFO, Status.PASS, "LLMNR disabled")
    return _finding("HRD012", "LLMNR", Severity.LOW, Status.WARN,
                    "LLMNR is enabled",
                    ["LLMNR is spoofable - Responder can harvest NTLM hashes "
                     "from it on a hostile network."],
                    "Set EnableMulticast=0 under the DNSClient policy key.")


CHECKS = [
    ("HRD001", "Windows Firewall", check_firewall),
    ("HRD002", "Antivirus engine", check_defender),
    ("HRD003", "User Account Control", check_uac),
    ("HRD004", "SMBv1 protocol", check_smb1),
    ("HRD005", "Remote Desktop", check_rdp),
    ("HRD006", "AutoRun", check_autorun),
    ("HRD007", "PowerShell policy", check_powershell_policy),
    ("HRD008", "PowerShell v2 engine", check_powershell_v2),
    ("HRD009", "WDigest credentials", check_wdigest),
    ("HRD010", "LM hash storage", check_lm_hash),
    ("HRD011", "SmartScreen", check_smartscreen),
    ("HRD012", "LLMNR", check_llmnr),
]