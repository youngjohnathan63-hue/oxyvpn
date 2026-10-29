"""Filesystem locations used by OxyVPN."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from . import APP_NAME


def _appdata() -> Path:
    base = os.environ.get("APPDATA")
    return Path(base) if base else Path.home() / "AppData" / "Roaming"


APP_DIR = _appdata() / APP_NAME
LOG_DIR = APP_DIR / "logs"
SETTINGS_FILE = APP_DIR / "settings.json"
OPENVPN_LOG = LOG_DIR / "openvpn-last.log"

LEGACY_SETTINGS = [_appdata() / "PyVPN" / "settings.json"]


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_profiles_dir() -> Path:
    return project_root() / "profiles"


def default_bin_dir() -> Path:
    return project_root() / "bin"


def ensure_dirs() -> None:
    for path in (APP_DIR, LOG_DIR, default_profiles_dir()):
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    _migrate_legacy()


def _migrate_legacy() -> None:
    """Carry settings across from an older PyVPN install."""
    if SETTINGS_FILE.exists():
        return
    for candidate in LEGACY_SETTINGS:
        if candidate.exists():
            try:
                shutil.copy2(str(candidate), str(SETTINGS_FILE))
            except OSError:
                pass
            return