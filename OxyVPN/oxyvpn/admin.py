"""Administrator privilege detection and UAC elevation."""

from __future__ import annotations

import ctypes
import sys


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated() -> bool:
    if is_admin():
        return False

    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = " ".join('"%s"' % a for a in sys.argv[1:])
    else:
        executable = sys.executable
        params = " ".join('"%s"' % a for a in sys.argv)

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, params, None, 1
        )
    except Exception:
        return False
    return result > 32