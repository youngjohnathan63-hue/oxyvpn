"""OxyVPN - a hard-edged OpenVPN client for Windows."""

from __future__ import annotations

import sys


def main() -> int:
    if sys.platform != "win32":
        print("[!] OxyVPN targets Windows; other platforms are untested.")

    from oxyvpn.ui.app import run

    return run()


if __name__ == "__main__":
    raise SystemExit(main())