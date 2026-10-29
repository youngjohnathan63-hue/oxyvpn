# PyVPN

A small, honest OpenVPN client for Windows with a native-feeling dark UI.

## Requirements

- Windows 8.1 or newer
- Python 3.8+ (with tkinter)
- [OpenVPN Community](https://openvpn.net/community-downloads/) installed
- A free ProtonVPN account

## Setup

1. Install OpenVPN. The installer also installs the TAP/Wintun driver.
2. Create a free ProtonVPN account and go to
   https://account.protonvpn.com/downloads
   Download the **OpenVPN configuration files** (pick UDP).
3. From https://account.protonvpn.com -> Account, copy your
   **OpenVPN / IKEv2 username and password**.
4. Put the downloaded `.ovpn` files into the `profiles\` folder.
5. Run `python main.py`, accept the UAC prompt, open **Settings**,
   paste your credentials and press **Save settings**.

## Usage

- **Servers** — pick a server, double-click to connect. "Measure latency"
  TCP-pings each server.
- **Connect** — the big button. Click to connect, click again to disconnect.
- **Logs** — live OpenVPN output plus the app's own messages.

## How the kill switch works

Windows Firewall gives BLOCK rules precedence over ALLOW rules, so
"block everything + allow the VPN server" does not work. PyVPN instead
creates one outbound block rule whose remote-address set is the exact
complement of everything that must stay reachable (the VPN server, LAN,
loopback, DHCP, multicast). If the tunnel drops, nothing leaks.

Rules are named `PyVPN-KillSwitch-Out`. If the app ever crashes and leaves
you offline, run `netsh advfirewall firewall delete rule name=PyVPN-KillSwitch-Out`
or use **Settings -> Remove kill-switch rules**.

## Files

- Settings live in `%APPDATA%\PyVPN\settings.json`
- The last OpenVPN log is at `%APPDATA%\PyVPN\logs\openvpn-last.log`
- Your password is base64-encoded in settings.json (obfuscation, not encryption)

## Limitations

- Windows only.
- One tunnel at a time.
- OpenVPN only (no WireGuard).
- Split tunnelling is not implemented.