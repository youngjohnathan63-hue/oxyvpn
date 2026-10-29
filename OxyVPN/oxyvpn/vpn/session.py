"""OpenVPN process lifecycle and the connection state machine.

Design notes:
  * connect() runs on a worker thread - blocking work must never freeze the UI.
  * Credentials go in an auth FILE, not through the management socket, so
    authentication never depends on the control channel being up.
  * _connect_lock serialises attempts; abort() cancels one instantly.
  * A generation counter invalidates threads left over from old attempts.
  * Watchers: process exit, OpenVPN's own log (terminal markers with real
    error text), live progress line, and a hard timeout.
"""

from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import Enum

from ..paths import APP_DIR, OPENVPN_LOG
from .locate import (find_openvpn, kill_lingering_openvpn, parse_version,
                     wait_for_adapter_free)
from .management import ManagementClient
from .profile import Profile

CREATE_NO_WINDOW = 0x08000000
CONNECT_TIMEOUT = 75.0
ADAPTER_WAIT = 10.0

STRICT_TLS_CIPHERS = ":".join([
    "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
    "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
    "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
    "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
    "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
])

TERMINAL_MARKERS = [
    ("Initialization Sequence Completed", "connected", ""),
    ("AUTH_FAILED", "failed",
     "authentication failed - regenerate your OpenVPN credentials"),
    ("Options error:", "failed", None),
    ("Exiting due to fatal error", "failed", None),
    ("All TAP-Windows adapters", "failed",
     "TAP adapter busy - close any other VPN client"),
    ("Cannot open TUN/TAP", "failed", "adapter missing - run as administrator"),
    ("TLS Error", "failed", "TLS negotiation failed"),
    ("TLS handshake failed", "failed", "TLS handshake failed"),
    ("TLS key negotiation failed", "failed", "TLS key negotiation timed out"),
    ("tls-cipher", "failed", "TLS cipher rejected - disable Strict crypto"),
    ("cipher negotiation failed", "failed", "cipher mismatch - disable Strict crypto"),
    ("Inactivity timeout", "failed", "no response from the server"),
]


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def write_auth_file(username: str, password: str):
    """Two-line credential file for --auth-user-pass."""
    path = APP_DIR / "auth.txt"
    try:
        path.write_text("%s\n%s\n" % (username, password), encoding="utf-8")
        return path
    except OSError:
        return None


class VpnState(str, Enum):
    IDLE = "IDLE"
    PREPARING = "PREPARING"
    CONNECTING = "CONNECTING"
    AUTHENTICATING = "AUTHENTICATING"
    GETTING_CONFIG = "GETTING_CONFIG"
    ASSIGNING_IP = "ASSIGNING_IP"
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    DISCONNECTING = "DISCONNECTING"
    DISCONNECTED = "DISCONNECTED"
    FAILED = "FAILED"

    @property
    def busy(self):
        return self in (
            VpnState.PREPARING, VpnState.CONNECTING, VpnState.AUTHENTICATING,
            VpnState.GETTING_CONFIG, VpnState.ASSIGNING_IP, VpnState.RECONNECTING,
        )


OPENVPN_STATES = {
    "CONNECTING": VpnState.CONNECTING,
    "WAIT": VpnState.CONNECTING,
    "AUTH": VpnState.AUTHENTICATING,
    "GET_CONFIG": VpnState.GETTING_CONFIG,
    "ASSIGN_IP": VpnState.ASSIGNING_IP,
    "ADD_ROUTES": VpnState.ASSIGNING_IP,
    "CONNECTED": VpnState.CONNECTED,
    "RECONNECTING": VpnState.RECONNECTING,
    "EXITING": VpnState.DISCONNECTING,
    "DISCONNECTED": VpnState.DISCONNECTED,
    "FAILED": VpnState.FAILED,
}


@dataclass
class SessionStatus:
    state: VpnState = VpnState.IDLE
    profile: object = None
    local_ip: str = ""
    remote_ip: str = ""
    detail: str = ""
    bytes_in: int = 0
    bytes_out: int = 0
    connected_since: float = 0.0
    last_error: str = ""

    @property
    def uptime(self):
        return time.time() - self.connected_since if self.connected_since else 0.0

    @property
    def is_up(self):
        return self.state == VpnState.CONNECTED


def hardening_args(version) -> list:
    args = []
    if version >= (2, 3):
        args += ["--tls-version-min", "1.2"]
    if version >= (2, 4):
        args += ["--remote-cert-tls", "server"]
        args += ["--tls-cipher", STRICT_TLS_CIPHERS]
    if version >= (2, 5):
        args += ["--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]
    return args


def pin_remote(profile: Profile, server_ip: str):
    try:
        text = profile.path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return profile.path
    if not re.search(r"(?im)^\s*remote\s+", text):
        return profile.path
    pinned = re.sub(r"(?im)^\s*remote\s+.*$",
                    "remote %s %d" % (server_ip, profile.port), text)
    target = profile.path.parent / (".oxyvpn-" + profile.path.name)
    try:
        target.write_text(pinned, encoding="utf-8")
    except OSError:
        return profile.path
    return target


class VpnSession:
    def __init__(self, on_state=None, on_log=None, on_traffic=None):
        self.on_state = on_state
        self.on_log = on_log
        self.on_traffic = on_traffic

        self.status = SessionStatus()
        self._proc = None
        self._mgmt = None
        self._creds = ("", "")
        self._lock = threading.RLock()
        self._connect_lock = threading.Lock()
        self._baseline = (0, 0, time.time())
        self._stopping = False
        self._generation = 0
        self._log_handle = None
        self._log_offset = 0

    @property
    def active(self):
        return self._proc is not None and self._proc.poll() is None

    # ------------------------------------------------------------- plumbing
    def _emit(self):
        if self.on_state:
            self.on_state(self.status)

    def log(self, message):
        if self.on_log:
            self.on_log(message)

    def _alive(self, generation):
        with self._lock:
            return generation == self._generation and not self._stopping

    def _set_state(self, state, detail=None, profile=None):
        with self._lock:
            self.status.state = state
            if detail is not None:
                self.status.detail = detail
            if profile is not None:
                self.status.profile = profile
            if state == VpnState.CONNECTED and not self.status.connected_since:
                self.status.connected_since = time.time()
                self._baseline = (self.status.bytes_in, self.status.bytes_out,
                                  time.time())
            if state in (VpnState.DISCONNECTED, VpnState.FAILED):
                self.status.connected_since = 0.0
        self._emit()

    def _fail(self, reason):
        with self._lock:
            if self.status.state == VpnState.FAILED:
                return
            self.status.last_error = reason or "connection failed"
            self.status.connected_since = 0.0
        self._set_state(VpnState.FAILED, detail=reason or "")

    def abort(self):
        with self._lock:
            self._generation += 1
            self._stopping = True
            proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    # -------------------------------------------------------------- connect
    def connect(self, profile: Profile, credentials, openvpn_path="",
                server_ip="", hardening=True, block_dns=True, attempts=3,
                connect_timeout=CONNECT_TIMEOUT) -> bool:
        with self._connect_lock:
            if self.active:
                self.disconnect(emit=False)
            self._teardown()

            with self._lock:
                self._generation += 1
                generation = self._generation
                self._stopping = False

            self._set_state(VpnState.PREPARING, detail="locating engine",
                            profile=profile)

            exe = find_openvpn(openvpn_path)
            if not exe:
                self._fail("openvpn.exe was not found - set the path in Settings")
                return False
            if not self._alive(generation):
                return False

            self.log("preparing: clearing stale openvpn processes")
            try:
                if kill_lingering_openvpn():
                    self.log("preparing: killed a leftover openvpn.exe")
            except Exception as exc:
                self.log("preparing: cleanup warning: %s" % exc)

            if not self._alive(generation):
                return False

            self._set_state(VpnState.PREPARING, detail="waiting for the virtual adapter")
            wait_for_adapter_free(ADAPTER_WAIT)

            if not self._alive(generation):
                return False

            version = parse_version(exe)
            self.log("preparing: openvpn %s"
                     % (".".join(str(v) for v in version) if version != (0, 0)
                        else "version unknown"))

            config_path = profile.path
            if server_ip:
                pinned = pin_remote(profile, server_ip)
                if pinned != profile.path:
                    config_path = pinned
                    self.log("preparing: remote pinned to %s:%d"
                             % (server_ip, profile.port))

            username, password = credentials or ("", "")
            auth_file = write_auth_file(username, password) if username else None

            port = free_port()
            args = [
                exe,
                "--config", str(config_path),
                "--management", "127.0.0.1", str(port),
                "--auth-nocache",
                "--persist-key",
                "--persist-tun",
                "--resolv-retry", "infinite",
                "--verb", "3",
            ]

            if auth_file:
                args += ["--auth-user-pass", str(auth_file)]
                self.log("preparing: credentials supplied via auth file")
            else:
                args += ["--management-query-passwords"]

            if version >= (2, 4):
                args += ["--connect-retry", "2",
                         "--connect-retry-max", str(max(1, attempts)),
                         "--connect-timeout", "20"]

            if hardening:
                args += hardening_args(version)
                self.log("crypto: TLS 1.2+, forward-secret ciphers, AES-GCM/ChaCha20")

            if block_dns and version >= (2, 4):
                args += ["--block-outside-dns"]
                self.log("crypto: DNS leak protection on")

            if not self._alive(generation):
                return False

            try:
                self._log_offset = (OPENVPN_LOG.stat().st_size
                                    if OPENVPN_LOG.exists() else 0)
            except OSError:
                self._log_offset = 0

            try:
                self._log_handle = OPENVPN_LOG.open("a", encoding="utf-8")
                self._log_handle.write(
                    "\n===== %s | %s | mgmt %d | hardening=%s =====\n"
                    % (time.strftime("%Y-%m-%d %H:%M:%S"), profile.name, port,
                       hardening))
                self._log_handle.write(" ".join(args) + "\n")
                self._log_handle.flush()
                proc = subprocess.Popen(
                    args,
                    stdout=self._log_handle,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW,
                    cwd=str(profile.path.parent),
                )
            except OSError as exc:
                self._fail("could not launch OpenVPN: %s" % exc)
                return False

            if not self._alive(generation):
                try:
                    proc.terminate()
                except Exception:
                    pass
                return False

            with self._lock:
                self._proc = proc
                self._creds = credentials or ("", "")

            self._set_state(VpnState.CONNECTING, detail="starting tunnel")

            self._mgmt = ManagementClient(
                port=port,
                on_state=self._on_openvpn_state,
                on_log=self.log,
                on_bytes=self._on_bytes,
                on_password_request=self._on_password,
            )
            self._mgmt.start()

            threading.Thread(target=self._watch, args=(proc, generation),
                             daemon=True).start()
            threading.Thread(target=self._log_watch,
                             args=(generation, self._log_offset), daemon=True).start()
            threading.Thread(target=self._progress_watch,
                             args=(generation,), daemon=True).start()
            threading.Thread(target=self._timeout_watch,
                             args=(generation, connect_timeout), daemon=True).start()
            return True

    # -------------------------------------------------------------- watchers
    def _watch(self, proc, generation):
        code = proc.wait()
        with self._lock:
            if generation != self._generation:
                return
            if self._stopping or code == 0:
                final, error = VpnState.DISCONNECTED, ""
            else:
                final, error = VpnState.FAILED, self._tail_log()
            self.status.connected_since = 0.0
            self.status.last_error = error
        self._set_state(final, detail=error)

    def _log_watch(self, generation, offset):
        seen = offset
        fired = False
        while not fired and self._alive(generation):
            time.sleep(0.4)
            try:
                text = OPENVPN_LOG.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            chunk = text[seen:]
            if not chunk:
                continue
            seen = len(text)

            for line in chunk.splitlines():
                lowered = line.lower()
                for marker, kind, hint in TERMINAL_MARKERS:
                    if marker.lower() not in lowered:
                        continue
                    if kind == "connected":
                        self._set_state(VpnState.CONNECTED, detail="")
                    else:
                        with self._lock:
                            current = self.status.state
                        if current != VpnState.CONNECTED:
                            self._fail(hint or line.strip()[:180])
                    fired = True
                    break
                if fired:
                    break

    def _progress_watch(self, generation):
        """Surface the live OpenVPN log line so a stall is visible."""
        last = ""
        while self._alive(generation):
            if self.status.state in (VpnState.CONNECTED, VpnState.FAILED,
                                     VpnState.DISCONNECTED):
                return
            line = self._last_log_line()
            if line and line != last:
                last = line
                with self._lock:
                    self.status.detail = line[:170]
                self._emit()
            time.sleep(1.0)

    def _timeout_watch(self, generation, timeout):
        deadline = time.time() + timeout
        while self._alive(generation) and time.time() < deadline:
            if self.status.state in (VpnState.CONNECTED, VpnState.FAILED,
                                     VpnState.DISCONNECTED):
                return
            time.sleep(0.5)
        if not self._alive(generation):
            return
        if self.status.state not in (VpnState.CONNECTED, VpnState.FAILED,
                                     VpnState.DISCONNECTED):
            self._fail("timed out after %ds: %s" % (int(timeout), self._tail_log(3)))

    def _tail_log(self, lines=5):
        try:
            text = OPENVPN_LOG.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return "OpenVPN exited unexpectedly"
        chunk = text[self._log_offset:] if self._log_offset else text
        tail = [ln.strip() for ln in chunk.splitlines() if ln.strip()][-lines:]
        return " | ".join(tail) or "OpenVPN exited unexpectedly"

    def _last_log_line(self):
        try:
            text = OPENVPN_LOG.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
        chunk = text[self._log_offset:] if self._log_offset else text
        for line in reversed(chunk.splitlines()):
            line = line.strip()
            if not line or line.startswith("====="):
                continue
            if line.startswith("OpenVPN 2"):
                continue
            return line
        return ""

    # ------------------------------------------------------------- callbacks
    def _on_password(self, kind):
        return self._creds

    def _on_openvpn_state(self, event):
        mapped = OPENVPN_STATES.get(event.name)
        if mapped is None:
            return
        with self._lock:
            self.status.state = mapped
            if event.local_ip:
                self.status.local_ip = event.local_ip
            if event.remote_ip:
                self.status.remote_ip = event.remote_ip
            if mapped == VpnState.CONNECTED and not self.status.connected_since:
                self.status.connected_since = time.time()
                self._baseline = (self.status.bytes_in, self.status.bytes_out,
                                  time.time())
            if mapped in (VpnState.DISCONNECTED, VpnState.FAILED):
                self.status.connected_since = 0.0
        self._emit()

    def _on_bytes(self, bytes_in, bytes_out):
        now = time.time()
        with self._lock:
            self.status.bytes_in = bytes_in
            self.status.bytes_out = bytes_out
            last_in, last_out, last_at = self._baseline
            elapsed = now - last_at
            if elapsed >= 0.9:
                if self.on_traffic:
                    self.on_traffic((bytes_in - last_in) / elapsed,
                                    (bytes_out - last_out) / elapsed)
                self._baseline = (bytes_in, bytes_out, now)

    # ----------------------------------------------------------- disconnect
    def disconnect(self, emit=True):
        with self._lock:
            self._generation += 1
            self._stopping = True
            proc = self._proc
            mgmt = self._mgmt
            if proc is None:
                self.status.state = VpnState.DISCONNECTED
                self.status.connected_since = 0.0
                if emit:
                    self._emit()
                return
            self.status.state = VpnState.DISCONNECTING
        if emit:
            self._emit()

        if mgmt:
            mgmt.send("signal SIGTERM")

        if proc:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

        self._teardown()
        with self._lock:
            self.status.state = VpnState.DISCONNECTED
            self.status.connected_since = 0.0
            self.status.bytes_in = 0
            self.status.bytes_out = 0
            self.status.local_ip = ""
        if emit:
            self._emit()

    def _teardown(self):
        if self._mgmt:
            self._mgmt.stop()
            self._mgmt = None
        self._proc = None
        if self._log_handle:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None

    def shutdown(self):
        if self.active:
            self.disconnect()
        self._teardown()