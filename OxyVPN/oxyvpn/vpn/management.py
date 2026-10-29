"""OpenVPN management interface client (127.0.0.1 TCP)."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass


@dataclass
class StateEvent:
    name: str
    detail: str = ""
    local_ip: str = ""
    remote_ip: str = ""
    raw: str = ""


class ManagementClient:
    def __init__(self, host="127.0.0.1", port=25340, on_state=None, on_log=None,
                 on_bytes=None, on_password_request=None):
        self.host = host
        self.port = port
        self.on_state = on_state
        self.on_log = on_log
        self.on_bytes = on_bytes
        self.on_password_request = on_password_request

        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._buffer = b""
        self.last_state = ""
        self.connected = threading.Event()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="openvpn-mgmt", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            sock = self._sock
            self._sock = None
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def wait_connected(self, timeout=20.0) -> bool:
        return self.connected.wait(timeout)

    def send(self, command: str) -> None:
        with self._lock:
            if not self._sock:
                return
            try:
                self._sock.sendall((command + "\n").encode("utf-8"))
            except OSError:
                pass

    # ------------------------------------------------------------ internals
    def _run(self) -> None:
        sock = None
        deadline = time.time() + 30.0
        while time.time() < deadline and not self._stop.is_set():
            try:
                sock = socket.create_connection((self.host, self.port), timeout=1.5)
                break
            except OSError:
                if self._stop.wait(0.12):
                    return

        if sock is None:
            self._log("control channel: could not reach OpenVPN (mgmt port closed)")
            return

        sock.settimeout(0.4)
        with self._lock:
            self._sock = sock

        try:
            self._handshake()
            self._loop()
        except Exception as exc:
            self._log("control channel: %s" % exc)
        finally:
            self.connected.clear()
            with self._lock:
                if self._sock:
                    try:
                        self._sock.close()
                    except OSError:
                        pass
                    self._sock = None

    def _handshake(self) -> None:
        banner = self._read_until(b"OpenVPN Management Interface", timeout=12.0)
        if b"ENTER PASSWORD" in banner:
            self.send("")
            self._read_until(b"OpenVPN Management Interface", timeout=5.0)
        if not banner:
            self._log("control channel: no banner, sending commands anyway")
        self.send("state on")
        self.send("log on")
        self.send("bytecount 1")
        self.send("echo on")
        self.connected.set()
        self._log("control channel attached")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            self._buffer += chunk
            while b"\n" in self._buffer:
                line, self._buffer = self._buffer.split(b"\n", 1)
                self._dispatch(line.decode("utf-8", "replace").rstrip("\r"))

    def _read_until(self, marker: bytes, timeout=10.0) -> bytes:
        data = b""
        deadline = time.time() + timeout
        while marker not in data and time.time() < deadline and not self._stop.is_set():
            try:
                chunk = self._sock.recv(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        return data

    def _dispatch(self, line: str) -> None:
        if line.startswith(">STATE:"):
            self._on_state_line(line[7:])
        elif line.startswith(">BYTECOUNT:"):
            self._on_bytecount(line[11:])
        elif line.startswith(">LOG:"):
            self._on_log_line(line[5:])
        elif line.startswith(">PASSWORD:"):
            self._on_password(line[10:])
        elif line.startswith(">HOLD:"):
            self.send("hold release")

    def _on_state_line(self, payload: str) -> None:
        parts = payload.split(",")
        if len(parts) < 2:
            return
        event = StateEvent(
            name=parts[1].strip(),
            detail=parts[2].strip() if len(parts) > 2 else "",
            local_ip=parts[3].strip() if len(parts) > 3 else "",
            remote_ip=parts[4].strip() if len(parts) > 4 else "",
            raw=payload,
        )
        self.last_state = event.name
        if self.on_state:
            self.on_state(event)

    def _on_bytecount(self, payload: str) -> None:
        if not self.on_bytes:
            return
        parts = payload.split(",")
        if len(parts) < 2:
            return
        try:
            self.on_bytes(int(parts[0]), int(parts[1]))
        except ValueError:
            pass

    def _on_log_line(self, payload: str) -> None:
        parts = payload.split(",", 2)
        message = parts[2] if len(parts) > 2 else payload
        self._log(message.strip())

    def _on_password(self, payload: str) -> None:
        if not payload.startswith("Need"):
            self._log("auth: " + payload)
            return
        if not self.on_password_request:
            return
        chunks = payload.split("'")
        kind = chunks[1] if len(chunks) > 1 else "Auth"
        creds = self.on_password_request(kind)
        if not creds:
            return
        username, password = creds
        self.send('username "%s" %s' % (kind, username))
        self.send('password "%s" %s' % (kind, password))

    def _log(self, message: str) -> None:
        if self.on_log:
            self.on_log(message)