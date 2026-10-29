"""Application shell: window, navigation, session wiring."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path

from .. import __version__
from ..admin import is_admin, relaunch_elevated
from ..killswitch import KillSwitch
from ..netinfo import (default_gateway, dns_servers, lookup_public_ip,
                       physical_ipv4_addresses, resolve)
from ..paths import default_profiles_dir, ensure_dirs
from ..store import SettingsStore
from ..vpn.profile import scan_profiles
from ..vpn.session import VpnState, VpnSession
from . import theme
from .page_connect import ConnectPage
from .page_logs import LogsPage
from .page_scanner import ScannerPage
from .page_servers import ServersPage
from .page_settings import SettingsPage
from .widgets import NavItem
from .window import FramelessWindow, enable_dpi_awareness

PAGE_ORDER = ["connect", "scanner", "servers", "settings", "logs"]
PAGE_LABELS = {
    "connect": ("Connect", "power"),
    "scanner": ("Scanner", "shield"),
    "servers": ("Servers", "globe"),
    "settings": ("Settings", "gear"),
    "logs": ("Logs", "terminal"),
}
MAX_AUTO_RETRIES = 2
SAFE_MODE_AFTER = 1
HEALTH_DELAY = 8000


class App:
    def __init__(self, window: FramelessWindow):
        ensure_dirs()
        self.window = window
        self.store = SettingsStore()
        self.events = queue.Queue()
        self.profiles = []
        self.selected = None
        self._closing = False
        self._connecting = False
        self._pending = None
        self._auto_retries = 0
        self._server_ip = ""
        self._toast = None
        self._last_toast = ""
        self._scan_score = None

        self.killswitch = KillSwitch()
        self.session = VpnSession(
            on_state=lambda status: self.events.put(("state", status)),
            on_log=lambda message: self.events.put(("log", message)),
            on_traffic=lambda down, up: self.events.put(("traffic", down, up)),
        )

        self._build()
        self._wire()
        self.reload_profiles()
        self._restore_selection()
        self._cleanup_stale()
        self.window.after(80, self._drain)
        self.window.after(400, self._start_ip_watch)
        self.window.after(1000, self._tick)

    # ------------------------------------------------------------- layout
    def _build(self):
        self.window.build_chrome("OxyVPN", "v" + __version__)
        if self.store.data.window_geometry:
            self.window.apply_saved_geometry(self.store.data.window_geometry)

        self.window.build_statusbar()

        body = tk.Frame(self.window.content, bg=theme.BG)
        body.pack(fill="both", expand=True)

        sidebar = tk.Frame(body, bg=theme.BG_ALT, width=190)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="MENU", bg=theme.BG_ALT, fg=theme.TEXT_FAINT,
                 font=theme.f(8, "bold"), anchor="w").pack(fill="x", padx=17, pady=(18, 6))

        self.nav = {}
        for key in PAGE_ORDER:
            label, icon = PAGE_LABELS[key]
            item = NavItem(sidebar, label, icon, lambda k=key: self.show_page(k))
            item.pack(fill="x")
            self.nav[key] = item

        footer = tk.Frame(sidebar, bg=theme.BG_ALT)
        footer.pack(side="bottom", fill="x", pady=14, padx=17)
        self.privilege = tk.Label(footer, text="", bg=theme.BG_ALT,
                                  fg=theme.TEXT_FAINT, font=theme.f(8), anchor="w")
        self.privilege.pack(fill="x")
        tk.Label(footer, text="OpenVPN front-end", bg=theme.BG_ALT,
                 fg=theme.TEXT_FAINT, font=theme.f(8), anchor="w").pack(fill="x")

        self.container = tk.Frame(body, bg=theme.BG)
        self.container.pack(side="left", fill="both", expand=True)

        self.pages = {
            "connect": ConnectPage(self.container, self),
            "scanner": ScannerPage(self.container, self),
            "servers": ServersPage(self.container, self),
            "settings": SettingsPage(self.container, self),
            "logs": LogsPage(self.container, self),
        }
        for page in self.pages.values():
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.show_page("connect")

    def _wire(self):
        self.window.on_close = self.shutdown
        self.privilege.configure(
            text="Administrator" if is_admin() else "Not elevated",
            fg=theme.GREEN if is_admin() else theme.AMBER)

    # ------------------------------------------------------------ helpers
    def post(self, callback):
        self.events.put(("call", callback))

    def log_line(self, text):
        self.post(lambda t=text: self.pages["logs"].append(t))

    def profiles_dir_text(self):
        return self.store.data.profiles_dir or str(default_profiles_dir())

    def show_page(self, key):
        for name, item in self.nav.items():
            item.set_active(name == key)
        self.pages[key].lift()
        if key == "servers":
            self.pages["servers"].refresh()

    def reload_profiles(self):
        directory = Path(self.store.data.profiles_dir or default_profiles_dir())
        self.profiles = scan_profiles(directory)
        if "servers" in self.pages:
            self.pages["servers"].refresh()

    def _restore_selection(self):
        last = self.store.data.last_server
        for profile in self.profiles:
            if profile.key == last:
                self.selected = profile
                break
        if self.selected is None and self.profiles:
            self.selected = self.profiles[0]
        self.pages["connect"].set_profile(self.selected)

    def select_profile(self, profile):
        self.selected = profile
        self.store.update(last_server=profile.key)
        self.pages["connect"].set_profile(profile)
        for row in self.pages["servers"].rows:
            row.set_selected(row.profile is profile)

    def set_scan_score(self, score, grade):
        self._scan_score = (score, grade)
        self.window.set_status_extra(scan="scan %d/100 (%s)" % (score, grade))

    def _cleanup_stale(self):
        try:
            if self.killswitch.present():
                self.killswitch.clear()
                self.pages["logs"].append("removed stale kill-switch rules")
        except Exception:
            pass

    def _start_ip_watch(self):
        threading.Thread(target=self._ip_worker, daemon=True).start()

    def _ip_worker(self):
        info = lookup_public_ip()

        def show():
            if info.ok:
                text = info.ip + ("  (%s)" % info.country if info.country else "")
                self.pages["connect"].set_exit_ip(text, theme.AMBER)
            else:
                self.pages["connect"].set_exit_ip("unavailable", theme.TEXT_FAINT)

        self.post(show)

    def toast(self, text, kind="info"):
        self.post(lambda: self._toast_now(text, kind))

    def _toast_now(self, text, kind):
        if text == self._last_toast:
            try:
                if self._toast is not None:
                    self._toast.destroy()
            except Exception:
                pass
        self._last_toast = text

        colours = {
            "info": (theme.SURFACE_HI, theme.TEXT),
            "good": (theme.GREEN_DIM, theme.GREEN),
            "bad": (theme.RED_DIM, theme.RED),
            "warn": (theme.AMBER_DIM, theme.AMBER),
        }
        bg, fg = colours.get(kind, colours["info"])
        try:
            if self._toast is not None:
                self._toast.destroy()
        except Exception:
            pass
        frame = tk.Frame(self.window.content, bg=bg)
        tk.Label(frame, text=text, bg=bg, fg=fg, font=theme.f(9, "bold"),
                 padx=16, pady=9).pack()
        frame.place(relx=0.5, y=10, anchor="n")
        frame.lift()
        self._toast = frame
        self.window.after(3600, lambda f=frame: self._kill_toast(f))

    def _kill_toast(self, frame):
        try:
            frame.destroy()
            if frame is self._toast:
                self._toast = None
        except Exception:
            pass

    def restore_internet(self):
        try:
            self.killswitch.clear()
        except Exception:
            pass
        self.toast("Firewall rules cleared - internet restored", "good")
        self.pages["logs"].append("kill-switch rules removed manually")

    # --------------------------------------------------------- kill switch
    def _arm_killswitch_async(self):
        threading.Thread(target=self._arm_killswitch, daemon=True).start()

    def _arm_killswitch(self):
        try:
            tunnel_ip = self.session.status.local_ip
            allowed = [self._server_ip] if self._server_ip else []
            allowed += dns_servers()
            gateway = default_gateway()
            if gateway:
                allowed.append(gateway)
            physical = physical_ipv4_addresses(exclude=[tunnel_ip])
            self.killswitch = KillSwitch(allowed, local_ips=physical)
            result = self.killswitch.arm()
            self.log_line(("kill switch armed: " if result.ok
                           else "kill switch failed: ") + result.detail)
        except Exception as exc:
            self.log_line("kill switch error: %s" % exc)

    def _disarm_killswitch(self):
        try:
            if self.killswitch.armed:
                self.killswitch.clear()
                self.log_line("kill switch disarmed")
        except Exception:
            pass

    def _health_check(self):
        try:
            info = lookup_public_ip()
        except Exception:
            info = None
        if info is None or not info.ok:
            if self.killswitch.armed:
                self._disarm_killswitch()
                self.log_line("health check failed - kill switch disabled")
                self.toast("Tunnel not passing traffic - kill switch disabled", "warn")
            return
        if info.country:
            self.post(lambda: self.pages["connect"].set_exit_ip(
                info.ip + "  (%s)" % info.country, theme.GREEN))

    # ---------------------------------------------------------- connection
    def toggle_connection(self):
        state = self.session.status.state
        if state == VpnState.CONNECTED or state.busy:
            self._auto_retries = 0
            self._pending = None
            self.disconnect()
        else:
            self._auto_retries = 0
            self.connect_to(self.selected)

    def connect_to(self, profile, safe_mode=False):
        if profile is None:
            self.show_page("servers")
            return
        self._pending = (profile, safe_mode)
        if self._connecting:
            self.session.abort()
            self.pages["connect"].set_state("connecting", "Switching", profile.title)
            return
        self._start_pending()

    def _start_pending(self):
        if self._pending is None or self._closing:
            return
        profile, safe_mode = self._pending
        self._pending = None
        if (self.session.status.state == VpnState.CONNECTED
                and self.session.status.profile is profile):
            self.toast("Already connected to " + profile.title, "info")
            return
        self._connecting = True
        self.selected = profile
        self.pages["connect"].set_profile(profile)
        self.store.update(last_server=profile.key)
        self.window.set_status_extra(server=profile.title)
        self.pages["connect"].set_state(
            "connecting", "Preparing" + (" (safe mode)" if safe_mode else ""),
            profile.title)
        threading.Thread(target=self._connect_worker, args=(profile, safe_mode),
                         daemon=True).start()

    def _connect_worker(self, profile, safe_mode):
        try:
            username = self.store.data.username
            password = self.store.data.password
            if not username or not password:
                self.post(lambda: self.show_page("settings"))
                self.toast("Credentials missing - fill them in Settings", "warn")
                return
            server_ip = resolve(profile.host)
            self._server_ip = server_ip
            if not server_ip:
                self.log_line("warning: could not resolve " + profile.host)
            if self.killswitch.armed:
                self._disarm_killswitch()
            self.session.connect(
                profile, (username, password), self.store.data.openvpn_path,
                server_ip=server_ip,
                hardening=self.store.data.crypto_hardening and not safe_mode,
                block_dns=self.store.data.block_dns and not safe_mode,
                attempts=self.store.data.retry_attempts,
            )
        except Exception as exc:
            self.log_line("connect error: %s" % exc)
            self.session._fail("internal error: %s" % exc)
        finally:
            self._connecting = False
            if self._pending is not None:
                self.post(self._start_pending)

    def disconnect(self):
        self.pages["connect"].set_state("connecting", "Disconnecting", "tearing down")
        threading.Thread(target=self._disconnect_worker, daemon=True).start()

    def _disconnect_worker(self):
        self.session.disconnect()
        self._disarm_killswitch()

    # ------------------------------------------------------------- pumping
    def _drain(self):
        if self._closing:
            return
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "state":
                    self._on_state(event[1])
                elif kind == "log":
                    self.pages["logs"].append(event[1])
                elif kind == "traffic":
                    self.pages["connect"].set_traffic(event[1], event[2])
                elif kind == "call":
                    try:
                        event[1]()
                    except Exception:
                        pass
        except queue.Empty:
            pass
        self.window.after(80, self._drain)

    def _on_state(self, status):
        state = status.state
        profile = status.profile or self.selected

        if state == VpnState.CONNECTED:
            self._auto_retries = 0
            title = profile.title if profile else "Connected"
            self.pages["connect"].set_state("connected", "Connected", title)
            if status.local_ip:
                self.pages["connect"].set_exit_ip(status.local_ip, theme.GREEN)
            self.window.set_status("Connected - " + title, theme.GREEN)
            self.toast("Connected to " + title, "good")
            if self.store.data.kill_switch and not self.killswitch.armed:
                self._arm_killswitch_async()
                self.window.after(HEALTH_DELAY, self._health_check)

        elif state == VpnState.FAILED:
            reason = status.last_error or "see logs"
            self.pages["connect"].set_state("failed", "Failed", reason[:150])
            self.window.set_status("Failed - " + reason[:60], theme.RED)
            self._disarm_killswitch()
            if (self.store.data.auto_retry
                    and self._auto_retries < MAX_AUTO_RETRIES
                    and profile is not None
                    and self._pending is None):
                self._auto_retries += 1
                safe = self._auto_retries > SAFE_MODE_AFTER
                self.toast("Retrying %d/%d%s..." % (
                    self._auto_retries, MAX_AUTO_RETRIES,
                    " in safe mode" if safe else ""), "warn")
                self.window.after(2400,
                                  lambda p=profile, s=safe: self.connect_to(p, safe_mode=s))
            else:
                self.toast("Connection failed", "bad")

        elif state == VpnState.DISCONNECTED:
            if self._connecting or self._pending is not None:
                target = (self._pending or (self.selected, False))[0]
                self.pages["connect"].set_state(
                    "connecting", "Switching", target.title if target else "")
            else:
                self.pages["connect"].set_state("idle", "Not connected",
                                                "Pick a server and hit connect")
                self.pages["connect"].set_traffic(0, 0)
                self.window.set_status("Disconnected", theme.TEXT_FAINT)
            self._disarm_killswitch()

        elif state.busy:
            label = state.value.replace("_", " ").title()
            detail = status.detail or (profile.title if profile else "")
            self.pages["connect"].set_state("connecting", label, detail)
            self.window.set_status(label + " - " + detail[:60], theme.AMBER)

    def _tick(self):
        if self._closing:
            return
        if self.session.status.is_up:
            self.pages["connect"].set_uptime(self.session.status.uptime)
        self.window.after(1000, self._tick)

    # -------------------------------------------------------------- closing
    def shutdown(self):
        if self._closing:
            return
        self._closing = True
        try:
            self.session.shutdown()
        except Exception:
            pass
        if self.store.data.kill_switch:
            try:
                self.killswitch.clear()
            except Exception:
                pass
        try:
            self.store.update(window_geometry=self.window.geometry())
        except Exception:
            pass
        try:
            self.window.destroy()
        except Exception:
            pass


def run() -> int:
    enable_dpi_awareness()

    if not is_admin():
        import tkinter.messagebox as messagebox
        probe = tk.Tk()
        probe.withdraw()
        answer = messagebox.askyesno(
            "OxyVPN needs administrator rights",
            "OpenVPN, the kill switch and several scanner checks all need "
            "elevation.\n\nRelaunch OxyVPN as administrator?")
        probe.destroy()
        if answer and relaunch_elevated():
            return 0

    window = FramelessWindow()
    App(window)
    window.mainloop()
    return 0