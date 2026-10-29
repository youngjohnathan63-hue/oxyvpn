"""Settings page."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog

from ..netinfo import lookup_public_ip
from ..vpn.locate import adapter_present, find_openvpn, version_of
from . import theme
from .widgets import Card, FlatButton, SectionTitle, ToggleSwitch


class Field(tk.Frame):
    def __init__(self, master, label, value, browse=None, secret=False):
        super().__init__(master, bg=theme.SURFACE)
        tk.Label(self, text=label.upper(), bg=theme.SURFACE, fg=theme.TEXT_FAINT,
                 font=theme.f(8, "bold"), anchor="w").pack(fill="x", pady=(0, 4))
        row = tk.Frame(self, bg=theme.SURFACE)
        row.pack(fill="x")
        self.var = tk.StringVar(value=value)
        entry = tk.Entry(row, textvariable=self.var, show="*" if secret else "",
                         bg=theme.BG, fg=theme.TEXT, insertbackground=theme.TEXT,
                         relief="flat", font=theme.f(9),
                         highlightthickness=1, highlightbackground=theme.BORDER,
                         highlightcolor=theme.ACCENT)
        entry.pack(side="left", fill="x", expand=True, ipady=6)
        if browse:
            FlatButton(row, "Browse", browse, kind="ghost").pack(side="right", padx=(8, 0))


class SettingsPage(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=theme.BG)
        self.app = app
        settings = app.store.data

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=30, pady=(22, 12))
        tk.Label(header, text="Settings", bg=theme.BG, fg=theme.TEXT,
                 font=theme.f(18, "bold")).pack(side="left")

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        openvpn_card = Card(body)
        openvpn_card.pack(fill="x", pady=(0, 12))
        SectionTitle(openvpn_card.body, "OpenVPN engine").pack(fill="x")
        self.openvpn_field = Field(openvpn_card.body, "openvpn.exe path",
                                   settings.openvpn_path, self._browse_openvpn)
        self.openvpn_field.pack(fill="x", pady=(10, 6))
        self.detect_label = tk.Label(openvpn_card.body, text="", bg=theme.SURFACE,
                                     fg=theme.TEXT_FAINT, font=theme.m(8),
                                     anchor="w", justify="left")
        self.detect_label.pack(fill="x")
        FlatButton(openvpn_card.body, "Auto-detect", self._detect,
                   kind="ghost").pack(anchor="w", pady=(8, 0))

        profiles_card = Card(body)
        profiles_card.pack(fill="x", pady=(0, 12))
        SectionTitle(profiles_card.body, "Profiles").pack(fill="x")
        self.profiles_field = Field(profiles_card.body, "folder containing .ovpn files",
                                    settings.profiles_dir, self._browse_profiles)
        self.profiles_field.pack(fill="x", pady=(10, 0))

        creds_card = Card(body)
        creds_card.pack(fill="x", pady=(0, 12))
        SectionTitle(creds_card.body, "ProtonVPN OpenVPN credentials").pack(fill="x")
        tk.Label(creds_card.body,
                 text="account.protonvpn.com > Account > OpenVPN / IKEv2 username",
                 bg=theme.SURFACE, fg=theme.TEXT_FAINT, font=theme.f(8),
                 anchor="w").pack(fill="x", pady=(6, 8))
        self.user_field = Field(creds_card.body, "username", settings.username)
        self.user_field.pack(fill="x", pady=(0, 8))
        self.pass_field = Field(creds_card.body, "password", settings.password, secret=True)
        self.pass_field.pack(fill="x")

        security = Card(body)
        security.pack(fill="x", pady=(0, 12))
        SectionTitle(security.body, "Security").pack(fill="x")
        self.kill_var = tk.BooleanVar(value=settings.kill_switch)
        self.dns_var = tk.BooleanVar(value=settings.block_dns)
        self.crypto_var = tk.BooleanVar(value=settings.crypto_hardening)
        self._toggle_row(security.body, "Kill switch",
                         "Block all non-VPN traffic while connected", self.kill_var)
        self._toggle_row(security.body, "DNS leak protection",
                         "Force all name resolution through the tunnel", self.dns_var)
        self._toggle_row(security.body, "Strict crypto",
                         "TLS 1.2+, forward-secret ciphers, AES-GCM / ChaCha20",
                         self.crypto_var)

        behaviour = Card(body)
        behaviour.pack(fill="x", pady=(0, 12))
        SectionTitle(behaviour.body, "Behaviour").pack(fill="x")
        self.retry_var = tk.BooleanVar(value=settings.auto_retry)
        self._toggle_row(behaviour.body, "Auto-retry",
                         "Re-attempt a failed handshake automatically", self.retry_var)

        actions = tk.Frame(body, bg=theme.BG)
        actions.pack(fill="x", pady=(4, 0))
        FlatButton(actions, "Save settings", self._save, kind="accent").pack(side="left")
        FlatButton(actions, "Check exit IP", self._check_ip, kind="ghost").pack(side="left", padx=8)
        FlatButton(actions, "Remove kill-switch rules", self._clear_killswitch,
                   kind="ghost").pack(side="left")

        self.status = tk.Label(body, text="", bg=theme.BG, fg=theme.TEXT_FAINT,
                               font=theme.f(9), anchor="w")
        self.status.pack(fill="x", pady=(10, 0))

        self.refresh()

    def _toggle_row(self, master, title, subtitle, variable):
        row = tk.Frame(master, bg=theme.SURFACE)
        row.pack(fill="x", pady=6)
        text = tk.Frame(row, bg=theme.SURFACE)
        text.pack(side="left", fill="x", expand=True)
        tk.Label(text, text=title, bg=theme.SURFACE, fg=theme.TEXT,
                 font=theme.f(10), anchor="w").pack(fill="x")
        tk.Label(text, text=subtitle, bg=theme.SURFACE, fg=theme.TEXT_FAINT,
                 font=theme.f(8), anchor="w").pack(fill="x")
        ToggleSwitch(row, variable, bg=theme.SURFACE).pack(side="right")

    def refresh(self):
        path = find_openvpn(self.app.store.data.openvpn_path)
        if not path:
            self.detect_label.configure(
                text="openvpn.exe not found. Install OpenVPN or point at the binary.",
                fg=theme.AMBER)
            return
        has_adapter = adapter_present()
        self.detect_label.configure(
            text="Found: %s\n%s\n%s" % (path, version_of(path) or "unknown version",
                                        "adapter present" if has_adapter
                                        else "no TAP/Wintun adapter yet"),
            fg=theme.GREEN if has_adapter else theme.AMBER)

    def _browse_openvpn(self):
        path = filedialog.askopenfilename(
            title="Select openvpn.exe",
            filetypes=[("OpenVPN executable", "openvpn.exe"), ("Executables", "*.exe")])
        if path:
            self.openvpn_field.var.set(path)

    def _browse_profiles(self):
        path = filedialog.askdirectory(title="Select the folder with .ovpn files")
        if path:
            self.profiles_field.var.set(path)

    def _detect(self):
        found = find_openvpn("")
        if found:
            self.openvpn_field.var.set(found)
            self.status.configure(text="Detected " + found, fg=theme.GREEN)
        else:
            self.status.configure(text="Not found on this system.", fg=theme.AMBER)
        self.refresh()

    def _save(self):
        self.app.store.update(
            openvpn_path=self.openvpn_field.var.get().strip(),
            profiles_dir=self.profiles_field.var.get().strip(),
            username=self.user_field.var.get().strip(),
            kill_switch=self.kill_var.get(),
            block_dns=self.dns_var.get(),
            crypto_hardening=self.crypto_var.get(),
            auto_retry=self.retry_var.get(),
        )
        self.app.store.data.password = self.pass_field.var.get()
        self.app.store.save()
        self.app.reload_profiles()
        self.status.configure(text="Settings saved.", fg=theme.GREEN)

    def _check_ip(self):
        self.status.configure(text="Checking...", fg=theme.TEXT_FAINT)

        def worker():
            info = lookup_public_ip()

            def show():
                if info.ok:
                    self.status.configure(
                        text="Exit IP: %s  %s %s  (%s)" % (info.ip, info.city,
                                                           info.country, info.isp),
                        fg=theme.GREEN)
                    self.app.pages["connect"].set_exit_ip(info.ip, theme.GREEN)
                else:
                    self.status.configure(text="Lookup failed: " + info.error,
                                          fg=theme.RED)
            self.app.post(show)

        threading.Thread(target=worker, daemon=True).start()

    def _clear_killswitch(self):
        self.app.killswitch.clear()
        self.status.configure(text="Kill-switch rules removed.", fg=theme.GREEN)