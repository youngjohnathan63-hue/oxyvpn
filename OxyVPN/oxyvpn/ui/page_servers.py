"""Server browser page."""

from __future__ import annotations

import threading
import tkinter as tk

from ..netinfo import tcp_latency
from . import theme
from .widgets import FlatButton, ScrollFrame, round_rect


class ServerRow(tk.Canvas):
    HEIGHT = 52

    def __init__(self, master, profile, on_connect, on_select):
        super().__init__(master, height=self.HEIGHT, bg=theme.BG,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.profile = profile
        self.on_connect = on_connect
        self.on_select = on_select
        self._hover = False
        self._selected = False

        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", lambda e: self.on_select(self.profile))
        self.bind("<Double-Button-1>", lambda e: self.on_connect(self.profile))
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))

    def _set_hover(self, value):
        self._hover = value
        self._draw()

    def set_selected(self, value):
        self._selected = value
        self._draw()

    def set_latency(self, ms):
        self._latency = ms
        self._draw()

    _latency = -2

    def _draw(self):
        self.delete("all")
        width = self.winfo_width()
        if width < 20:
            return

        if self._selected:
            fill, border = theme.ACCENT_DIM, theme.ACCENT
        elif self._hover:
            fill, border = theme.SURFACE_HI, theme.BORDER_HI
        else:
            fill, border = theme.SURFACE, theme.BORDER

        round_rect(self, 1, 2, width - 2, self.HEIGHT - 2, 10, fill, border, 1)

        self.create_text(20, self.HEIGHT / 2, text=(self.profile.country_code or "??").upper(),
                         fill=theme.TEXT_DIM, font=theme.f(9, "bold"), anchor="w")
        self.create_text(56, self.HEIGHT / 2 - 8, text=self.profile.title,
                         fill=theme.TEXT, font=theme.f(10, "bold"), anchor="w")
        self.create_text(56, self.HEIGHT / 2 + 8, text=self.profile.subtitle,
                         fill=theme.TEXT_FAINT, font=theme.m(8), anchor="w")

        if self._latency == -2:
            text, colour = "--", theme.TEXT_FAINT
        elif self._latency < 0:
            text, colour = "timeout", theme.TEXT_FAINT
        else:
            colour = theme.GREEN if self._latency < 90 else \
                theme.AMBER if self._latency < 200 else theme.RED
            text = "%d ms" % int(self._latency)
        self.create_text(width - 16, self.HEIGHT / 2, text=text, fill=colour,
                         font=theme.m(8), anchor="e")

        if self.profile.is_free:
            self.create_text(width - 74, self.HEIGHT / 2, text="FREE",
                             fill=theme.GREEN, font=theme.f(8, "bold"), anchor="e")


class ServersPage(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=theme.BG)
        self.app = app
        self.rows = []

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=30, pady=(22, 12))
        tk.Label(header, text="Servers", bg=theme.BG, fg=theme.TEXT,
                 font=theme.f(18, "bold")).pack(side="left")
        FlatButton(header, "Rescan", self.app.reload_profiles,
                   kind="ghost").pack(side="right")
        FlatButton(header, "Measure latency", self.measure_latency,
                   kind="ghost").pack(side="right", padx=8)

        self.query = tk.StringVar()
        try:
            self.query.trace_add("write", lambda *_: self._filter())
        except AttributeError:
            self.query.trace("w", lambda *_: self._filter())
        entry = tk.Entry(self, textvariable=self.query, bg=theme.SURFACE,
                         fg=theme.TEXT, insertbackground=theme.TEXT, relief="flat",
                         font=theme.f(10), highlightthickness=1,
                         highlightbackground=theme.BORDER, highlightcolor=theme.ACCENT)
        entry.pack(fill="x", padx=30, ipady=7)

        self.scroll = ScrollFrame(self, bg=theme.BG)
        self.scroll.pack(fill="both", expand=True, padx=30, pady=(12, 20))

        self.empty = tk.Label(self.scroll.inner, text="", bg=theme.BG,
                              fg=theme.TEXT_FAINT, font=theme.f(9), justify="left")

    def refresh(self):
        for row in self.rows:
            row.destroy()
        self.rows = []

        if not self.app.profiles:
            self.empty.configure(
                text=("No .ovpn profiles found.\n\nPut ProtonVPN's OpenVPN config "
                      "files in:\n" + self.app.profiles_dir_text()
                      + "\n\nthen press Rescan.")
            )
            self.empty.pack(anchor="w", pady=12)
            return

        self.empty.pack_forget()
        for profile in self.app.profiles:
            row = ServerRow(self.scroll.inner, profile,
                            on_connect=self.app.connect_to,
                            on_select=self.app.select_profile)
            row.pack(fill="x", pady=2)
            row.set_selected(profile is self.app.selected)
            self.rows.append(row)

    def _filter(self):
        needle = self.query.get().strip().lower()
        for row in self.rows:
            haystack = (row.profile.title + " " + row.profile.subtitle).lower()
            if not needle or needle in haystack:
                row.pack(fill="x", pady=2)
            else:
                row.pack_forget()

    def measure_latency(self):
        rows = list(self.rows)

        def worker():
            for row in rows:
                ms = tcp_latency(row.profile.host, row.profile.port)
                self.app.post(lambda r=row, m=ms: r.set_latency(m))

        threading.Thread(target=worker, daemon=True).start()