"""Primary connection page."""

from __future__ import annotations

import tkinter as tk

from . import theme
from .widgets import Card, ConnectButton, FlatButton, Sparkline, StatTile


class ConnectPage(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=theme.BG)
        self.app = app

        wrap = tk.Frame(self, bg=theme.BG)
        wrap.pack(fill="both", expand=True, padx=30, pady=22)

        header = tk.Frame(wrap, bg=theme.BG)
        header.pack(fill="x")
        tk.Label(header, text="Connection", bg=theme.BG, fg=theme.TEXT,
                 font=theme.f(18, "bold"), anchor="w").pack(side="left")
        self.state_pill = tk.Label(header, text="  IDLE  ", bg=theme.SURFACE_HI,
                                   fg=theme.TEXT_FAINT, font=theme.f(8, "bold"))
        self.state_pill.pack(side="right", pady=(6, 0))
        FlatButton(header, "Restore internet", self.app.restore_internet,
                   kind="ghost").pack(side="right", padx=(0, 10))

        self.button = ConnectButton(wrap, size=182, command=self.app.toggle_connection)
        self.button.pack(pady=(14, 8))

        self.headline = tk.Label(wrap, text="Not connected", bg=theme.BG,
                                 fg=theme.TEXT, font=theme.f(15, "bold"))
        self.headline.pack()
        self.subline = tk.Label(wrap, text="Pick a server and hit connect",
                                bg=theme.BG, fg=theme.TEXT_FAINT, font=theme.f(9),
                                wraplength=620, justify="center")
        self.subline.pack(pady=(4, 16))

        server_card = Card(wrap, pad=14)
        server_card.pack(fill="x")
        row = server_card.body
        tk.Label(row, text="ACTIVE SERVER", bg=theme.SURFACE, fg=theme.TEXT_FAINT,
                 font=theme.f(8, "bold"), anchor="w").pack(fill="x")
        line = tk.Frame(row, bg=theme.SURFACE)
        line.pack(fill="x", pady=(5, 0))
        self.flag = tk.Label(line, text="--", bg=theme.SURFACE_HI, fg=theme.TEXT_DIM,
                             font=theme.f(8, "bold"), width=3, pady=3)
        self.flag.pack(side="left")
        self.server_name = tk.Label(line, text="None selected", bg=theme.SURFACE,
                                    fg=theme.TEXT, font=theme.f(11, "bold"), anchor="w")
        self.server_name.pack(side="left", padx=10)
        FlatButton(line, "Change", lambda: self.app.show_page("servers"),
                   kind="ghost").pack(side="right")
        self.server_detail = tk.Label(row, text="", bg=theme.SURFACE,
                                      fg=theme.TEXT_FAINT, font=theme.m(8), anchor="w")
        self.server_detail.pack(fill="x", pady=(5, 0))

        traffic_card = Card(wrap, pad=16)
        traffic_card.pack(fill="x", pady=(12, 0))
        tk.Label(traffic_card.body, text="THROUGHPUT", bg=theme.SURFACE,
                 fg=theme.TEXT_FAINT, font=theme.f(8, "bold"), anchor="w").pack(fill="x")
        self.graph = Sparkline(traffic_card.body, height=52, bg=theme.SURFACE)
        self.graph.pack(fill="x", pady=(8, 10))

        stats = tk.Frame(traffic_card.body, bg=theme.SURFACE)
        stats.pack(fill="x")
        for column in range(4):
            stats.columnconfigure(column, weight=1)
        self.down = StatTile(stats, "Download", "0 B/s", theme.GREEN)
        self.down.grid(row=0, column=0, sticky="w")
        self.up = StatTile(stats, "Upload", "0 B/s", theme.ACCENT)
        self.up.grid(row=0, column=1, sticky="w")
        self.uptime = StatTile(stats, "Uptime", "00:00:00")
        self.uptime.grid(row=0, column=2, sticky="w")
        self.exit_ip = StatTile(stats, "Exit IP", "checking...", theme.AMBER)
        self.exit_ip.grid(row=0, column=3, sticky="w")

    def set_profile(self, profile):
        if profile is None:
            self.flag.configure(text="--")
            self.server_name.configure(text="None selected")
            self.server_detail.configure(text="")
            return
        self.flag.configure(text=(profile.country_code or "??").upper())
        self.server_name.configure(text=profile.title)
        self.server_detail.configure(text=profile.subtitle)

    def set_state(self, state, headline, subline):
        self.button.set_state({"connected": "connected", "failed": "failed",
                               "connecting": "connecting"}.get(state, "idle"))
        self.headline.configure(text=headline)
        self.subline.configure(text=subline)

        colour, pill = {
            "connected": (theme.GREEN, "CONNECTED"),
            "failed": (theme.RED, "FAILED"),
            "connecting": (theme.ACCENT, "WORKING"),
        }.get(state, (theme.TEXT_FAINT, "IDLE"))
        self.state_pill.configure(text="  %s  " % pill, fg=colour)

    def set_traffic(self, down_bps, up_bps):
        self.down.set(self._rate(down_bps))
        self.up.set(self._rate(up_bps))
        self.graph.push(down_bps)

    def set_uptime(self, seconds):
        self.uptime.set("%02d:%02d:%02d" % (int(seconds // 3600),
                                            int((seconds % 3600) // 60),
                                            int(seconds % 60)))

    def set_exit_ip(self, text, colour=None):
        self.exit_ip.set(text, colour)

    @staticmethod
    def _rate(bps):
        if bps < 1024:
            return "%d B/s" % bps
        if bps < 1024 * 1024:
            return "%.1f KB/s" % (bps / 1024.0)
        return "%.2f MB/s" % (bps / (1024.0 * 1024.0))