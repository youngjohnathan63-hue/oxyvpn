"""Live log page."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog

from ..paths import OPENVPN_LOG
from . import theme
from .widgets import FlatButton


class LogsPage(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=theme.BG)
        self.app = app

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=30, pady=(22, 12))
        tk.Label(header, text="Logs", bg=theme.BG, fg=theme.TEXT,
                 font=theme.f(18, "bold")).pack(side="left")
        FlatButton(header, "Save", self._save, kind="ghost").pack(side="right")
        FlatButton(header, "Clear", self._clear, kind="ghost").pack(side="right", padx=8)
        FlatButton(header, "OpenVPN log", self._open_file, kind="ghost").pack(side="right")

        wrap = tk.Frame(self, bg=theme.BORDER)
        wrap.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self.text = tk.Text(wrap, bg=theme.BG_ALT, fg=theme.TEXT_DIM,
                            insertbackground=theme.TEXT, relief="flat",
                            font=theme.m(9), wrap="none", padx=12, pady=10)
        scroll = tk.Scrollbar(wrap, command=self.text.yview, bd=0, width=10,
                              bg=theme.SURFACE_HI, troughcolor=theme.BG_ALT)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.text.configure(state="disabled")

    def append(self, message: str):
        try:
            self.text.configure(state="normal")
            self.text.insert("end", message + "\n")
            if int(self.text.index("end-1c").split(".")[0]) > 4000:
                self.text.delete("1.0", "500.0")
            self.text.see("end")
            self.text.configure(state="disabled")
        except tk.TclError:
            pass

    def _clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def _save(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            initialfile="oxyvpn.log")
        if path:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.text.get("1.0", "end"))

    def _open_file(self):
        if OPENVPN_LOG.exists():
            os.startfile(str(OPENVPN_LOG))