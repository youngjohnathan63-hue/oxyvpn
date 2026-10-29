"""Host security scanner page."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog

from ..scan.engine import Scanner, total_checks
from ..scan.models import ScanReport
from . import theme
from .widgets import Card, Chip, FlatButton, FindingRow, ScoreGauge, ScrollFrame

CATEGORY_ORDER = ["All", "System", "Hardening", "Persistence", "Network",
                  "Files", "Accounts"]


class ScannerPage(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=theme.BG)
        self.app = app
        self.report = None
        self.rows = []
        self._filter = "All"
        self._scanner = None
        self._running = False

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=30, pady=(22, 12))
        tk.Label(header, text="System Scanner", bg=theme.BG, fg=theme.TEXT,
                 font=theme.f(18, "bold")).pack(side="left")
        self.export_button = FlatButton(header, "Export", self._export, kind="ghost")
        self.export_button.pack(side="right")
        self.run_button = FlatButton(header, "Run scan", self._toggle_scan, kind="accent")
        self.run_button.pack(side="right", padx=8)

        top = tk.Frame(self, bg=theme.BG)
        top.pack(fill="x", padx=30)

        gauge_card = Card(top, pad=16)
        gauge_card.pack(side="left")
        self.gauge = ScoreGauge(gauge_card.body, size=146)
        self.gauge.pack()
        tk.Label(gauge_card.body, text="SECURITY SCORE", bg=theme.SURFACE,
                 fg=theme.TEXT_FAINT, font=theme.f(8, "bold")).pack(pady=(4, 0))

        summary_card = Card(top, pad=18)
        summary_card.pack(side="left", fill="both", expand=True, padx=(12, 0))
        self.summary_title = tk.Label(summary_card.body, text="No scan yet",
                                      bg=theme.SURFACE, fg=theme.TEXT,
                                      font=theme.f(13, "bold"), anchor="w")
        self.summary_title.pack(fill="x")
        self.summary_text = tk.Label(
            summary_card.body,
            text="Runs %d checks across system, hardening, persistence, "
                 "network, files and accounts." % total_checks(),
            bg=theme.SURFACE, fg=theme.TEXT_FAINT, font=theme.f(9),
            anchor="w", justify="left", wraplength=560)
        self.summary_text.pack(fill="x", pady=(6, 12))

        self.progress = tk.Canvas(summary_card.body, height=6, bg=theme.SURFACE,
                                  highlightthickness=0, bd=0)
        self.progress.pack(fill="x")
        self._bar = self.progress.create_rectangle(0, 0, 0, 6,
                                                   fill=theme.ACCENT, outline="")

        self.progress_label = tk.Label(summary_card.body, text="Idle",
                                       bg=theme.SURFACE, fg=theme.TEXT_FAINT,
                                       font=theme.m(8), anchor="w")
        self.progress_label.pack(fill="x", pady=(8, 0))

        chips = tk.Frame(self, bg=theme.BG)
        chips.pack(fill="x", padx=30, pady=(16, 8))
        self.chips = {}
        for name in CATEGORY_ORDER:
            chip = Chip(chips, name, lambda n=name: self._set_filter(n))
            chip.pack(side="left", padx=(0, 6))
            self.chips[name] = chip
        self.chips["All"].set_selected(True)

        self.scroll = ScrollFrame(self, bg=theme.BG)
        self.scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self.empty = tk.Label(self.scroll.inner, text="Press Run scan to begin.",
                              bg=theme.BG, fg=theme.TEXT_FAINT, font=theme.f(9))
        self.empty.pack(anchor="w", pady=14)

    # ------------------------------------------------------------------ run
    def _toggle_scan(self):
        if self._running:
            if self._scanner:
                self._scanner.cancel()
            return
        self._start()

    def _start(self):
        self._running = True
        self.run_button.configure(text="Cancel")
        for row in self.rows:
            row.destroy()
        self.rows = []
        self.empty.pack_forget()
        self.report = None
        self.gauge.set_score(0, "-")
        self.summary_title.configure(text="Scanning...")
        self.summary_text.configure(text="Collecting host information.")
        self.progress_label.configure(text="starting")

        self._scanner = Scanner(
            on_progress=lambda d, t, c, n: self.app.post(
                lambda: self._on_progress(d, t, c, n)),
            on_finding=lambda f: self.app.post(lambda: self._add_finding(f)),
        )
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            report = self._scanner.run()
        except Exception as exc:
            self.app.post(lambda: self.summary_title.configure(
                text="Scan failed: %s" % exc))
            self.app.post(self._finish)
            return
        self.app.post(lambda: self._done(report))

    def _on_progress(self, done, total, category, title):
        try:
            width = max(1, self.progress.winfo_width())
            self.progress.coords(self._bar, 0, 0, width * (done / float(total)), 6)
            self.progress_label.configure(text="%d/%d  %s - %s"
                                          % (done, total, category, title))
        except tk.TclError:
            pass

    def _add_finding(self, finding):
        row = FindingRow(self.scroll.inner, finding, self._on_row_toggle)
        row.pack(fill="x", pady=2)
        self.rows.append(row)

    def _on_row_toggle(self, row):
        target = not row.expanded
        for other in self.rows:
            if other is not row and other.expanded:
                other.set_expanded(False)
        row.set_expanded(target)
        self._resize(row)

    def _resize(self, row):
        base = 46
        if not row.expanded:
            row.configure(height=base)
            row._height = base
            row._draw()
            return
        finding = row.finding
        lines = 1 + len(finding.details) + (2 if finding.remediation else 0)
        row._height = max(base, 30 + lines * 16)
        row.configure(height=row._height)
        row._draw()
        self._draw_detail(row)

    def _draw_detail(self, row):
        row.delete("detail")
        finding = row.finding
        width = row.winfo_width()
        y = 40
        for line in finding.details[:10]:
            row.create_text(20, y, text=line[:130], fill=theme.TEXT_DIM,
                            font=theme.m(8), anchor="w", tags="detail")
            y += 15
        if finding.remediation:
            y += 4
            row.create_text(20, y, text="Fix: " + finding.remediation[:150],
                            fill=theme.ACCENT, font=theme.f(8), anchor="w",
                            tags="detail")
            y += 16
        if finding.evidence:
            y += 2
            row.create_text(20, y, text=finding.evidence[:150].replace("\n", "  |  "),
                            fill=theme.TEXT_FAINT, font=theme.m(8), anchor="w",
                            tags="detail")

    def _done(self, report):
        self.report = report
        self._finish()
        counts = report.counts
        self.gauge.set_score(report.score, report.grade)
        self.summary_title.configure(
            text="Grade %s - %d issue(s) in %.1fs"
                 % (report.grade, len(report.issues), report.duration))
        self.summary_text.configure(
            text="%d critical  ·  %d high  ·  %d medium  ·  %d low"
                 % (counts["critical"], counts["high"], counts["medium"], counts["low"]))
        self.progress_label.configure(
            text="%d checks completed" % len(report.findings))
        if report.errors:
            self.app.log_line("scanner: %d check(s) errored" % len(report.errors))
        self.app.set_scan_score(report.score, report.grade)

    def _finish(self):
        self._running = False
        try:
            self.run_button.configure(text="Run scan")
        except tk.TclError:
            pass

    # --------------------------------------------------------------- filter
    def _set_filter(self, name):
        self._filter = name
        for key, chip in self.chips.items():
            chip.set_selected(key == name)
        self._apply_filter()

    def _apply_filter(self):
        for row in self.rows:
            if self._filter == "All" or row.finding.category == self._filter:
                row.pack(fill="x", pady=2)
            else:
                row.pack_forget()

    # --------------------------------------------------------------- export
    def _export(self):
        if not self.report:
            self.app.toast("Run a scan first", "warn")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile="oxyvpn_scan.txt",
            filetypes=[("Text report", "*.txt"), ("JSON report", "*.json")])
        if not path:
            return
        if path.lower().endswith(".json"):
            import json
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(self.report.to_dict(), handle, indent=2)
        else:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self._render_text())
        self.app.toast("Scan report saved", "good")

    def _render_text(self):
        report = self.report
        lines = ["=" * 74, "  OxyVPN system scan", "=" * 74,
                 "Host      : %s" % report.host.get("hostname", "?"),
                 "OS        : %s" % report.host.get("Caption", "?"),
                 "Started   : %s" % report.started_at,
                 "Duration  : %.1fs" % report.duration,
                 "Score     : %d/100 (grade %s)" % (report.score, report.grade),
                 "Issues    : %d" % len(report.issues), ""]
        for finding in report.findings:
            lines.append("[%s] %s - %s" % (finding.severity.value.upper(),
                                           finding.check_id, finding.title))
            lines.append("    %s" % finding.summary)
            for detail in finding.details[:8]:
                lines.append("      . %s" % detail)
            if finding.remediation:
                lines.append("    Fix: %s" % finding.remediation)
            lines.append("")
        lines.append("Heuristic host audit - not a substitute for a full AV sweep.")
        return "\n".join(lines)