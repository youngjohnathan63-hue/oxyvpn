"""Reusable themed widgets.

NOTE: never assign to self._w - Tkinter stores the widget's Tcl path there.
"""

from __future__ import annotations

import math
import tkinter as tk

from . import theme
from .icons import ICONS


def round_rect(canvas, x1, y1, x2, y2, radius, fill, outline="", width=1, tags=None):
    points = [
        x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
        x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
        x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, splinesteps=24,
                                 fill=fill, outline=outline, width=width, tags=tags)


class Card(tk.Frame):
    def __init__(self, master, pad=16, radius=theme.RADIUS, fill=None, bg=None):
        fill = fill or theme.SURFACE
        bg = bg or master["bg"]
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)

        self.body = tk.Frame(self.canvas, bg=fill)
        self._win = self.canvas.create_window(pad, pad, window=self.body, anchor="nw")
        self._pad = pad
        self._radius = radius
        self._fill = fill

        self.body.bind("<Configure>", self._sync)
        self.canvas.bind("<Configure>", self._on_canvas)

    def _on_canvas(self, event):
        self.canvas.itemconfigure(self._win, width=max(1, event.width - 2 * self._pad))
        self._draw()

    def _sync(self, _event=None):
        needed = self.body.winfo_reqheight() + 2 * self._pad
        if abs(self.canvas.winfo_height() - needed) > 1:
            self.canvas.configure(height=needed)
        self._draw()

    def _draw(self):
        self.canvas.delete("panel")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w <= 2 or h <= 2:
            return
        round_rect(self.canvas, 1, 1, w - 2, h - 2, self._radius,
                   self._fill, theme.BORDER, 1, tags="panel")
        self.canvas.tag_lower("panel")


class SectionTitle(tk.Label):
    def __init__(self, master, text, **kw):
        super().__init__(master, text=text.upper(), bg=master["bg"],
                         fg=theme.TEXT_FAINT, font=theme.f(8, "bold"),
                         anchor="w", **kw)


class ToggleSwitch(tk.Canvas):
    def __init__(self, master, variable, width=44, height=23, command=None, bg=None):
        bg = bg or master["bg"]
        super().__init__(master, width=width, height=height, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.var = variable
        self.command = command
        self._width = width
        self._height = height
        self.bind("<Button-1>", self._toggle)
        try:
            self.var.trace_add("write", lambda *_: self._draw())
        except AttributeError:
            self.var.trace("w", lambda *_: self._draw())
        self._draw()

    def _toggle(self, _event=None):
        self.var.set(not self.var.get())
        if self.command:
            self.command()

    def _draw(self):
        self.delete("all")
        on = bool(self.var.get())
        radius = self._height / 2.0
        track = theme.ACCENT if on else theme.BORDER_HI
        self.create_oval(0, 0, self._height, self._height, fill=track, outline=track)
        self.create_oval(self._width - self._height, 0, self._width, self._height,
                         fill=track, outline=track)
        self.create_rectangle(radius, 0, self._width - radius, self._height,
                              fill=track, outline=track)
        knob = radius - 3
        cx = self._width - radius if on else radius
        self.create_oval(cx - knob, radius - knob, cx + knob, radius + knob,
                         fill="#ffffff", outline="#ffffff")


class StatTile(tk.Frame):
    def __init__(self, master, label, value="--", accent=None, bg=None):
        bg = bg or theme.SURFACE
        super().__init__(master, bg=bg)
        self._accent = accent or theme.TEXT
        tk.Label(self, text=label.upper(), bg=bg, fg=theme.TEXT_FAINT,
                 font=theme.f(8, "bold"), anchor="w").pack(fill="x")
        self.value = tk.Label(self, text=value, bg=bg, fg=self._accent,
                              font=theme.f(15, "bold"), anchor="w")
        self.value.pack(fill="x", pady=(3, 0))

    def set(self, text, colour=None):
        try:
            self.value.configure(text=text, fg=colour or self._accent)
        except tk.TclError:
            pass


class NavItem(tk.Frame):
    def __init__(self, master, label, icon, command, bg=None):
        bg = bg or theme.BG_ALT
        super().__init__(master, bg=bg, cursor="hand2")
        self.command = command
        self.icon_name = icon
        self._active = False
        self._base = bg

        self.marker = tk.Frame(self, bg=bg, width=3)
        self.marker.pack(side="left", fill="y")

        self.icon = tk.Canvas(self, width=22, height=22, bg=bg,
                              highlightthickness=0, bd=0)
        self.icon.pack(side="left", padx=(12, 10), pady=11)

        self.label = tk.Label(self, text=label, bg=bg, fg=theme.TEXT_DIM,
                              font=theme.f(10), anchor="w")
        self.label.pack(side="left", fill="x", expand=True)

        for widget in (self, self.icon, self.label):
            widget.bind("<Button-1>", lambda e: self.command())
            widget.bind("<Enter>", lambda e: self._hover(True))
            widget.bind("<Leave>", lambda e: self._hover(False))

        self._draw()

    def _draw(self):
        self.icon.delete("all")
        colour = theme.ACCENT if self._active else theme.TEXT_FAINT
        ICONS[self.icon_name](self.icon, 11, 11, 16, colour, 2)

    def _hover(self, on):
        if self._active:
            return
        colour = theme.SURFACE_HI if on else self._base
        for widget in (self, self.icon, self.label, self.marker):
            widget.configure(bg=colour)

    def set_active(self, active):
        self._active = active
        bg = theme.SURFACE_ACTIVE if active else self._base
        for widget in (self, self.icon, self.label):
            widget.configure(bg=bg)
        self.marker.configure(bg=theme.ACCENT if active else bg)
        self.label.configure(fg=theme.TEXT if active else theme.TEXT_DIM)
        self._draw()


class FlatButton(tk.Label):
    def __init__(self, master, text, command, kind="normal", bg=None, width=None):
        bg = bg or theme.SURFACE
        colours = {
            "normal": (theme.SURFACE_HI, theme.TEXT),
            "accent": (theme.ACCENT, "#ffffff"),
            "ghost": (bg, theme.TEXT_DIM),
            "danger": (theme.RED_DIM, theme.RED),
            "violet": (theme.VIOLET_DIM, theme.VIOLET),
        }
        base_bg, fg = colours.get(kind, colours["normal"])
        super().__init__(master, text=text, bg=base_bg, fg=fg,
                         font=theme.f(9, "bold"), padx=14, pady=7,
                         cursor="hand2", width=width)
        self._base_bg = base_bg
        self.command = command
        self.bind("<Button-1>", lambda e: command())
        self.bind("<Enter>", lambda e: self.configure(bg=self._lighten(base_bg)))
        self.bind("<Leave>", lambda e: self.configure(bg=self._base_bg))

    @staticmethod
    def _lighten(colour):
        return {
            theme.SURFACE_HI: theme.SURFACE_ACTIVE,
            theme.ACCENT: theme.ACCENT_HOVER,
            theme.RED_DIM: "#4d1b21",
            theme.VIOLET_DIM: "#382a63",
        }.get(colour, colour)


class Chip(tk.Label):
    """Selectable filter pill."""

    def __init__(self, master, text, command, bg=None):
        bg = bg or theme.BG
        super().__init__(master, text=text, bg=theme.SURFACE_HI, fg=theme.TEXT_DIM,
                         font=theme.f(8, "bold"), padx=11, pady=5, cursor="hand2")
        self.command = command
        self._bg = bg
        self._selected = False
        self.bind("<Button-1>", lambda e: self.command())
        self.bind("<Enter>", lambda e: self._hover(True))
        self.bind("<Leave>", lambda e: self._hover(False))

    def _hover(self, on):
        if not self._selected:
            self.configure(bg=theme.SURFACE_ACTIVE if on else theme.SURFACE_HI)

    def set_selected(self, value):
        self._selected = value
        self.configure(bg=theme.ACCENT if value else theme.SURFACE_HI,
                       fg="#ffffff" if value else theme.TEXT_DIM)


class ScrollFrame(tk.Frame):
    def __init__(self, master, bg=None):
        bg = bg or theme.BG
        super().__init__(master, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = tk.Scrollbar(self, orient="vertical",
                                      command=self.canvas.yview,
                                      bg=theme.SURFACE_HI, troughcolor=bg,
                                      bd=0, width=10)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

    def _on_inner(self, _event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, event):
        self.canvas.itemconfigure(self._win, width=event.width)

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


class Sparkline(tk.Canvas):
    def __init__(self, master, height=58, colour=theme.ACCENT, bg=None, samples=70):
        bg = bg or theme.SURFACE
        super().__init__(master, height=height, bg=bg, highlightthickness=0, bd=0)
        self.colour = colour
        self.samples = [0.0] * samples
        self.peak = 1024.0
        self.bind("<Configure>", lambda e: self.redraw())

    def push(self, value):
        self.samples.append(max(0.0, value))
        self.samples.pop(0)
        self.peak = max(max(self.samples), 1024.0)
        self.redraw()

    def redraw(self):
        self.delete("all")
        width = self.winfo_width()
        height = self.winfo_height()
        if width < 8 or height < 8:
            return
        step = width / float(len(self.samples) - 1)
        points = []
        for index, value in enumerate(self.samples):
            x = index * step
            y = height - 2 - (value / self.peak) * (height - 8)
            points.append((x, y))
        flat = [coord for point in points for coord in point]
        self.create_polygon(flat + [width, height, 0, height],
                            fill=theme.ACCENT_DIM, outline="", smooth=True)
        self.create_line(flat, fill=self.colour, width=2, smooth=True)
        last = points[-1]
        self.create_oval(last[0] - 2.5, last[1] - 2.5, last[0] + 2.5, last[1] + 2.5,
                         fill=self.colour, outline=self.colour)


class ScoreGauge(tk.Canvas):
    """Circular 0-100 score gauge with animated sweep."""

    def __init__(self, master, size=150, bg=None):
        bg = bg or theme.BG
        super().__init__(master, width=size, height=size, bg=bg,
                         highlightthickness=0, bd=0)
        self.size = size
        self.value = 0.0
        self.target = 0.0
        self.grade = "-"
        self._job = None
        self._halo = self.create_oval(0, 0, 0, 0, outline=theme.BORDER, width=1)
        self._track = self.create_arc(0, 0, 0, 0, start=90, extent=-360,
                                      style="arc", outline=theme.SURFACE_HI, width=9)
        self._sweep = self.create_arc(0, 0, 0, 0, start=90, extent=0,
                                      style="arc", outline=theme.ACCENT, width=9)
        self._value = self.create_text(0, 0, text="--", font=theme.f(30, "bold"),
                                       fill=theme.TEXT)
        self._grade = self.create_text(0, 0, text="", font=theme.f(10, "bold"),
                                       fill=theme.TEXT_FAINT)
        self._layout()

    def _layout(self):
        pad = 12
        self.coords(self._halo, pad - 4, pad - 4, self.size - pad + 4, self.size - pad + 4)
        for item in (self._track, self._sweep):
            self.coords(item, pad, pad, self.size - pad, self.size - pad)
        self.coords(self._value, self.size / 2, self.size / 2 - 6)
        self.coords(self._grade, self.size / 2, self.size / 2 + 24)

    def set_score(self, score, grade):
        self.target = max(0.0, min(100.0, float(score)))
        self.grade = grade
        if self._job is None:
            self._step()

    def _step(self):
        try:
            delta = self.target - self.value
            if abs(delta) < 0.6:
                self.value = self.target
                self._job = None
            else:
                self.value += delta * 0.18
                self._job = self.after(20, self._step)
            self._render()
        except tk.TclError:
            self._job = None

    def _render(self):
        score = int(round(self.value))
        colour = (theme.GREEN if score >= 85 else theme.ACCENT if score >= 70
                  else theme.AMBER if score >= 55 else theme.RED)
        self.itemconfigure(self._sweep, extent=-3.6 * self.value, outline=colour)
        self.itemconfigure(self._value, text=str(score), fill=colour)
        self.itemconfigure(self._grade, text=self.grade)


class ConnectButton(tk.Canvas):
    def __init__(self, master, size=190, command=None, bg=None):
        bg = bg or theme.BG
        super().__init__(master, width=size, height=size, bg=bg,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.size = size
        self.command = command
        self.state = "idle"
        self.hover = False
        self._spin = 0
        self._halo_w = 1
        self._halo_dir = 1
        self._job = None

        cx = cy = size / 2.0
        self._outer = size * 0.46
        self._inner = size * 0.372

        self._halo = self.create_oval(0, 0, 0, 0, outline=theme.BORDER, width=1)
        self._arc1 = self.create_arc(0, 0, 0, 0, start=0, extent=110,
                                     style="arc", outline=theme.ACCENT, width=3,
                                     state="hidden")
        self._arc2 = self.create_arc(0, 0, 0, 0, start=180, extent=70,
                                     style="arc", outline=theme.ACCENT_DIM, width=3,
                                     state="hidden")
        self._disc = self.create_oval(0, 0, 0, 0, outline="")
        self._glyph_arc = self.create_arc(0, 0, 0, 0, start=58, extent=244,
                                          style="arc", width=3, outline=theme.TEXT)
        self._glyph_line = self.create_line(0, 0, 0, 0, width=3, fill=theme.TEXT)
        self._label = self.create_text(0, 0, text="CONNECT",
                                       font=theme.f(9, "bold"), fill=theme.TEXT)

        self.bind("<Button-1>", lambda e: self.command() if self.command else None)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self._layout()
        self.redraw()

    def _layout(self):
        size = self.size
        cx = cy = size / 2.0
        outer, inner = self._outer, self._inner
        for item in (self._halo, self._arc1, self._arc2):
            self.coords(item, cx - outer, cy - outer, cx + outer, cy + outer)
        self.coords(self._disc, cx - inner, cy - inner, cx + inner, cy + inner)
        g = size * 0.28
        r = g / 2.0
        self.coords(self._glyph_arc, cx - r, cy - r + g * 0.10, cx + r, cy + r + g * 0.10)
        self.coords(self._glyph_line, cx, cy - r - g * 0.10, cx, cy + g * 0.06)
        self.coords(self._label, cx, cy + size * 0.21)

    def _on_enter(self, _e):
        self.hover = True
        self.redraw()

    def _on_leave(self, _e):
        self.hover = False
        self.redraw()

    def set_state(self, state):
        if state == self.state:
            return
        self.state = state
        if self._job is None:
            self._tick()
        self.redraw()

    def _tick(self):
        try:
            if self.state == "connecting":
                self._spin = (self._spin + 6) % 360
                self.itemconfigure(self._arc1, start=self._spin)
                self.itemconfigure(self._arc2, start=(self._spin + 180) % 360)
            elif self.state == "connected":
                self._halo_w += self._halo_dir
                if self._halo_w >= 3 or self._halo_w <= 1:
                    self._halo_dir = -self._halo_dir
                self.itemconfigure(self._halo, width=self._halo_w)
            self._job = self.after(33, self._tick)
        except tk.TclError:
            self._job = None

    def _palette(self):
        if self.state == "connected":
            return theme.GREEN, theme.GREEN_DIM, theme.GREEN, "DISCONNECT"
        if self.state == "connecting":
            return theme.ACCENT, theme.ACCENT_DIM, theme.ACCENT, "CANCEL"
        if self.state == "failed":
            return theme.RED, theme.RED_DIM, theme.RED, "RETRY"
        if self.hover:
            return theme.ACCENT, theme.ACCENT_DIM, theme.ACCENT, "CONNECT"
        return theme.BORDER_HI, theme.SURFACE_HI, theme.TEXT, "CONNECT"

    def redraw(self):
        ring, fill, glyph, label = self._palette()
        spinning = self.state == "connecting"
        self.itemconfigure(self._halo, outline=ring, width=1 if not spinning else 2)
        self.itemconfigure(self._arc1, state="normal" if spinning else "hidden", outline=ring)
        self.itemconfigure(self._arc2, state="normal" if spinning else "hidden", outline=ring)
        self.itemconfigure(self._disc, fill=fill, outline=fill)
        self.itemconfigure(self._glyph_arc, outline=glyph)
        self.itemconfigure(self._glyph_line, fill=glyph)
        self.itemconfigure(self._label, text=label, fill=glyph)


class FindingRow(tk.Canvas):
    """Expandable scanner result row."""

    def __init__(self, master, finding, on_toggle):
        self.finding = finding
        self._expanded = False
        self._hover = False
        self._height = 46
        super().__init__(master, height=self._height, bg=theme.BG,
                         highlightthickness=0, bd=0, cursor="hand2")
        self.on_toggle = on_toggle
        self.bind("<Configure>", lambda e: self._draw())
        self.bind("<Button-1>", self._click)
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))

    def _set_hover(self, value):
        self._hover = value
        self._draw()

    def _click(self, _event):
        self._expanded = not self._expanded
        self.on_toggle(self)
        self._draw()

    @property
    def expanded(self):
        return self._expanded

    def _draw(self):
        self.delete("all")
        width = self.winfo_width()
        if width < 20:
            return
        finding = self.finding
        colour = theme.severity_colour(finding.severity.value)

        fill = theme.SURFACE_HI if self._hover else theme.SURFACE
        round_rect(self, 1, 2, width - 2, self._height - 2, 9, fill, theme.BORDER, 1)

        # severity bar
        self.create_rectangle(1, 8, 4, self._height - 8, fill=colour, outline=colour)

        badge = finding.severity.value.upper()
        if finding.status.value == "pass":
            badge, colour = "PASS", theme.GREEN
        elif finding.status.value == "info":
            badge, colour = "INFO", theme.TEXT_FAINT

        self.create_text(18, self._height / 2, text=badge, fill=colour,
                         font=theme.f(8, "bold"), anchor="w")
        self.create_text(86, self._height / 2 - 8, text=finding.title,
                         fill=theme.TEXT, font=theme.f(10, "bold"), anchor="w")
        self.create_text(86, self._height / 2 + 9, text=finding.summary[:110],
                         fill=theme.TEXT_FAINT, font=theme.f(8), anchor="w")
        self.create_text(width - 16, self._height / 2,
                         text="v" if self._expanded else ">",
                         fill=theme.TEXT_FAINT, font=theme.m(9), anchor="e")

    def set_expanded(self, value):
        self._expanded = value
        self._draw()