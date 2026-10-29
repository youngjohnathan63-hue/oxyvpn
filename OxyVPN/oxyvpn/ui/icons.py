"""Vector icons drawn directly on a canvas."""

from __future__ import annotations

import math


def power(canvas, cx, cy, size, colour, width=3):
    r = size / 2.0
    canvas.create_arc(cx - r, cy - r + size * 0.10, cx + r, cy + r + size * 0.10,
                      start=58, extent=244, style="arc", outline=colour, width=width)
    canvas.create_line(cx, cy - r - size * 0.10, cx, cy + size * 0.06,
                       fill=colour, width=width)


def shield(canvas, cx, cy, size, colour, width=2):
    w = size * 0.80
    top = cy - size * 0.52
    canvas.create_polygon([
        cx, top,
        cx + w / 2, top + size * 0.20,
        cx + w / 2, cy + size * 0.06,
        cx, cy + size * 0.54,
        cx - w / 2, cy + size * 0.06,
        cx - w / 2, top + size * 0.20,
    ], outline=colour, fill="", width=width)


def globe(canvas, cx, cy, size, colour, width=2):
    r = size / 2.0
    canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline=colour, width=width)
    canvas.create_oval(cx - r * 0.45, cy - r, cx + r * 0.45, cy + r,
                       outline=colour, width=width)
    canvas.create_line(cx - r, cy, cx + r, cy, fill=colour, width=width)
    canvas.create_arc(cx - r, cy - r * 0.5, cx + r, cy + r * 0.5,
                      start=0, extent=180, style="arc", outline=colour, width=width)


def gear(canvas, cx, cy, size, colour, width=2):
    r = size / 2.0
    inner = r * 0.44
    for i in range(8):
        angle = math.radians(i * 45)
        canvas.create_line(cx + math.cos(angle) * inner, cy + math.sin(angle) * inner,
                           cx + math.cos(angle) * r, cy + math.sin(angle) * r,
                           fill=colour, width=width)
    canvas.create_oval(cx - inner, cy - inner, cx + inner, cy + inner,
                       outline=colour, width=width)


def terminal(canvas, cx, cy, size, colour, width=2):
    w = size * 0.9
    h = size * 0.74
    canvas.create_rectangle(cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2,
                            outline=colour, width=width)
    canvas.create_line(cx - w * 0.28, cy - h * 0.16, cx - w * 0.06, cy,
                       fill=colour, width=width)
    canvas.create_line(cx - w * 0.28, cy + h * 0.16, cx - w * 0.06, cy,
                       fill=colour, width=width)
    canvas.create_line(cx + w * 0.06, cy + h * 0.22, cx + w * 0.30, cy + h * 0.22,
                       fill=colour, width=width)


ICONS = {
    "shield": shield,
    "globe": globe,
    "gear": gear,
    "terminal": terminal,
    "power": power,
}