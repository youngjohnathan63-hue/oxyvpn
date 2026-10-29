"""Colour palette, spacing and fonts."""

from __future__ import annotations

BG = "#080a0f"
BG_ALT = "#0c1017"
SURFACE = "#11161f"
SURFACE_HI = "#181e29"
SURFACE_ACTIVE = "#202838"
BORDER = "#1c2330"
BORDER_HI = "#2b3444"

TEXT = "#eef2f8"
TEXT_DIM = "#95a1b7"
TEXT_FAINT = "#5d677d"

ACCENT = "#4d8dff"
ACCENT_HOVER = "#6ea1ff"
ACCENT_DIM = "#122540"

GREEN = "#2fd98a"
GREEN_DIM = "#0d3526"
AMBER = "#f5b83d"
AMBER_DIM = "#3a2c0d"
RED = "#f4626f"
RED_DIM = "#3a1419"
VIOLET = "#a78bfa"
VIOLET_DIM = "#2a1f4d"

FONT = "Segoe UI"
MONO = "Consolas"

RADIUS = 12
RADIUS_SM = 8

SEVERITY_COLOURS = {
    "critical": RED,
    "high": "#ff8a4c",
    "medium": AMBER,
    "low": ACCENT,
    "info": TEXT_FAINT,
}


def f(size=10, weight="normal"):
    return (FONT, size, weight)


def m(size=9):
    return (MONO, size)


def severity_colour(value):
    return SEVERITY_COLOURS.get(str(value).lower(), TEXT_FAINT)