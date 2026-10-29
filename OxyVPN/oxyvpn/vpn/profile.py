"""Discovery and parsing of OpenVPN .ovpn profiles."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

REMOTE_RE = re.compile(r"^\s*remote\s+(\S+)(?:\s+(\d+))?", re.IGNORECASE | re.MULTILINE)
PROTO_RE = re.compile(r"^\s*proto\s+(\S+)", re.IGNORECASE | re.MULTILINE)
NAME_RE = re.compile(r"^([a-z]{2})[-_ ]?([a-z0-9#_\-]*)", re.IGNORECASE)

COUNTRY_NAMES = {
    "us": "United States", "nl": "Netherlands", "jp": "Japan", "pl": "Poland",
    "ro": "Romania", "de": "Germany", "fr": "France", "gb": "United Kingdom",
    "uk": "United Kingdom", "ca": "Canada", "ch": "Switzerland", "se": "Sweden",
    "no": "Norway", "dk": "Denmark", "fi": "Finland", "es": "Spain",
    "it": "Italy", "at": "Austria", "be": "Belgium", "ie": "Ireland",
    "pt": "Portugal", "cz": "Czechia", "hu": "Hungary", "sk": "Slovakia",
    "bg": "Bulgaria", "gr": "Greece", "au": "Australia", "sg": "Singapore",
    "hk": "Hong Kong", "in": "India", "br": "Brazil", "ar": "Argentina",
    "za": "South Africa", "il": "Israel", "tr": "Turkey", "ua": "Ukraine",
    "ee": "Estonia", "lv": "Latvia", "lt": "Lithuania", "is": "Iceland",
    "lu": "Luxembourg", "mx": "Mexico", "cl": "Chile", "co": "Colombia",
    "cr": "Costa Rica", "md": "Moldova", "rs": "Serbia", "hr": "Croatia",
    "si": "Slovenia", "tw": "Taiwan", "kr": "South Korea", "my": "Malaysia",
    "th": "Thailand", "nz": "New Zealand", "ae": "United Arab Emirates",
    "ng": "Nigeria", "ke": "Kenya", "eg": "Egypt", "ma": "Morocco",
    "tn": "Tunisia", "cy": "Cyprus", "mt": "Malta", "ge": "Georgia",
    "am": "Armenia", "kz": "Kazakhstan", "vn": "Vietnam", "ph": "Philippines",
    "id": "Indonesia", "pk": "Pakistan", "bd": "Bangladesh", "lk": "Sri Lanka",
}


@dataclass
class Profile:
    path: Path
    name: str
    host: str
    port: int
    proto: str
    country_code: str = ""
    country: str = ""
    city: str = ""
    tier: str = ""
    is_free: bool = False
    extras: dict = field(default_factory=dict)

    @property
    def title(self):
        if self.country and self.city:
            return "%s - %s" % (self.country, self.city)
        return self.country or self.country_code.upper() or self.name

    @property
    def subtitle(self):
        return "%s:%d  %s" % (self.host, self.port, self.proto.upper())

    @property
    def key(self):
        return str(self.path)


def _tidy_city(raw: str) -> str:
    text = raw.replace("#", "-").replace("_", "-")
    text = re.sub(r"-(udp|tcp|\d+)$", "", text, flags=re.IGNORECASE)
    text = text.strip("-")
    if text.lower() in ("free", "basic", "plus", "pro"):
        return text.title()
    return text.replace("-", " ").title()


def parse_profile(path: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    remote = REMOTE_RE.search(text)
    if not remote:
        return None

    host = remote.group(1)
    port = int(remote.group(2)) if remote.group(2) else 1194
    proto_match = PROTO_RE.search(text)
    proto = proto_match.group(1).lower() if proto_match else "udp"

    base = path.stem.split(".")[0]
    profile = Profile(path=path, name=base, host=host, port=port, proto=proto)

    match = NAME_RE.match(base)
    if match:
        code = match.group(1).lower()
        profile.country_code = code
        profile.country = COUNTRY_NAMES.get(code, code.upper())
        profile.city = _tidy_city(match.group(2))

    lowered = base.lower()
    profile.is_free = "free" in lowered
    for tier in ("free", "basic", "plus", "pro"):
        if tier in lowered:
            profile.tier = tier
            break

    return profile


def scan_profiles(directory: Path):
    if not directory or not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.rglob("*.ovpn")):
        profile = parse_profile(path)
        if profile is not None:
            found.append(profile)
    return found